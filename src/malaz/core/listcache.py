"""Persist parsed blocklists across processes.

WHY THIS EXISTS
===============
The real lists are large: 845k URL hashes (55 MB), 386k domains (11 MB).
Parsing them costs ~6.9 s on a cold process and is paid by every CLI run,
every ``evaluation.py`` run and every new GUI process — even though the
content only changes when a feed is imported.

The cache stores the already-normalised set in ``%LocalAppData%\\Malaz\\cache``
and keys it on the source path, mtime and size. A changed file, a different
size, a corrupt payload or a bumped ``LIST_CACHE_VERSION`` is a miss and the
caller parses the original. An unreadable source is never cached: the caller
raises instead and the next attempt tries again.

SECURITY
========
The cache is local per-user data, like the imported lists themselves. It is
never loaded from network input, and a cache file is only accepted when its
embedded path/mtime/size match the current source file. ``marshal`` is used
for speed; a corrupted payload degrades to a parse, never a crash.
"""

from __future__ import annotations

import hashlib
import marshal
import os
import time
from contextlib import suppress
from pathlib import Path

from .. import config
from .atomicwrite import path_lock

# A parsed set of strings is normally smaller than the source text. This cap
# only rejects absurd/tampered cache files before they are deserialized.
_MAX_CACHE_OVERHEAD = 4 * 1024 * 1024
# Small lists are parsed in microseconds; a cache file would cost more than it
# saves and would bypass a permission change on a file the loader should read.
MIN_CACHE_SIZE = 1 * 1024 * 1024


def _cache_path(source: Path, kind: str) -> Path:
    digest = hashlib.sha256(str(source).encode("utf-8", "replace")).hexdigest()[:16]
    return Path(config.CACHE_DIR) / f"{kind}-{digest}.marshal"


def _stat_key(source: Path) -> tuple[int, int] | None:
    try:
        stat = source.stat()
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def stat_key(source: Path) -> tuple[int, int] | None:
    """The cache key for ``source``, captured at call time.

    Loaders must capture this BEFORE parsing and pass it to
    :func:`store_cached`: the key inside the cache file has to describe the
    bytes that were actually parsed, not the file's state after parsing.
    """
    return _stat_key(Path(source))


# Sentinel for "no key captured by the caller" (store uses the current stat).
class _Uncaptured:
    """Type marker for :data:`_UNCAPTURED` (keeps the union checkable)."""


_UNCAPTURED = _Uncaptured()


def load_cached(source: Path, kind: str) -> frozenset[str] | None:
    """Return the cached set for ``source``, or ``None`` on any mismatch."""
    source = Path(source)
    key = _stat_key(source)
    if key is None or key[1] < MIN_CACHE_SIZE:
        return None
    target = _cache_path(source, kind)
    try:
        if target.stat().st_size > source.stat().st_size * 3 + _MAX_CACHE_OVERHEAD:
            return None
        with target.open("rb") as handle:
            # Local per-user cache, never network input; the payload is
            # validated against the source path/mtime/size before use.
            payload = marshal.load(handle)  # noqa: S302  # nosec B302
    except (OSError, EOFError, ValueError, TypeError):
        return None
    if not isinstance(payload, tuple) or len(payload) != 5:
        return None
    version, path, mtime_ns, size, values = payload
    if (
        version != config.LIST_CACHE_VERSION
        or path != str(source)
        or (mtime_ns, size) != key
        or not isinstance(values, frozenset)
        or not all(isinstance(value, str) for value in values)
    ):
        return None
    # A cache hit must not hide a source that became unreadable: the loader's
    # contract is "existing but unreadable = failed stage", not "use stale
    # data silently". Opening one byte is cheap and catches permission/AV
    # interference on Windows.
    try:
        with source.open("rb") as handle:
            handle.read(1)
    except OSError:
        return None
    return values


def store_cached(
    source: Path,
    kind: str,
    values: frozenset[str],
    *,
    expected_key: tuple[int, int] | _Uncaptured | None = _UNCAPTURED,
) -> None:
    """Write the parsed set atomically; failures are a cache miss, not an error.

    ``expected_key`` is the :func:`stat_key` value the caller captured BEFORE
    it parsed ``source``. If the file changed in the meantime (a feed import
    replaced it atomically while we were parsing), the parsed values describe
    the OLD content: storing them under the new stat key would hand every
    later process a stale list that no mtime/size check can ever invalidate —
    exactly the silent stale-blocklist bug. The store is then skipped and the
    next call parses the new file. Callers that do not pass a key keep the
    historical behaviour (key taken at store time).
    """
    source = Path(source)
    current = _stat_key(source)
    if isinstance(expected_key, _Uncaptured):
        key = current
    else:
        key = expected_key
        if key is None or current != key:
            return
    if key is None or key[1] < MIN_CACHE_SIZE:
        return
    target = _cache_path(source, kind)
    payload = (
        config.LIST_CACHE_VERSION,
        str(source),
        key[0],
        key[1],
        values,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    try:
        with path_lock(target):
            with temp.open("wb") as handle:
                marshal.dump(payload, handle, 4)
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(40):
                try:
                    os.replace(temp, target)
                    return
                except PermissionError:
                    if attempt == 39:
                        raise
                    time.sleep(0.025)
    except OSError:
        return
    finally:
        with suppress(OSError):
            temp.unlink(missing_ok=True)
