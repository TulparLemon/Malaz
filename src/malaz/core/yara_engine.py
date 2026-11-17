"""YARA signature engine.

Loads ``.yar`` source rules from ``rules/yara`` (compiled at runtime), the
third-party feeds below it (``external``, ``signature_base`` — only ever
written by an explicit user action) and, when present, precompiled ``.yarc``
rulesets directly into RAM for fast signature matching. Degrades gracefully
when ``yara-python`` is unavailable.
"""

from __future__ import annotations

import copy
import logging
import math
import os
import re
import stat
import threading
import time
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from ..models import Severity

log = logging.getLogger(__name__)

try:  # optional dependency
    import yara as _yara

    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _yara = None
    _HAVE_YARA = False


_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _load_disabled_rules() -> frozenset[str]:
    """Rule names switched off via ``rules/yara/external_disabled.txt``.

    Kill switch for third-party feed rules (both feeds) that misfire on
    benign files: one rule name per line, ``#`` starts a comment. Missing
    file -> nothing disabled. Own curated rules cannot be disabled this way —
    their vetting is the regression suite, not a user list.
    """
    path = config.YARA_EXTERNAL_DISABLED
    try:
        if not path.is_file():
            return frozenset()
        names = set()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry:
                names.add(entry)
        return frozenset(names)
    except OSError:
        return frozenset()


# SEC-038: ``import "console"`` makes YARA write to stdout for every match —
# outside the log sink and invisible in the report. Rule sources from feeds
# and curated files are rejected before compiling. ``include`` is disabled for
# feed sources so a downloaded rule cannot read arbitrary local/UNC files.
_CONSOLE_IMPORT = re.compile(r'\bimport\s*"\s*console\s*"', re.IGNORECASE)


def _imports_console(path: Path) -> bool:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(_CONSOLE_IMPORT.search(source))


# Windows marks junctions, mount points and similar links with this FILE_
# attribute. The constant only exists on Windows; the walk below checks the
# attribute defensively and is a no-op elsewhere.
_REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_contained(root: Path, candidate: Path) -> bool:
    """True only if ``candidate`` really resolves to a path inside ``root``.

    ``resolve()`` follows junctions and symlinks: a file reachable below
    ``root`` only through a reparse point resolves outside and is rejected.
    Used as the last gate before any ``unlink()``/compile in the rule trees,
    so a junction planted below ``rules/yara`` can never make the update or
    the loader touch a user directory.
    """
    try:
        return Path(candidate).resolve().is_relative_to(Path(root).resolve())
    except (OSError, RuntimeError):
        return False


def _is_reparse_point(entry: os.DirEntry) -> bool:
    """Junction, symlink or other reparse point — never descended into."""
    try:
        if entry.is_symlink() or entry.is_junction():
            return True
    except (AttributeError, OSError):
        return True
    try:
        attributes = entry.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & _REPARSE_POINT_ATTRIBUTE)


def iter_rule_files(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """Yield rule files below ``root`` without ever leaving the tree.

    ``Path.rglob`` skips symlinks but NOT directory junctions
    (``is_symlink()`` is ``False`` for them). A ``mklink /J`` below
    ``rules/yara/external`` made the cleanup loop delete ``*.yar`` files in
    the user's Documents folder, and ``_load_feed`` compiled them (SEC-036).
    This walk prunes every reparse point; callers additionally check
    :func:`is_contained` before using a path.
    """
    root = Path(root)
    if not root.is_dir():
        return
    stack = [root]
    while stack:
        current = stack.pop()
        if not is_contained(root, current):
            continue
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if _is_reparse_point(entry):
                            continue
                        path = Path(entry.path)
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(path)
                        elif (
                            entry.is_file(follow_symlinks=False)
                            and path.suffix.lower() in suffixes
                        ):
                            yield path
                    except OSError:
                        continue
        except OSError:
            continue


@dataclass
class YaraMatch:
    rule: str
    severity: Severity
    description: str
    weight: int | None
    matched_strings: list[str] = field(default_factory=list)
    # DRL 1.1 requires the author in hit-based reports. Empty for rules that
    # do not declare one (curated Malaz rules).
    author: str = ""


@dataclass(frozen=True)
class YaraScanOutcome:
    """Per-file result of a YARA scan, independent of engine-global state."""

    matches: list[YaraMatch]
    load_error: str | None
    scan_error: str | None


class YaraEngine:
    """Loads and applies YARA rules."""

    def __init__(self, rules_dir: Path | None = None):
        self.rules_dir = rules_dir or config.YARA_RULES_DIR
        self._rules_lock = threading.RLock()
        self._rules: list = []  # compiled rule sets, one per rule file
        self._disabled: frozenset[str] = frozenset()
        self.available = _HAVE_YARA
        self.load_error: str | None = None
        # Gesetzt, wenn ein Regelsatz zur LAUFZEIT geworfen hat (Timeout,
        # praeparierte Eingabe). Die Pipeline macht daraus einen sichtbaren
        # Befund: "nicht geprueft" darf nicht wie "sauber" aussehen.
        self.scan_error: str | None = None
        if _HAVE_YARA:
            self._load()

    def _load(self) -> None:
        """Compile a complete rule snapshot, then publish it atomically."""
        lock = getattr(self, "_rules_lock", None)
        if lock is None:
            lock = self._rules_lock = threading.RLock()
        rules: list = []
        feed_rule_ids: set[int] = set()
        disabled = _load_disabled_rules()
        errors: list[str] = []
        load_error: str | None = None
        try:
            rule_files: list[Path] = []
            yarc_stems: set[str] = set()
            if self.rules_dir.exists():
                for pattern in ("*.yar", "*.yara"):
                    rule_files.extend(sorted(self.rules_dir.glob(pattern)))
                yarc_stems = {p.stem for p in self.rules_dir.glob("*.yarc")}
            rule_files = [p for p in rule_files if p.stem not in yarc_stems]
            for path in rule_files:
                try:
                    if _imports_console(path):
                        errors.append(
                            f"{path.name}: import \"console\" ist gesperrt"
                        )
                        log.warning(
                            "YARA rule file rejected (console import): %s", path.name
                        )
                        continue
                    rules.append(_yara.compile(filepath=str(path)))
                except _yara.Error as exc:
                    errors.append(f"{path.name}: {exc}")
                    log.warning(
                        "YARA rule file failed to compile: %s: %s", path.name, exc
                    )
            if self.rules_dir.exists():
                for yarc in sorted(self.rules_dir.glob("*.yarc")):
                    try:
                        rules.append(_yara.load(str(yarc)))
                    except _yara.Error as exc:
                        errors.append(f"{yarc.name}: {exc}")
                        log.warning(
                            "YARC rule file failed to load: %s: %s", yarc.name, exc
                        )
            for name in config.YARA_FEED_DIRS:
                self._load_feed(
                    self.rules_dir / name, errors, rules, feed_rule_ids
                )
            if errors:
                load_error = "; ".join(errors)[: config.MAX_STRING_CAPTURE]
        except Exception as exc:  # malformed rules must not crash the app
            load_error = f"{type(exc).__name__}: {exc}"
            rules = []
            log.warning("YARA rules failed to compile: %s", load_error)

        with lock:
            self._rules = rules
            self._feed_rule_ids = frozenset(feed_rule_ids)
            self._disabled = disabled
            self.load_error = load_error

    def _load_feed(
        self,
        feed: Path,
        errors: list[str],
        rules: list,
        feed_rule_ids: set[int],
    ) -> None:
        """Load one third-party feed into the caller's unpublished snapshot.

        Feed sources are compiled with ``includes=False`` and without the
        ``console`` module (SEC-038). ``feed_rule_ids`` remembers which
        compiled sets came from a feed, so the disable list only applies to
        those — a curated rule with the same name stays active (BUG-078).
        """
        if not feed.exists():
            return
        yarcs = sorted(iter_rule_files(feed, (".yarc",)))
        if yarcs:
            for yarc in yarcs:
                if not is_contained(feed, yarc):
                    errors.append(
                        f"{yarc.relative_to(feed)}: ausserhalb des Regelverzeichnisses"
                    )
                    continue
                try:
                    loaded = _yara.load(str(yarc))
                    rules.append(loaded)
                    feed_rule_ids.add(id(loaded))
                except _yara.Error as exc:
                    errors.append(f"{yarc.relative_to(feed)}: {exc}")
                    log.warning(
                        "Feed YARC failed to load (%s): %s: %s", feed.name, yarc.name, exc
                    )
            return
        for path in sorted(
            [*iter_rule_files(feed, (".yar",)), *iter_rule_files(feed, (".yara",))]
        ):
            if not is_contained(feed, path):
                errors.append(
                    f"{path.name}: ausserhalb des Regelverzeichnisses"
                )
                continue
            try:
                if _imports_console(path):
                    errors.append(
                        f"{path.name}: import \"console\" ist gesperrt"
                    )
                    log.warning(
                        "Feed YARA rule rejected (console import, %s): %s",
                        feed.name,
                        path.name,
                    )
                    continue
                compiled = _yara.compile(filepath=str(path), includes=False)
                rules.append(compiled)
                feed_rule_ids.add(id(compiled))
            except _yara.Error as exc:
                errors.append(f"{path.name}: {exc}")
                log.warning(
                    "Feed YARA rule file failed to compile (%s): %s: %s",
                    feed.name,
                    path.name,
                    exc,
                )

    def reload(self) -> None:
        """Re-read rule files and atomically publish the new snapshot."""
        if _HAVE_YARA:
            self._load()

    @property
    def rule_count(self) -> int:
        lock = getattr(self, "_rules_lock", None)
        if lock is None:
            return len(self._rules)
        with lock:
            return len(self._rules)

    def scan_with_status(self, data: bytes) -> YaraScanOutcome:
        """Scan in-memory bytes against an immutable rule snapshot."""
        return self._scan_with_status(data=data)

    def scan_file_with_status(self, path) -> YaraScanOutcome:
        """Scan a whole file from disk (mmap), used for large files.

        The file is never loaded into a Python bytes buffer; yara-python maps
        it internally. A missing/unreadable file degrades to a scan error,
        which the pipeline turns into a visible incomplete finding.
        """
        return self._scan_with_status(filepath=path)

    def _scan_with_status(self, data: bytes | None = None, filepath=None) -> YaraScanOutcome:
        """Shared implementation for in-memory and path-backed scans."""
        lock = getattr(self, "_rules_lock", None)
        if lock is None:
            lock = self._rules_lock = threading.RLock()
        with lock:
            rules = tuple(self._rules)
            feed_rule_ids: frozenset[int] = frozenset(getattr(self, "_feed_rule_ids", ()))
            disabled = self._disabled
            load_error = self.load_error

        if not self.available or (not data and filepath is None):
            return YaraScanOutcome([], load_error, "")
        if not rules:
            # BUG-079: an empty rule set is NOT a clean scan — every file
            # would pass the stage unexamined. Report it through the
            # "incomplete" channel so the pipeline's YARA_SCAN_ERROR stays
            # visible (weight 25) instead of reading as an acquittal.
            return YaraScanOutcome(
                [],
                load_error,
                "keine YARA-Regeln geladen — es wurde nichts geprüft; ein "
                "Treffer wäre unentdeckt geblieben.",
            )

        matches: list[tuple[bool, Any]] = []
        fehler: list[str] = []
        deadline = time.monotonic() + float(
            getattr(config, "YARA_SCAN_BUDGET_SECONDS", 30)
        )
        for nummer, rule_set in enumerate(rules):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fehler.append("YARA-Gesamtbudget fuer diese Datei ueberschritten")
                break
            try:
                timeout = max(1, math.ceil(min(10.0, remaining)))
                if filepath is not None:
                    hits = rule_set.match(filepath=str(filepath), timeout=timeout)
                else:
                    hits = rule_set.match(data=data, timeout=timeout)
                is_feed = id(rule_set) in feed_rule_ids
                matches.extend((is_feed, match) for match in hits)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("YARA scan error (Regelsatz %d): %s", nummer, exc)
                fehler.append(f"{type(exc).__name__}: {exc}")
        scan_error = "; ".join(fehler)[: config.MAX_STRING_CAPTURE]

        results: list[YaraMatch] = []
        for is_feed, match in matches:
            # Only FEED rules are user-disableable. A curated rule with the
            # same name must keep firing (BUG-078); its vetting is the
            # regression suite, not a name list.
            if is_feed and match.rule in disabled:
                continue
            meta = getattr(match, "meta", {}) or {}
            severity = _SEVERITY_MAP.get(
                str(meta.get("severity", "high")).lower(), Severity.HIGH
            )
            weight_raw = meta.get("weight")
            weight: int | None = None
            if isinstance(weight_raw, bool):
                weight = None
            elif isinstance(weight_raw, int):
                weight = weight_raw
            elif isinstance(weight_raw, str) and weight_raw.lstrip("-").isdigit():
                weight = int(weight_raw)
            strings = []
            for item in getattr(match, "strings", []) or []:
                identifier = getattr(item, "identifier", None)
                if identifier:
                    strings.append(identifier)
            results.append(
                YaraMatch(
                    rule=match.rule,
                    severity=severity,
                    description=str(meta.get("description", match.rule)),
                    weight=weight,
                    matched_strings=strings,
                    author=str(meta.get("author", ""))[:120],
                )
            )
        return YaraScanOutcome(
            matches=results,
            load_error=load_error,
            scan_error=scan_error,
        )

    def scan(self, data: bytes) -> list[YaraMatch]:
        """Compatibility view; new pipeline code consumes ``scan_with_status``."""
        outcome = self.scan_with_status(data)
        self.scan_error = outcome.scan_error
        return outcome.matches



def read_zip_member_bounded(
    bundle: zipfile.ZipFile, info: zipfile.ZipInfo, max_bytes: int
) -> tuple[bytes, bool]:
    """Read up to ``max_bytes + 1`` decompressed bytes without trusting ``file_size``.

    ``ZipExtFile`` clamps reads at ``zipinfo.file_size`` and only checks CRC at
    that artificial EOF, so a forged ``file_size == 0`` (or ``1``) header can
    hide a large deflate stream or evade cumulative volume accounting (SEC-008).
    Probing with ``file_size = max_bytes + 1`` and explicit CRC/length checks
    exposes the real stream volume while bounding memory to ``max_bytes + 1``.

    Returns ``(payload, oversized)`` where ``oversized`` is ``True`` when the
    stream exceeded ``max_bytes`` (``len(payload)`` is still the byte count read
    for cumulative budget accounting). Raises ``zipfile.BadZipFile`` when a
    non-oversized member's stream length or CRC disagrees with its header.
    """
    probe = copy.copy(info)
    expected_crc = getattr(info, "CRC", None)
    probe.file_size = max_bytes + 1
    if hasattr(probe, "CRC"):
        probe.CRC = None  # type: ignore[assignment]
    chunks: list[bytes] = []
    read_len = 0
    limit = max_bytes + 1
    with bundle.open(probe) as handle:
        while read_len < limit:
            chunk = handle.read(min(65536, limit - read_len))
            if not chunk:
                break
            chunks.append(chunk)
            read_len += len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        return data, True
    if len(data) != info.file_size:
        raise zipfile.BadZipFile(
            f"Größenangabe im Archiv gefälscht für {info.filename!r}: "
            f"deklariert {info.file_size} B, gelesen {len(data)} B"
        )
    if expected_crc is not None and (zlib.crc32(data) & 0xFFFFFFFF) != expected_crc:
        raise zipfile.BadZipFile(f"CRC-32 ungültig für {info.filename!r}")
    return data, False
