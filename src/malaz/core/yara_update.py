"""External YARA rule update (explicit user action only).

Pulls the pinned, MIT-licensed ReversingLabs ruleset (~1.5k rules in
``yara/<category>/*.yara``) from GitHub's codeload endpoint into
``rules/yara/external`` — the same offline contract as the ClamAV/freshclam
button: Malaz never goes online at scan time, only this explicitly
triggered update does, and only to the fixed allowlisted URL.

Hardened by construction:
* fixed URL + host re-check (no user input reaches the network target),
* download capped (``YARA_UPDATE_MAX_ZIP_BYTES``),
* only ``.yar``/``.yara`` members are considered; their paths are reduced
  to the sanitized part below the feed's ``yara/`` directory (category
  subdirs preserved, traversal/drive segments rejected — zip-slip cannot
  survive, executables are never extracted),
* per-file and total-count caps against zip bombs,
* every rule file must COMPILE, and the whole feed is compiled into ONE
  namespaced bundle (``bundle.yarc``) that is swapped in atomically —
  1.5k individual compiles at engine start would cost seconds, one
  precompiled bundle costs milliseconds,
* an empty/failed extraction never wipes the existing feed.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import zipfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .. import config
from ..security.safe_extract import is_safe_member_name
from .atomicwrite import replace_tree
from .yara_engine import is_contained, iter_rule_files, read_zip_member_bounded

try:  # optional dependency, mirrors yara_engine
    import yara as _yara

    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _yara = None
    _HAVE_YARA = False


@dataclass
class YaraUpdateResult:
    ok: bool = False
    installed: int = 0
    skipped: int = 0
    error: str = ""
    lines: list[str] = field(default_factory=list)


def _validated_url() -> str:
    """Re-check the fixed update target (scheme + allowlisted host)."""
    url = config.YARA_UPDATE_URL
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != config.YARA_UPDATE_HOST:
        raise ValueError(f"unerlaubtes Regel-Update-Ziel: {url}")
    return url


def _download(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Malaz rule update"})
    cap = config.YARA_UPDATE_MAX_ZIP_BYTES
    with urlopen(request, timeout=120) as response:  # nosec B310 - fixed URL
        final = urlparse(response.geturl() or url)
        if final.hostname != config.YARA_UPDATE_HOST or final.scheme != "https":
            raise ValueError(f"Regel-Update wurde umgeleitet: {response.geturl()}")
        data = response.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"Archiv größer als {cap // (1024 * 1024)} MB-Limit")
    return data


def _safe_member_subpath(name: str) -> str | None:
    """Sanitized relative path (category subdir preserved), or None.

    Keeps at most the part below the feed's ``yara/`` directory (the zip
    root carries the repo-branch prefix), flattens anything without that
    marker, and rejects traversal or drive-like segments outright.

    Both separators are normalised first — the same step
    ``core.yara_signature_base._flat_members`` performs, and the reason it
    was never affected: a member named ``a\\..\\..\\evil.yar`` carries no
    ``/`` at all, so splitting on ``/`` left the ``..`` segments inside ONE
    component and the checks below waved them through. Windows resolves
    that backslash form as a separator all the same (measured: the write
    target escaped to the parent of ``external/``). ``is_safe_member_name``
    then applies the repo-wide Zip-Slip rule, which also covers the
    Windows-only bypasses of an exact segment match (``".. "`` collapses to
    ``..`` when resolving, alternate data streams, device names).
    """
    marker = "/yara/"
    name = name.replace("\\", "/")
    name = name.split(marker, 1)[1] if marker in name else name.rsplit("/", 1)[-1]
    if not is_safe_member_name(name):
        return None
    parts = []
    for segment in name.split("/"):
        if segment in ("", ".", "..") or ":" in segment:
            return None
        parts.append(segment)
    if not parts or not parts[-1].lower().endswith((".yar", ".yara")):
        return None
    return "/".join(parts)


def _extract_rule_files(archive: bytes) -> list[tuple[str, bytes]]:
    """Validated (relative name, content) pairs of the rule members.

    Besides the per-file cap, the SUM of the extracted content is bounded:
    the per-file limit alone let 2000 files of 2 MiB buffer ~4 GiB from a
    small archive (SEC-039). Both the declared sizes (before reading) and the
    bytes actually read count against the budget.
    """
    out: list[tuple[str, bytes]] = []
    total = 0
    budget = config.YARA_UPDATE_MAX_TOTAL_BYTES

    def _budget_error() -> ValueError:
        return ValueError(
            f"Archiv enthält mehr als {budget // (1024 * 1024)} MB "
            "Regel-Inhalt (Gesamtlimit) — Update abgebrochen, damit "
            "das Entpacken keinen Speicher sprengt"
        )

    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        infos = [
            info for info in bundle.infolist()
            if not info.is_dir()
            and info.filename.lower().endswith((".yar", ".yara"))
        ]
        if len(infos) > config.YARA_UPDATE_MAX_RULE_FILES:
            raise ValueError(
                f"Archiv enthält {len(infos)} Regel-Dateien "
                f"(Limit {config.YARA_UPDATE_MAX_RULE_FILES})"
            )
        max_file = config.YARA_UPDATE_MAX_FILE_BYTES
        seen: set[str] = set()
        for info in infos:
            if info.file_size > max_file:
                continue  # oversized member: skip, do not abort the update
            subpath = _safe_member_subpath(info.filename)
            if subpath is None or subpath in seen:
                continue
            if total + info.file_size > budget:
                raise _budget_error()
            content, oversized = read_zip_member_bounded(bundle, info, max_file)
            total += len(content)
            if total > budget:
                raise _budget_error()
            if oversized:
                continue
            seen.add(subpath)
            out.append((subpath, content))
    return out


def _compiles(content: bytes) -> bool:
    if not _HAVE_YARA:
        return True  # engine absent: file validity is checked on next load
    try:
        _yara.compile(source=content.decode("utf-8", "replace"))
        return True
    except Exception:
        return False


def update_external_rules(line_callback=None) -> YaraUpdateResult:
    """Fetch, validate and install the external ruleset. Never partial."""
    result = YaraUpdateResult()

    def say(line: str) -> None:
        result.lines.append(line)
        if line_callback is not None:
            # A broken callback (dialog already closed) must not kill the run.
            with suppress(Exception):
                line_callback(line)

    try:
        url = _validated_url()
        say(f"[Malaz] Lade Regel-Set von {url} …")
        archive = _download(url)
        say(f"[Malaz] Archiv: {len(archive) // 1024} KiB — extrahiere *.yar …")
        candidates = _extract_rule_files(archive)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        say(f"[Malaz] Update fehlgeschlagen: {result.error} — Bestand unverändert.")
        return result
    if not candidates:
        result.error = "keine Regel-Dateien im Archiv"
        say("[Malaz] Update abgebrochen: keine Regel-Dateien im Archiv.")
        return result

    external = config.YARA_EXTERNAL_DIR
    try:
        external.mkdir(parents=True, exist_ok=True)
        # Validate every rule file, then build ONE compiled bundle: 1.5k
        # individual compiles at engine start would cost many seconds, a
        # single precompiled .yarc costs milliseconds to load. Namespaces
        # (one per relative file path) make duplicate rule names legal.
        staged: dict[str, bytes] = {}
        for subpath, content in candidates:
            if _compiles(content):
                staged[subpath] = content
            else:
                result.skipped += 1
                say(f"[Malaz] Übersprungen (compiliert nicht): {subpath}")
        if not staged:
            result.error = "keine der Regel-Dateien compiliert"
            say("[Malaz] Update abgebrochen: keine brauchbaren Regeln.")
            return result
        if _HAVE_YARA:
            sources = {
                subpath: content.decode("utf-8", "replace")
                for subpath, content in staged.items()
            }
            bundle = _yara.compile(sources=sources)
            # Stage the bundle next to its target and swap atomically: a
            # crash mid-update must never leave the feed wiped.
            temp = external / ".bundle.yarc.tmp"
            target = external / "bundle.yarc"
            bundle.save(str(temp))
            # Install first; only then remove the previous source files. If the
            # swap fails, the old feed remains loadable.
            os.replace(temp, target)
            # The walk prunes junctions/reparse points and the containment
            # check guards the unlink itself: rglob followed a junction planted
            # below external/ and deleted rule files in the user's home
            # (SEC-036).
            for old in iter_rule_files(external, (".yar", ".yara", ".yarc")):
                if old == target:
                    continue
                if not is_contained(external, old):
                    continue
                old.unlink()
            result.installed = len(staged)
            say(f"[Malaz] {result.installed} Regeln zu einem Bundle "
                f"vorkompiliert ({result.skipped} übersprungen) — gelten ab "
                f"dem nächsten Scan.")
        else:
            # Ohne yara-python werden die Quellen selbst installiert. Auch
            # dieser Zweig darf keinen halben Feed hinterlassen: erst komplett
            # in eine Nachbarinstanz schreiben, dann den Baum veröffentlichen.
            staging = Path(
                tempfile.mkdtemp(prefix=f".{external.name}.staging-", dir=external.parent)
            )
            try:
                for subpath, content in staged.items():
                    target = staging / subpath
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                _write_attribution(staging, url)
                replace_tree(staging, external)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
            result.installed = len(staged)
            say(f"[Malaz] {result.installed} Regel-Dateien installiert "
                f"({result.skipped} übersprungen) — gelten ab dem nächsten Scan.")
        if _HAVE_YARA:
            _write_attribution(external, url)
        result.ok = True
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        say(f"[Malaz] Schreibfehler: {result.error}")
    except Exception as exc:  # compile failure of the combined bundle
        result.error = f"{type(exc).__name__}: {exc}"
        say(f"[Malaz] Bundle-Kompilierung fehlgeschlagen: {result.error}")
    return result


def _write_attribution(external: Path, url: str) -> None:
    """License/attribution note shipped next to the rules (MIT requires it)."""
    import datetime

    note = external / "README-externe-regeln.txt"
    note.write_text(
        "Externe YARA-Regeln — Quelle: ReversingLabs (MIT-Lizenz)\n"
        f"Quell-URL: {url}\n"
        f"Aktualisiert: {datetime.datetime.now().astimezone():%d.%m.%Y %H:%M}\n"
        "Lizenz: https://github.com/reversinglabs/reversinglabs-yara-rules\n"
        "Die Regeln liegen unverändert neben dieser Datei.\n",
        encoding="utf-8",
    )
