"""Neo23x0 signature-base rule acquisition (explicit user action only).

The second, independent third-party rule source beside the ReversingLabs
feed (``core.yara_update``). signature-base is published under the
``Detection Rule License (DRL) 1.1``: sharing the rules is permitted, but
only with attribution (rule ``author``, source URI, license text). Malaz
itself ships NO third-party rules — for licence and licensing-clarity
reasons the user fetches them consciously with
``scripts/update_signature_base.bat``. The offline contract is the same as
for ClamAV/freshclam and the ReversingLabs feed: Malaz never goes online at
scan time, only this explicitly triggered run does, and only to the fixed,
allowlisted codeload URL.

Hardening mirrors ``core.yara_update``:
* fixed URL + host re-check (no user input reaches the network target),
* download capped (``YARA_SIGNATURE_BASE_MAX_ZIP_BYTES``),
* only ``yara/<name>.yar`` members of the archive are read and reduced to
  their BASE name (the feed's ``yara`` directory is flat and vendor rules in
  ``vendor/yara`` are deliberately not part of it) — a name containing a
  separator or a drive segment is rejected, so zip-slip cannot survive and
  executables are never extracted,
* the rules listed in the feed's own ``yara/external-variable-rules.txt``
  (``filepath``/``filename``/``extension``) are skipped: Malaz defines no
  external variables at compile time, those rules cannot compile,
* per-file and total-count caps against zip bombs,
* every remaining rule file must COMPILE, and the whole feed is compiled
  into ONE namespaced bundle (``bundle.yarc``) that is swapped in
  atomically — 736 individual compiles at engine start would cost ~1 s,
  the precompiled bundle ~60 ms,
* an empty/failed extraction never wipes the existing feed,
* the license text of the fetched revision plus an attribution note are
  written next to the rules; the rules' ``author`` metadata survives inside
  the compiled bundle.
"""

from __future__ import annotations

import datetime
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


#: Upstream list of rules that need YARA external variables (unusable here).
_EXCLUSION_LIST = "external-variable-rules.txt"
_RULE_SUFFIXES = (".yar", ".yara")
#: Sanity cap for the license text taken out of the archive.
_MAX_LICENSE_BYTES = 64 * 1024


@dataclass
class SignatureBaseUpdateResult:
    ok: bool = False
    installed: int = 0  # rule FILES compiled into the bundle
    rules: int = 0  # individual rules inside the bundle
    skipped: int = 0  # rule files that did not compile / are extern-var rules
    excluded: int = 0  # rules skipped via external-variable-rules.txt
    error: str = ""
    lines: list[str] = field(default_factory=list)


def _validated_url() -> str:
    """Re-check the fixed update target (scheme + allowlisted host)."""
    url = config.YARA_SIGNATURE_BASE_URL
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != config.YARA_SIGNATURE_BASE_HOST:
        raise ValueError(f"unerlaubtes Regel-Update-Ziel: {url}")
    return url


def _download(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Malaz rule update"})
    cap = config.YARA_SIGNATURE_BASE_MAX_ZIP_BYTES
    with urlopen(request, timeout=120) as response:  # nosec B310 - fixed URL
        final = urlparse(response.geturl() or url)
        if final.hostname != config.YARA_SIGNATURE_BASE_HOST or final.scheme != "https":
            raise ValueError(f"Regel-Update wurde umgeleitet: {response.geturl()}")
        data = response.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"Archiv größer als {cap // (1024 * 1024)} MB-Limit")
    return data


def _flat_members(archive: bytes) -> dict[str, bytes]:
    """``{basename: content}`` of the archive's top-level ``yara/`` files.

    The feed layout is ``<repo>-<branch>/yara/<file>``. Anything at another
    depth (``iocs``, ``misc``, ``vendor/yara``) or with a path separator in
    the final segment is ignored — extraction cannot leave the target
    directory because only bare names are ever produced.

    Enforces both per-file and cumulative decompression budgets using bounded
    stream reads so falsified ``file_size == 0`` ZIP headers cannot inflate
    unbounded data or bypass the cumulative budget via repeated skips
    (SEC-008 / SEC-039).
    """
    members: dict[str, bytes] = {}
    total = 0
    budget = config.YARA_SIGNATURE_BASE_MAX_TOTAL_BYTES
    max_file = config.YARA_SIGNATURE_BASE_MAX_FILE_BYTES

    def _budget_error() -> ValueError:
        return ValueError(
            f"Archiv enthält mehr als {budget // (1024 * 1024)} MB "
            "Regel-Inhalt (Gesamtlimit) — Update abgebrochen, damit "
            "das Entpacken keinen Speicher sprengt"
        )

    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        rule_infos = 0
        for info in bundle.infolist():
            if info.is_dir():
                continue
            parts = info.filename.replace("\\", "/").split("/")
            if len(parts) != 3 or parts[1] != "yara":
                continue
            name = parts[2]
            if not is_safe_member_name(name) or name in members:
                continue
            is_rule = name.lower().endswith(_RULE_SUFFIXES)
            if is_rule:
                rule_infos += 1
                if rule_infos > config.YARA_SIGNATURE_BASE_MAX_RULE_FILES:
                    raise ValueError(
                        f"Archiv enthält mehr als "
                        f"{config.YARA_SIGNATURE_BASE_MAX_RULE_FILES} Regel-Dateien"
                    )
            elif name != _EXCLUSION_LIST:
                continue
            if info.file_size > max_file:
                continue  # oversized member: skip, do not abort the update
            if total + info.file_size > budget:
                raise _budget_error()
            data, oversized = read_zip_member_bounded(bundle, info, max_file)
            total += len(data)
            if total > budget:
                raise _budget_error()
            if oversized:
                continue
            members[name] = data
    return members


def _parse_exclusion_list(raw: bytes) -> frozenset[str]:
    """File names from the feed's own ``external-variable-rules.txt``."""
    names = set()
    for line in raw.decode("utf-8", "replace").splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            names.add(entry)
    return frozenset(names)


def _extract_rule_files(archive: bytes) -> tuple[list[tuple[str, bytes]], frozenset[str]]:
    """``(rule files, excluded rule names)`` from the archive."""
    members = _flat_members(archive)
    excluded = _parse_exclusion_list(members.pop(_EXCLUSION_LIST, b""))
    rules = [
        (name, content)
        for name, content in sorted(members.items())
        if name.lower().endswith(_RULE_SUFFIXES) and name not in excluded
    ]
    return rules, excluded


def _license_text(archive: bytes) -> bytes | None:
    """The LICENSE text of the fetched revision, bounded against stream bombs."""
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for info in bundle.infolist():
            parts = info.filename.replace("\\", "/").split("/")
            if len(parts) == 2 and parts[1].upper() == "LICENSE":
                if info.file_size > _MAX_LICENSE_BYTES:
                    raise ValueError(
                        f"LICENSE im Archiv überschreitet {_MAX_LICENSE_BYTES // 1024}-KiB-Limit"
                    )
                data, oversized = read_zip_member_bounded(bundle, info, _MAX_LICENSE_BYTES)
                if oversized:
                    raise ValueError(
                        f"LICENSE im Archiv überschreitet {_MAX_LICENSE_BYTES // 1024}-KiB-Limit"
                    )
                return data
    return None


def _compiles(content: bytes) -> bool:
    if not _HAVE_YARA:
        return True  # engine absent: file validity is checked on next load
    try:
        _yara.compile(source=content.decode("utf-8", "replace"))
        return True
    except Exception:
        return False


def _count_rules(compiled) -> int:
    """Individual rules inside a compiled rule set (0 when not countable)."""
    try:
        return len(list(compiled))
    except Exception:  # pragma: no cover - yara-python has no cheap counter
        return 0


def update_signature_base_rules(line_callback=None) -> SignatureBaseUpdateResult:
    """Fetch, validate and install the signature-base ruleset. Never partial."""
    result = SignatureBaseUpdateResult()

    def say(line: str) -> None:
        result.lines.append(line)
        if line_callback is not None:
            # A broken callback (dialog already closed) must not kill the run.
            with suppress(Exception):
                line_callback(line)

    try:
        url = _validated_url()
        say(f"[Malaz] Lade signature-base-Regeln von {url} …")
        archive = _download(url)
        say(f"[Malaz] Archiv: {len(archive) // 1024} KiB — extrahiere yara/*.yar …")
        candidates, excluded = _extract_rule_files(archive)
        license_bytes = _license_text(archive)
        result.excluded = len(excluded)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        say(f"[Malaz] Update fehlgeschlagen: {result.error} — Bestand unverändert.")
        return result
    if not candidates:
        result.error = "keine Regel-Dateien im Archiv"
        say("[Malaz] Update abgebrochen: keine Regel-Dateien im Archiv.")
        return result

    target_dir = config.YARA_SIGNATURE_BASE_DIR
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        # Validate every rule file, then build ONE compiled bundle: hundreds
        # of individual compiles at engine start would cost about a second,
        # a single precompiled .yarc costs milliseconds to load. Namespaces
        # (the original file names) keep duplicate rule names legal.
        staged: dict[str, bytes] = {}
        for name, content in candidates:
            if _compiles(content):
                staged[name] = content
            else:
                result.skipped += 1
                say(f"[Malaz] Übersprungen (compiliert nicht): {name}")
        say(
            f"[Malaz] {result.excluded} Regeln übersprungen (externe Variablen: "
            f"filepath/filename/extension — Malaz setzt keine)."
        )
        if not staged:
            result.error = "keine der Regel-Dateien compiliert"
            say("[Malaz] Update abgebrochen: keine brauchbaren Regeln.")
            return result
        if _HAVE_YARA:
            sources = {
                name: content.decode("utf-8", "replace")
                for name, content in staged.items()
            }
            bundle = _yara.compile(sources=sources)
            result.rules = _count_rules(bundle)
            # Stage the bundle next to its target and swap it in BEFORE the old
            # files are removed: a crash mid-update must never leave the feed
            # wiped. The reverse order wiped ``bundle.yarc`` first, so a failing
            # os.replace (target held by another process, e.g. an AV scanner)
            # lost the whole feed — the new bundle stayed behind as
            # ``.bundle.yarc.tmp``, which the engine's *.yarc/*.yar/*.yara
            # globs never load.
            temp = target_dir / ".bundle.yarc.tmp"
            target = target_dir / "bundle.yarc"
            bundle.save(str(temp))
            os.replace(temp, target)
            # Same guard as core.yara_update: the walk never crosses a
            # junction/reparse point, and the containment check runs again
            # right before the unlink (SEC-036).
            for old in iter_rule_files(target_dir, (".yar", ".yara", ".yarc")):
                if old == target:  # the bundle just installed
                    continue
                if not is_contained(target_dir, old):
                    continue
                old.unlink()
            result.installed = len(staged)
            say(
                f"[Malaz] {result.installed} Regel-Dateien zu einem Bundle mit "
                f"{result.rules} Regeln vorkompiliert ({result.skipped} "
                f"übersprungen) — gelten ab dem nächsten Scan."
            )
        else:
            # Auch ohne yara-python wird zuerst ein vollständiger Nachbarbaum
            # geschrieben und dann als Ganzes veröffentlicht.
            staging = Path(
                tempfile.mkdtemp(prefix=f".{target_dir.name}.staging-", dir=target_dir.parent)
            )
            try:
                for name, content in staged.items():
                    target = staging / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                _write_attribution(staging, url, license_bytes, result.excluded)
                replace_tree(staging, target_dir)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
            result.installed = len(staged)
            say(
                f"[Malaz] {result.installed} Regel-Dateien installiert "
                f"({result.skipped} übersprungen) — gelten ab dem nächsten Scan."
            )
        if _HAVE_YARA:
            _write_attribution(target_dir, url, license_bytes, result.excluded)
        result.ok = True
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        say(f"[Malaz] Schreibfehler: {result.error}")
    except Exception as exc:  # compile failure of the combined bundle
        result.error = f"{type(exc).__name__}: {exc}"
        say(f"[Malaz] Bundle-Kompilierung fehlgeschlagen: {result.error}")
    return result


def _write_attribution(
    target_dir: Path, url: str, license_bytes: bytes | None, excluded: int
) -> None:
    """License + attribution note next to the rules (DRL 1.1 requires both)."""
    if license_bytes:
        (target_dir / "LICENSE-DRL-1.1.txt").write_bytes(license_bytes)
    (target_dir / "README-signature-base.txt").write_text(
        "signature-base (Neo23x0) — externe YARA-Regeln\n"
        "================================================\n"
        "Quelle:       https://github.com/Neo23x0/signature-base\n"
        f"Bezogen von:  {url}\n"
        f"Aktualisiert: {datetime.datetime.now().astimezone():%d.%m.%Y %H:%M}\n"
        "Lizenz:       Detection Rule License (DRL) 1.1 — Text siehe "
        "LICENSE-DRL-1.1.txt (https://github.com/Neo23x0/signature-base/blob/"
        "master/LICENSE)\n"
        "\n"
        "Die Regel-Dateien wurden lokal zu bundle.yarc vorkompiliert "
        "(Namespace = urspruenglicher Dateiname). Die 'author'-Metadaten der\n"
        "Regeln bleiben im Bundle erhalten und sind dort je Regel "
        "verzeichnet.\n"
        f"{excluded} Regeln aus yara/external-variable-rules.txt wurden "
        "uebersprungen (externe Variablen filepath/filename/extension;\n"
        "Malaz setzt keine externen Variablen).\n"
        "\n"
        "Malaz liefert diese Regeln NICHT mit aus: Sie liegen nur lokal auf "
        "diesem Rechner und wurden durch eine bewusste Nutzeraktion\n"
        "(scripts/update_signature_base.bat) beschafft. Bei einer Weitergabe "
        "der Regeln sind die Attributionspflichten der DRL 1.1\n"
        "einzuhalten (Urheber, Quell-URI, Lizenztext).\n",
        encoding="utf-8",
    )


def describe_install() -> list[str]:
    """Human-readable state of the installed feed (CLI ``--status``)."""
    target_dir = config.YARA_SIGNATURE_BASE_DIR
    lines = [f"Verzeichnis: {target_dir}"]
    if not target_dir.is_dir():
        lines.append("Status:      nicht installiert (keine Regel-Dateien).")
        return lines
    bundle = target_dir / "bundle.yarc"
    if bundle.is_file():
        stats = bundle.stat()
        stamp = datetime.datetime.fromtimestamp(stats.st_mtime).astimezone()
        lines.append(
            f"Bundle:      {bundle.name} ({stats.st_size / 1048576:.1f} MB, "
            f"Stand {stamp:%d.%m.%Y %H:%M})"
        )
        if _HAVE_YARA:
            with suppress(Exception):
                lines.append(f"Regeln:      {_count_rules(_yara.load(str(bundle)))} im Bundle")
        else:
            lines.append("Regeln:      unbekannt (yara-python fehlt).")
    else:
        lines.append("Bundle:      fehlt.")
    sources = [p.name for p in iter_rule_files(target_dir, (".yar", ".yara"))]
    lines.append(f"Quell-Dateien: {len(sources)} (nur ohne yara-python erwartet)")
    attribution = target_dir / "README-signature-base.txt"
    licence = target_dir / "LICENSE-DRL-1.1.txt"
    names = [p.name for p in (attribution, licence) if p.is_file()]
    lines.append("Attribution: " + (", ".join(names) if names else "fehlt."))
    return lines
