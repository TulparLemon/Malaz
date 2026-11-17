"""Dispatcher: routes a file to the right pipelines and aggregates the result.

Responsibilities:
* read the file within the configured size limits and compute hashes,
* detect the real type via magic bytes (not the extension),
* select and run the matching pipelines with per-pipeline error isolation,
* recursively expand archives (Zip-Slip- and bomb-safe) and scan members,
* run the local Windows Defender scan for top-level files,
* aggregate all indicators (including nested members) into a score.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import config
from ..analysis.clamav import ClamAVScanner
from ..analysis.defender_status import DefenderStatus
from ..analysis.defender_status import probe as probe_defender
from ..analysis.external_scanner import ExternalScanner, build_scanners
from ..analysis.windows_av import WindowsDefenderScanner
from ..models import (
    CAT_ARCHIVE,
    CAT_AV,
    CAT_CLAMAV,
    CAT_RESOURCE,
    AnalysisContext,
    Indicator,
    ScanResult,
    Severity,
    StageTiming,
)
from ..pipelines.archive_pipeline import ArchivePipeline
from ..pipelines.base import Pipeline
from ..pipelines.elf_pipeline import ElfPipeline
from ..pipelines.eml_pipeline import EmlPipeline
from ..pipelines.generic_pipeline import GenericPipeline
from ..pipelines.image_pipeline import ImagePipeline
from ..pipelines.macho_pipeline import MachoPipeline
from ..pipelines.office_pipeline import OfficePipeline
from ..pipelines.pdf_pipeline import PdfPipeline
from ..pipelines.pe_pipeline import PePipeline
from ..security.limits import LimitExceeded, guard_file_size, guard_read_size
from . import magic
from .archive import (
    BUDGET_STOP_PREFIX,
    UNSAFE_NAME_PREFIX,
    ZIPSLIP_PREFIX,
    iter_zip_members,
)
from .engine_verdicts import build_engine_verdicts
from .filesource import FileSource
from .log_privacy import anonymize_name
from .mail_view import parse_msg, probe_outlook_msg, render_msg, sender_verdict
from .scoring import compute_score
from .yara_engine import YaraEngine

log = logging.getLogger(__name__)

_OOXML_OFFICE_SUFFIXES = {
    ".docx", ".xlsx", ".pptx", ".xlsm", ".docm", ".pptm", ".xlam",
    # Macro-enabled template/add-in formats share the same OOXML container
    # and the same VBA/XLM attack surface — silently skipping their deep
    # scan would be indistinguishable from "clean".
    ".dotm", ".xltm", ".potm", ".ppsm",
    # Binary workbook: same OOXML container, same macro/XLM surface. The
    # office pipeline's XLM stage already handles .xlsb (BUG-024); without
    # the routing entry it never ran.
    ".xlsb",
}

# Types whose ``_scan`` branch already expands the container. Anything else
# has no archive stage, so a ZIP hidden behind a prefix would lose its whole
# content scan (see ``_prefixed_zip_type``).
_ARCHIVE_TYPES = frozenset(
    {"zip", "rar", "7z", "deb", "rpm", "cab", "iso", "tar", "gzip", "bzip2", "xz"}
)

# End-of-central-directory record: 22 fixed bytes plus an archive comment of
# at most 65535 bytes. That is the whole window a ZIP's end marker can be in.
_ZIP_EOCD = b"PK\x05\x06"
_ZIP_EOCD_SEARCH = 22 + 0xFFFF


def _file_revision(path: Path) -> tuple[int, int] | None:
    """``(size, mtime_ns)`` of one revision, or ``None`` if it is gone."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def _is_real_pe(data: bytes) -> bool:
    """Structurally confirmed PE (``magic._looks_like_pe`` is lenient).

    The magic check deliberately types a truncated/blind ``MZ`` blob as "pe"
    for recall. For the ZIP fallback that leniency is the attack: ``MZ`` plus
    padding plus a ZIP becomes "pe" without ever carrying a PE header. A
    REAL PE with an appended archive, by contrast, is an Electron/Go
    installer — its embedded app ZIP must not steal the file's type (guarded
    by ``tests/test_archive.py::test_pe_with_embedded_zip_stays_green``), so
    only the verified ``PE\\0\\0`` header is trusted here.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    return (
        e_lfanew > 0
        and e_lfanew + 4 <= len(data)
        and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
    )


def _prefixed_pdf_type(ftype: magic.FileType, data: bytes) -> magic.FileType:
    """Promote a PDF whose ``%PDF-`` header is not at offset 0.

    ISO 32000-1 §7.5.2 lets readers accept the header anywhere in the first
    1024 bytes, and viewers do. ``magic.detect`` only looks at offset 0, so one
    filler byte dropped the file out of the PDF pipeline: measured, the same
    document with /Launch and /OpenAction scored RED 100 clean and YELLOW 30
    with a single 'X' in front — every PDF_* rule was gone.

    More than the marker is required so binary junk that merely contains the
    string is not relabelled: a real object body has to follow.
    """
    if ftype.type == "pdf":
        return ftype
    if ftype.type not in ("unknown", "text"):
        return ftype
    offset = data[:1024].find(b"%PDF-")
    if offset <= 0:
        return ftype
    if b"endobj" not in data and b"trailer" not in data:
        return ftype
    return magic.FileType("pdf", "application/pdf")


def _prefixed_zip_type(
    ftype: magic.FileType,
    data: bytes,
    source: FileSource | None,
) -> magic.FileType:
    """Type a ZIP whose local header does not start at offset 0 as archive.

    ``magic.detect`` checks signatures at fixed offsets, so a single filler
    byte in front of a ZIP leaves the file "unknown" (or "pe", when the filler
    starts with ``MZ``) and ``_scan`` never enters the archive branch. Measured
    (SEC-001): the same ZIP with a malicious member scored RED 100 plain and
    GREEN 5 prefixed. The container is recognised at its END instead — but
    only when ``zipfile`` can actually open it: arbitrary data carrying a
    coincidental ``PK\\x05\\x06`` has no readable central directory and keeps
    its detected type.
    """
    if ftype.type in _ARCHIVE_TYPES:
        return ftype
    if ftype.type == "pe":
        if _is_real_pe(data):
            # A real executable with an overlay archive stays a PE; its content
            # is still analysed by the PE and generic pipelines.
            return ftype
    elif ftype.type not in ("unknown", "text"):
        # Jeder andere ERKANNTE Typ hat einen eigenen Analyse-Zweig (ole:
        # Office/Outlook, pdf, Bilder, ELF/Mach-O, Mail …). Ihn wegen eines
        # ZIP-Anhangs auf "zip" zu heben schaltet diesen Zweig ab. Gemessen
        # nach dem SEC-001-Fix: eine Outlook-.msg mit ZIP-Anhang wurde "zip"
        # (magic sagte korrekt "ole") — ``is_msg`` lief nie, mail_preview und
        # mail_security blieben leer, die Anhaenge wurden nicht als Kinder
        # gescannt. ``zipfile`` oeffnet die CFB nur, weil es beliebige
        # Praefixe vor dem ZIP akzeptiert; das ist Beleg fuer einen ANHANG,
        # nicht fuer den Dateityp. Der SEC-001-Fall (Praefixbyte -> "unknown",
        # MZ-Polsterung -> "pe" ohne PE-Header) bleibt unten abgedeckt.
        return ftype
    if source is not None:
        # Only a prefix of a large file lives in ``data``, so its EOCD is not
        # here. ``ZipFile`` seeks to the end and validates the central
        # directory of the real file — bounded, no member is decompressed.
        try:
            with zipfile.ZipFile(source.path):
                pass
        except Exception:  # not only BadZipFile — see core.archive rationale
            return ftype
    else:
        if data.rfind(_ZIP_EOCD, max(0, len(data) - _ZIP_EOCD_SEARCH)) == -1:
            return ftype
        try:
            with zipfile.ZipFile(io.BytesIO(data)):
                pass
        except Exception:  # not only BadZipFile — see core.archive rationale
            return ftype
    return magic.FileType("zip", "application/zip")


_DRAIN_BYTES = 8 * 1024 * 1024  # drain budget, see _drain_container_notes


class _ScanBudget:
    """Global per-top-level-file budget across ALL nesting levels.

    The per-container limits (MAX_RECURSIVE_MEMBERS, AV_ARCHIVE_MEMBER_LIMIT)
    reset on every recursion level — a fractal/quine zip multiplies them up
    to billions of scan calls and AV engine runs. One budget object travels
    through the whole recursion tree of a single scan_path() call (hunt
    finding: global recursion DoS).
    """

    __slots__ = ("av_left", "members_left")

    def __init__(self) -> None:
        self.members_left = config.MAX_TOTAL_SCAN_MEMBERS
        self.av_left = config.MAX_TOTAL_AV_MEMBER_SCANS

    def take_member(self) -> bool:
        if self.members_left <= 0:
            return False
        self.members_left -= 1
        return True

    def take_av(self) -> bool:
        if self.av_left <= 0:
            return False
        self.av_left -= 1
        return True


def _iter_directory_files(root: Path):
    """Yield regular files below ``root`` WITHOUT following links/junctions.

    ``Path.rglob`` follows directory junctions and symlinks on Windows: a
    single junction inside a dropped folder made the batch walk pull the
    target tree (e.g. ``C:\\Windows``) into the scan — the folder scope escaped
    to a completely different data set, with an attacker-chosen target.
    ``os.scandir`` with ``follow_symlinks=False`` sees the entry type before
    descending, so junctions/symlinks are pruned instead of traversed.

    Order is unspecified (the caller sorts), and every ``OSError`` ends that
    subtree only — a locked or vanishing directory must not abort the batch.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink() or entry.is_junction():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue


def expand_scan_paths(paths, max_files: int | None = None) -> tuple[list[Path], bool]:
    """Expand a mix of files and directories into a flat list of file paths.

    Directories are walked recursively (regular files only, junctions and
    symlinks pruned). The result is de-duplicated while preserving order and
    capped at ``max_files`` (default ``config.MAX_BATCH_FILES``) as a DoS guard
    for batch scans. Returns ``(files, truncated)`` where ``truncated`` is True
    when the cap stopped the walk before all inputs were exhausted.
    Non-existent inputs are skipped silently — callers report them separately.
    """
    if max_files is None:
        max_files = config.MAX_BATCH_FILES
    files: list[Path] = []
    seen: set[str] = set()

    def _add(candidate: Path) -> bool:
        """Register one file; return False once one was SKIPPED due to the cap.

        The cap counts only newly added files; when the walk yields exactly
        ``max_files`` files nothing is skipped and ``truncated`` stays False
        (previously the exact-max case raised a false truncation warning).
        Case-insensitive keys: Windows paths do not distinguish case.
        """
        key = str(candidate).lower()
        if key in seen:
            return True
        if len(files) >= max_files:
            return False  # this candidate was skipped -> walk must stop
        seen.add(key)
        files.append(candidate)
        return True

    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            # Collect only up to the cap (plus ONE lookahead element) before
            # sorting: sorted(rglob("*")) would materialise the *entire* tree
            # first, so a huge directory would defeat the batch DoS guard.
            # The extra element proves whether MORE files exist beyond the
            # cap — without it the exact-max case could not be distinguished
            # from an actual truncation.
            collected: list[Path] = []
            try:
                for child in _iter_directory_files(path):
                    collected.append(child)
                    if len(collected) >= max_files + 1:
                        break
            except OSError:
                pass
            for child in sorted(collected):
                if not _add(child):
                    return files, True
        elif path.is_file():
            if not _add(path):
                return files, True
    return files, False


def _walk_results(result: ScanResult):
    """Dieses Ergebnis und alle Kinder — iterativ, ohne Rekursion.

    Ein Archiv kann tief verschachtelt sein; ``walk()`` ueber eine
    selbstgebaute Rekursion waere bei 200 Ebenen ein RecursionError.
    """
    stapel = [result]
    while stapel:
        aktuell = stapel.pop()
        yield aktuell
        stapel.extend(aktuell.children)


class Dispatcher:
    """Orchestrates the full analysis of one file."""

    def __init__(
        self,
        yara: YaraEngine | None = None,
        av_scanner: WindowsDefenderScanner | None = None,
        clam_scanner: ClamAVScanner | None = None,
    ):
        self.yara = yara if yara is not None else YaraEngine()
        self.av_scanner = (
            av_scanner if av_scanner is not None else WindowsDefenderScanner()
        )
        self.clam_scanner = (
            clam_scanner if clam_scanner is not None else ClamAVScanner()
        )
        self.external_scanners: list[ExternalScanner] = build_scanners()
        self.passwords = config.load_zip_passwords()
        self._defender_status: DefenderStatus | None = None
        self._status_lock = threading.Lock()
        self._engine_overview_done = False
        self._engine_overview_lock = threading.Lock()

        # Pipelines are stateless and shared across scans.
        self.generic = GenericPipeline(yara=self.yara)
        self.pdf = PdfPipeline()
        self.office = OfficePipeline()
        self.image = ImagePipeline()
        self.archive = ArchivePipeline()
        self.pe = PePipeline()
        self.eml = EmlPipeline()
        self.elf = ElfPipeline()
        self.macho = MachoPipeline()

    @property
    def defender_status(self) -> DefenderStatus:
        """Lazily probe Defender status once (read-only, cached).

        Guarded by a lock: with parallel scan workers several threads can hit
        this property at the same time, and the probe shells out to PowerShell
        (up to 20 s) — without the lock every thread would run its own probe.
        """
        with self._status_lock:
            if self._defender_status is None:
                try:
                    self._defender_status = probe_defender()
                except Exception as exc:  # never let diagnosis break a scan
                    self._defender_status = DefenderStatus(error=str(exc))
            return self._defender_status

    def _log_engine_overview(self) -> None:
        """Log a one-line-per-engine availability snapshot (once per run).

        malaz.log must answer "warum geht Defender/ClamAV nicht?" without
        re-running the scan: where the binary was found, whether the clamd
        daemon answered, where the signature DB lives — or which candidate
        paths came up empty. Guarded by a lock: parallel scan workers hit
        scan_path at the same time, the block must appear exactly once.
        """
        with self._engine_overview_lock:
            if self._engine_overview_done:
                return
            self._engine_overview_done = True

        av = self.av_scanner
        if av.available:
            log.info("[Engines] Defender: an (%s)", getattr(av, "mpcmdrun", "?"))
        elif getattr(av, "enabled", False):
            log.warning(
                "[Engines] Defender: nicht verfügbar — MpCmdRun nicht gefunden "
                "(Kandidaten: %s)", list(config.AV_MPCMDRUN_CANDIDATES),
            )
        else:
            log.info("[Engines] Defender: deaktiviert (Konfiguration)")

        clam = self.clam_scanner
        if clam.available:
            binary = getattr(clam, "binary", None)
            is_daemon = (
                binary is not None
                and binary.name.lower().startswith("clamdscan")
            )
            db_dir = getattr(clam, "database", None)
            db = f", DB: {db_dir}" if db_dir else ""
            log.info(
                "[Engines] ClamAV: an (%s%s)",
                "clamd-Daemon" if is_daemon else "clamscan", db,
            )
        elif getattr(clam, "enabled", False):
            log.warning(
                "[Engines] ClamAV: nicht verfügbar — weder clamscan noch ein "
                "antwortender clamd gefunden (Kandidaten: %s)",
                list(config.CLAMAV_SCAN_CANDIDATES),
            )
        else:
            log.info("[Engines] ClamAV: deaktiviert (Konfiguration)")

        if not self.yara.available:
            log.warning("[Engines] YARA: nicht verfügbar (yara-python fehlt)")
        elif self.yara.load_error:
            log.warning("[Engines] YARA: Regelfehler: %s", self.yara.load_error)

        ext = [s.name for s in self.external_scanners if s.available]
        if ext:
            log.info("[Engines] Extern: %s", ", ".join(ext))

    # -- public API -------------------------------------------------------- #

    def scan_path(self, path: str | Path) -> ScanResult:
        """Scan a file on disk (top-level entry point)."""
        self._log_engine_overview()
        path = Path(path)
        started = time.perf_counter()
        result = ScanResult(path=str(path))
        try:
            stat = path.stat()
            result.size = stat.st_size
            guard_file_size(stat.st_size)
            # Ordinary files keep the historical "read up to MAX_READ_SIZE"
            # behaviour. Above MAX_LARGE_FILE_SIZE only a small prefix is
            # loaded; hash/YARA/entropy/IOC stream the full file through
            # FileSource. This is what makes a 2 GB file fit the memory
            # budget without silently pretending the prefix is the file.
            is_large = stat.st_size > config.MAX_LARGE_FILE_SIZE
            read_size = (
                config.MAX_LARGE_PREFIX_SIZE
                if is_large
                else guard_read_size(stat.st_size)
            )
            with open(path, "rb") as fh:
                data = fh.read(read_size)
            # ``stat`` was taken BEFORE the read. A file that shrinks in that
            # window (still being written, being backed up, AV interference,
            # editor save) yields a short buffer that the code below used to
            # treat as a complete revision — measured with a stat made stale on
            # purpose (announced 1 MiB, read 4096 bytes): reported size 1 MiB,
            # reported sha256 = the hash of exactly those 4096 bytes, zero
            # indicators, GREEN. The sibling cap branch reported
            # CORE_READ_TRUNCATED 20 for the same "only a prefix was analysed"
            # fact, so the window was strictly quieter than the cap. The
            # analysed size is therefore derived from the bytes actually read.
            short_read = len(data) < read_size
            analyzed_size = len(data) if short_read else stat.st_size
            if stat.st_size <= read_size:
                # Data already covers the whole file; hash it in memory.
                full_sha256 = hashlib.sha256(data).hexdigest()
                full_md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
            else:
                # Files larger than the read cap must not be reported with the
                # hash of a truncated prefix (integrity/blocklist would break).
                # Hash the complete file streaming, never loading it at once.
                sha = hashlib.sha256()
                md5 = hashlib.md5(usedforsecurity=False)
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(config.READ_CHUNK_SIZE), b""):
                        sha.update(chunk)
                        md5.update(chunk)
                full_sha256 = sha.hexdigest()
                full_md5 = md5.hexdigest()
            # Second look at the file after all reads: (size, mtime_ns) against
            # the pre-read stat tells whether the analysed bytes and the
            # reported metadata belong to one and the same revision. The hash
            # is taken last for the capped case, so without this check a file
            # rewritten during the streaming hash would be reported as a
            # coherent (size, sha256, md5) triple that exists in no revision.
            try:
                after = path.stat()
            except OSError:
                # Vanished: _scan's own existence check owns that case
                # (AV_EINGRIFF, weight 30) — not a second finding here.
                after = None
            changed = after is not None and (
                after.st_size != stat.st_size
                or after.st_mtime_ns != stat.st_mtime_ns
            )
            read_hash_ms = int((time.perf_counter() - started) * 1000)
            source = FileSource(path, stat.st_size) if is_large else None
            result = self._scan(
                data=data,
                path=path,
                depth=0,
                display_path=path.name,
                real_path=path,
                size=analyzed_size,
                sha256=full_sha256,
                md5=full_md5,
                budget=_ScanBudget(),
                source=source,
            )
            result.stage_timings.insert(
                0,
                StageTiming("read+hash", read_hash_ms),
            )
            if short_read:
                # Same statement as CORE_READ_TRUNCATED — "only part of what
                # was announced got analysed" — so the same weight 20: above
                # SCORE_GREEN_MAX (19), so the file can never come out GREEN,
                # yet together with the container note of the same event
                # (ARCH_TAR_ERROR 25) it stays at 45 < ANCHOR_CRITICAL_SCORE:
                # a harmless file that merely changed mid-scan must not read
                # as malicious.
                result.indicators.append(
                    Indicator(
                        rule_id="CORE_READ_SHORT",
                        title="Datei während des Scans verkürzt — nur ein Teil analysiert",
                        detail=(
                            f"Angekündigt waren {read_size} Bytes, gelesen wurden "
                            f"nur {len(data)}"
                            + (
                                f"; die Datei ist jetzt {after.st_size} Bytes groß "
                                f"(mtime_ns {after.st_mtime_ns})"
                                if after is not None
                                else "; sie ist inzwischen nicht mehr vorhanden"
                            )
                            + ". Die Datei wurde also zwischen Größenabfrage und "
                            "Lesen verändert (laufender Schreibvorgang, Speichern "
                            "durch einen Editor, AV-Eingriff). Analysiert wurde "
                            "damit eine ANDERE Revision als angekündigt: Größe, "
                            "Hash und Urteil können zu verschiedenen Revisionen "
                            "gehören. Das Ergebnis ist unvollständig und NICHT "
                            "als 'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_RESOURCE,
                        weight=20,
                    )
                )
                self._finalize_score(result)
            elif after is not None and changed:
                # No short read, but the file is not the one we measured: it
                # grew, or was replaced in place. Everything appended after our
                # stat was never analysed and nothing else would say so.
                result.indicators.append(
                    Indicator(
                        rule_id="CORE_FILE_CHANGED",
                        title="Datei während des Scans verändert (Größe/mtime)",
                        detail=(
                            f"Vor dem Lesen: {stat.st_size} Bytes "
                            f"(mtime_ns {stat.st_mtime_ns}), danach: "
                            f"{after.st_size} Bytes (mtime_ns {after.st_mtime_ns}). "
                            "Analysiert wurde der Stand von vorher — ein danach "
                            "angehängter oder ausgetauschter Inhalt ist NICHT "
                            "geprüft, und der gemeldete Hash gehört zu einer "
                            "Revision, die so nicht mehr auf dem Datenträger "
                            "liegt. Das Ergebnis ist unvollständig und NICHT als "
                            "'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_RESOURCE,
                        weight=20,
                    )
                )
                self._finalize_score(result)
            if read_size < stat.st_size and not short_read:
                # The analysis saw only the first MAX_READ_SIZE bytes. Between
                # that cap and MAX_FILE_SIZE no limit indicator fires, so a
                # payload placed past the cap was neither analysed nor
                # mentioned — measured: identical bytes scored RED 80 below
                # the cap and GREEN 0 above it. The five sibling stages
                # (swf_extract, office_pipeline, pdf_pipeline) all report a
                # truncation; this one did not.
                #
                # ``not short_read``: when the file shrank below the cap during
                # the window, the whole (new) file was read — the old announced
                # size is no longer the file's size, so the cap statement would
                # be untrue. That case is reported once, as CORE_READ_SHORT.
                if is_large and source is not None and source.budget_exceeded:
                    stream_note = (
                        " Die Streaming-Stufen liefen nur bis zum Zeitbudget "
                        "(siehe CORE_TIME_BUDGET); die tiefen Parser sahen "
                        "diesen Präfix."
                    )
                elif is_large:
                    stream_note = (
                        " Hash, Entropie und IOC-Adressen liefen über die "
                        "gesamte Datei (Streaming), YARA ebenfalls über die "
                        "volle Datei (scan_file_with_status); die tiefen "
                        "Parser sahen nur diesen Präfix, soweit ihr Budget "
                        "reichte."
                    )
                else:
                    stream_note = ""
                result.indicators.append(
                    Indicator(
                        rule_id="CORE_READ_TRUNCATED",
                        title=(
                            "Tiefenanalyse nur auf dem Dateipräfix"
                            if is_large
                            else "Datei nur teilweise analysiert"
                        ),
                        detail=(
                            f"Es wurden die ersten {read_size} von "
                            f"{stat.st_size} Bytes an die tiefen Parser "
                            f"gegeben; der Rest wurde dort NICHT geprüft."
                            f"{stream_note} Das Ergebnis ist unvollständig und "
                            "nicht als 'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_RESOURCE,
                        # 20 statt 25: die Kappung MUSS sichtbar bleiben (ein
                        # einzelnes Gewicht über SCORE_GREEN_MAX = 19 => GELB),
                        # darf aber zusammen mit den Folgebefunden derselben
                        # Ursache nicht auf 50 = ROT springen: die Container-
                        # Stufe meldet "nicht lesbar" (25) für genau den
                        # Präfix, den diese Kappung erzeugt hat. Gemessen:
                        # 101-MiB-TAR aus reinen Nullbytes ROT 55 (25 + 25 + 5),
                        # derselbe Bytes-Strom mit angehobener Lesegrenze
                        # GRÜN 5 — in der Datei steckte kein Signal. 20 + 25 =
                        # 45 bleibt GELB: unvollständig, nicht kritisch
                        # (docs/ARCHITECTURE.md: Ziel 0 % ROT-Fehlalarme).
                        weight=20,
                    )
                )
                self._finalize_score(result)
        except LimitExceeded as exc:
            result.indicators.append(
                Indicator(
                    rule_id="CORE_LIMIT",
                    title="Ressourcen-Limit überschritten",
                    detail=str(exc),
                    severity=Severity.HIGH,
                    category=CAT_RESOURCE,
                    weight=30,
                )
            )
            result.error = str(exc)
            self._finalize_score(result)
        except Exception as exc:  # defensive: never let a scan crash the worker
            log.exception("Scan failed for %s", path)
            result.error = f"{type(exc).__name__}: {exc}"
            # A scan that could not run at all must never present itself as a
            # clean result. This is exactly what an AV blocking the file
            # (EICAR: OSError 22), a locked/vanishing file or a permissions
            # problem looks like — the file was NOT inspected, so the verdict
            # has to say so with a non-zero weight (audit finding; the same
            # reasoning as the PE_PARSE_WARN fix).
            result.indicators.append(
                Indicator(
                    rule_id="CORE_ERROR",
                    title="Datei konnte nicht analysiert werden",
                    detail=(
                        f"{result.error} — die Datei wurde nicht geprüft. "
                        "Das Ergebnis ist NICHT als 'sauber' zu werten "
                        "(z. B. durch Virenschutz gesperrt, gesperrt oder "
                        "nicht lesbar)."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_RESOURCE,
                    # 25, not 5: SCORE_GREEN_MAX is 19, so weight 5 classified
                    # a file that was NEVER inspected as GREEN — the exact
                    # false all-clear this indicator's own comment forbids.
                    # A scan that could not run is YELLOW, never green.
                    weight=25,
                )
            )
            self._finalize_score(result)
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    # -- core scan --------------------------------------------------------- #

    def _scan(
        self,
        data: bytes,
        path: Path,
        depth: int,
        display_path: str,
        real_path: Path | None,
        size: int,
        sha256: str | None = None,
        md5: str | None = None,
        budget: _ScanBudget | None = None,
        source: FileSource | None = None,
    ) -> ScanResult:
        if budget is None:  # defensive: direct callers (tests) ohne Budget
            budget = _ScanBudget()
        result = ScanResult(path=display_path or str(path), size=size, depth=depth)
        if sha256 is None:
            sha256 = hashlib.sha256(data).hexdigest()
        if md5 is None:
            # MD5 serves only as a short identification fingerprint (e.g. for
            # hash blocklists / IOC correlation), not for any security property.
            md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        result.sha256 = sha256
        result.md5 = md5

        stage_start = time.perf_counter()
        ftype = magic.refine_text_type(magic.detect(data), path.suffix)
        ftype = magic.refine_script_content(ftype, data)
        # SEC-001: a ZIP is found by magic only at offset 0; one filler byte in
        # front hides it from the archive branch entirely, so its members were
        # never scanned. Promote on the END marker (and a successful open)
        # before the type decides pipelines and container recursion.
        ftype = _prefixed_zip_type(ftype, data, source)
        # Same finding for PDF: the header may sit anywhere in the first
        # 1024 bytes and viewers accept that. Without this the PDF pipeline
        # (and every PDF_* rule) never runs for such a file.
        ftype = _prefixed_pdf_type(ftype, data)
        result.detected_type = ftype.type
        result.mime_hint = ftype.mime
        result.stage_timings.append(
            StageTiming("type", int((time.perf_counter() - stage_start) * 1000))
        )

        # scan_path only ever reads the first MAX_READ_SIZE bytes of a larger
        # file, and it is the only caller that can pass a short buffer (nested
        # member payloads always arrive complete, so len(data) == size there).
        # The container layer below therefore works on a prefix — and a
        # structure stored at the END of the file (ZIP central directory, TAR
        # end blocks, CFB directory) is then regularly unparseable. What it
        # reports as "container not readable" is a consequence of the cap, not
        # a second finding: CORE_READ_TRUNCATED already counts it.
        truncated_prefix = depth == 0 and len(data) < size

        ctx = AnalysisContext(
            path=path,
            data=data,
            source=source,
            deadline=(
                time.monotonic() + config.MAX_FILE_SCAN_SECONDS
                if source is not None
                else None
            ),
            detected_type=ftype.type,
            size=size,
            depth=depth,
            display_path=display_path,
            sha256=sha256,
        )

        indicators: list[Indicator] = []
        for pipeline in self._select_pipelines(ftype.type, path.suffix):
            stage_start = time.perf_counter()
            try:
                indicators.extend(pipeline.analyze(ctx))
            except Exception as exc:  # isolate pipeline failures
                log.warning("Pipeline %s failed: %s", pipeline.name, exc)
                indicators.append(
                    Indicator(
                        rule_id=f"{pipeline.name.upper()}_ERROR",
                        title=f"Pipeline '{pipeline.name}' fehlerhaft",
                        detail=(
                            f"{type(exc).__name__}: {exc} — die Stufe "
                            f"'{pipeline.name}' lief nicht; der von ihr "
                            "abgedeckte Inhalt wurde NICHT geprüft. Das "
                            "Ergebnis ist unvollständig und nicht als "
                            "'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_RESOURCE,
                        # 25 statt 0: ein ausgefallener Pipeline-Lauf ist
                        # derselbe Fall wie CORE_ERROR (Runde 2: 5 -> 25) —
                        # die Stufe hat nichts analysiert, ihr Ergebnis ist
                        # unbekannt. Gewicht 0 ließ genau das als GRÜN 0
                        # durchgehen; gemessen: dasselbe PDF ROT 60 bzw.
                        # GRÜN 5, sobald die Tiefenstufe warf oder fehlte.
                        weight=25,
                        source=pipeline.name,
                    )
                )
            finally:
                result.stage_timings.append(
                    StageTiming(
                        pipeline.name,
                        int((time.perf_counter() - stage_start) * 1000),
                    )
                )

        if source is not None and source.budget_exceeded:
            indicators.append(
                Indicator(
                    rule_id="CORE_TIME_BUDGET",
                    title="Zeitbudget erreicht — nicht alle Bytes geprüft",
                    detail=(
                        f"Die Streaming-Analyse wurde nach "
                        f"{config.MAX_FILE_SCAN_SECONDS} s gestoppt. Der bereits "
                        "gelesene Teil wurde geprüft, der Rest NICHT. Das "
                        "Ergebnis ist unvollständig und nicht als 'sauber' zu "
                        "werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_RESOURCE,
                    weight=20,
                )
            )

        # One probe for the whole scan: it used to run twice (once for the
        # container branch, once for the preview), i.e. the OLE directory was
        # walked twice for every office document.
        is_msg, msg_problem = (False, "")
        if ftype.type == "ole":
            is_msg, msg_problem = probe_outlook_msg(data)
            if msg_problem:
                # A container we could not read is NOT "no message": saying so
                # was the silent path (measured: the attachments of such a
                # container were never scanned and nothing said why). It is
                # not a confirmed message either, so the mail path stays shut
                # — taking it would only add false EMAIL_* findings, since
                # the attachment walk fails on the very same read.
                indicators.append(
                    Indicator(
                        rule_id="MAIL_CONTAINER_WARN",
                        title="OLE-Container nicht lesbar",
                        detail=(
                            f"{msg_problem} — dieser Container konnte nicht "
                            "gelesen werden, sein Inhalt wurde NICHT geprüft "
                            "(weder Makros noch Anhänge). Das Ergebnis ist "
                            "unvollständig und nicht als 'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_RESOURCE,
                        weight=25,
                        source="dispatcher",
                    )
                )

        # Archive recursion (Zip-Slip- and bomb-safe via core.archive /
        # core.sevenzip for RAR/7z/deb/rpm).
        if ftype.type in ("zip", "rar", "7z", "deb", "rpm", "cab", "iso"):
            if depth >= config.MAX_ARCHIVE_DEPTH:
                indicators.append(self._depth_limit_indicator("Archiv"))
            elif ftype.type == "zip":
                result.children = self._guarded_members(
                    "Archiv-Inhalt",
                    lambda: self._scan_archive_members(
                        data, depth, budget, truncated_prefix,
                        source_path=source.path if source is not None else None,
                    ),
                    indicators,
                )
            elif ftype.type in ("rar", "7z", "deb", "rpm", "cab", "iso"):
                result.children = self._guarded_members(
                    "Archiv-Inhalt (7-Zip)",
                    lambda: self._scan_sevenzip_members(
                        data, depth, path.suffix.lower(), budget, truncated_prefix
                    ),
                    indicators,
                )
        elif ftype.type in ("tar", "gzip", "bzip2", "xz"):
            if depth >= config.MAX_ARCHIVE_DEPTH:
                indicators.append(self._depth_limit_indicator("Archiv"))
            else:
                result.children = self._guarded_members(
                    "TAR/komprimierter Inhalt",
                    lambda: self._scan_compressed_members(
                        data, depth, ftype.type, budget, truncated_prefix
                    ),
                    indicators,
                )
        elif ftype.type == "eml" or (ftype.type == "ole" and is_msg):
            if depth >= config.MAX_ARCHIVE_DEPTH:
                indicators.append(self._depth_limit_indicator("E-Mail"))
            else:
                kind = "msg" if ftype.type == "ole" else "eml"
                result.children = self._guarded_members(
                    "E-Mail-Inhalt",
                    lambda: self._scan_email_members(
                        data, depth, kind, budget, truncated_prefix
                    ),
                    indicators,
                )
        elif ftype.type == "rtf":
            if depth >= config.MAX_ARCHIVE_DEPTH:
                indicators.append(self._depth_limit_indicator("RTF"))
            else:
                result.children = self._guarded_members(
                    "RTF-Inhalt",
                    lambda: self._scan_rtf_objects(
                        data, depth, budget, truncated_prefix
                    ),
                    indicators,
                )
        elif ftype.type == "swf":
            # Nested CWS-in-CWS streams could recurse without a depth guard
            # (each level is a fresh zlib stream), so mirror the archive limit.
            if depth >= config.MAX_ARCHIVE_DEPTH:
                indicators.append(
                    self._depth_limit_indicator("SWF", "dekomprimiert")
                )
            else:
                result.children = self._guarded_members(
                    "SWF-Inhalt",
                    lambda: self._scan_swf_payload(
                        data, depth, budget, truncated_prefix
                    ),
                    indicators,
                )

        # Windows Defender scan for top-level files with a real on-disk path.
        if depth == 0 and real_path is not None:
            av_start = time.perf_counter()
            # SEC-005: the read/stat check in ``scan_path`` happens BEFORE
            # ``_scan``; the engines open the file again afterwards. A file
            # swapped between those two moments can therefore be judged in a
            # revision that was never analysed (and a clean verdict from the
            # swapped copy discounts the score). Take the revision around the
            # engine calls as well, so that window is named instead of silent.
            av_before = _file_revision(real_path)
            try:
                indicators.extend(self._scan_av_pair(real_path))
            except Exception as exc:  # never lose the findings collected so far
                log.warning("AV-Paar fehlgeschlagen: %s", exc)
                indicators.append(
                    self._engine_error_indicator(
                        "AV_ERROR", "Defender/ClamAV", exc, "dispatcher"
                    )
                )
            for scanner in self.external_scanners:
                tag = "".join(ch if ch.isalnum() else "_" for ch in scanner.name).upper()
                src = scanner.name.lower()
                try:
                    res = scanner.scan_path(real_path)
                except Exception as exc:
                    # BUG-006: this call used to sit outside every isolation
                    # layer. A throwing scanner escaped to scan_path's broad
                    # catch, which REPLACED the whole result with CORE_ERROR —
                    # a PDF already scored RED 80 came back as YELLOW 25 with
                    # no indicators left. The engine failed to judge the file;
                    # that is one note, not the loss of the whole scan.
                    log.warning("Externer Scanner %s fehlgeschlagen: %s", scanner.name, exc)
                    indicators.append(
                        self._engine_error_indicator(
                            f"EXT_{tag}_ERROR", scanner.name, exc, src
                        )
                    )
                    continue
                if res.threat_found:
                    indicators.append(
                        Indicator(
                            rule_id=f"EXT_{tag}_THREAT",
                            title=f"{scanner.name}: Bedrohung erkannt",
                            # HIER bleibt die rohe Ausgabe — bewusst: bei einer
                            # erkannten Bedrohung ist der Name und die
                            # Fundstelle aus dem Werkzeug die Information, die
                            # der Nutzer an die IT weitergibt.
                            detail=res.detail,
                            severity=Severity.CRITICAL,
                            category=CAT_AV,
                            weight=50,
                            source=src,
                        )
                    )
                elif res.clean:
                    indicators.append(
                        Indicator(
                            rule_id=f"EXT_{tag}_CLEAN",
                            title=f"{scanner.name}: keine Bedrohung",
                            # Dieselbe Regel wie bei AV_CLEAN und CLAMAV_CLEAN:
                            # die rohe Werkzeugausgabe gehoert ins Protokoll,
                            # nicht in die Laienansicht. Ueber den externen
                            # Engine-Pfad ist diese Stelle heute nicht
                            # erreichbar ("Extern=keine konfiguriert"), aber
                            # sie ist es, sobald jemand eine Fremd-Engine
                            # eintraegt — und dann waere der Fehler wieder da.
                            detail=(
                                f"{scanner.name} hat diese Datei geprüft und "
                                "nichts gefunden."
                            ),
                            severity=Severity.INFO,
                            category=CAT_AV,
                            weight=0,
                            source=src,
                        )
                    )
                else:
                    indicators.append(
                        Indicator(
                            rule_id=f"EXT_{tag}_SKIPPED",
                            title=f"{scanner.name}: Scan übersprungen",
                            detail=res.skipped_reason or res.detail,
                            severity=Severity.INFO,
                            category=CAT_AV,
                            weight=0,
                            source=src,
                        )
                    )
            result.stage_timings.append(
                StageTiming(
                    "av (Defender+ClamAV)",
                    int((time.perf_counter() - av_start) * 1000),
                )
            )
            av_after = _file_revision(real_path)
            if (
                av_before is not None
                and av_after is not None
                and av_after != av_before
            ):
                indicators.append(
                    Indicator(
                        rule_id="CORE_FILE_CHANGED",
                        title="Datei während der AV-Prüfung verändert",
                        detail=(
                            f"Vor dem Engine-Lauf: {av_before[0]} Bytes "
                            f"(mtime_ns {av_before[1]}), danach: "
                            f"{av_after[0]} Bytes (mtime_ns {av_after[1]}). "
                            "Die AV-Engines öffnen die Datei selbst; ihr Urteil "
                            "kann deshalb zu einer ANDEREN Revision gehören als "
                            "die analysierten Bytes (TOCTOU). Ein 'sauber' aus "
                            "diesem Lauf ist kein Freispruch für den geprüften "
                            "Inhalt. Das Ergebnis ist unvollständig."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_RESOURCE,
                        weight=20,
                        source="dispatcher",
                    )
                )

        # AV-Eingriffs-Erkennung: Ist die Datei während des Scans von der
        # Platte verschwunden (Quarantäne/Entfernung durch ein AV), muss das
        # sichtbar sein — statt eines stillen "keine Bedrohung".
        if depth == 0 and real_path is not None and not real_path.exists():
            av_threat_reported = any(
                i.rule_id in ("AV_THREAT", "CLAMAV_THREAT")
                or (i.rule_id.startswith("EXT_") and i.rule_id.endswith("_THREAT"))
                for i in indicators
            )
            if av_threat_reported:
                # Treffer wurde bereits gemeldet — ergänzende Info ohne Gewicht.
                indicators.append(
                    Indicator(
                        rule_id="AV_EINGRIFF",
                        title="Datei wurde durch den AV-Scan entfernt",
                        detail=(
                            "Die Datei existiert auf dem Datenträger nicht mehr — "
                            "ein Antivirenprogramm hat sie bei der Erkennung "
                            "entfernt oder in Quarantäne verschoben."
                        ),
                        severity=Severity.INFO,
                        category=CAT_AV,
                        weight=0,
                        source="dispatcher",
                    )
                )
            else:
                # Anomalie: Kein AV-Treffer gemeldet, aber die Datei ist weg —
                # genau der Fall, der sonst fälschlich als "sauber" angezeigt
                # würde, obwohl ein AV eingegriffen hat.
                indicators.append(
                    Indicator(
                        rule_id="AV_EINGRIFF",
                        title="Datei wurde während des Scans entfernt (möglicher AV-Eingriff)",
                        detail=(
                            "Die Datei existiert auf dem Datenträger nicht mehr, "
                            "obwohl kein AV-Treffer gemeldet wurde. Ein Virenschutz "
                            "(Windows Defender, ClamAV oder ein Drittanbieter) hat "
                            "sie möglicherweise in Quarantäne verschoben oder "
                            "entfernt. Das Ergebnis ist unvollständig und NICHT "
                            "als 'sauber' zu werten."
                        ),
                        severity=Severity.HIGH,
                        category=CAT_AV,
                        weight=30,
                        source="dispatcher",
                    )
                )

        # An Outlook .msg is a mail inside an OLE container: the office pipeline
        # owns it (macros, embedded objects), while subject/body/attachments sit
        # in the OLE property streams instead of MIME headers. Its plain-text
        # preview is therefore built here — see core.mail_view. The .eml
        # pipelines deliberately do NOT run on it: Received and
        # Authentication-Results are not part of the OLE properties, and their
        # absence would surface as findings that are untrue for a .msg.
        if is_msg:
            ctx.preview = render_msg(data)
            # A .msg carries no Authentication-Results: the OLE properties hold
            # subject, sender and attachments, not the receiving server's
            # verdict. Reported as "unknown" rather than left empty, so a row
            # does not look like a mail that simply was not checked.
            msg_facts = parse_msg(data)
            ctx.mail_security = {
                "spf": "unknown",
                "dkim": "unknown",
                "dmarc": "unknown",
                "sender": sender_verdict(msg_facts),
                # Ob die Mail ueberhaupt einen Absender hat, ist eine eigene
                # Tatsache — ``bool(mail_security)`` ist bei JEDER Mail True,
                # weil die Keys oben immer gesetzt werden. Das Panel las daraus
                # "Absender vorhanden" und bewertete eine Mail ohne From mit
                # 70 ("teilweise stimmig") statt mit 0 ("Kein Absender").
                # Als eigener Key, damit die Anzeige die Unterscheidung sieht,
                # ohne die Auth-Felder zu interpretieren.
                "has_from": "1" if msg_facts.from_addr else "0",
            }

        result.indicators = indicators
        # A pipeline may have produced a preview worth showing (the plain-text
        # mail view). Copied here so the GUI and reports get it without parsing
        # the file a second time.
        result.mail_preview = ctx.preview
        # The same verdicts, structured — the list view shows them per row, and
        # parsing them back out of the preview text would be fragile.
        result.mail_security = dict(ctx.mail_security)
        result.mail_links = list(ctx.mail_links)
        result.capa_capabilities = list(ctx.capa_capabilities)
        self._finalize_score(result)
        self._log_stages(result)
        return result

    def _log_stages(self, result: ScanResult) -> None:
        """Protokollieren, welche Stufen GELAUFEN sind — je Datei eine Zeile.

        Der Grundsatz: *was wir nicht geprüft haben, darf nicht wie geprüft
        aussehen.* Im Fenster steht das an der Ampel und im Bericht; im
        Protokoll fehlte es. Wer hinterher nachvollziehen will, ob ein Grün
        ein Freispruch war, findet hier die Antwort.

        Eine Zeile je Datei, auch wenn alles lief: eine LÜCKE ist in einem
        Protokoll nur dann erkennbar, wenn die vollstaendigen Faelle
        danebenstehen. Ein fehlender Eintrag saehe sonst aus wie ein Scan,
        der nie stattfand.

        Die Kinder zaehlen mit (ein Archiv ist nur so geprueft wie seine
        Mitglieder), aber die Ausgabe bleibt EINE Zeile: bei 200
        Archivmitgliedern waere alles andere unlesbar.
        """
        offen = [
            i.title
            for r in _walk_results(result)
            for i in r.incomplete_stages
        ]
        if offen:
            log.info(
                "[Stufen] %s: UNVOLLSTÄNDIG — %d Stufe(n) nicht gelaufen: %s",
                anonymize_name(result.display_name),
                len(offen),
                " | ".join(dict.fromkeys(offen)),
            )
        else:
            log.info(
                "[Stufen] %s: vollständig geprüft",
                anonymize_name(result.display_name),
            )

    # -- container recursion drivers ---------------------------------------- #

    def _drain_container_notes(
        self,
        iterator,
        children: list[ScanResult],
        path_label: str,
        depth: int,
        container_rule: str,
        container_title: str,
        limit: int = 16,
        max_bytes: int = 8 * 1024 * 1024,
        truncated_prefix: bool = False,
    ) -> None:
        """Collect the trailing container-level notes after a member limit.

        ``break`` abandons the generator, and container iterators emit their
        summary notes at the END: the Zip-Slip report in
        ``iter_compressed_members`` is the last yield, after the walk. With a
        plain ``break`` that note never arrived — measured: a TAR with a
        traversal entry scored RED 50 with 250 members and GREEN 0 with 251,
        the attempt vanishing without a trace.

        Only name-less notes are taken (``name == ""`` with an error). A named
        entry here is a member we decided not to scan; it is already covered by
        the skip note above, and scanning it would defeat the limit.

        Reaching those trailing notes means pulling the iterator to its end,
        and every ``next()`` materializes one member — on a 10 500-entry
        archive that is 10 500 payloads, exactly what the ``break`` exists to
        avoid. ``max_bytes`` bounds the payload materialized for this; cheap
        members (the common case for a tripped cap) still let us reach the
        summary, an archive of fat members stops early and keeps the note it
        already has.

        Fat members therefore *can* end the drain before the summary arrives,
        and the note is then unreachable: reaching it would mean pulling every
        remaining member (measured: a 260 MiB TAR of 1 MiB members needs 260
        pulls, and the note sits behind the last one), which is exactly what
        ``max_bytes`` forbids. Two things follow from that, and both are
        needed:

        * The loss must not be silent — a stage that did not evaluate content
          has to be score-effective or explicitly "ungeprüft". The drain
          therefore appends an explicit ``ARCH_NOTE_UNREAD`` note when the
          byte budget ends it (see ``_unread_tail_note``).
        * An iterator that knows the summary before the walk ends should not
          depend on the drain at all — ``iter_compressed_members`` collects the
          Zip-Slip names in a metadata pre-pass over the TAR headers and yields
          the report BEFORE any member is read (see ``core/archive.py``), so the
          CRITICAL finding is independent of this budget and of the member cap.
          Measured with the cap at 20 and 300 members of 200 KB: without the
          pre-pass a traversal at position 120 or 295 scored YELLOW 25 with no
          ``ARCH_ZIPSLIP``, numerically identical to the same archive without
          any traversal entry at all.
        """
        remaining = limit
        budget = max_bytes
        reason = "Volumen-Budget erschöpft"
        tail_unread = False
        try:
            for name, payload, error in iterator:
                if remaining <= 0:
                    break
                if budget <= 0:
                    # The next member's payload is what the budget forbids;
                    # the summary notes live behind it. Reported below instead
                    # of dropped in silence.
                    tail_unread = True
                    break
                budget -= len(payload) if payload else 0
                if not error or name:
                    continue
                children.append(
                    self._container_note(
                        error, path_label, depth, container_rule, container_title,
                        truncated_prefix=truncated_prefix,
                    )
                )
                remaining -= 1
        except Exception as exc:  # a broken iterator must not lose the result
            log.warning("Container-Nachlauf fehlgeschlagen: %s: %s", type(exc).__name__, exc)
            reason = f"Iterator-Abbruch {type(exc).__name__}"
            tail_unread = True
        if tail_unread:
            children.append(self._unread_tail_note(path_label, depth, reason))

    def _unread_tail_note(self, path_label: str, depth: int, reason: str) -> ScanResult:
        """Report a container drain that ended before the trailing summary.

        ``_drain_container_notes`` walks the iterator past the member limit to
        collect the container's summary notes, which every iterator emits as its
        LAST yield (Zip-Slip list, bomb stop, entry-limit stop). That walk is
        bounded by ``max_bytes`` because each ``next()`` materializes one
        member; when the remaining members are fat the budget is spent before
        the summary, and when the iterator raises the rest is unknown as well.
        Either way the summary is *not read* — and an unread stage must be
        explicitly visible (audit rule: score-effective or "ungeprüft").

        Weight 0 on purpose: the cause that got us here — the member limit
        tripping — is already weighted once as ``ARCH_MEMBER_SKIP`` /
        ``ARCH_TOTAL_LIMIT`` (25) at the call site, and "one cause, one weighted
        statement" forbids charging it a second time. Weight 25 here would push
        a benign archive of fat members to 50 = RED without a single content
        signal (the same double count that made a 101 MiB zero-byte TAR score
        RED 55). The note documents *which* stage noticed, not the finding.
        """
        note = ScanResult(path=path_label, depth=depth + 1)
        note.error = f"Abschlussnotiz des Containers nicht gelesen ({reason})"
        note.indicators = [
            Indicator(
                rule_id="ARCH_NOTE_UNREAD",
                title="Abschlussnotiz des Containers NICHT gelesen (ungeprüft)",
                detail=(
                    f"Der Nachlauf nach dem Mitgliederlimit endete vor der "
                    f"abschließenden Meldung des Containers ({reason}). Ob der "
                    "Container eine solche Meldung hatte (Zip-Slip-Liste, "
                    "Bomben-Stopp, Eintrags-Limit), ist damit UNGEPRÜFT. Die "
                    "Gewichtung derselben Ursache trägt ARCH_MEMBER_SKIP."
                ),
                severity=Severity.INFO,
                category=CAT_ARCHIVE,
                weight=0,
                source="dispatcher",
            )
        ]
        self._finalize_score(note)
        return note

    def _scan_children(
        self,
        iterator,
        depth: int,
        *,
        path_label: str,
        container_rule: str,
        container_title: str,
        member_rule: str = "ARCH_MEMBER_ERROR",
        member_title: str = "Mitglied nicht entpackbar",
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
        member_budget=None,
    ) -> list[ScanResult]:
        """Shared driver for every container member recursion.

        Turns ``(name, payload, error)`` streams (ZIP, 7z/RAR, tar/gzip,
        e-mail attachments, RTF objects, SWF payloads) into child results:
        container-level errors and bomb-protection stops become visible
        notes, per-member errors become "not examined" findings (MEDIUM/25,
        like the skip/stop notes — the iterator delivers no payload for
        them), and healthy members are re-scanned recursively — bounded by
        ``MAX_RECURSIVE_MEMBERS`` with an explicit truncation note when the
        cap trips.
        """
        children: list[ScanResult] = []
        scanned = 0
        if budget is None:  # defensive
            budget = _ScanBudget()
        # Budget for AV member scans: at most N members per archive go
        # through the real engines (each run costs seconds); the GLOBAL
        # cap in the budget bounds the total across all nesting levels.
        av_budget = (
            config.AV_ARCHIVE_MEMBER_LIMIT if config.AV_SCAN_ARCHIVE_MEMBERS else 0
        )
        for name, payload, error in iterator:
            if not name and error:
                children.append(
                    self._container_note(
                        error, path_label, depth, container_rule, container_title,
                        truncated_prefix=truncated_prefix,
                    )
                )
                continue

            if not budget.take_member():
                note = ScanResult(path=path_label, depth=depth + 1)
                note.error = (
                    "Globales Scan-Limit erreicht — weitere Mitglieder über "
                    "alle Verschachtelungsebenen nicht gescannt"
                )
                note.indicators = [
                    Indicator(
                        rule_id="ARCH_TOTAL_LIMIT",
                        title="Globales Scan-Limit erreicht",
                        detail=(
                            f"Limit von {config.MAX_TOTAL_SCAN_MEMBERS} rekursiv "
                            "gescannter Mitglieder (global, über alle "
                            "Verschachtelungsebenen) erreicht — z. B. bei "
                            "Fractal-/Quine-Archiven. Das Ergebnis ist "
                            "unvollständig."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_ARCHIVE,
                        weight=25,
                        source="dispatcher",
                    )
                ]
                self._finalize_score(note)
                children.append(note)
                if member_budget is not None:
                    member_budget.left = _DRAIN_BYTES
                self._drain_container_notes(
                    iterator, children, path_label, depth,
                    container_rule, container_title,
                    truncated_prefix=truncated_prefix,
                )
                break

            if scanned >= config.MAX_RECURSIVE_MEMBERS:
                note = ScanResult(path=path_label, depth=depth + 1)
                note.error = "Weitere Mitglieder nicht gescannt (Responsiveness-Limit)"
                note.indicators = [
                    Indicator(
                        rule_id="ARCH_MEMBER_SKIP",
                        title="Mitglieder nicht gescannt — Inhalt ungeprüft",
                        detail=(
                            f"Limit {config.MAX_RECURSIVE_MEMBERS} rekursiv "
                            "gescannter Mitglieder erreicht; der Rest dieses "
                            "Containers wurde NICHT analysiert. Der Inhalt ist "
                            "unbekannt, nicht sauber — ein schädliches Mitglied "
                            "hinter dieser Grenze bleibt unentdeckt."
                        ),
                        # Weight, not 0: skipping members removes the whole
                        # content stage from the verdict. With weight 0 a
                        # payload placed behind enough harmless entries scored
                        # GREEN — measured: the same archive scored RED 90 with
                        # the payload first and YELLOW 30 with it last.
                        severity=Severity.MEDIUM,
                        category=CAT_ARCHIVE,
                        weight=25,
                        source="dispatcher",
                    )
                ]
                self._finalize_score(note)
                children.append(note)
                if member_budget is not None:
                    member_budget.left = _DRAIN_BYTES
                self._drain_container_notes(
                    iterator, children, path_label, depth,
                    container_rule, container_title,
                    truncated_prefix=truncated_prefix,
                )
                if any(
                    indicator.rule_id == "ARCH_MEMBER_STOP"
                    and "Eintrags-Limit" in indicator.detail
                    # ALLE Kinder, nicht nur der Nachlauf: die TAR-Notiz
                    # (iter_compressed_members) kommt VOR dem Walk, weil sie
                    # aus dem Metadaten-Vorlauf stammt; ZIP/7z liefern sie am
                    # Ende. Der Nachlauf-Bereich begann hinter dieser Notiz,
                    # also blieb sie unentdeckt und 25 + 25 = 50 = ROT fuer ein
                    # blosses Quelltext-Tarball (>10.000 Dateien). Gemessen:
                    # TAR 50 ROT, dasselbe ZIP 25 GELB.
                    for tail in children
                    for indicator in tail.indicators
                ):
                    # The iterator's entry-limit note is the single weighted
                    # statement for this cause. Keep the responsiveness note
                    # visible, but do not charge the same limit twice.
                    note.indicators[0].weight = 0
                    note.indicators[0].severity = Severity.INFO
                    self._finalize_score(note)
                break

            if error:
                child = ScanResult(path=name, depth=depth + 1, error=error)
                child.indicators = [
                    Indicator(
                        rule_id=member_rule,
                        title=member_title,
                        detail=(
                            f"{error} — dieses Mitglied wurde NICHT "
                            "analysiert; sein Inhalt ist unbekannt, nicht "
                            "sauber."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_ARCHIVE,
                        # 25 statt 5 — dieselbe Gewichtsklasse wie
                        # ARCH_MEMBER_SKIP und ARCH_MEMBER_ERROR. Dieser Zweig
                        # bekommt seinen Fehler aus dem Iterator, und jeder
                        # Produzent liefert dazu einen LEEREN Payload
                        # (archive.py: "Eintrag zu groß", "Verschlüsselt",
                        # "Entpacken fehlgeschlagen", "nicht lesbar";
                        # sevenzip.py: "Eintrag nicht lesbar"; email_extract.py:
                        # "Anhang nicht dekodierbar"). Es gibt hier also keinen
                        # reinen Metadaten-Fehler, bei dem der Inhalt noch
                        # vorliegt — jedes error-Feld heißt "kein Inhalt".
                        # Gewicht 5 lag unter SCORE_GREEN_MAX (19): ein ZIP,
                        # dessen einziges Problem ein nicht entpackbares
                        # Nutzlast-Mitglied war, meldete GRÜN (gemessen:
                        # Verfahrensfeld 8 -> 98 GRÜN 5 gegen ROT 80 intakt,
                        # verschlüsselt markiert GRÜN 10).
                        weight=25,
                        source="dispatcher",
                    )
                ]
                self._finalize_score(child)
                children.append(child)
                continue

            try:
                child = self._scan(
                    data=payload,
                    path=Path(name),
                    depth=depth + 1,
                    display_path=name,
                    real_path=None,
                    size=len(payload),
                    budget=budget,
                )
            except Exception as exc:
                # Isolate per member. An exception here used to escape to
                # scan_path and replace the WHOLE result (no indicators left,
                # only CORE_ERROR) — measured: one crafted member turned a RED
                # archive GREEN. Now it costs this member only.
                log.warning(
                    "Mitglied %r fehlgeschlagen: %s: %s",
                    anonymize_name(name), type(exc).__name__, exc,
                )
                child = ScanResult(path=name, depth=depth + 1)
                child.error = f"{type(exc).__name__}: {exc}"
                child.indicators = [
                    # Same rule id as the ``if error:`` branch above — both say
                    # "this member was not analysed, its content is unknown" —
                    # and the two are told apart by the title suffix. It used to
                    # be ARCH_MEMBER_STOP, which the bomb-protection stop also
                    # used; keeping the id unchanged across the whole
                    # "member was not inspected" class means one id, one
                    # meaning, and no third reading of ARCH_MEMBER_STOP.
                    # 25 = same weight class as the other "not inspected" notes:
                    # an unexamined member must not read as clean.
                    Indicator(
                        rule_id="ARCH_MEMBER_ERROR",
                        title=f"{member_title} (unerwarteter Fehler)",
                        detail=(
                            f"{type(exc).__name__}: {exc} — dieses Mitglied "
                            "wurde NICHT analysiert."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_ARCHIVE,
                        weight=25,
                        source="dispatcher",
                    )
                ]
                self._finalize_score(child)
                children.append(child)
                continue
            # Real AV verdict for archive members, too — bounded by the
            # per-archive budget AND the global cap so huge or fractal
            # archives cannot explode the engine-call count.
            if av_budget > 0 and payload and budget.take_av():
                av_budget -= 1
                self._av_scan_member(child, payload)
            children.append(child)
            scanned += 1
            if (
                member_budget is not None
                and scanned >= config.MAX_RECURSIVE_MEMBERS
            ):
                # Arm the payload budget BEFORE the next member is pulled: the
                # ``for`` statement materialises it before the cap check in the
                # loop body can fire, so arming later came too late — measured,
                # a 30 MB member was still decompressed although the drain was
                # about to drop it.
                member_budget.left = _DRAIN_BYTES
        return children

    @staticmethod
    def _depth_limit_indicator(what: str, verb: str = "entpackt") -> Indicator:
        """The container stage stopped at ``MAX_ARCHIVE_DEPTH``.

        Below this level nothing is expanded — and therefore nothing is
        analysed. Weight 25 (not 5): the established size for "stage did not
        run", above ``SCORE_GREEN_MAX`` (19) so the file can never come out
        GREEN, and far below ``ANCHOR_CRITICAL_SCORE`` (50) so a single stopped
        level stays YELLOW. Measured: a six-level ZIP with a PowerShell payload
        in the innermost layer scored GREEN 5, the same payload two levels deep
        scored RED 50.
        """
        return Indicator(
            rule_id="ARCH_DEPTH_LIMIT",
            title="Maximale Verschachtelungstiefe erreicht",
            detail=(
                f"{what} wird nicht tiefer {verb} (Limit "
                f"{config.MAX_ARCHIVE_DEPTH}). Der Inhalt unterhalb dieser "
                "Ebene wurde NICHT geprüft."
            ),
            severity=Severity.MEDIUM,
            category=CAT_ARCHIVE,
            weight=25,
            source="dispatcher",
        )

    def _guarded_members(self, what: str, fn, indicators: list[Indicator]):
        """Run a container recursion; a failure costs the stage, not the verdict.

        An exception from a member iterator used to escape all the way up to
        ``scan_path``, where the catch-all replaced the WHOLE result: the
        assignment ``result = self._scan(...)`` had never completed, so the
        fresh ``ScanResult`` carried no indicator at all and only ``CORE_ERROR``
        remained. Measured: an archive with a Zip-Slip entry scored RED 50, and
        GREEN 5 once one crafted member raised — a single member turned a
        detection into a false all-clear.

        Returns ``[]`` for the affected container so the rest of the scan (and
        every indicator collected so far) survives.

        Own rule id ``ARCH_CONTAINER_ERROR``. It used to share
        ``ARCH_MEMBER_STOP`` with the bomb-protection stop
        (``_container_note``) and with the per-member catch below — three
        different conditions behind one id, so any rule-id-based evaluation
        (report columns, corpus comparison, golden snapshot) collapsed "the
        container recursion raised" and "the archive was deliberately only
        partly extracted" into one indistinguishable set. The id itself is now
        unambiguous; weight 25 and MEDIUM are unchanged.
        """
        try:
            return fn()
        except Exception as exc:
            log.warning(
                "Container %s fehlgeschlagen: %s: %s", what, type(exc).__name__, exc
            )
            indicators.append(
                Indicator(
                    rule_id="ARCH_CONTAINER_ERROR",
                    title=f"{what}: Inhalt nicht auswertbar",
                    detail=(
                        f"{type(exc).__name__}: {exc} — dieser Teil des "
                        "Containers wurde NICHT geprüft. Das Ergebnis ist "
                        "unvollständig und nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    weight=25,
                    source="dispatcher",
                )
            )
            return []

    def _scan_archive_members(
        self, data: bytes, depth: int, budget: _ScanBudget | None = None,
        truncated_prefix: bool = False, source_path=None,
    ) -> list[ScanResult]:
        # SEC-006: a path-backed source means ``iter_zip_members`` reads the
        # FULL file (central directory included), so a container error there is
        # a real ARCH_ZIP_ERROR — not a consequence of the in-memory prefix
        # cap. Passing the cap flag on let ``_container_note`` zero its weight
        # (25 -> 0, "Folge der Lesekappung") for a genuinely broken ZIP >64 MB.
        effective_truncation = truncated_prefix and source_path is None
        from .archive import MemberBudget

        member_budget = MemberBudget()
        return self._scan_children(
            iter_zip_members(
                data, self.passwords, path=source_path, member_budget=member_budget
            ),
            depth,
            path_label="(ZIP-Inhalt)",
            container_rule="ARCH_ZIP_ERROR",
            container_title="Archiv konnte nicht gelesen werden",
            budget=budget,
            truncated_prefix=effective_truncation,
            member_budget=member_budget,
        )

    def _scan_sevenzip_members(
        self, data: bytes, depth: int, suffix: str,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        """Scan members of a RAR/7z/CAB/ISO archive via the 7-Zip binary."""
        from .sevenzip import find_7z_binary, iter_7z_members

        label = "CAB/ISO-Inhalt" if suffix in (".cab", ".iso") else "RAR/7z-Inhalt"

        if not config.SEVENZIP_ENABLED:
            # A disabled stage must be visible: container content silently not
            # being scanned is indistinguishable from "clean" otherwise.
            note = ScanResult(path=f"({label})", depth=depth + 1)
            note.error = f"{label}-Auswertung deaktiviert (config.SEVENZIP_ENABLED=False)"
            note.indicators = [
                Indicator(
                    rule_id="ARCH_7Z_DISABLED",
                    title=f"{label} nicht geprüft",
                    detail=(
                        "Die 7-Zip-Integration ist in der Konfiguration "
                        "deaktiviert. Die Datei wurde nur oberflächlich "
                        "geprüft (Entropie/Signaturen); der "
                        f"{label} wurde NICHT analysiert und ist nicht als "
                        "'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    # 20 wie der Geschwisterzweig ARCH_7Z_MISSING: beide
                    # bedeuten "der Inhalt wurde nicht analysiert".
                    # Gewicht 0 (INFO) ließ den Bericht stattdessen
                    # "Grün (unauffällig) ... bedenkenlos verwendet werden"
                    # für einen nie angesehenen Container ausgeben (gemessen:
                    # bad.7z GRÜN 0 abgeschaltet gegen GELB 20 ohne 7-Zip).
                    weight=20,
                    source="dispatcher",
                )
            ]
            self._finalize_score(note)
            return [note]

        if find_7z_binary() is None:
            note = ScanResult(path=f"({label})", depth=depth + 1)
            note.error = "7-Zip nicht installiert — Inhalt nicht gescannt"
            note.indicators = [
                Indicator(
                    rule_id="ARCH_7Z_MISSING",
                    title=f"{label} nicht geprüft",
                    detail=(
                        "Zum Entpacken von RAR/7z/CAB/ISO-Containern wird eine "
                        "installierte 7-Zip-CLI (7z/7zz) benötigt. Der "
                        f"{label} wurde NICHT analysiert — das Ergebnis ist "
                        "nicht als 'sauber' zu werten (7-Zip installieren und "
                        "erneut scannen)."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    weight=20,
                    source="dispatcher",
                )
            ]
            self._finalize_score(note)
            return [note]

        return self._scan_children(
            iter_7z_members(data, suffix, self.passwords),
            depth,
            path_label=f"({label})",
            container_rule="ARCH_7Z_ERROR",
            container_title="Archiv konnte nicht entpackt werden",
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_compressed_members(
        self, data: bytes, depth: int, kind: str,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        """Scan members of a tar/gzip/bzip2/xz container (in-memory)."""
        from .archive import MemberBudget, iter_compressed_members

        member_budget = MemberBudget()
        return self._scan_children(
            iter_compressed_members(data, kind, member_budget=member_budget),
            depth,
            path_label="(TAR/komprimierter Inhalt)",
            container_rule="ARCH_TAR_ERROR",
            container_title="Container konnte nicht entpackt werden",
            budget=budget,
            truncated_prefix=truncated_prefix,
            member_budget=member_budget,
        )

    def _scan_email_members(
        self, data: bytes, depth: int, kind: str,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        """Scan every attachment of an .eml/.msg mail (in-memory)."""
        from .email_extract import iter_email_attachments

        return self._scan_children(
            iter_email_attachments(data, kind),
            depth,
            path_label="(E-Mail)",
            container_rule="EMAIL_PARSE_ERROR",
            container_title="E-Mail konnte nicht entpackt werden",
            member_rule="EMAIL_ATTACH_ERROR",
            member_title="Anhang nicht entpackbar",
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_rtf_objects(
        self, data: bytes, depth: int, budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        """Scan OLE/embedded objects decoded from an RTF (in-memory)."""
        from .rtf_extract import iter_rtf_objects

        return self._scan_children(
            iter_rtf_objects(data),
            depth,
            path_label="(RTF)",
            container_rule="RTF_PARSE_ERROR",
            container_title="RTF-Objekte konnten nicht gelesen werden",
            member_rule="RTF_OBJ_ERROR",
            member_title="Eingebettetes Objekt nicht lesbar",
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_swf_payload(
        self, data: bytes, depth: int, budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        """Scan the decompressed content of a compressed SWF."""
        from .swf_extract import iter_swf_payloads

        return self._scan_children(
            iter_swf_payloads(data),
            depth,
            path_label="(SWF)",
            container_rule="SWF_PARSE_ERROR",
            container_title="SWF konnte nicht dekomprimiert werden",
            member_rule="SWF_PAYLOAD_ERROR",
            member_title="SWF-Inhalt nicht lesbar",
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    # -- AV ---------------------------------------------------------------- #

    def _av_scan(self, real_path: Path) -> Indicator:
        return self._av_indicator(self.av_scanner.scan_path(real_path))

    def _scan_av_pair(self, real_path: Path) -> tuple[Indicator, Indicator]:
        """Run Defender and ClamAV on one file in parallel.

        Both engines are pure subprocess wait time (MpCmdRun start-up,
        clamscan DB load — measured ~15 s per fresh clamscan process).
        Running them concurrently drops the per-file bottleneck from the
        sum of both to the slower of the two. Verdict parsing and indicator
        order stay as in the sequential version; an engine that RAISES is
        converted into its own ``*_ERROR`` indicator instead of escaping the
        pair (BUG-006) — otherwise the caller's broad catch replaced the
        whole result.
        """
        with ThreadPoolExecutor(max_workers=2) as pool:
            av_future = pool.submit(self._av_scan, real_path)
            clam_future = pool.submit(self._clam_scan, real_path)
            outcomes: list[Indicator] = []
            for future, rule_id, engine, source in (
                (av_future, "AV_ERROR", "Windows Defender", "windows_av"),
                (clam_future, "CLAMAV_ERROR", "ClamAV", "clamav"),
            ):
                try:
                    outcomes.append(future.result())
                except Exception as exc:
                    # BUG-006: one throwing engine used to escape this pair
                    # wholesale; the caller's broad catch then replaced the
                    # ENTIRE result. The other engine's verdict, already in
                    # flight, was lost with it. Keep each engine independent.
                    log.warning("%s-Scan fehlgeschlagen: %s", engine, exc)
                    outcomes.append(
                        self._engine_error_indicator(rule_id, engine, exc, source)
                    )
            return outcomes[0], outcomes[1]

    def _engine_error_indicator(
        self, rule_id: str, engine: str, exc: Exception, source: str
    ) -> Indicator:
        """A failed optional engine: visible, but not a verdict about the file."""
        return Indicator(
            rule_id=rule_id,
            title=f"{engine}: Scan fehlgeschlagen",
            detail=(
                f"{type(exc).__name__}: {exc} — die Engine konnte diese Datei "
                "nicht prüfen. Ihr Urteil fehlt; die übrigen Stufen liefen "
                "weiter. Das Ergebnis ist insoweit unvollständig."
            ),
            severity=Severity.INFO,
            category=CAT_AV,
            weight=0,
            source=source,
        )

    def _av_indicator(self, av) -> Indicator:
        if av.threat_found:
            title = (
                "Windows Defender: Bedrohung erkannt & bereinigt"
                if av.remediated
                else "Windows Defender: Bedrohung erkannt"
            )
            return Indicator(
                rule_id="AV_THREAT",
                title=title,
                detail=av.detail,
                severity=Severity.CRITICAL,
                category=CAT_AV,
                weight=50,
                source="windows_av",
            )
        if av.clean:
            return Indicator(
                rule_id="AV_CLEAN",
                title="Windows Defender: keine Bedrohung",
                # NICHT die rohe Werkzeugausgabe. GEMESSEN im gerenderten
                # Fenster: unter "Was gefunden wurde" stand als ERSTES ein
                # Block MpCmdRun-Text ("Scanning C:\... found no threats",
                # "----------- SCAN SUMMARY -----------", "Infected files: 0").
                # Fuer den Laien ist das Rauschen, und es begraebt die echten
                # Befunde darunter. Die vollstaendige Ausgabe steht ohnehin
                # woertlich in malaz.log (siehe analysis/windows_av: "logged
                # verbatim so a wrong verdict can be diagnosed").
                detail="Der Virenscanner hat diese Datei geprüft und nichts gefunden.",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="windows_av",
            )
        # Skipped / inconclusive -> informational only, no score impact.
        return Indicator(
            rule_id="AV_SKIPPED",
            title="Windows Defender: Scan übersprungen",
            detail=av.skipped_reason or av.detail,
            severity=Severity.INFO,
            category=CAT_AV,
            weight=0,
            source="windows_av",
        )

    def _clam_scan(self, real_path: Path) -> Indicator:
        return self._clam_indicator(self.clam_scanner.scan_path(real_path))

    def _clam_indicator(self, clam) -> Indicator:
        if getattr(clam, "limit_exceeded", False):
            # The engine reported "OK" because it skipped the file. That is
            # the one case where a clean-reading engine output must be turned
            # into an explicit "not checked" — otherwise every file above
            # clamd's MaxFileSize is a false CLEAN.
            return Indicator(
                rule_id="CLAMAV_SIZE_LIMIT",
                title="ClamAV: Datei wegen Größenlimit nicht geprüft",
                detail=(
                    f"{clam.skipped_reason or 'ClamAV hat die Datei übersprungen.'} "
                    "Das ist NICHT als 'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_CLAMAV,
                weight=25,
                source="clamav",
            )
        if clam.threat_found:
            name = clam.threat_name or "unbekannte Signatur"
            unconfirmed = name.startswith("unbestätigt")
            return Indicator(
                rule_id="CLAMAV_THREAT",
                title=(
                    f"ClamAV: Bedrohung erkannt ({name})"
                    if not unconfirmed
                    else f"ClamAV: unbestätigter Fund-Hinweis ({name})"
                ),
                detail=clam.detail,
                # A FOUND-line match is a hard CRITICAL anchor. rc==1 without
                # a parsable FOUND line (encoding damage) stays visible but
                # must not carry the full 50-weight anchor on no evidence.
                #
                # 25, not 15: MEDIUM's base weight is 15, which is BELOW
                # SCORE_GREEN_MAX (19) — an rc=1 verdict therefore produced
                # GREEN 15 and read as an all-clear, although ClamAV said the
                # file was infected. 25 keeps it one step above GREEN (YELLOW)
                # without inventing the CRITICAL anchor the missing FOUND line
                # does not justify.
                severity=Severity.MEDIUM if unconfirmed else Severity.CRITICAL,
                category=CAT_CLAMAV,
                weight=25 if unconfirmed else 50,
                source="clamav",
            )
        if clam.clean:
            return Indicator(
                rule_id="CLAMAV_CLEAN",
                title="ClamAV: keine Bedrohung",
                # Aus demselben Grund wie bei AV_CLEAN: die rohe Ausgabe
                # ("----------- SCAN SUMMARY -----------", "Infected files: 0",
                # Start/End Date) gehoert ins Protokoll, nicht in die
                # Laienansicht. GEMESSEN im gerenderten Fenster stand sie unter
                # "Was gefunden wurde" und schob die echten Befunde nach unten.
                detail="Der Virenscanner hat diese Datei geprüft und nichts gefunden.",
                severity=Severity.INFO,
                category=CAT_CLAMAV,
                weight=0,
                source="clamav",
            )
        return Indicator(
            rule_id="CLAMAV_SKIPPED",
            title="ClamAV: Scan übersprungen",
            detail=clam.skipped_reason or clam.detail,
            severity=Severity.INFO,
            category=CAT_CLAMAV,
            weight=0,
            source="clamav",
        )

    def _av_scan_member(self, child: ScanResult, payload: bytes) -> None:
        """Run the AV engines on one in-memory archive member.

        The member never existed on disk, so without this stage the real
        engines would never judge it — only static heuristics would.
        Findings land on the member's own result (visible per member in
        report and GUI); the budget in ``_scan_children`` bounds the cost.
        """
        # The suffix only helps the engine's file-type detection; it can come
        # from an archive member name, so strip anything a Windows filesystem
        # would reject.
        raw_suffix = Path(child.path).suffix or ".bin"
        suffix = "".join(
            ch if (ch.isalnum() or ch in ".-_") else "_" for ch in raw_suffix
        ) or ".bin"
        try:
            # Both engines in parallel (see _scan_av_pair): member scans pay
            # the same subprocess cost, archives can contain many members.
            with ThreadPoolExecutor(max_workers=2) as pool:
                av_future = (
                    pool.submit(self.av_scanner.scan_bytes, payload, suffix)
                    if self.av_scanner.available else None
                )
                clam_future = (
                    pool.submit(self.clam_scanner.scan_bytes, payload, suffix)
                    if self.clam_scanner.available else None
                )
                if av_future is not None:
                    child.indicators.append(self._av_indicator(av_future.result()))
                if clam_future is not None:
                    child.indicators.append(self._clam_indicator(clam_future.result()))
        except Exception as exc:  # an AV hiccup must never lose the member scan
            child.indicators.append(
                Indicator(
                    rule_id="AV_MEMBER_ERROR",
                    title="AV-Mitgliedsscan fehlerhaft",
                    detail=f"{type(exc).__name__}: {exc}",
                    # Weight 0, and deliberately not raised in the round-3 sweep
                    # that lifted every other "not examined" note to 25. This is
                    # not that class: this stage runs AFTER the member's own scan
                    # (the child already carries its YARA/heuristic findings), so
                    # a failure here means "the AV did not judge it", not "the
                    # content was never looked at". It matches AV_SKIPPED /
                    # CLAMAV_SKIPPED, which are weight 0 by the same decision —
                    # the engines are optional and their absence is the user's
                    # documented choice. Reachability is infrastructure-level,
                    # too: the scanners catch their own failures and report them
                    # through _av_indicator / _clam_indicator.
                    severity=Severity.INFO,
                    category=CAT_AV,
                    weight=0,
                    source="dispatcher",
                )
            )
        self._finalize_score(child)

    # -- helpers ----------------------------------------------------------- #

    def _container_note(
        self,
        error: str,
        path_label: str,
        depth: int,
        error_rule: str,
        error_title: str,
        *,
        truncated_prefix: bool = False,
    ) -> ScanResult:
        """Build a child note for a container-level error or budget stop.

        A bomb-protection stop (``BUDGET_STOP_PREFIX``) means the archive was
        NOT fully analysed — that is a visible finding of its own, not an
        extraction failure, and must never be silently dropped.

        A traversal attempt (``ZIPSLIP_PREFIX``) is an attack indicator, not a
        degradation: it carries the same CRITICAL weight the ZIP pipeline
        assigns to ``ARCH_ZIPSLIP``, so RAR/7z cannot be the quiet route.

        ``truncated_prefix`` says the container was handed a cut-off prefix of
        a larger file (see ``_scan``). Its "not readable" message is then the
        consequence of that cap, not a second finding: it stays visible but
        carries no weight of its own, because CORE_READ_TRUNCATED counts the
        cap once. Without this the two weights added up to 50 =
        ANCHOR_CRITICAL_SCORE — a 101 MiB zero-byte TAR scored RED 55.
        """
        note = ScanResult(path=path_label, depth=depth + 1, error=error)
        if error.startswith(ZIPSLIP_PREFIX):
            detail = error[len(ZIPSLIP_PREFIX):].strip()
            note.indicators = [
                Indicator(
                    rule_id="ARCH_ZIPSLIP",
                    title="Zip-Slip-Versuch",
                    detail=detail,
                    severity=Severity.CRITICAL,
                    category=CAT_ARCHIVE,
                    weight=50,
                    source="dispatcher",
                )
            ]
        elif error.startswith(UNSAFE_NAME_PREFIX):
            # Der ZWEITE Marker aus core.archive: derselbe Pruefer, aber ein
            # anderer Grund. Ein reservierter Geraetename oder ein
            # Doppelpunkt im Namen ist kein Pfad-Escape — ihn mit dem Anker
            # zu belegen behauptete einen Angriff, den es nicht gibt.
            # LOW/5 wie ARCH_ENCRYPTED: sichtbar, aber kein Urteil.
            detail = error[len(UNSAFE_NAME_PREFIX):].strip()
            note.indicators = [
                Indicator(
                    rule_id="ARCH_UNSAFE_NAME",
                    title="Ungewöhnliche Eintragsnamen",
                    detail=detail,
                    severity=Severity.LOW,
                    category=CAT_ARCHIVE,
                    weight=5,
                    source="dispatcher",
                )
            ]
        elif error.startswith(BUDGET_STOP_PREFIX):
            note.indicators = [
                Indicator(
                    rule_id="ARCH_MEMBER_STOP",
                    title="Archiv nicht vollständig ausgewertet",
                    detail=error,
                    # Bombenschutz-Stopp: das Archiv wurde bewusst nur
                    # teilweise entpackt — alleiniges GELB, damit der Stopp
                    # nie in einem grünen Gesamtergebnis verschwindet.
                    #
                    # Diese ID gehört ALLEIN diesem Stopp. Die beiden anderen
                    # "Stufe nicht gelaufen"-Fälle des Dispatchers tragen
                    # eigene IDs (ARCH_CONTAINER_ERROR für die geworfene
                    # Container-Rekursion, ARCH_MEMBER_ERROR für das nicht
                    # analysierte Mitglied), sonst kollabiert jede Auswertung
                    # über die Regel-ID "bewusst nur teilentpackt" mit
                    # "Container-Ausnahme".
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    weight=25,
                    source="dispatcher",
                )
            ]
        else:
            note.indicators = [
                Indicator(
                    rule_id=error_rule,
                    title=error_title,
                    # "Konnte nicht geöffnet werden" heißt: Der Inhalt wurde
                    # ÜBERHAUPT nicht analysiert (passwortgeschützter Header,
                    # defektes Archiv, …). Nach dem Grundsatz "nicht
                    # analysierbar ≠ sauber" muss so ein Fund allein schon
                    # GELB geben — der Live-VM-Test hat genau hier eine
                    # bösartige 7z als GRÜN durchrutschen sehen.
                    #
                    # Ausnahme: Der Container bekam nur einen abgeschnittenen
                    # Präfix der Datei. Dann ist "nicht lesbar" die Folge der
                    # Lesekappung, die CORE_READ_TRUNCATED bereits mit 20
                    # bewertet — der Befund bleibt sichtbar (Gewicht 0), zählt
                    # aber nicht ein zweites Mal (25 + 25 = 50 = ROT).
                    detail=(
                        f"{error} — Folge der Lesekappung: der Rest der Datei "
                        "wurde nicht gelesen (siehe CORE_READ_TRUNCATED)."
                        if truncated_prefix
                        else error
                    ),
                    severity=(
                        Severity.INFO if truncated_prefix else Severity.MEDIUM
                    ),
                    category=CAT_ARCHIVE,
                    weight=0 if truncated_prefix else 25,
                    source="dispatcher",
                )
            ]
        self._finalize_score(note)
        return note

    def _select_pipelines(self, ftype: str, suffix: str) -> list[Pipeline]:
        pipelines: list[Pipeline] = [self.generic]
        suffix = (suffix or "").lower()
        if ftype == "pdf":
            pipelines.append(self.pdf)
        elif ftype == "ole":
            pipelines.append(self.office)
        elif ftype == "eml":
            # Mail content: headers, body text, links (attachments still run
            # as children through _scan_email_members).
            pipelines.append(self.eml)
        elif ftype == "zip":
            pipelines.append(self.archive)
            if suffix in _OOXML_OFFICE_SUFFIXES:
                pipelines.append(self.office)
        elif ftype in ("png", "jpeg", "gif", "bmp", "heic", "avif"):
            pipelines.append(self.image)
        elif ftype == "pe":
            pipelines.append(self.pe)
        elif ftype == "elf":
            pipelines.append(self.elf)
        elif ftype == "macho":
            pipelines.append(self.macho)
        # 'unknown', etc. -> generic only (entropy + YARA).
        return pipelines

    def _finalize_score(self, result: ScanResult) -> None:
        breakdown = compute_score(result.all_indicators())
        result.score = breakdown.score
        result.risk_level = breakdown.risk_level
        result.anchored = breakdown.anchored
        result.av_discount = breakdown.discount
        result.engine_verdicts = build_engine_verdicts(
            result,
            yara_available=bool(getattr(self.yara, "available", False)),
        )
