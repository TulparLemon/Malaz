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
from ..pipelines.web_pipeline import WebContentPipeline
from ..security.limits import LimitExceeded, guard_file_size, guard_read_size
from . import magic
from .container_dispatch import (
    _DRAIN_BYTES as _DRAIN_BYTES,
)
from .container_dispatch import (
    ContainerScanContext,
    container_note,
    depth_limit_indicator,
    drain_container_notes,
    guarded_members,
    scan_archive_members,
    scan_children,
    scan_compressed_members,
    scan_email_members,
    scan_onenote_objects,
    scan_rtf_objects,
    scan_sevenzip_members,
    scan_swf_payload,
    unread_tail_note,
)
from .container_dispatch import (
    _ScanBudget as _ScanBudget,
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
    {
        "zip", "rar", "7z", "deb", "rpm", "cab", "iso",
        "chm", "vhdx", "ntfs", "fat",
        "tar", "gzip", "bzip2", "xz",
    }
)
_SEVENZIP_TYPES = frozenset(
    {"rar", "7z", "deb", "rpm", "cab", "iso", "chm", "vhdx", "ntfs", "fat"}
)
_WEB_TEXT_SUFFIXES = frozenset(
    {".html", ".htm", ".shtml", ".xhtml", ".xht", ".hta", ".mht", ".mhtml", ".svg"}
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
        elif path.is_file() and not _add(path):
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
        self.web = WebContentPipeline()

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
        if ftype.type == "zip" or ftype.type in _SEVENZIP_TYPES:
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
            elif ftype.type in _SEVENZIP_TYPES:
                raw_suffix = path.suffix.lower()
                canonical_suffix = f".{ftype.type}"
                sz_suffix = (
                    canonical_suffix
                    if ftype.type in ("chm", "vhdx", "ntfs", "fat") or raw_suffix != canonical_suffix
                    else raw_suffix
                )
                result.children = self._guarded_members(
                    "Archiv-Inhalt (7-Zip)",
                    lambda: self._scan_sevenzip_members(
                        data, depth, sz_suffix, budget, truncated_prefix
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
        elif ftype.type == "onenote":
            if depth >= config.MAX_ARCHIVE_DEPTH:
                indicators.append(self._depth_limit_indicator("OneNote"))
            else:
                result.children = self._guarded_members(
                    "OneNote-Inhalt",
                    lambda: self._scan_onenote_objects(
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


    def _container_ctx(self) -> ContainerScanContext:
        return ContainerScanContext(
            scan_child=self._scan,
            av_scan_member=self._av_scan_member,
            finalize_score=self._finalize_score,
            passwords=self.passwords,
        )

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
        drain_container_notes(
            self._container_ctx(),
            iterator,
            children,
            path_label,
            depth,
            container_rule,
            container_title,
            limit=limit,
            max_bytes=max_bytes,
            truncated_prefix=truncated_prefix,
        )

    def _unread_tail_note(self, path_label: str, depth: int, reason: str) -> ScanResult:
        return unread_tail_note(self._container_ctx(), path_label, depth, reason)

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
        return scan_children(
            self._container_ctx(),
            iterator,
            depth,
            path_label=path_label,
            container_rule=container_rule,
            container_title=container_title,
            member_rule=member_rule,
            member_title=member_title,
            budget=budget,
            truncated_prefix=truncated_prefix,
            member_budget=member_budget,
        )

    @staticmethod
    def _depth_limit_indicator(what: str, verb: str = "entpackt") -> Indicator:
        return depth_limit_indicator(what, verb)

    def _guarded_members(self, what: str, fn, indicators: list[Indicator]):
        return guarded_members(self._container_ctx(), what, fn, indicators)

    def _scan_archive_members(
        self,
        data: bytes,
        depth: int,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
        source_path=None,
    ) -> list[ScanResult]:
        return scan_archive_members(
            self._container_ctx(),
            data,
            depth,
            budget=budget,
            truncated_prefix=truncated_prefix,
            source_path=source_path,
        )

    def _scan_sevenzip_members(
        self,
        data: bytes,
        depth: int,
        suffix: str,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        return scan_sevenzip_members(
            self._container_ctx(),
            data,
            depth,
            suffix,
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_compressed_members(
        self,
        data: bytes,
        depth: int,
        kind: str,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        return scan_compressed_members(
            self._container_ctx(),
            data,
            depth,
            kind,
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_email_members(
        self,
        data: bytes,
        depth: int,
        kind: str,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        return scan_email_members(
            self._container_ctx(),
            data,
            depth,
            kind,
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_rtf_objects(
        self,
        data: bytes,
        depth: int,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        return scan_rtf_objects(
            self._container_ctx(),
            data,
            depth,
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_onenote_objects(
        self,
        data: bytes,
        depth: int,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        return scan_onenote_objects(
            self._container_ctx(),
            data,
            depth,
            budget=budget,
            truncated_prefix=truncated_prefix,
        )

    def _scan_swf_payload(
        self,
        data: bytes,
        depth: int,
        budget: _ScanBudget | None = None,
        truncated_prefix: bool = False,
    ) -> list[ScanResult]:
        return scan_swf_payload(
            self._container_ctx(),
            data,
            depth,
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
        return container_note(
            self._container_ctx(),
            error,
            path_label,
            depth,
            error_rule,
            error_title,
            truncated_prefix=truncated_prefix,
        )


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
        elif ftype in ("html", "xml") or (
            ftype in ("text", "unknown") and suffix in _WEB_TEXT_SUFFIXES
        ):
            pipelines.append(self.web)
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
