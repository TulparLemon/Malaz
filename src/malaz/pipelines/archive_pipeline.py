"""Archive analysis pipeline (inspection only).

Inspects the archive's central directory *without* extracting payloads and
flags structural attacks:

* Zip-Slip — member names that escape the target directory.
* Zip-bomb characteristics — entry count, total uncompressed volume and
  compression ratio beyond the configured limits.
* Encryption — password-protected entries.

Actual safe in-memory extraction and recursion is orchestrated by the
dispatcher via :mod:`malaz.core.archive`.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterable

from .. import config
from ..core.archive import (
    _declared_zip_entry_count,
    _read_zip_member,
    split_unsafe_names,
)
from ..models import (
    CAT_ARCHIVE,
    AnalysisContext,
    Indicator,
    Severity,
)
from ..security.limits import LimitExceeded, guard_ratio
from ..security.safe_extract import (
    is_safe_member_name,
    unsafe_name_reason,
)
from .base import Pipeline

# Container-Magics, die ein Mitglied selbst als Archiv ausweisen. Kurze
# Signaturen (GZIP/BZIP2/XZ) zählen nur zusammen mit der passenden Endung —
# "BZh" allein sind drei harmlose Bytes. TAR hat seine Signatur bei Offset 257.
_NESTED_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"MSCF", "CAB"),
)
_NESTED_SUFFIX_MAGICS: tuple[tuple[bytes, tuple[str, ...], str], ...] = (
    (b"\x1f\x8b", (".gz", ".tgz"), "GZIP"),
    (b"BZh", (".bz2", ".tbz2"), "BZIP2"),
    (b"\xfd7zXZ\x00", (".xz", ".txz"), "XZ"),
)
_NESTED_TAR_SUFFIXES = (".tar",)
# Nur so viel eines verschachtelten Archivs lesen, um dessen eigenes
# Zentralverzeichnis zu prüfen. 4 MiB reichen für normale Pakete; ein
# größeres inneres Archiv bleibt unbeanstandet, statt den Scan zu belasten.
_NESTED_PROBE_MEMBER_BYTES = 4 * 1024 * 1024
_NESTED_PROBE_MEMBERS = 64
# Der Probe-Walk ist ein ZWEITER Lesevorgang neben der Dispatcher-Extraktion.
# Ohne eigenes Budget könnte ein Archiv mit 1000 kleinen ZIP-Mitgliedern
# Gigabytes entpacken, obwohl die Sammelgrenzen des Dispatchers diesen Pfad
# nicht kennen. Höchstens 8 Treffer und 16 MiB entpackte Probe-Bytes.
_NESTED_MAX_HITS = 8
_NESTED_PROBE_TOTAL_BYTES = 16 * 1024 * 1024


def _nested_container_label(name: str, head: bytes) -> str | None:
    """Return the inner container type, or ``None`` for ordinary data."""
    for magic, label in _NESTED_MAGICS:
        if head.startswith(magic):
            return label
    lower = name.lower()
    for magic, suffixes, label in _NESTED_SUFFIX_MAGICS:
        if head.startswith(magic) and lower.endswith(suffixes):
            return label
    if lower.endswith(_NESTED_TAR_SUFFIXES) and head[257:262] == b"ustar":
        return "TAR"
    return None


def _archive_contains_archive(blob: bytes) -> str | None:
    """Kind of the first archive found inside ``blob`` (itself a ZIP)."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as inner:
            for info in inner.infolist()[:_NESTED_PROBE_MEMBERS]:
                if info.filename.endswith("/") or info.flag_bits & 0x1:
                    continue
                if not is_safe_member_name(info.filename):
                    continue
                try:
                    with inner.open(info) as handle:
                        head = handle.read(264)
                except Exception:
                    continue
                label = _nested_container_label(info.filename, head)
                if label is not None:
                    return label
    except Exception:
        return None
    return None


def _nested_archives(
    archive: zipfile.ZipFile, infos: Iterable[zipfile.ZipInfo]
) -> list[tuple[str, str]]:
    """``(member name, chain)`` for archives that contain another archive.

    Only *recursive* nesting is returned. One wrapping level is a normal
    distribution bundle (the harmless corpus contains exactly that shape:
    ``bundle.zip`` → ``bundle/inner.zip`` → files), and flagging it produced a
    measured false positive. A second level is the evasion shape: unpackers
    and static scanners commonly stop after one container.

    Each candidate member is read through the bounded, CRC-checked reader from
    ``core.archive``; members above 4 MiB are not probed (cost, not trust).
    """
    found: list[tuple[str, str]] = []
    budget = _NESTED_PROBE_TOTAL_BYTES
    for info in infos:
        if len(found) >= _NESTED_MAX_HITS or budget <= 0:
            break
        if info.filename.endswith("/") or info.flag_bits & 0x1:
            continue
        if not is_safe_member_name(info.filename):
            continue
        if info.file_size > _NESTED_PROBE_MEMBER_BYTES:
            continue
        try:
            with archive.open(info) as handle:
                head = handle.read(264)
        except Exception:
            continue
        label = _nested_container_label(info.filename, head)
        if label is None:
            continue
        payload, error = _read_zip_member(archive, info)
        if payload is None or error is not None:
            continue
        budget -= len(payload)
        inner_label = _archive_contains_archive(payload)
        if inner_label is not None:
            found.append((info.filename, f"{label} > {inner_label}"))
    return found


class ArchivePipeline(Pipeline):
    name = "archive"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        if ctx.detected_type != "zip":
            return []
        try:
            file_source = getattr(ctx, "source", None)
            source = (
                file_source.path
                if file_source is not None and file_source.size > len(ctx.data)
                else io.BytesIO(ctx.data)
            )
            # SEC-009 follow-up: ``ZipFile.__init__`` materialises the WHOLE
            # central directory, so the entry limit has to run before it —
            # afterwards it only measures what was already allocated
            # (measured: 100 000 entries = 8.4 MB file, 5.25 s and 57 MB peak
            # just to open). The declared count comes from the EOCD and is
            # attacker-controlled, so the in-walk limit stays as the second
            # guard; here it rejects the honest over-limit case without
            # touching a single entry.
            declared = _declared_zip_entry_count(
                file_source.path if file_source is not None else None,
                None if file_source is not None else ctx.data,
            )
            if declared is not None and declared > config.MAX_ARCHIVE_ENTRIES:
                return [
                    self._indicator(
                        "ARCH_TOO_MANY",
                        f"Zu viele Einträge ({declared})",
                        detail=(
                            f"Überschreitet Limit {config.MAX_ARCHIVE_ENTRIES} "
                            "(Zip-Bomben-Schutz). Das Archiv wurde nicht "
                            "geöffnet; die gewichtete Aussage liefert der "
                            "Dispatcher als ARCH_MEMBER_SKIP."
                        ),
                        severity=Severity.INFO,
                        category=CAT_ARCHIVE,
                        weight=0,
                    )
                ]
            zf = zipfile.ZipFile(source)
        except zipfile.BadZipFile:
            return [
                self._indicator(
                    "ARCH_BADZIP",
                    "Beschädigtes ZIP",
                    detail=(
                        "Die ZIP-Struktur ist ungültig (Zentralverzeichnis "
                        "nicht lesbar). Der Archivinhalt konnte nicht entpackt "
                        "und damit NICHT geprüft werden — die Local File Header "
                        "und ihre Datenströme bleiben erhalten."
                    ),
                    # Gewicht 0 — und zwar bewusst, nicht weil der Befund
                    # harmlos waere: eine Ursache, eine gewichtete Aussage.
                    # Die scorewirksame Meldung derselben Ursache liefert die
                    # namenlose Container-Notiz aus ``core.archive``
                    # (ARCH_ZIP_ERROR, MEDIUM/25), die der Dispatcher aus dem
                    # Mitglieder-Iterator baut. Zwei Gewichte fuer denselben
                    # Fakt summierten sich (5+25 bzw. 25+25) und behaupteten bei
                    # 50 = ANCHOR_CRITICAL_SCORE "boesartig", wo nur
                    # "ungeprueft" gilt: gemessen standen dem Archiv mit vier
                    # zerstörten EOCD-Bytes 50 ROT zu, ohne dass eine Nutzlast
                    # nachgewiesen war. ARCH_BADZIP bleibt als Diagnose
                    # erhalten: sie sagt, welche Stufe es gemerkt hat.
                    # Der zugehoerige Guard-Test
                    # (tests/test_archive.py::
                    #  test_corrupt_zip_keeps_the_weighted_unchecked_note)
                    # nagelt fest, dass beide nur gemeinsam auftreten.
                    severity=Severity.INFO,
                    category=CAT_ARCHIVE,
                    weight=0,
                )
            ]
        except Exception as exc:
            return [
                self._indicator(
                    "ARCH_OPEN_WARN",
                    "ZIP konnte nicht geöffnet werden",
                    detail=f"{type(exc).__name__}: {exc}",
                    severity=Severity.INFO,
                    category=CAT_ARCHIVE,
                    weight=0,
                )
            ]

        out: list[Indicator] = []
        with zf:
            infos = zf.infolist()

            # Entry count.
            if len(infos) > config.MAX_ARCHIVE_ENTRIES:
                out.append(
                    self._indicator(
                        "ARCH_TOO_MANY",
                        f"Zu viele Einträge ({len(infos)})",
                        detail=(
                            f"Überschreitet Limit {config.MAX_ARCHIVE_ENTRIES} "
                            "(Zip-Bomben-Schutz). Die gewichtete Aussage liefert "
                            "der Dispatcher als ARCH_MEMBER_SKIP; diese Meldung "
                            "bleibt als Diagnose sichtbar."
                        ),
                        severity=Severity.INFO,
                        category=CAT_ARCHIVE,
                        weight=0,
                    )
                )

            # Zip-Slip detection.
            unsafe = [i.filename for i in infos if not is_safe_member_name(i.filename)]
            # GETRENNT melden. Der Pruefer lehnt zweierlei ab: echte
            # Pfad-Escapes (Angriff, Anker) und ungewoehnliche Namen
            # (Geraetename, Doppelpunkt — auf Unix gueltige Dateinamen, also
            # meistens Schlamperei). Beides als "Zip-Slip-Versuch" zu melden
            # behauptete einen Angriff, den es nicht gibt: gemessen ergab ein
            # Zip mit NUR "CON.txt" ROT 50 "Zip-Slip-Versuch (1 Eintraege)".
            angriff, ungewoehnlich = split_unsafe_names(unsafe)
            if angriff:
                out.append(
                    self._indicator(
                        "ARCH_ZIPSLIP",
                        f"Zip-Slip-Versuch ({len(angriff)} Einträge)",
                        detail=(
                            "Eintragsnamen würden beim Entpacken aus dem Zielverzeichnis "
                            "schreiben (Path Traversal). Beispiele: "
                            + ", ".join(angriff[:5])
                        ),
                        severity=Severity.CRITICAL,
                        category=CAT_ARCHIVE,
                        weight=50,
                    )
                )
            if ungewoehnlich:
                gruende = {unsafe_name_reason(n) for n in ungewoehnlich}
                was = {
                    "device": "reservierte Windows-Gerätenamen",
                    "ads": "Doppelpunkt im Namen (Alternate Data Stream)",
                    "empty": "Namen, die beim Entpacken leer werden",
                    "dotname": "Namen, die mit zwei Punkten beginnen",
                }
                warum = ", ".join(sorted(was.get(g, str(g)) for g in gruende if g))
                out.append(
                    self._indicator(
                        "ARCH_UNSAFE_NAME",
                        f"Ungewöhnliche Eintragsnamen ({len(ungewoehnlich)})",
                        detail=(
                            f"{warum}. Der INHALT dieser Einträge wird trotzdem "
                            "geprüft (im Speicher, ohne Entpacken auf die "
                            "Platte); das Entpacken auf ein Zielverzeichnis "
                            "kann für diese Namen fehlschlagen. Ein Pfad-Escape "
                            "ist es NICHT. Beispiele: "
                            + ", ".join(ungewoehnlich[:5])
                        ),
                        severity=Severity.LOW,
                        category=CAT_ARCHIVE,
                        weight=5,
                    )
                )

            # Total uncompressed volume + compression ratio.
            total_uncompressed = sum(i.file_size for i in infos)
            total_compressed = sum(i.compress_size for i in infos)
            if total_uncompressed > config.MAX_UNCOMPRESSED_SIZE:
                out.append(
                    self._indicator(
                        "ARCH_BOMB_SIZE",
                        f"Zip-Bombe: entpacktes Volumen {total_uncompressed} Bytes",
                        detail=f"Überschreitet Limit {config.MAX_UNCOMPRESSED_SIZE} Bytes.",
                        severity=Severity.HIGH,
                        category=CAT_ARCHIVE,
                        weight=30,
                    )
                )
            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                try:
                    # Shared guard from security.limits — the same limit the
                    # rest of the app honours (single source of truth).
                    guard_ratio(total_compressed, total_uncompressed)
                except LimitExceeded:
                    out.append(
                        self._indicator(
                            "ARCH_BOMB_RATIO",
                            f"Zip-Bombe: Kompressionsverhältnis {ratio:.0f}:1",
                            detail=f"Überschreitet Limit {config.MAX_COMPRESSION_RATIO}:1.",
                            severity=Severity.HIGH,
                            category=CAT_ARCHIVE,
                            weight=30,
                        )
                    )

            # Recursively nested archives (dropper shape). One level is a
            # normal bundle — the harmless corpus fixture ``bundle.zip`` has
            # exactly that shape and must stay GREEN (measured false positive
            # with a one-level rule). A second level is the evasion shape.
            # Deliberately only when the OUTER container is an archive: a PE
            # embedding a ZIP is the normal Go-/Electron-installer shape and
            # stays a weight-0 note in
            # ``generic_pipeline._embedded_signatures`` (benign counterexample
            # in the corpus). 20 = GELB, so this reads "look", not "block";
            # ROT needs an additional weighted signal.
            nested = _nested_archives(zf, infos)
            if nested:
                kinds = sorted({kind for _, kind in nested})
                shown = ", ".join(f"{name} ({kind})" for name, kind in nested[:5])
                out.append(
                    self._indicator(
                        "ARCH_NESTED_ARCHIVE",
                        f"Rekursiv verschachtelte Archive ({len(nested)} Einträge)",
                        detail=(
                            f"Der Container enthält Archive, die selbst wieder "
                            f"ein Archiv tragen ({', '.join(kinds)}): {shown}. "
                            "Eine Verpackungsebene ist normal (Software-Bundles) "
                            "und wird bewusst nicht gemeldet; ab der zweiten "
                            "Ebene ist es ein typisches Auspack-/Scanner-Umgehungs-"
                            "Muster — Hinweis (20), kein Anker."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_ARCHIVE,
                        weight=20,
                    )
                )

            # Encryption.
            encrypted = [i.filename for i in infos if i.flag_bits & 0x1]
            if encrypted:
                out.append(
                    self._indicator(
                        "ARCH_ENCRYPTED",
                        f"Passwortgeschützte Einträge ({len(encrypted)})",
                        detail=(
                            "Einige Einträge sind verschlüsselt; Standard-Passwörter werden "
                            "bei der Entpackung automatisch geprüft."
                        ),
                        severity=Severity.LOW,
                        category=CAT_ARCHIVE,
                        weight=5,
                    )
                )
        return out
