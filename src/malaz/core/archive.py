"""Safe in-memory archive extraction for recursive scanning.

Used by the dispatcher to expand ZIP archives and feed each member back into
the analysis loop. Extraction happens entirely in memory, honours every
resource limit, validates each member name against Zip-Slip and tries a small
list of standard passwords for encrypted entries.
"""

from __future__ import annotations

import bz2
import copy
import gzip
import io
import lzma
import tarfile
import time
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path

from .. import config
from ..security.safe_extract import (
    ATTACK_REASONS,
    is_safe_member_name,
    unsafe_name_reason,
)

# Container iterators yield ("", b"", "<prefix> …") when a bomb-protection
# budget stops the walk early. The dispatcher turns these into a visible
# "analysis incomplete" indicator instead of silently dropping members.
BUDGET_STOP_PREFIX = "Auswertung gestoppt:"

# Same convention for a detected path-traversal (zip-slip) attempt. Needed
# because the ZIP path reports this from its pipeline, while RAR/7z only
# report through the member iterator — without a shared marker the attempt
# would go unnoticed there. 7-Zip itself sanitises such names away, so the
# extraction succeeds cleanly and NOTHING else would reveal the attempt.
ZIPSLIP_PREFIX = "Zip-Slip:"
# Der ZWEITE Marker: derselbe Pruefer, aber ein anderer Grund. Ein
# Geraetename oder ein Doppelpunkt ist kein Pfad-Escape, und ihn als
# "Zip-Slip-Versuch" (CRITICAL, Anker) zu melden behauptet einen Angriff,
# den es nicht gibt. Gemessen: ein Zip, das NUR "CON.txt" enthaelt, ergab
# ROT 50 "Zip-Slip-Versuch (1 Eintraege)".
UNSAFE_NAME_PREFIX = "Ungewoehnlicher Name:"


def split_unsafe_names(names: list[str]) -> tuple[list[str], list[str]]:
    """Trennt ``(Angriffe, ungewoehnliche Namen)``.

    Die Trennung steht hier an EINER Stelle, weil DREI Wege sie brauchen: die
    ZIP-Pipeline, der TAR-Walk und der 7z-Weg. Ein Pfad-Escape ist ein
    Angriff; ein reservierter Geraetename oder ein ":" im Namen ist meistens
    Schlamperei — auf Unix sind beide gueltige Dateinamen.
    """
    angriff: list[str] = []
    mild: list[str] = []
    for name in names:
        grund = unsafe_name_reason(name)
        if grund is None:
            continue
        (angriff if grund in ATTACK_REASONS else mild).append(name)
    return angriff, mild


_ZIP_EOCD_SIG = b"PK\x05\x06"
_ZIP64_LOCATOR_SIG = b"PK\x06\x07"
_ZIP64_EOCD_SIG = b"PK\x06\x06"
_EOCD_MIN_SIZE = 22
_MAX_ZIP_COMMENT = 0xFFFF


def _read_at(path, data: bytes | None, offset: int, length: int) -> bytes:
    """Read ``length`` bytes at ``offset`` from a path-backed or in-memory ZIP."""
    if path is not None:
        try:
            with open(path, "rb") as handle:
                handle.seek(offset)
                return handle.read(length)
        except OSError:
            return b""
        except (OverflowError, ValueError):
            # An 8-byte ZIP64 offset is attacker-controlled and can exceed
            # what the OS seek accepts: measured, 2**64-1 raises ValueError
            # ("cannot fit 'int' into an offset-sized integer"), which is NOT
            # an OSError and escaped this helper. A record that cannot be
            # reached is simply not there.
            return b""
    payload = data or b""
    if offset < 0:
        offset += len(payload)
    return payload[offset:offset + length]


_CD_RECORD_SIG = b"PK\x01\x02"
_CD_RECORD_FIXED = 46


def _count_central_directory(
    path, data: bytes | None, cd_end: int, size_cd: int
) -> int | None:
    """Count ``PK\\x01\\x02`` records in the central directory, bounded.

    ``size_cd`` says how many bytes the directory occupies; the records inside
    it are counted by walking their declared lengths, never by constructing
    ``ZipInfo`` objects. Returns ``None`` when the window cannot be read or
    does not look like a central directory — the caller then falls back to the
    declared count.

    The read is capped at ``MAX_ARCHIVE_ENTRIES + 1`` records, so a forged
    ``size_cd`` cannot turn this into a long loop.
    """
    if size_cd <= 0 or size_cd > cd_end:
        return None
    # ``cd_end`` is where the central directory ENDS — the EOCD record for a
    # plain archive, the ZIP64 record for a ZIP64 one. Computing it from the
    # file size was wrong twice: the EOCD (22 bytes + comment) follows the
    # directory, and a ZIP64 archive carries its record and locator after it.
    start = cd_end - size_cd
    budget = config.MAX_ARCHIVE_ENTRIES + 1
    counted = 0
    offset = start
    # Read in windows so a huge directory never lands in memory at once.
    window = 1 << 20
    buffer = b""
    buffer_start = start
    while counted <= budget and offset < start + size_cd:
        rel = offset - buffer_start
        while rel + _CD_RECORD_FIXED > len(buffer):
            chunk = _read_at(path, data, buffer_start + len(buffer), window)
            if not chunk:
                return counted if counted else None
            buffer += chunk
        if buffer[rel:rel + 4] != _CD_RECORD_SIG:
            return counted if counted else None
        name_len = int.from_bytes(buffer[rel + 28:rel + 30], "little")
        extra_len = int.from_bytes(buffer[rel + 30:rel + 32], "little")
        comment_len = int.from_bytes(buffer[rel + 32:rel + 34], "little")
        step = _CD_RECORD_FIXED + name_len + extra_len + comment_len
        if step <= _CD_RECORD_FIXED:
            return counted if counted else None
        counted += 1
        offset += step
        # Drop consumed bytes so the buffer stays one window.
        if offset - buffer_start > window:
            drop = offset - buffer_start - _CD_RECORD_FIXED
            buffer = buffer[drop:]
            buffer_start += drop
    return counted


def _declared_zip_entry_count(path, data: bytes | None) -> int | None:
    """Entry count from the EOCD trailer, WITHOUT opening the archive.

    ``zipfile.ZipFile(...)`` builds the WHOLE central directory in
    ``filelist`` inside ``__init__``; the entry limit in the walk therefore
    came after the allocation it was meant to prevent (SEC-009). The EOCD sits
    in the last 64 KiB + 22 bytes, so its declared count can be checked first:
    an archive that declares more entries than the limit is refused before a
    single ``ZipInfo`` is materialised.

    ``None`` means "could not determine" (missing EOCD, unreadable file) — the
    caller then walks normally and the in-loop limit remains the fallback.

    The count field alone is attacker-controlled, which is why ``size_cd`` is
    checked as well: the bytes it describes must actually be present, so
    ``size_cd // 46`` (the minimum record size) is an upper bound on the
    entries that will be materialised. Measured: a 5.7 MB archive with 60 000
    real entries and a forged count of 1 passed the count check and cost
    42.7 MB peak and 22 s; with the size_cd bound it is refused in 4.3 s at
    8.3 MB. A forged ``size_cd`` does not help an attacker either — zipfile
    reads exactly those bytes and raises BadZipFile (measured: 0.0 MB peak).
    """
    if path is not None:
        try:
            size = Path(path).stat().st_size
        except OSError:
            return None
    else:
        size = len(data or b"")
    window = min(size, _MAX_ZIP_COMMENT + _EOCD_MIN_SIZE)
    tail = _read_at(path, data, size - window, window)
    idx = tail.rfind(_ZIP_EOCD_SIG)
    if idx < 0 or len(tail) - idx < _EOCD_MIN_SIZE:
        return None
    # The count field is a claim; ``size_cd`` is not free to lie, because the
    # bytes it describes must actually be present. Counting the records inside
    # that window gives the real number without materialising a single
    # ZipInfo — exactly what SEC-009 needs, and it costs one pass over bytes
    # that are already in memory for small archives and one bounded read for
    # large ones.
    #
    # A ``size_cd // 46`` bound was tried first and is WRONG as a refusal: a
    # record is 46 + name + extra + comment bytes, so the bound is always
    # larger than the real count and rejects honest archives. Measured: 9 000
    # entries (limit 10 000) gave bound 10 736 and were refused.
    size_cd = int.from_bytes(tail[idx + 12:idx + 16], "little")
    if size_cd == 0xFFFFFFFF:
        # ZIP64 placeholder: the real size lives in the ZIP64 record, which is
        # handled below. Do not read 4 GiB of "central directory" here.
        size_cd = 0
    if size_cd:
        counted = _count_central_directory(path, data, size - window + idx, size_cd)
        if counted is not None and counted > config.MAX_ARCHIVE_ENTRIES:
            return counted
    entries = int.from_bytes(tail[idx + 10:idx + 12], "little")
    # 0xFFFF means "65535 or more, see ZIP64" — it is NOT a count. Returning
    # it made a forged EOCD (three members, field set to 0xFFFF) look like an
    # over-limit archive, so the whole file was refused without examining a
    # single member: measured, the same content scored RED 60 with a child
    # scan and RED 55 with "too many entries" and no children at all. Without
    # a readable ZIP64 record the count is simply unknown; the in-walk limit
    # still applies.
    #
    # The ZIP64 record is consulted whenever the locator is present, NOT only
    # when the classic field says 0xFFFF: zipfile's _EndRecData calls
    # _EndRecData64 unconditionally and takes size_cd from there, so an
    # attacker can leave the classic fields small and honest-looking while the
    # ZIP64 record describes a huge directory. Measured: classic count 1 and
    # size_cd 200 with a ZIP64 record over 60 000 entries — this function said
    # 1, zipfile read 60 000 (34.5 MB peak).
    #
    # ZIP64: the locator directly precedes the EOCD and points at the ZIP64
    # EOCD, whose "total entries" field is an 8-byte value at offset +32.
    locator = idx - 20
    if locator >= 0 and tail[locator:locator + 4] == _ZIP64_LOCATOR_SIG:
        z64_offset = int.from_bytes(tail[locator + 8:locator + 16], "little")
        record = _read_at(path, data, z64_offset, 56)
        if len(record) >= 48 and record[:4] == _ZIP64_EOCD_SIG:
            # The ZIP64 record carries its own size_cd at +40, and the same
            # argument as above applies: the bytes it describes must be
            # present, so size_cd // 46 bounds the entries. Without this the
            # classic EOCD's size_cd=0 was the only bound consulted, and a
            # ZIP64 record declaring 1 entry over a 60 000-entry directory
            # passed the pre-check (measured: 34.5 MB peak, 6 s).
            size_cd64 = int.from_bytes(record[40:48], "little")
            if size_cd64:
                counted64 = _count_central_directory(
                    path, data, z64_offset, size_cd64
                )
                if (
                    counted64 is not None
                    and counted64 > config.MAX_ARCHIVE_ENTRIES
                ):
                    return counted64
            return int.from_bytes(record[32:40], "little")
    if entries != 0xFFFF:
        return entries
    return None


class _VolumeStop(Exception):
    """Internal: the cumulative extraction budget is exhausted mid-member."""


def _volume_stop_note() -> str:
    return (
        f"{BUDGET_STOP_PREFIX} Entpacktes Gesamtvolumen würde Limit "
        f"{config.MAX_UNCOMPRESSED_SIZE} Bytes überschreiten "
        "(Zip-Bomben-Schutz) — weitere Mitglieder wurden übersprungen."
    )


class MemberBudget:
    """Byte budget shared between the container walk and the dispatcher.

    ``left`` is ``None`` while the normal member walk runs (the per-member cap
    applies). When the dispatcher stops scanning and only collects the trailing
    notes, it sets ``left`` to the remaining drain budget; from then on a member
    whose DECLARED size exceeds it is never decompressed. Without this the drain
    loaded one member of up to MAX_EXTRACTED_FILE_SIZE (512 MB) although it was
    not going to be examined.
    """

    __slots__ = ("left",)

    def __init__(self) -> None:
        self.left: int | None = None


def iter_zip_members(
    data: bytes | None = None,
    passwords: list[str] | None = None,
    *,
    path=None,
    member_budget: MemberBudget | None = None,
) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(member_name, member_bytes, error)`` for each safe member.

    * Unsafe (path-traversal) names are skipped — they are reported separately
      by the archive pipeline.
    * Members larger than ``MAX_EXTRACTED_FILE_SIZE`` yield an ``error`` instead
      of their content.
    * The declared ``file_size`` is never taken as the truth about the stream:
      each member is read in chunks up to its declaration and the result is
      compared against it, so a forged size is reported instead of handing on
      a silently truncated prefix (see ``_read_zip_member``).
    * Extraction stops once the cumulative extracted volume or the entry count
      exceeds the configured bomb-protection limits.
    * An unreadable central directory yields a name-less container error — the
      walk cannot start, and that must be visible (see below).
    * The EOCD's declared entry count is checked BEFORE ``zipfile.ZipFile``
      materialises the central directory; over-limit archives stop without
      being opened (SEC-009).
    * Encrypted members are tried against ``passwords`` (plus the built-ins).

    The ``error`` element is ``None`` on success.
    """
    if passwords is None:
        passwords = []
    candidate_passwords = list(passwords) + [
        pw for pw in config.load_zip_passwords() if pw not in passwords
    ]

    # SEC-009: check the declared entry count BEFORE ``ZipFile.__init__``
    # materialises the central directory. Same message/stop marker as the
    # in-loop limit so the dispatcher classifies both identically.
    declared_entries = _declared_zip_entry_count(path, data)
    if (
        declared_entries is not None
        and declared_entries > config.MAX_ARCHIVE_ENTRIES
    ):
        yield (
            "",
            b"",
            (f"{BUDGET_STOP_PREFIX} Eintrags-Limit {config.MAX_ARCHIVE_ENTRIES} "
             "erreicht — weitere Mitglieder wurden nicht gelesen."),
        )
        return

    try:
        # A path-backed source is used for files too large to load whole: the
        # ZIP central directory is at the END, so a prefix would make every
        # large archive look corrupt. zipfile reads the directory lazily.
        source = path if path is not None else io.BytesIO(data or b"")
        zf = zipfile.ZipFile(source)
    except Exception as exc:
        # Not just ``BadZipFile``. Fuzzing found a 131-byte archive whose
        # central directory declares version 14.8: the stdlib raises
        # ``NotImplementedError("zip file version 14.8")`` from
        # ``_RealGetContents``, not a ``BadZipFile`` — the exception escaped
        # ``iter_zip_members`` and the whole scan died instead of showing the
        # container note. The pipeline-level open (``archive_pipeline``) always
        # caught broadly for the same reason; the iterator must not be the
        # narrow hole. Regression input:
        # ``tests/data/fuzz_regressions/zip-2f73b69e165bbb06.bin``.
        #
        # Damage to the END of central directory (4 bytes are enough) leaves
        # every local file header and its deflate stream intact — 7-Zip,
        # `zip -FF` and friends still recover the payload. A silent ``return``
        # therefore handed the caller an empty zip and a clean verdict for a
        # file whose content was never looked at: measured, the same archive
        # scored RED 100 (member scanned) and GREEN 5 (only ARCH_BADZIP, the
        # payload never extracted). Same convention as
        # ``iter_compressed_members`` ("TAR-Container nicht lesbar") and
        # ``iter_7z_members``: the dispatcher turns this name-less error into a
        # visible "content not analysed" note (MEDIUM/25).
        yield (
            "",
            b"",
            (f"ZIP-Container nicht lesbar: {type(exc).__name__}: {exc} — der "
             "Archivinhalt wurde NICHT geprüft (Local File Header samt "
             "Datenstrom können eine Nutzlast enthalten)."),
        )
        return

    extracted_total = 0
    processed = 0

    def _charge(amount: int) -> None:
        """Count an ATTEMPTED expansion against the cumulative budget.

        Charged before the stream is read, and for every password attempt:
        a member that fails its CRC/size check was still decompressed up to
        the declared size, and six wrong passwords expand it six times. Not
        counting those let five forged 20 MiB members read 100 MiB against a
        64 MiB budget without a BUDGET_STOP (SEC-008).
        """
        nonlocal extracted_total
        extracted_total += amount
        if extracted_total > config.MAX_UNCOMPRESSED_SIZE:
            raise _VolumeStop

    with zf:
        for info in zf.infolist():
            if processed >= config.MAX_ARCHIVE_ENTRIES:
                yield (
                    "",
                    b"",
                    (f"{BUDGET_STOP_PREFIX} Eintrags-Limit {config.MAX_ARCHIVE_ENTRIES} "
                     "erreicht — weitere Mitglieder wurden nicht gelesen."),
                )
                return
            processed += 1

            # Directory entries are empty — but the DECLARATION is attacker
            # controlled, and skipping on it alone was a bypass twice over:
            # first the trailing slash (RED 75 as "evil.txt", GREEN 0 as
            # "evil.exe/"), then the same name with a forged central-directory
            # size of 0 while the local header carried the full stream
            # (measured: GREEN 0, no child). The entry is therefore READ once:
            # an honest directory yields nothing and is skipped, a lying one
            # comes back as "Größenangabe gefälscht" and is reported.
            if info.filename.endswith("/") and info.file_size == 0:
                # The probe can raise like any other read (unknown compression
                # method raises NotImplementedError, a corrupt stream raises
                # BadZipFile). The caller's outer guard caught it, but a
                # directory entry must not be able to end the walk: it becomes
                # a member note like every other unreadable member.
                try:
                    _probe, probe_error = _read_zip_member(zf, info)
                except Exception as exc:
                    yield (info.filename, b"", f"{type(exc).__name__}: {exc}")
                    continue
                if probe_error is not None:
                    yield (info.filename, b"", probe_error)
                continue
            # An unsafe name is a reason not to EXTRACT to disk — nothing is
            # ever written here, so the payload is still decompressed in memory
            # and scanned. Skipping it made the name a content gate: the same
            # PowerShell cradle scored RED 90 as "payload.txt" and YELLOW 35 as
            # "..payload.txt", with no child scan at all. The name itself is
            # reported separately by ARCH_UNSAFE_NAME.

            if (
                member_budget is not None
                and member_budget.left is not None
                and info.file_size > member_budget.left
            ):
                # Drain mode and the member does not fit: do not decompress it.
                yield (
                    "",
                    b"",
                    (f"Mitglied '{info.filename[:80]}' nicht geladen: "
                     f"{info.file_size} Bytes überschreiten das verbleibende "
                     f"Budget ({member_budget.left} Bytes)"),
                )
                continue
            # Per-member size guard.
            if info.file_size > config.MAX_EXTRACTED_FILE_SIZE:
                yield (
                    info.filename,
                    b"",
                    (f"Eintrag zu groß ({info.file_size} Bytes > "
                     f"{config.MAX_EXTRACTED_FILE_SIZE})"),
                )
                continue

            # Cumulative bomb-protection budget (pre-read; the per-attempt
            # charge inside the read is the second, exact guard).
            if extracted_total + info.file_size > config.MAX_UNCOMPRESSED_SIZE:
                yield ("", b"", _volume_stop_note())
                return

            member_bytes: bytes | None = None
            error: str | None = None
            try:
                if info.flag_bits & 0x1:  # encrypted
                    member_bytes, error = _read_encrypted(
                        zf, info, candidate_passwords, consume=_charge
                    )
                    if member_bytes is None and error is None:
                        error = "Verschlüsselt; kein Standard-Passwort passte"
                else:
                    _charge(info.file_size)
                    member_bytes, error = _read_zip_member(zf, info)
            except _VolumeStop:
                yield ("", b"", _volume_stop_note())
                return
            except RuntimeError as exc:
                error = f"Entpacken fehlgeschlagen: {exc}"
            except Exception as exc:  # defensive
                error = f"{type(exc).__name__}: {exc}"

            if member_bytes is not None:
                yield (info.filename, member_bytes, None)
            else:
                yield (info.filename, b"", error or "Unbekannter Fehler")


def _read_zip_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    pwd: bytes | None = None,
) -> tuple[bytes | None, str | None]:
    """Read one member through the chunked reader, bounded by OUR limit.

    ``zf.read(info)`` materializes the WHOLE remaining deflate stream in one
    ``decompress()`` call and only then cuts the result down to the DECLARED
    ``file_size``: ``ZipExtFile._read1`` ends with ``data = data[:self._left]``,
    and ``_left`` is the central-directory value the archive author writes.
    The size guard therefore never bounded the work. Measured: a 1.0 MiB ZIP
    whose member declared 1000 bytes but held 1 GiB of zeros produced a
    2049.0 MiB tracemalloc peak in 2.09 s, returned 1000 bytes and reported no
    error — the dispatcher scored it GREEN 0 while the same bytes declared
    honestly scored RED 85.

    The read is turned around so that the declaration can only make it
    SMALLER, never larger, and so that it cannot lie unnoticed:

    * the stream is opened through a copy of the ``ZipInfo`` whose
      ``file_size`` is ``declared + 1``. The stdlib clamps at that value, so a
      member that delivers the extra byte has proven its declaration wrong,
      while the amount we can be made to expand is ``declared + 1`` — and the
      caller rejected claims above ``MAX_EXTRACTED_FILE_SIZE`` before reading.
    * the bytes are read in chunks through ``_decompress_bounded`` (the
      chunked pattern this module already uses for gzip/bzip2/xz) instead of
      ``read(-1)``, so per decompression call the output is capped by the
      chunk size rather than by what the stream contains.
    * the returned length and the CRC are then checked against the
      declaration. A forged size is reported AS a forged size; the payload is
      not handed on, because a truncated prefix is not this member's content.

    ``(None, None)`` cannot happen here; either the bytes or a reason come
    back. Exceptions from the stream (corrupt data, unsupported method) are
    propagated — the caller reports them the same way it always did.
    """
    probe = copy.copy(info)
    probe.file_size = info.file_size + 1  # one byte beyond the claim
    if pwd is None:
        # BUG-013: the probe deliberately reads one byte past the declared
        # size, so the stdlib's CRC check fires on exactly that over-read and
        # its BadZipFile was reported as a FORGED size — even for a merely
        # damaged STORED member whose CRC branch was unreachable. Without a
        # password the ZipCrypto check byte is irrelevant, so the stdlib check
        # can be disabled here; the payload is verified explicitly below and
        # the two causes (damaged stream vs. lying declaration) stay apart.
        probe.CRC = None  # type: ignore[assignment]
    # With a password (``_read_encrypted``) ``probe.CRC`` must stay EXACTLY as
    # declared. Clearing it is the obvious way to stop the stdlib's CRC check
    # from firing on the clamped prefix, but it silently destroyed every
    # classic-encrypted member: ``ZipExtFile.__init__`` derives the ZipCrypto
    # check byte from it —
    # ``check_byte = (zipinfo.CRC >> 24) & 0xff`` — so ``None >> 24`` raised
    # TypeError, which the candidate-password loop reads as "wrong password".
    # Measured: a STORED member with flag 0x1 and the correct password came
    # back as 0 bytes and "Verschluesselt; kein Standard-Passwort passte"
    # (YELLOW 30 end to end) where the previous release read its 14 bytes and
    # flagged the traversal inside it (RED 55). Verification therefore happens
    # below, on the real payload, with the same algorithm.
    def factory():
        """Open the probe stream; the password form only when one is given."""
        return zf.open(probe) if pwd is None else zf.open(probe, pwd=pwd)

    chunks: list[bytes] = []
    total = 0
    limit = info.file_size + 1
    checksum_tripped = False
    over_limit = False
    try:
        with factory() as src:
            while True:
                chunk = src.read(config.READ_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    # The declaration is disproven by the stream itself. This
                    # must be recorded, not just acted on: with a plain break
                    # the chunk is dropped, ``payload`` stays empty, and every
                    # check below passes — len(b"") > 0 is false, the CRC of
                    # b"" is 0, and a member declaring 0 bytes with CRC 0 comes
                    # back as (b"", None), i.e. "honest empty member". With
                    # flag bit 3 the stdlib sets _left = None, so the clamp on
                    # file_size+1 does not apply at all and the first chunk
                    # crosses the limit.
                    over_limit = True
                    break
                chunks.append(chunk)
    except zipfile.BadZipFile:
        # Reading past the declared size cannot match the declared checksum, so
        # the stdlib's own check fires — and it fires inside the FIRST read that
        # crosses the claim, which is why the collected chunks can be empty.
        # That is the probe working, not a damaged member we should hide: it is
        # exactly the evidence that the declaration does not describe the
        # stream. The honest member never reaches this branch, because its
        # stream ends at the declared size.
        checksum_tripped = True
    payload = b"".join(chunks)
    if over_limit:
        return None, (
            f"Größenangabe im Zentralverzeichnis gefälscht: deklariert sind "
            f"{info.file_size} Bytes, der Datenstrom liefert mehr (mehr als "
            f"{total} Bytes gelesen — er wurde an der Deklaration gekappt). "
            "Dieses Mitglied wurde NICHT analysiert; ein Präfix davon ist "
            "nicht sein Inhalt."
        )
    if len(payload) > info.file_size:
        return None, (
            f"Größenangabe im Zentralverzeichnis gefälscht: deklariert sind "
            f"{info.file_size} Bytes, der Datenstrom liefert mehr (mindestens "
            f"{len(payload)} Bytes — er wurde an der Deklaration gekappt). "
            "Dieses Mitglied wurde NICHT analysiert; ein Präfix davon ist "
            "nicht sein Inhalt."
        )
    if checksum_tripped and info.file_size == 0:
        # A declaration of 0 bytes that still trips the checksum cannot be a
        # damaged stream: an honest empty member reads EOF cleanly. The bytes
        # are there, the central directory just denies them — that is a forged
        # size, not an ambiguous CRC failure.
        return None, (
            "Größenangabe im Zentralverzeichnis gefälscht: deklariert sind 0 "
            "Bytes, der Datenstrom liefert Inhalt. Dieses Mitglied wurde NICHT "
            "analysiert; ein Präfix davon ist nicht sein Inhalt."
        )
    if checksum_tripped:
        return None, (
            f"Prüfsumme stimmt nicht: deklariert sind {info.file_size} Bytes, "
            "der Datenstrom passt nicht zu Größe und CRC im "
            "Zentralverzeichnis. Die Ursache ist entweder eine Beschädigung "
            "des Datenstroms ODER eine gefälschte Größen-/Prüfsummenangabe — "
            "beides ist an dieser Stelle nicht unterscheidbar. Dieses Mitglied "
            "wurde NICHT analysiert; ein Präfix davon ist nicht sein Inhalt."
        )
    if len(payload) < info.file_size:
        return None, (
            f"Datenstrom widerspricht dem Zentralverzeichnis: deklariert sind "
            f"{info.file_size} Bytes, gelesen wurden nur {len(payload)}. "
            "Dieses Mitglied wurde NICHT analysiert."
        )
    if zlib.crc32(payload) & 0xFFFFFFFF != info.CRC:
        if info.file_size == 0:
            # An honest empty member has CRC 0 and reads EOF cleanly. A
            # declaration of 0 bytes with a non-zero CRC is self-contradictory:
            # the central directory describes content it refuses to admit. The
            # stream is not even opened in that case (compress_size 0), so the
            # contradiction is the only evidence there is — and it is enough.
            return None, (
                "Größenangabe im Zentralverzeichnis gefälscht: deklariert sind 0 "
                "Bytes, die Prüfsumme gehört aber zu Inhalt. Dieses Mitglied "
                "wurde NICHT analysiert; ein Präfix davon ist nicht sein Inhalt."
            )
        return None, (
            "CRC-Prüfsumme stimmt nicht: der Datenstrom ist beschädigt. "
            "Dieses Mitglied wurde NICHT analysiert."
        )
    return payload, None


def _read_encrypted(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    passwords: list[str],
    *,
    consume=None,
) -> tuple[bytes | None, str | None]:
    """Try each password; return ``(plaintext, error)``.

    ``(None, None)`` means "no candidate password produced plaintext" — the
    caller reports the encrypted limitation. ``(None, error)`` means a
    password DID open the member and the stream itself is the problem (a
    forged size declaration must not hide behind "wrong password").

    Every attempt goes through ``_read_zip_member``: ``zf.read(info, pwd=...)``
    materialized the whole remaining stream per attempt, i.e. the same hole as
    the plaintext path, multiplied by the number of candidate passwords.

    ``consume`` is called with the declared member size BEFORE every attempt
    (including the empty-password fallback) so the caller's cumulative budget
    also counts the attempts that end in CRC/size/password failure. It may
    raise to abort the walk (see ``_VolumeStop``); the call is deliberately
    outside the ``try`` blocks so that abort is not mistaken for a wrong
    password.
    """
    first_error: str | None = None
    for pw in passwords:
        if consume is not None:
            consume(info.file_size)
        try:
            payload, error = _read_zip_member(
                zf, info, pwd=pw.encode("utf-8", "ignore")
            )
        except RuntimeError:
            continue  # wrong password -> next candidate
        except Exception:
            # e.g. AES entries: the stdlib cannot read them at all. Reported by
            # the caller as "encrypted, no standard password matched".
            return None, None
        if payload is not None:
            return payload, None
        if error is not None:
            # A wrong candidate password passes the 1-byte ZipCrypto check with
            # probability 1/256, decrypts to garbage and then fails the CRC
            # check — which arrives here as an error. Returning at the first
            # error therefore gave up on a member the NEXT candidate would have
            # opened. Keep the first error (it is the honest report if nothing
            # else matches) and try the remaining candidates.
            first_error = first_error or error
            continue
    if first_error is not None:
        return None, first_error
    # No empty-password fallback: it cannot work, and pretending otherwise
    # cost a scan attempt. ``zipfile`` refuses an empty password outright —
    # ``ZipExtFile`` raises RuntimeError("password required") for
    # ``pwd in (None, b"")`` alike (measured against a 7-Zip ZipCrypto archive
    # with an empty password: both forms raise, so the old "last resort" call
    # without a password could never decrypt anything and its exception was
    # swallowed). A member encrypted with an empty password is therefore
    # reported as "kein Standard-Passwort passte" — YELLOW 30 with
    # ARCH_ENCRYPTED, which is the honest answer: unexamined, not clean.
    return None, None


# Everything a TAR/compressed stream can raise while being read. ``tarfile``
# translates its own errors, but the decompressors do not go through it:
# measured, a truncated ``.tar.gz`` raised ``EOFError: Compressed file ended
# before the end-of-stream marker was reached`` from inside ``next()``, escaped
# this module entirely and turned into a hard container failure
# (``ARCH_CONTAINER_ERROR``) instead of the soft "TAR-Fehler" note.
_TAR_READ_ERRORS = (tarfile.TarError, OSError, EOFError, ValueError, zlib.error)

# Two 512-byte zero blocks close a TAR (POSIX). Their absence is the only
# reliable truncation signal for an UNCOMPRESSED stream, because a cut inside a
# header block raises nothing at all.
_TAR_END_MARKER = 1024

_TRUNCATION_NOTE = (
    f"{BUDGET_STOP_PREFIX} Das Archiv endet ohne Endmarker — der Strom ist "
    "unvollständig (gekappter Download, abgeschnittener Anhang). Die "
    "Mitglieder davor wurden gelesen, alles danach NICHT."
)


# The truncation check may inspect at most this much of the remaining
# decompressed stream, read in chunks so the peak stays at one chunk. The
# leftover after a TAR end marker is padding (normally two zero blocks); the
# old un-capped ``tf.fileobj.read()`` let a 32 KiB ``.tar.gz`` expand to
# 33.5 MB and a 2 MB one to ~4 GB before the check decided anything (SEC-007).
_TAR_TAIL_LIMIT = 1 * 1024 * 1024
_TAR_TAIL_CHUNK = 64 * 1024


def _tar_truncation_note(tf, data: bytes, kind: str) -> str:
    """``""`` when the stream ended properly, else the truncation note.

    Two shapes, two checks. An uncompressed TAR is verified against its
    end-of-archive marker, because a cut inside a header block is silent. A
    compressed stream is pulled to its end instead: the decompressor then runs
    its own trailer check, which is what a cut near the end would otherwise
    escape (measured: a ``.tar.gz`` cut at 119 of 127 bytes delivered all three
    members and said nothing).

    The pull is bounded (``_TAR_TAIL_LIMIT``) and chunked; only NON-ZERO
    content counts as "the stream continues past the end".

    Reaching the limit while the stream is STILL all padding used to be
    treated as clean, on the theory that a cut that deep cannot hide anything.
    That was wrong and measurable: a benign TAR, then 1 MiB of zero bytes,
    then a second TAR holding a PowerShell cradle scored GREEN 0 with only the
    benign member scanned — the padding pushed the appended archive past the
    window, and the check reported nothing. The limit therefore ends in the
    truncation note: the remainder was NOT examined, and saying so is the
    whole point of the check.
    """
    if kind == "tar":
        if len(data) < _TAR_END_MARKER or data[-_TAR_END_MARKER:].strip(b"\x00"):
            return _TRUNCATION_NOTE
        # AND scan everything between the walk's current position and the end.
        # tarfile stops at the first zero-block pair, so a second container
        # appended behind it and topped off with zero padding stayed invisible
        # to the tail-only check above. This is additive: the tail check keeps
        # catching a cut, the remainder scan catches an appended payload.
        try:
            position = tf.fileobj.tell()
        except Exception:
            position = 0
        if data[position:].strip(b"\x00"):
            return _TRUNCATION_NOTE
        return ""
    try:
        left = _TAR_TAIL_LIMIT
        while left > 0:
            chunk = tf.fileobj.read(min(_TAR_TAIL_CHUNK, left))
            if not chunk:
                break
            # A clean archive still has its two zero blocks in the stream —
            # tarfile stopped at the marker, it did not consume it. Only
            # NON-ZERO content left over means the stream continues past where
            # the walk believed the end to be (measured: treating any leftover
            # as truncation reported a perfectly good .tar.gz as cut).
            if chunk.strip(b"\x00"):
                return _TRUNCATION_NOTE
            left -= len(chunk)
        else:
            # The window is exhausted and everything in it was padding. The
            # stream may still continue (measured bypass above), so this is
            # "not examined", never "clean".
            return _TRUNCATION_NOTE
    except Exception:  # the decompressor's own verdict on a cut stream
        return _TRUNCATION_NOTE
    return ""


def _zipslip_note(names: list[str], *, complete: bool) -> str | None:
    """Die Traversal-Meldung fuer einen TAR, formuliert wie der 7z-Zwilling.

    ``complete`` unterscheidet die beiden Stellen, die sie aussenden: die
    sofortige IM Walk (es koennen weitere Namen folgen, also keine Summe
    versprechen) und die am Ende. Beide tragen ``ZIPSLIP_PREFIX``, den der
    Dispatcher zu ARCH_ZIPSLIP (CRITICAL) macht — der Marker ist der Vertrag,
    nicht der Wortlaut.

    Gibt ``None`` zurueck, wenn KEIN Angriff dabei ist. Dann meldet der
    Aufrufer die milden Namen ueber ``unsafe_name_note`` — ein Zip mit nur
    "CON.txt" darf nicht als Traversal gelten.
    """
    angriff, _mild = split_unsafe_names(names)
    if not angriff:
        return None
    examples = ", ".join(angriff[:5])
    count = (
        f"{len(angriff)} Eintragsname(n)"
        if complete
        else "mindestens 1 Eintragsname"
    )
    return (
        f"{ZIPSLIP_PREFIX} {count} würden beim Entpacken aus dem "
        f"Zielverzeichnis schreiben (Path Traversal). Beispiele: {examples}"
    )


def unsafe_name_note(names: list[str]) -> str | None:
    """Die MILDE Meldung fuer ungewoehnliche Namen — oder ``None``.

    Kein Pfad-Escape: reservierte Geraetenamen (CON, NUL, COM1), ein
    Doppelpunkt (NTFS-Alternate-Data-Stream) oder ein Name, der beim
    Entpacken leer wird. Auf Unix sind das gueltige Dateinamen, solche
    Archive entstehen also auch ohne Absicht. Der Dispatcher macht daraus
    ARCH_UNSAFE_NAME (LOW) — sichtbar, aber kein Anker.
    """
    _angriff, mild = split_unsafe_names(names)
    if not mild:
        return None
    gruende = {r for r in (unsafe_name_reason(n) for n in mild) if r is not None}
    was = {
        "device": "reservierte Windows-Geraetenamen",
        "ads": "Doppelpunkt im Namen (Alternate Data Stream)",
        "empty": "Namen, die beim Entpacken leer werden",
        "dotname": "Namen, die mit zwei Punkten beginnen",
    }
    warum = ", ".join(sorted(was.get(g, str(g)) for g in gruende))
    return (
        f"{UNSAFE_NAME_PREFIX} {len(mild)} Eintragsname(n) sind ungewoehnlich "
        f"({warum}). Das Entpacken kann fuer diese Eintraege fehlschlagen; ein "
        f"Pfad-Escape ist es NICHT. Beispiele: {', '.join(mild[:5])}"
    )


#: A single read() above this is not a TAR header or a member block. tarfile
#: reads member data in 16 KiB blocks and PAX/longname headers are small; the
#: only caller that asks for more is the metadata header whose declared size is
#: attacker-controlled (measured: 56 bytes of .tar.gz declaring ~8 GB).
#: Memory the LZMA decoder may allocate for its dictionary. ``xz -9`` uses a
#: 64 MiB dictionary plus decoder overhead, so the payload cap (64 MiB) is too
#: tight and refused ordinary source tarballs — measured: preset 9 failed with
#: "Memory usage limit exceeded" while preset 6 passed. 256 MiB covers every
#: real preset with headroom and still bounds the allocation (a crafted header
#: can declare up to 4 GiB).
_LZMA_MEM_LIMIT = 256 * 1024 * 1024

_TAR_MAX_SINGLE_READ = 1 << 20


class _BoundedRead:
    """File-like wrapper that refuses oversized single reads.

    ``tarfile`` materializes a GNU longname/PAX header with one ``read(size)``
    of the DECLARED size, before the walk can apply any per-member limit.
    Refusing that read turns an 8.6 GB allocation into a ValueError, which
    ``_TAR_READ_ERRORS`` already handles as "TAR-Fehler".
    """

    __slots__ = ("_inner", "_max")

    def __init__(self, inner, max_single_read: int = _TAR_MAX_SINGLE_READ) -> None:
        self._inner = inner
        self._max = max_single_read

    def read(self, size: int = -1) -> bytes:
        if self._max and (size is None or size < 0 or size > self._max):
            raise ValueError(
                f"TAR-Lesewunsch {size} Bytes überschreitet das Einzel-Limit "
                f"{self._max} Bytes (Metadatenkopf mit gefälschter Größe)"
            )
        return self._inner.read(size)

    def unguard(self) -> None:
        """Stop refusing large reads.

        The guard exists for the METADATA pass: tarfile materializes a PAX or
        GNU longname header with one read of its declared size, before any
        per-member limit can apply. Member payloads are read the same way —
        ``extractfile().read()`` asks for the whole member at once — so the
        limit must be lifted once the header walk is done. Measured: with the
        guard left on, a legitimate 2 MiB member was refused with "TAR-Lesewunsch
        2097152 Bytes überschreitet das Einzel-Limit".
        """
        self._max = 0

    # The rest of the io.RawIOBase surface tarfile may touch. Delegated rather
    # than inherited so the proxy stays a thin filter over whatever stream it
    # wraps (BytesIO, GzipFile, BZ2File, LZMAFile).
    def seek(self, *args):
        return self._inner.seek(*args)

    def tell(self):
        return self._inner.tell()

    def write(self, data: bytes) -> int:
        # typeshed's tarfile._Fileobj protocol requires write even for reading;
        # a read-only stream must not silently accept it.
        raise io.UnsupportedOperation("_BoundedRead ist schreibgeschützt")

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def close(self) -> None:
        self._inner.close()

    @property
    def closed(self) -> bool:
        return self._inner.closed

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class _BoundedLZMA:
    """LZMAFile-compatible reader that caps dictionary size and buffer.

    Two separate allocations matter and both are attacker-controlled:

    * The .xz block header declares the LZMA2 dictionary the decoder allocates
      while parsing it, before any payload comes back. Measured: a 72-byte .xz
      declaring 1 GiB produced a 2149 MB peak and scored GREEN 0.
      ``LZMADecompressor`` takes ``memlimit``; ``LZMAFile`` does not.
    * tarfile seeks over every member, so keeping the whole decompressed
      stream is the second one. Measured: a 0.1 MB .tar.xz with 20 x 40 MB
      members peaked at 1327 MB and ran 76 s.

    Only a sliding window is therefore retained. tarfile seeks forward only
    (measured: max backward jump 0 over a five-member archive), so the window
    holds the bytes from the last read position onward.
    """

    __slots__ = ("_at", "_base", "_buf", "_data", "_dec", "_eof", "_pos")

    #: Bytes kept behind the read position. tarfile re-reads at most one
    #: 512-byte header block, so 1 MiB is generous.
    _WINDOW = 1 << 20

    def __init__(self, data: bytes, memlimit: int) -> None:
        self._data = data
        self._pos = 0
        self._eof = False
        self._buf = bytearray()
        self._base = 0   # absolute position of _buf[0]
        self._at = 0     # absolute read position
        self._dec = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO, memlimit=memlimit)

    def _fill(self, upto: int) -> None:
        """Decompress until the buffer covers absolute position ``upto``."""
        while not self._eof and self._base + len(self._buf) < upto:
            if self._dec.eof:
                self._eof = True
                break
            if self._dec.needs_input:
                if self._pos >= len(self._data):
                    self._eof = True
                    break
                chunk = self._data[self._pos:self._pos + (1 << 16)]
                self._pos += len(chunk)
            else:
                chunk = b""
            piece = self._dec.decompress(chunk, max_length=1 << 20)
            if piece:
                self._buf += piece
            elif not chunk:
                self._eof = True
        # Drop what is older than the window.
        keep_from = max(0, self._at - self._WINDOW)
        drop = keep_from - self._base
        if drop > 0:
            del self._buf[:drop]
            self._base += drop

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = 1 << 20
        self._fill(self._at + size)
        start = self._at - self._base
        out = bytes(self._buf[start:start + size])
        self._at += len(out)
        return out

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._at + offset
        else:
            raise io.UnsupportedOperation("_BoundedLZMA: kein Seek vom Ende")
        if target < self._base:
            raise ValueError(
                "TAR-Rücksprung weiter als das Lesefenster — der dekomprimierte "
                "Strom wurde nicht vollständig gehalten"
            )
        if target > self._base + len(self._buf):
            self._fill(target)
            if target > self._base + len(self._buf):
                raise ValueError("_BoundedLZMA: Position hinter dem Ende")
        self._at = target
        return self._at

    def tell(self) -> int:
        return self._at

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def _bounded_tar_stream(data: bytes, compressed: bool):
    """The decompressed stream tarfile should read, or the raw bytes.

    ``tarfile.open(mode="r:*")`` sniffs the compression itself and wraps the
    fileobj, which puts any read guard on the wrong side (see the call site).
    Decompressing here keeps the guard where the allocation happens.
    """
    if not compressed:
        return io.BytesIO(data)
    if data[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=io.BytesIO(data))
    if data[:3] == b"BZh":
        return bz2.BZ2File(io.BytesIO(data))
    if data[:6] == b"\xfd7zXZ\x00":
        # memlimit: see iter_single_stream — the declared dictionary size is
        # the attacker's number and is allocated before any read returns.
        return _BoundedLZMA(data, _LZMA_MEM_LIMIT)
    return io.BytesIO(data)


def iter_compressed_members(
    data: bytes, kind: str, member_budget: MemberBudget | None = None
) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(member_name, member_bytes, error)`` for tar/gzip/bzip2/xz.

    ``kind`` is the magic-detected type (``tar``, ``gzip``, ``bzip2``, ``xz``).
    Tar streams (``.tar``, ``.tar.gz``/``.tgz``, ``.tar.bz2``, ``.tar.xz``) are
    walked member by member with the same per-member and cumulative volume
    guards as ZIP. A compressed stream that is *not* a tar (plain ``.gz`` /
    ``.bz2`` / ``.xz`` payload) is decompressed as one bounded member instead,
    so single-file payloads get analysed rather than staying opaque blobs.
    Symlinks/hardlinks are never followed; only regular files are yielded.
    """

    # A TAR metadata header (GNU longname/longlink 'L'/'K', PAX 'x'/'g') is
    # read by tarfile BEFORE the walk sees a member, and its declared size is
    # materialized in ONE read: measured, a 56-byte .tar.gz whose longname
    # header declared ~8 GB produced an 8.6 GB tracemalloc peak and scored
    # GREEN 0 — the size guard below never ran, because it looks at
    # ``member.size`` of the REAL member, not at the metadata header tarfile
    # consumed on the way there. The walk deadline cannot help either: the
    # allocation happens inside a single ``next()``, and the header is not
    # reachable through the tarfile API before it is read.
    #
    compressed_stream = (
        data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00"
    )
    # The lever is the fileobj tarfile reads from: a proxy whose read() refuses
    # a single request above _TAR_MAX_SINGLE_READ. Legitimate PAX/longname
    # headers are far below that, and member payloads are read in 16 KiB
    # blocks, so only the one giant read is caught. ValueError is in
    # _TAR_READ_ERRORS, so the refusal becomes a "TAR-Fehler" note instead of
    # an OOM.
    #
    # The proxy must sit on the DECOMPRESSED side. Wrapping only the compressed
    # bytes does nothing: tarfile then builds GzipFile ON TOP, and the giant
    # read goes to GzipFile, which satisfies it in 8 KiB pulls from the proxy
    # and assembles the 8 GB in its own buffer — measured, that placement left
    # the peak at 8.59 GB. The stream is therefore decompressed here and the
    # proxy is wrapped around the decompressor (which offers seek/tell, as
    # tarfile requires).
    #
    # The generator yields between open and close; a plain "with" would close
    # the archive after the first yield. try/finally IS the resource guard here.
    try:
        raw = _bounded_tar_stream(data, compressed_stream)
        guarded = _BoundedRead(raw)
        tf = tarfile.open(fileobj=guarded, mode="r:")  # noqa: SIM115
    except _TAR_READ_ERRORS as exc:
        # zlib.error and lzma.LZMAError are NOT covered by the four types that
        # used to stand here: opening a magic-valid but corrupt .gz/.xz body
        # raises them from inside the decompressor, and they escaped the
        # generator (the dispatcher caught them as ARCH_CONTAINER_ERROR, but
        # the container note is the honest place). _TAR_READ_ERRORS already
        # lists exactly the types the walk below handles.
        if kind == "tar":
            yield ("", b"", f"TAR-Container nicht lesbar: {exc}")
        else:
            # Not a tar stream -> decompress as a single bounded member.
            yield from iter_single_stream(data, kind)
        return

    # ONE metadata pass before the payload walk. ``iter(tf)`` reads only the
    # 512-byte headers — no payload is materialized (measured: 0.02 s and
    # 0.1 MiB for a 58 MiB .tar, 0.29 s / 0.3 MiB for its .tar.gz) — and it is
    # what makes the traversal report independent of every limit below.
    #
    # Reporting during the payload walk was not enough, and the round-4 fix
    # (yield at the first unsafe name) only moved the boundary. The dispatcher
    # stops the walk at its own member cap and abandons the generator; the
    # drain then continues on an 8 MiB budget, which fat members exhaust long
    # before the traversal is reached. Measured with a cap of 20 and 300 members
    # of 200 KB: traversal at position 10 -> RED 75 with ARCH_ZIPSLIP, at
    # position 120 and 295 -> YELLOW 25 without it, numerically identical to the
    # same archive WITHOUT any traversal entry. The report now comes from the
    # declared names, in the sibling order of core/sevenzip.py:253-267.
    # A member of a COMPRESSED tar is as much a bomb vector as a plain stream:
    # the 8.3 MB/8.6 GB case and the 3.9 MB/106 MB case both live here. The
    # same 64 MB cap that bounds single streams applies, and because the walk
    # then aborts, the whole stream is never inflated.
    member_limit = (
        min(config.MAX_EXTRACTED_FILE_SIZE, config.MAX_SINGLE_STREAM_BYTES)
        if compressed_stream
        else config.MAX_EXTRACTED_FILE_SIZE
    )
    extracted_total = 0
    try:
        members: list[tarfile.TarInfo] = []
        unsafe: list[str] = []
        oversized_member = ""
        entry_limit_hit = False
        walk_deadline_hit = False
        header_error = ""
        walk_deadline = time.monotonic() + config.MAX_CONTAINER_SECONDS
        try:
            for member in tf:
                if time.monotonic() >= walk_deadline:
                    # The declared-size check below cannot see a stream that
                    # spins without returning a header; the clock can. Same
                    # budget as the payload walk.
                    walk_deadline_hit = True
                    break
                if len(members) >= config.MAX_ARCHIVE_ENTRIES:
                    # Bound the metadata pass itself: a TAR of ten million
                    # headers must not become the memory it was meant to avoid
                    # being.
                    entry_limit_hit = True
                    break
                if member.size > member_limit and compressed_stream:
                    # Stop the walk BEFORE the next header is requested: asking
                    # tarfile for the following member makes it SKIP this one's
                    # payload, and for a compressed stream that means
                    # decompressing all of it. Measured: an 8.3 MB .tar.gz that
                    # inflates to 8.6 GB spent 20 s here while the scan itself
                    # never saw more than a capped prefix. Declared sizes are
                    # attacker-controlled, so this only bounds the honest case;
                    # an under-declared member is still caught by the byte cap
                    # during the payload walk. A plain .tar needs no such
                    # shortcut: skipping there is a seek, so the walk simply
                    # continues and the member gets its own "too large" note.
                    oversized_member = member.name
                    break
                members.append(member)
                # Every entry type, not just regular files: a symlink or
                # hardlink whose NAME is a traversal is exactly the shape an
                # unpacker follows. The payload walk skips non-files, so such
                # an entry produced no yield and no note at all — measured: a
                # TAR whose only suspicious entry was a symlink named
                # "../../etc/evil" scored GREEN 0 with no indicator.
                if not is_safe_member_name(member.name):
                    unsafe.append(member.name)
        except _TAR_READ_ERRORS as exc:
            # A truncated TAR raises HERE, while the headers are read — before a
            # single member was handed on. Letting that end the generator threw
            # the whole container away: measured, a TAR cut inside the last
            # member's data yielded ONE note and no members at all, losing both
            # the readable payloads and the Zip-Slip report, while the round-4
            # code still delivered two members and the traversal. The objects
            # collected so far stay valid and usable (measured: ``extractfile``
            # returns the payloads of the complete members, only the truncated
            # one raises), so the walk continues over them and the truncation
            # becomes a note beside the content instead of replacing it.
            header_error = f"TAR-Fehler: {exc}"
        # A cut inside a 512-byte HEADER block never raises: tarfile swallows
        # TruncatedHeaderError/EmptyHeaderError whenever offset != 0
        # (tarfile.py:2657-2661) and reports a clean end of archive. The scan
        # then returned the members before the cut and said nothing — measured,
        # 1024 of 10 239 cut points of a three-member TAR lost content silently,
        # and cut=2816 scored GREEN 0 while cut=3072 (one byte later) scored
        # RED 50. The stream is therefore checked for its end-of-archive marker
        # instead of trusting the absence of an exception.
        # Any mid-walk stop leaves tf positioned INSIDE the archive, so the
        # truncation check would report a complete stream as cut. BUG-002 fixed
        # that for the entry limit only; the oversized-member break and the
        # walk deadline stop in exactly the same way. Measured: a complete
        # .tar.gz whose first member exceeded the limit was reported as
        # "endet ohne Endmarker - gekappter Download".
        # The metadata pass is over; member payloads may now be read in one
        # piece (see _BoundedRead.unguard).
        guarded.unguard()
        if (
            not header_error
            and not entry_limit_hit
            and not oversized_member
            and not walk_deadline_hit
        ):
            # BUG-002: after the entry-limit stop the stream is intentionally
            # NOT at its end (tarfile stopped mid-walk). Treating that leftover
            # as a cut reported a COMPLETE .tar.gz as "gekappter Download".
            header_error = _tar_truncation_note(tf, data, kind)
        if unsafe:
            # ZWEI Meldungen aus einer Liste: der Angriff behaelt den Anker,
            # der ungewoehnliche Name wird als solcher benannt. Beide koennen
            # ``None`` sein — dann gibt es nichts zu melden.
            angriff = _zipslip_note(unsafe, complete=True)
            if angriff:
                yield ("", b"", angriff)
            mild = unsafe_name_note(unsafe)
            if mild:
                yield ("", b"", mild)
        if header_error:
            yield ("", b"", header_error)
        if entry_limit_hit:
            yield (
                "",
                b"",
                (f"{BUDGET_STOP_PREFIX} Eintrags-Limit {config.MAX_ARCHIVE_ENTRIES} "
                 "erreicht — weitere Mitglieder wurden nicht gelesen."),
            )
        if walk_deadline_hit:
            # A separate flag, not a sentinel in oversized_member: a member
            # name is attacker-controlled and may itself begin with "(".
            # Measured: a member named "(evil)" was rendered as "evil".
            yield (
                "",
                b"",
                (
                    f"{BUDGET_STOP_PREFIX} Zeitbudget erschöpft beim Lesen der "
                    "Mitgliederliste — der Rest des Archivs wurde NICHT gelesen."
                ),
            )
            return
        if oversized_member:
            # NO return: the members collected BEFORE the oversized one are
            # already in ``members`` and must still be scanned. Returning here
            # threw them away — measured: a .tar.gz whose first member carried
            # a PowerShell cradle and whose second exceeded the limit scored
            # YELLOW 25 with no child at all, the cradle never examined. The
            # oversized member itself is not in ``members``, so the payload
            # walk cannot grow from it.
            yield (
                "",
                b"",
                (f"{BUDGET_STOP_PREFIX} Mitglied '{oversized_member[:80]}' "
                 f"überschreitet {config.MAX_EXTRACTED_FILE_SIZE} Bytes — die "
                 "Mitgliederliste wurde an dieser Stelle abgebrochen, der Rest "
                 "des Archivs wurde NICHT gelesen."),
            )
        for member in members:
            # Regular files only: directories, symlinks, hardlinks, devices and
            # FIFOs are skipped (symlink following must never happen).
            if not member.isfile():
                continue
            # Same rule as ZIP: the name decides whether we would write the
            # member, never whether we look at it. The payload is scanned in
            # memory; ARCH_UNSAFE_NAME reports the name separately.
            if member.size > member_limit:
                yield (
                    member.name,
                    b"",
                    (f"Eintrag zu groß ({member.size} Bytes > {member_limit})"),
                )
                continue
            if (
                member_budget is not None
                and member_budget.left is not None
                and member.size > member_budget.left
            ):
                yield (
                    "",
                    b"",
                    (f"Mitglied '{member.name[:80]}' nicht geladen: "
                     f"{member.size} Bytes überschreiten das verbleibende "
                     f"Budget ({member_budget.left} Bytes)"),
                )
                continue
            if extracted_total + member.size > config.MAX_UNCOMPRESSED_SIZE:
                yield (
                    "",
                    b"",
                    (f"{BUDGET_STOP_PREFIX} Entpacktes Gesamtvolumen würde Limit "
                     f"{config.MAX_UNCOMPRESSED_SIZE} Bytes überschreiten "
                     "(Zip-Bomben-Schutz) — weitere Mitglieder wurden übersprungen."),
                )
                break
            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                # Chunked, not one read(): the member's declared size is the
                # attacker's number, and a single read materializes all of it
                # at once. Measured with a 30 x 20 MB .tar.gz: one read per
                # member left a 650 MB peak, the chunked loop stays at one
                # chunk. The declared size was already checked against
                # MAX_EXTRACTED_FILE_SIZE above, so this bounds the RESULT
                # rather than the claim.
                chunks: list[bytes] = []
                with fh:
                    while True:
                        chunk = fh.read(config.READ_CHUNK_SIZE)
                        if not chunk:
                            break
                        chunks.append(chunk)
                member_bytes = b"".join(chunks)
            except Exception as exc:  # defensive: malformed members degrade
                if header_error:
                    # The stream is already known to be cut — this member's
                    # failure is that same cause, not a second one. Yielding it
                    # added a second 25 to the container note and took a merely
                    # truncated download to 25+25 = 50 = ANCHOR_CRITICAL_SCORE
                    # ("malicious"). Measured: cut at 3584 -> RED 50 before this
                    # branch, YELLOW 25 after; the container note already says
                    # that everything past the cut was NOT read.
                    break
                yield (member.name, b"", f"{type(exc).__name__}: {exc}")
                continue
            extracted_total += len(member_bytes)
            yield (member.name, member_bytes, None)
    except _TAR_READ_ERRORS as exc:
        yield ("", b"", f"TAR-Fehler: {exc}")
    finally:
        with suppress(Exception):
            tf.close()


def iter_single_stream(
    data: bytes, kind: str
) -> Iterator[tuple[str, bytes, str | None]]:
    """Decompress a non-tar gzip/bzip2/xz stream as a single bounded member.

    The decompressed payload is capped at ``MAX_EXTRACTED_FILE_SIZE`` (chunked
    read, never materialised beyond the cap), so a tiny bomb stream cannot
    exhaust memory. The gzip FNAME header, when present, provides a display
    name; otherwise ``payload.bin`` is used.
    """
    if kind == "gzip":
        import gzip

        def factory():
            return gzip.GzipFile(fileobj=io.BytesIO(data))

        # CPython's GzipFile discards the FNAME header field when reading, so
        # extract the stored original filename ourselves (RFC 1952).
        name = _gzip_fname(data)
    elif kind == "bzip2":
        import bz2

        def factory():
            return bz2.BZ2File(io.BytesIO(data))

        name = ""
    elif kind == "xz":

        def factory():
            # memlimit bounds the LZMA2 DICTIONARY the decoder allocates, and
            # the .xz format lets the file declare it. Measured: a 72-byte .xz
            # declaring a 1 GiB dictionary produced a 2149 MB tracemalloc peak
            # and scored GREEN 0 — the chunked read never helped, because the
            # allocation happens while parsing the block header. The limit is
            # the same one the payload may reach.
            return _BoundedLZMA(data, _LZMA_MEM_LIMIT)

        name = ""
    else:
        return

    limit = min(config.MAX_EXTRACTED_FILE_SIZE, config.MAX_SINGLE_STREAM_BYTES)
    payload, error = _decompress_bounded(
        factory,
        limit,
        deadline=time.monotonic() + config.MAX_CONTAINER_SECONDS,
    )
    if error is not None:
        yield ("", b"", error)
        return
    if payload is None:
        return
    display = Path(name).name if name else "payload.bin"
    yield (display, payload, None)


def _gzip_fname(data: bytes) -> str:
    """Extract the FNAME field of a gzip header (RFC 1952), if present."""
    try:
        if len(data) < 10 or data[:2] != b"\x1f\x8b":
            return ""
        flags = data[3]
        pos = 10
        if flags & 0x04:  # FEXTRA: 2-byte length + payload
            if pos + 2 > len(data):
                return ""
            pos += 2 + int.from_bytes(data[pos : pos + 2], "little")
        if flags & 0x08:  # FNAME: null-terminated string
            end = data.find(b"\x00", pos)
            if end == -1:
                return ""
            return data[pos:end].decode("utf-8", errors="replace")
    except Exception:  # defensive: malformed headers yield no name
        return ""
    return ""


def _decompress_bounded(
    factory, limit: int, *, raise_errors: bool = False, deadline: float | None = None
) -> tuple[bytes | None, str | None]:
    """Read a decompressor stream in chunks, capped at ``limit`` bytes.

    Returns ``(payload, error)``; ``error`` is set when the stream is corrupt,
    exceeds the cap, or the ``deadline`` (a ``time.monotonic()`` value) is
    reached. With ``raise_errors`` the underlying exception is propagated
    instead of returned — the ZIP member path has to tell "wrong password, try
    the next candidate" apart from "the stream contradicts its own
    declaration".

    The deadline exists because the byte cap alone still lets one small stream
    buy a minute of CPU: measured, an 8.3 MB ``.gz`` inflates to 8.6 GB and the
    scan spent 20 s on the capped 512 MB. A container that cannot be examined
    within the budget is reported as not examined instead of blocking the run.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        with factory() as src:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    return None, (
                        "Entpacken abgebrochen: Zeitbudget "
                        f"({config.MAX_CONTAINER_SECONDS} s) erschöpft"
                    )
                chunk = src.read(config.READ_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    return None, (
                        f"Entpacktes Volumen überschreitet Limit {limit} Bytes"
                    )
                chunks.append(chunk)
    except Exception as exc:
        if raise_errors:
            raise
        return None, f"{type(exc).__name__}: {exc}"
    return b"".join(chunks), None
