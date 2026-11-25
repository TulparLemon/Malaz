"""File-type detection via magic bytes (header signatures).

Detection is based on the actual header bytes, *not* the file extension, which
defends against format spoofing (e.g. an executable renamed to ``.png``). When no
binary signature matches, a conservative text heuristic classifies plain text,
HTML, XML and RFC-822 mail so that such files no longer show up as "unknown".
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    type: str
    mime: str
    offset: int
    magic: bytes


# Ordered: first match wins. More specific signatures come first.
_SIGNATURES: tuple[Signature, ...] = (
    Signature("pdf", "application/pdf", 0, b"%PDF-"),
    Signature("zip", "application/zip", 0, b"PK\x03\x04"),
    Signature("zip", "application/zip", 0, b"PK\x05\x06"),  # empty archive
    Signature("zip", "application/zip", 0, b"PK\x07\x08"),  # spanned
    Signature("ole", "application/x-ole-storage", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    Signature("png", "image/png", 0, b"\x89PNG\r\n\x1a\n"),
    Signature("jpeg", "image/jpeg", 0, b"\xff\xd8\xff"),
    Signature("gif", "image/gif", 0, b"GIF87a"),
    Signature("gif", "image/gif", 0, b"GIF89a"),
    # BMP needs the DIB header size sanity check below — "BM" alone also
    # prefixes plenty of text/data formats.
    Signature("bmp", "image/bmp", 0, b"BM"),
    # TIFF/WebP/ICO: their four-byte magics also occur in arbitrary binary
    # data ("II*\0" is just 0x49 0x49 0x2a 0x00), so each one is validated
    # structurally below before the image type is claimed.
    Signature("tiff", "image/tiff", 0, b"II*\x00"),
    Signature("tiff", "image/tiff", 0, b"MM\x00*"),
    Signature("webp", "image/webp", 0, b"RIFF"),
    Signature("ico", "image/x-icon", 0, b"\x00\x00\x01\x00"),
    Signature("rar", "application/x-rar", 0, b"Rar!\x1a\x07\x00"),
    Signature("rar", "application/x-rar", 0, b"Rar!\x1a\x07\x01\x00"),
    Signature("7z", "application/x-7z-compressed", 0, b"7z\xbc\xaf\x27\x1c"),
    # Linux package containers: ALWAYS-compressed archives (7-Zip can read
    # both). Typed explicitly so the entropy stage does not flag their
    # structural ~8 bit/byte as "packed/hidden" (live finding: legit sysdig/
    # Cynet .deb/.rpm landed at ROT 50-70 purely via GEN_ENTROPY).
    Signature("rpm", "application/x-rpm", 0, b"\xed\xab\xee\xdb"),
    Signature("deb", "application/vnd.debian.binary-package", 0, b"!<arch>\ndebian-binary"),
    Signature("gzip", "application/gzip", 0, b"\x1f\x8b"),
    Signature("bzip2", "application/x-bzip2", 0, b"BZh"),
    Signature("xz", "application/x-xz", 0, b"\xfd7zXZ\x00"),
    Signature("cab", "application/vnd.ms-cab-compressed", 0, b"MSCF"),
    Signature("chm", "application/vnd.ms-htmlhelp", 0, b"ITSF\x03\x00\x00\x00"),
    Signature("chm", "application/vnd.ms-htmlhelp", 0, b"ITSF\x02\x00\x00\x00"),
    Signature("vhdx", "application/x-vhdx", 0, b"vhdxfile"),
    # Microsoft OneNote section file (.one), MS-ONESTORE guidFileType
    # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} in little-endian bytes.
    Signature(
        "onenote",
        "application/onenote",
        0,
        b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3",
    ),
    Signature("rtf", "application/rtf", 0, b"{\\rtf"),
    Signature("swf", "application/x-shockwave-flash", 0, b"FWS"),
    Signature("swf", "application/x-shockwave-flash", 0, b"CWS"),
    Signature("swf", "application/x-shockwave-flash", 0, b"ZWS"),
    # Java class file (CAFEBABE) must precede the Mach-O fat magic.
    Signature("class", "application/java-vm", 0, b"\xca\xfe\xba\xbe"),
    Signature("macho", "application/x-mach-binary", 0, b"\xca\xfe\xba\xbf"),
    Signature("macho", "application/x-mach-binary", 0, b"\xfe\xed\xfa\xce"),
    Signature("macho", "application/x-mach-binary", 0, b"\xfe\xed\xfa\xcf"),
    Signature("macho", "application/x-mach-binary", 0, b"\xce\xfa\xed\xfe"),
    Signature("macho", "application/x-mach-binary", 0, b"\xcf\xfa\xed\xfe"),
    Signature("elf", "application/x-elf", 0, b"\x7fELF"),
    # Windows shell link (LNK): fixed CLSID 00021401-0000-0000-C000-000000000046.
    Signature(
        "lnk",
        "application/x-ms-shortcut",
        0,
        b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46",
    ),
    # Audio/video. The ID3 tag is a stable three-byte signature; a raw MPEG
    # frame has no fixed prefix and is validated separately in ``detect``.
    Signature("mp3", "audio/mpeg", 0, b"ID3"),
    # ISO-BMFF video: ``ftyp`` at offset 4. HEIC/AVIF are also ``ftyp``
    # containers and MUST be classified before this entry (see ``detect``);
    # the brand check below keeps MOV/MP4 apart from unknown ISO-BMFF blobs.
    Signature("mp4", "video/mp4", 4, b"ftyp"),
    # Offset-based signatures.
    Signature("tar", "application/x-tar", 257, b"ustar"),
    Signature("iso", "application/x-iso9660-image", 0x8001, b"CD001"),
)

_MZ = b"MZ"
_UTF16_BE = b"\xfe\xff"
_UTF16_LE = b"\xff\xfe"

# Bytes that are unusual in plain text (control chars except tab/lf/cr, plus DEL
# and the C1 range). A high share of these means binary, not text.
_TEXT_SUSPECT = frozenset(
    [*range(0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F]
)

_HTML_TAGS = (b"<!doctype html", b"<html", b"<head", b"<body")


@dataclass(frozen=True)
class FileType:
    type: str
    mime: str


# CPU types of a fat (universal) Mach-O's first arch entry, big-endian u32.
_MACHO_CPU_TYPES = frozenset({
    0x00000007, 0x01000007,  # x86 / x86_64
    0x0000000C, 0x0100000C,  # arm / arm64
    0x00000012, 0x01000012,  # ppc / ppc64
})


def _looks_like_fat_macho(data: bytes) -> bool:
    """Disambiguate the CAFEBABE collision between fat Mach-O and Java class.

    A fat Mach-O's ``nfat_arch`` (big-endian u32 at offset 4) is a small
    count whose high bytes are zero, and the following arch entry starts
    with a known ``cpu_type``. A Java class file places its minor/major
    version there — real class files have major >= 45, so the u32 at
    offset 4 can never fall into the 1..32 arch-count range. A macOS
    universal binary misdetected as "class" lands in the wrong pipeline
    (seen in the live VM corpus: a Mach-O sample scanned as Java class).
    """
    if len(data) < 12:
        return False
    nfat_arch = int.from_bytes(data[4:8], "big")
    if not 1 <= nfat_arch <= 32:
        return False
    return int.from_bytes(data[8:12], "big") in _MACHO_CPU_TYPES




def _looks_like_pe(data: bytes) -> bool:
    """Classify MZ blobs as PE, tolerating a truncated PE header.

    Deliberately more lenient than ``generic_pipeline._pe_at``: classification
    wants recall (a truncated EXE still belongs in the PE pipeline), while the
    embedded-signature scan wants precision (a stray "MZ" inside a PNG does
    not, on its own, mean an embedded executable).
    """
    if len(data) < 0x40 or data[:2] != _MZ:
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew <= 0 or e_lfanew + 4 > len(data):
        return True
    return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def _header_block(data: bytes) -> int:
    """Length of the RFC-822 header block, INCLUDING its blank-line separator.

    ``\r\n\r\n`` and ``\n\n`` both end it (a mail written on a system with
    LF line ends is still a mail). No separator found means the whole blob is
    headers as far as this probe is concerned.

    The separator is part of the slice on purpose: ``_looks_like_mail`` needs
    ``has_body_separator``, and excluding it made that predicate impossible to
    satisfy — the header-poor path (no ``Message-ID``) could then never fire,
    and a hand-crafted phishing mail without one was classified "text" with
    every MAIL_* check skipped. Measured: with the separator excluded, the same
    mail with and without ``Message-ID`` gave "eml" and "text"; that is exactly
    the case the predicate's docstring names.
    """
    separators = (b"\r\n\r\n", b"\n\n")
    found = [
        (data.find(sep), len(sep)) for sep in separators if data.find(sep) != -1
    ]
    if not found:
        return len(data)
    pos, length = min(found)
    return pos + length


def _looks_like_mail(blob: bytes) -> bool:
    """Decide whether a text blob is an RFC-822 mail.

    ``blob`` is the HEADER BLOCK (see :func:`_header_block`), raw — the searches
    are case-insensitive patterns rather than a lowercased copy. Measured on
    9 MiB: ``blob.lower()`` costs 0.012 s but allocates a 9.5 MiB copy, the
    patterns cost 0.068 s and allocate nothing. On a 100 MB header block that
    difference is the copy itself, which is the amplification this project
    bounds everywhere else.

    A ``Message-ID`` plus a sender is the classic marker, but phishing mails
    are routinely hand-crafted and may omit it. Requiring it would route
    exactly those suspicious mails into the plain-text path — where the
    ``MAIL_NO_MESSAGE_ID`` finding that is supposed to flag them can never
    fire. So: accept either the classic pair, or a combination of several
    mail-specific headers that no ordinary text file carries.
    """
    def has(pattern: bytes) -> bool:
        return re.search(pattern, blob, re.IGNORECASE) is not None

    has_from = has(rb"^from:") or has(rb"\nfrom:")
    if has(rb"message-id:") and (has_from or has(rb"\nreceived:")):
        return True
    # Header-poor mail: needs at least three independent mail markers so a
    # config/log file that happens to contain "from:" is not misrouted.
    signals = sum(
        (
            has_from,
            has(rb"mime-version:"),
            has(rb"content-type:"),
            has(rb"^to:") or has(rb"\nto:"),
            has(rb"^subject:") or has(rb"\nsubject:"),
            has(rb"\nreturn-path:"),
            has(rb"content-transfer-encoding:"),
        )
    )
    has_body_separator = has(rb"\r\n\r\n") or has(rb"\n\n")
    return signals >= 3 and has_body_separator


# Byte Order Marks. Sie stehen VOR dem eigentlichen Inhalt und gehoeren nicht
# zu ihm — wer sie stehen laesst, sieht das falsche Format.
_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")

# Windows Internet shortcuts (.url) are INI files, not a binary format. The
# extension alone is not evidence: a renamed .url must still be typed by its
# bytes. Requiring BOTH the section header and a URL line keeps ordinary INI
# files (which also start with a [section]) out of the shortcut path.
_SHORTCUT_SECTION = re.compile(rb"(?im)^[ \t]*\[InternetShortcut\][ \t]*\r?$")
_SHORTCUT_URL = re.compile(rb"(?im)^[ \t]*URL[ \t]*=[ \t]*\S")


def _looks_like_internet_shortcut(data: bytes) -> bool:
    """True for a text blob carrying ``[InternetShortcut]`` and ``URL=``."""
    sample = data[:65536]
    for bom in _BOMS:
        if sample.startswith(bom):
            sample = sample[len(bom) :]
            break
    return bool(
        _SHORTCUT_SECTION.search(sample) and _SHORTCUT_URL.search(sample)
    )


def decode_utf16_if_detected(data: bytes, max_bytes: int | None = None) -> str | None:
    """Decode UTF-16 (with BOM or BOM-less XML/HTML ``<`` prefix), else ``None``."""
    if len(data) < 2:
        return None
    view = data if max_bytes is None else data[:max_bytes]
    if view[:2] in (_UTF16_LE, _UTF16_BE):
        return view.decode("utf-16", errors="replace").lstrip("\ufeff")
    if len(view) >= 8 and view[:2] in (b"<\x00", b"\x00<"):
        sample = view[:256]
        even_nuls = sample[0::2].count(0)
        odd_nuls = sample[1::2].count(0)
        half = max(1, len(sample) // 2)
        if view[:2] == b"<\x00" and odd_nuls >= half * 0.4 and even_nuls <= half * 0.1:
            return view.decode("utf-16-le", errors="replace").lstrip("\ufeff")
        if view[:2] == b"\x00<" and even_nuls >= half * 0.4 and odd_nuls <= half * 0.1:
            return view.decode("utf-16-be", errors="replace").lstrip("\ufeff")
    return None


def skip_xml_prolog_pos(text: str) -> int:
    """Linear O(N) prolog skip over BOM, whitespace, ``<?...?>``, ``<!--...-->`` and ``<!DOCTYPE ...>``."""
    n = len(text)
    pos = 0
    if pos < n and text[pos] == "\ufeff":
        pos += 1
    while pos < n:
        while pos < n and text[pos] in " \t\r\n\f":
            pos += 1
        if pos >= n:
            break
        if text.startswith("<!--", pos):
            end = text.find("-->", pos + 4)
            if end == -1:
                return n
            pos = end + 3
            continue
        if text.startswith("<?", pos):
            end = text.find("?>", pos + 2)
            if end == -1:
                return n
            pos = end + 2
            continue
        if text[pos : pos + 9].lower() == "<!doctype":
            # Handle optional internal subset [...] linearly.
            gt = text.find(">", pos + 9)
            if gt == -1:
                return n
            lb = text.find("[", pos + 9, gt)
            if lb != -1:
                rb = text.find("]>", lb + 1)
                if rb == -1:
                    return n
                pos = rb + 2
            else:
                pos = gt + 1
            continue
        break
    return pos


def is_svg_root(text: str) -> bool:
    """Return True if the first root element after XML prolog is ``<svg`` or ``<prefix:svg``."""
    pos = skip_xml_prolog_pos(text)
    if pos >= len(text) or text[pos] != "<":
        return False
    i = pos + 1
    n = len(text)
    if i >= n:
        return False
    # Read optional namespace prefix + local name without regex backtracking.
    start = i
    while i < n and (text[i].isalnum() or text[i] in "_.-:"):
        i += 1
    name = text[start:i].lower()
    if not name:
        return False
    local = name.rsplit(":", 1)[-1]
    if local != "svg":
        return False
    return i < n and text[i] in " \t\r\n/>"


def _filesystem_type(data: bytes) -> FileType | None:
    """Detect raw NTFS / FAT12 / FAT16 / FAT32 / exFAT partition boot sectors."""
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return None
    if data[3:11] == b"NTFS    ":
        return FileType("ntfs", "application/x-ntfs-image")
    if (
        data[3:11] == b"EXFAT   "
        or data[54:62].startswith((b"FAT12   ", b"FAT16   ", b"FAT     "))
        or data[82:90].startswith(b"FAT32   ")
    ):
        return FileType("fat", "application/x-fat-image")
    return None


def _classify_text(data: bytes) -> FileType:
    """Refine a text blob into html/xml/eml/json when recognisable."""
    # BOM ENTFERNEN, nicht nur Leerzeichen: ``lstrip()`` kennt \xef\xbb\xbf
    # nicht, und das ist kein Sonderfall. GEMESSEN: die XML-Mitglieder in
    # .docx/.xlsx/.pptx beginnen mit einer UTF-8-BOM ("\xef\xbb\xbf<?xml"),
    # wurden deshalb als "text" erkannt — und weil die Endung ".xml" etwas
    # anderes behauptet, feuerte GEN_FORMAT_MISMATCH (Schwere HOCH) auf JEDEM
    # XML-Mitglied JEDES Office-Dokuments. Eine echte .docx kam damit auf
    # ROT 100, ohne dass irgendetwas daran auffaellig war.
    head = data[:1024]
    for bom in _BOMS:
        if head.startswith(bom):
            head = head[len(bom):]
            break
    head = head.lstrip()
    lower = head.lower()
    if lower.startswith((b"<?xml", b"<svg")):
        return FileType("xml", "application/xml")
    if b"<" in data[:65536]:
        prolog_text = data[:65536].decode("utf-8", errors="replace")
        if is_svg_root(prolog_text):
            return FileType("xml", "application/xml")
    if any(tag in lower[:256] for tag in _HTML_TAGS):
        return FileType("html", "text/html")
    # A .url is an INI file with a fixed section and a target. Checked before
    # the generic text fallback so the shortcut parser gets to see it. Full
    # data (not ``head``): a padded shortcut must not be able to push the
    # section/URL past the 1 KiB preview.
    if _looks_like_internet_shortcut(data):
        return FileType("url", "application/x-mswinurl")
    # XML without a declaration is valid per spec (office tools such as
    # openpyxl write <worksheet xmlns=...> directly). A namespace attribute is
    # a reliable marker for well-formed XML, checked after the HTML tags so
    # XHTML still lands in "html".
    if lower.startswith(b"<") and b"xmlns" in lower:
        return FileType("xml", "application/xml")
    # The HEADER BLOCK, not a fixed window. A 4096-byte probe was an evasion
    # route: padding the From display name pushed the Message-ID past the
    # window, the blob was classified "text", and every MAIL_* check —
    # authentication, sender comparison, link analysis — was skipped.
    # Measured: padding 0/1000/4000 bytes -> type "eml" with MAIL_AUTH_FAIL;
    # 5000/20000 -> type "text" with no MAIL_* finding at all.
    #
    # A mail's headers end at the first blank line, so that is the region to
    # search — bounded, because the block itself is attacker-controlled.
    if _looks_like_mail(data[:_header_block(data)]):
        return FileType("eml", "message/rfc822")
    if head[:1] in (b"{", b"["):
        # Only claim JSON when it plausibly parses: a bare "{" prefix is far
        # too common in text formats (JS object literals, config files).
        # Large inputs are parsed with a length-tolerant fallback — cutting
        # at 64 KiB misclassified every legitimate JSON document above that
        # size as text/plain (hunt finding 8.1). The re-parse is capped:
        # input is already bounded by MAX_READ_SIZE, but the transient
        # object tree multiplies that — 16 MiB is plenty for real JSON.
        try:
            import json as _json

            probe = data[:65536].decode("utf-8", "replace")
            try:
                _json.loads(probe)
            except ValueError as exc:
                # Truncation artefacts at the probe END ("Expecting ..." /
                # "Unterminated string ...") mean the probe simply ran out
                # of data — parse the whole document instead.
                is_truncated = (
                    len(data) > 65536
                    and len(data) <= 16 * 1024 * 1024
                    and ("Expecting" in str(exc) or "Unterminated" in str(exc))
                )
                if is_truncated:
                    _json.loads(data.decode("utf-8", "replace"))
                else:
                    raise
            return FileType("json", "application/json")
        except Exception:
            pass
    return FileType("text", "text/plain")


def _looks_like_text(data: bytes) -> bool:
    """Heuristic: is ``data`` predominantly printable text?"""
    sample = data[:8192]
    if not sample:
        return False
    suspect = 0
    for byte in sample:
        if byte in _TEXT_SUSPECT:
            suspect += 1
    # Allow at most ~3% control noise; a single NUL byte already disqualifies
    # most binary formats (PE/ZIP/PNG all contain NULs early).
    if b"\x00" in sample:
        return False
    return suspect / len(sample) < 0.03


def _plausible_bmp(data: bytes) -> bool:
    """Sanity-check the DIB header of a "BM"-prefixed blob.

    Plain text/data files can start with "BM"; a real BMP carries a DIB
    header whose declared size is one of the known values and whose pixel
    data offset stays inside the file.
    """
    if len(data) < 0x1A:
        return False
    dib_size = int.from_bytes(data[14:18], "little")
    if dib_size not in (12, 40, 52, 56, 64, 108, 124):
        return False
    pix_offset = int.from_bytes(data[10:14], "little")
    # The pixel data must start inside the file — a bogus huge offset is a
    # text/data file wearing a BMP header, not an image.
    return 0 < pix_offset <= len(data)


def _plausible_tiff(data: bytes) -> bool:
    """Check byte order, magic 42 and the first IFD offset.

    ``II*\\0`` alone is four arbitrary bytes. A real TIFF states its byte
    order, the magic number 42, and an offset to the first IFD that must lie
    inside the file (at least the 2-byte entry count must be readable).
    """
    if len(data) < 10:
        return False
    if data[:2] == b"II":
        magic = int.from_bytes(data[2:4], "little")
        offset = int.from_bytes(data[4:8], "little")
    elif data[:2] == b"MM":
        magic = int.from_bytes(data[2:4], "big")
        offset = int.from_bytes(data[4:8], "big")
    else:
        return False
    return magic == 42 and 8 <= offset <= len(data) - 2


def _plausible_webp(data: bytes) -> bool:
    """RIFF container whose fourcc is WEBP and whose size field is sane.

    ``RIFF`` also prefixes AVI and WAV. Only the ``WEBP`` fourcc at offset 8
    makes this an image; a declared RIFF payload smaller than the fourcc is
    malformed. The upper bound is deliberately NOT checked against ``len``:
    detection also runs on the bounded prefix of a large file.
    """
    if len(data) < 12 or data[8:12] != b"WEBP":
        return False
    return int.from_bytes(data[4:8], "little") >= 4


def _plausible_ico(data: bytes) -> bool:
    """ICONDIR with a non-zero image count and a directory that fits.

    A run of NUL bytes is not an icon. The header declares the number of
    16-byte directory entries; zero entries or a directory beyond the loaded
    bytes means this is not a usable ICO.
    """
    if len(data) < 6:
        return False
    count = int.from_bytes(data[4:6], "little")
    return 1 <= count <= 255 and 6 + 16 * count <= len(data)


def _plausible_id3(data: bytes) -> bool:
    """ID3v2 header: version 2.2-2.4, reserved flag bits clear, syncsafe size.

    A bare "ID3" prefix is also common in plain text ("ID3 ..."). The header
    carries enough structure to reject that: version byte, revision byte and
    four size bytes whose top bit must be zero (syncsafe integer).
    """
    if len(data) < 10 or data[:3] != b"ID3":
        return False
    if data[3] not in (2, 3, 4):
        return False
    if data[4] == 0xFF:
        return False
    # The lower four bits are reserved in every ID3v2 version (v2.2 uses only
    # the top two, v2.3 the top three, v2.4 the top four — including the
    # footer flag 0x10). Checking 0x0F therefore rejects reserved bits without
    # rejecting a valid v2.4 footer.
    if data[5] & 0x0F:
        return False
    return all(byte < 0x80 for byte in data[6:10])


def _looks_like_mpeg_frame(data: bytes, offset: int = 0) -> bool:
    """Plausible MPEG audio frame header (no bare 0xFF false positive).

    The 11-bit frame sync alone matches random bytes. Version/layer bits must
    not be the reserved values, the bitrate index must be neither "free" (0)
    nor invalid (15), and the sample-rate index must be valid.
    """
    if len(data) < offset + 4:
        return False
    if data[offset] != 0xFF:
        return False
    second, third = data[offset + 1], data[offset + 2]
    if second & 0xE0 != 0xE0:
        return False
    version = (second >> 3) & 0x03
    layer = (second >> 1) & 0x03
    bitrate = (third >> 4) & 0x0F
    sample_rate = (third >> 2) & 0x03
    return (
        version != 1  # reserved
        and layer != 0  # reserved
        and bitrate not in (0, 15)  # free / invalid
        and sample_rate != 3  # reserved
    )


#: ISO-BMFF video brands (MP4/MOV). Kept as an explicit allowlist: an
#: unknown ``ftyp`` brand is not evidence of video, and a wrong "mp4" verdict
#: would suppress GEN_ENTROPY for a format that can carry arbitrary payloads.
_MP4_BRANDS = frozenset(
    {b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V ", b"qt  "}
)


def _mp4_type(data: bytes) -> FileType | None:
    """Recognise a known MP4/MOV brand at offset 8."""
    if len(data) < 12 or data[4:8] != b"ftyp":
        return None
    brand = data[8:12]
    if brand not in _MP4_BRANDS:
        return None
    mime = "video/quicktime" if brand == b"qt  " else "video/mp4"
    return FileType("mp4", mime)



#: ISO-BMFF-Brands, die ein BILD sind (HEIF/HEIC/AVIF). Sie werden sonst als
#: "unknown" gelesen — und dann greift keine Format-Erklaerung fuer die hohe
#: Entropie, worauf GEN_ENTROPY mit vollem Gewicht 30 feuerte. GEMESSEN: ein
#: HEIC mit rauschhaftem mdat ergab Score 30/GELB, obwohl es ein normales Foto
#: war. Betroffen ist jedes iPhone-Foto.
_HEIF_BRANDS = frozenset(
    {b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"mif1", b"msf1",
     b"avif", b"avis"}
)


def _heif_type(data: bytes) -> FileType | None:
    """HEIC/HEIF/AVIF erkennen: ``ftyp``-Box an Offset 4 mit passendem Brand."""
    if len(data) < 12 or data[4:8] != b"ftyp":
        return None
    brand = data[8:12]
    if brand not in _HEIF_BRANDS:
        return None
    # AVIF ist ein eigenes Format mit eigenem MIME; HEIC/HEIF teilen sich einen.
    if brand in (b"avif", b"avis"):
        return FileType("avif", "image/avif")
    return FileType("heic", "image/heic")


def detect(data: bytes) -> FileType:
    """Detect the file type from the leading bytes."""
    if not data:
        return FileType("empty", "application/octet-stream")

    if _looks_like_pe(data):
        return FileType("pe", "application/x-dosexec")

    heif = _heif_type(data)
    if heif is not None:
        return heif

    for sig in _SIGNATURES:
        end = sig.offset + len(sig.magic)
        if len(data) >= end and data[sig.offset : end] == sig.magic:
                if sig.type == "bmp" and not _plausible_bmp(data):
                    # "BM" also prefixes text/data files; require a sane DIB
                    # header before claiming the image pipeline.
                    continue
                if sig.type == "tiff" and not _plausible_tiff(data):
                    continue
                if sig.type == "webp" and not _plausible_webp(data):
                    continue
                if sig.type == "ico" and not _plausible_ico(data):
                    continue
                if sig.type == "mp3" and not _plausible_id3(data):
                    continue
                if sig.type == "mp4":
                    mp4 = _mp4_type(data)
                    if mp4 is None:
                        # Unknown brand — an ISO-BMFF blob without a video
                        # brand is not evidence of a video and stays unknown.
                        continue
                    return mp4
                if sig.type == "class" and _looks_like_fat_macho(data):
                    # CAFEBABE is shared with fat Mach-O binaries; the fat
                    # header check above decides which of the two it is.
                    return FileType("macho", "application/x-mach-binary")
                return FileType(sig.type, sig.mime)

    # UTF-16 text (BOM) is binary-looking to the byte heuristic and its BOM
    # (0xFF 0xFE) also satisfies the 11-bit MPEG sync, so this MUST run before
    # the raw-frame probe. "Hallo Welt".encode("utf-16") otherwise became
    # "mp3" (FF FE + printable+NUL bytes looked like a frame header).
    fs_type = _filesystem_type(data)
    if fs_type is not None:
        return fs_type

    utf16_text = decode_utf16_if_detected(data, max_bytes=65536)
    if utf16_text is not None:
        return _classify_text(utf16_text.encode("utf-8", errors="replace"))

    # Raw MPEG audio has no fixed prefix (0xFF is only an 11-bit sync), so it
    # needs the header plausibility check instead of a signature entry.
    if _looks_like_mpeg_frame(data):
        return FileType("mp3", "audio/mpeg")

    if _looks_like_text(data):
        return _classify_text(data)

    return FileType("unknown", "application/octet-stream")


# Extension -> expected canonical type, used to flag extension/header mismatch.
# Only extensions whose type this module can actually produce are listed, so a
# real file never triggers a false mismatch.
_EXTENSION_MAP = {
    ".pdf": "pdf",
    ".zip": "zip",
    ".docx": "zip",
    ".xlsx": "zip",
    ".pptx": "zip",
    ".odt": "zip",
    ".ods": "zip",
    ".jar": "zip",
    ".doc": "ole",
    ".xls": "ole",
    ".ppt": "ole",
    ".7z": "7z",
    ".rar": "rar",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".bmp": "bmp",
    ".tif": "tiff",
    ".tiff": "tiff",
    ".webp": "webp",
    ".ico": "ico",
    ".mp3": "mp3",
    ".mp4": "mp4",
    ".m4v": "mp4",
    ".url": "url",
    # HEIC/HEIF und AVIF sind jetzt eigene Typen (siehe _heif_type), also
    # gehoeren ihre Endungen hierher: ein als .heic getarntes PE faellt damit
    # als Format-Taeuschung auf — und ein echtes HEIC bleibt still.
    ".heic": "heic",
    ".heif": "heic",
    ".avif": "avif",
    ".exe": "pe",
    ".dll": "pe",
    ".scr": "pe",
    ".sys": "pe",
    ".lnk": "lnk",
    ".rtf": "rtf",
    ".swf": "swf",
    ".cab": "cab",
    ".chm": "chm",
    ".vhdx": "vhdx",
    ".one": "onenote",
    ".ntfs": "ntfs",
    ".fat": "fat",
    ".class": "class",
    ".html": "html",
    ".htm": "html",
    ".xml": "xml",
    ".svg": "xml",
    ".xsl": "xml",
    ".xslt": "xml",
    ".eml": "eml",
    # Plain-text family: this module reports these as "text"/"json".
    ".txt": "text",
    ".log": "text",
    ".csv": "text",
    ".tsv": "text",
    ".ini": "text",
    ".cfg": "text",
    ".conf": "text",
    ".md": "text",
    ".js": "js",
    ".mjs": "js",
    ".vbs": "vbs",
    ".ps1": "ps1",
    ".psm1": "ps1",
    ".bat": "batch",
    ".cmd": "batch",
    ".sh": "text",
    ".py": "text",
    ".json": "json",
}


# Script formats carry no magic bytes — they are plain text whose dialect is
# defined by the extension. When the content IS text, the extension refines
# the type into the concrete script flavor so pipelines and the UI treat it
# as the executable content it is (a .bat displayed as "Text" hides that
# double-clicking it runs code). Windows-relevant flavors only; .sh/.py stay
# plain text as ordinary development files.
_SCRIPT_EXTENSION_TYPES = {
    ".bat": "batch", ".cmd": "batch",
    ".ps1": "ps1", ".psm1": "ps1",
    ".vbs": "vbs",
    ".js": "js", ".mjs": "js",
}


def refine_text_type(ftype: FileType, suffix: str) -> FileType:
    """Refine a detected text/json type into the concrete script type.

    Binary detections pass through untouched — an .exe stays an .exe no
    matter its name. ``json`` also refines: valid JSON is valid JavaScript,
    so a .json body inside a .js file must not read as a format mismatch.
    """
    script_type = _SCRIPT_EXTENSION_TYPES.get((suffix or "").lower())
    if script_type and ftype.type in ("text", "json"):
        return FileType(script_type, "text/plain")
    return ftype


# Content-based script detection (stage 2, libmagic-style: a renamed
# .bat must not read as plain "Text" either). Only strong markers count —
# these change the TYPE, so a false positive would mislabel ordinary text.
# ``@echo off`` at the very start is the classic batch opener (libmagic's
# rule of choice); the PowerShell/VBScript dialects require at least two
# DISTINCT tokens so prose quoting one command never trips the check.
# JavaScript deliberately has no content stage: its vocabulary overlaps
# with JSON/HTML/plain text far too much for a safe byte-level rule.
_SCRIPT_SAMPLE_SIZE = 8192

_BATCH_HEAD = re.compile(rb"^\s*@echo\s+(?:off|on)\b", re.IGNORECASE)

_PS_CONTENT_TOKENS = (
    b"#requires", b"param(", b"invoke-expression", b"write-host",
    b"get-content", b"new-object", b"set-executionpolicy", b"$env:",
    b"foreach ($", b"$psitem", b"get-childitem", b"set-strictmode",
)
_VBS_CONTENT_TOKENS = (
    b"createobject(", b"wscript.", b"on error resume next", b"msgbox ",
    b"dim ", b"call ",
)


def _script_sample(data: bytes) -> bytes:
    """Lowercased, ASCII-normalised head of the file for token matching."""
    head = data[:_SCRIPT_SAMPLE_SIZE]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        # UTF-16 (BOM) is common for .ps1 — match tokens after decoding.
        try:
            return head.decode("utf-16").encode("latin-1", "replace").lower()
        except (UnicodeDecodeError, UnicodeEncodeError):
            return b""
    return head.lower()


def refine_script_content(ftype: FileType, data: bytes) -> FileType:
    """Detect a script dialect from CONTENT when the extension said nothing.

    Runs after :func:`refine_text_type` and only ever upgrades a remaining
    ``text``/``json`` detection — a binary verdict or an extension-based
    script type is never overridden by content guesses.
    """
    if ftype.type not in ("text", "json") or not data:
        return ftype
    sample = _script_sample(data)
    if _BATCH_HEAD.match(sample):
        return FileType("batch", "text/plain")
    if sum(1 for token in _PS_CONTENT_TOKENS if token in sample) >= 2:
        return FileType("ps1", "text/plain")
    if sum(1 for token in _VBS_CONTENT_TOKENS if token in sample) >= 2:
        return FileType("vbs", "text/plain")
    return ftype


def expected_type_for_extension(extension: str) -> str | None:
    """Return the canonical type an extension claims, or ``None`` if unknown."""
    return _EXTENSION_MAP.get(extension.lower())
