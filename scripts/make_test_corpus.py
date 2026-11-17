"""Generate a synthetic, fully INERT malware-like test corpus.

Every file in this corpus is a *benign-but-suspicious* fixture: it carries the
byte patterns malware uses (obfuscated PDF keywords, launch actions, DDE
formulas, packer section names, zip-slip names, embedded payloads, …) but is
plain, dead data — nothing is executable, nothing activates. The corpus is
used by ``tests/test_corpus.py`` to verify that every pipeline produces its
expected indicators.

Why synthetic instead of real malware: the tool's analysis is purely static,
so byte patterns are all it needs — and no VM is ever at risk.

Usage:
    python scripts/make_test_corpus.py [target-dir]
"""

from __future__ import annotations

import random
import struct
import sys
import zlib
from pathlib import Path

import corpus_determinism as _det

# NOTE: there is deliberately no module-level RNG. A shared generator advances
# between calls, so two builds of the same fixture produced different bytes —
# which broke the "deterministic across runs" promise below. Fixtures that need
# random-looking bytes create a fresh seeded instance per call instead
# (see pe_high_entropy_sections). scripts/corpus_determinism documents why the
# writers needed pinning too.


# -- PDF fixtures ------------------------------------------------------------ #


def pdf_obfuscated() -> bytes:
    return b"%PDF-1.7\n/Type /Catalog\n/J#61vaScript (x)\n/Open#41ction 1\n%%EOF"


def pdf_launch() -> bytes:
    return b"%PDF-1.7\n/Launch /JavaScript\n%%EOF"


def pdf_incremental() -> bytes:
    """A valid PDF plus a trailing second %%EOF marker (qpdf tolerates it;
    the structure scan counts both markers -> incremental-update hint)."""

    import pikepdf

    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792])
        )
    )
    return _det.save_pdf_deterministic(pdf) + b"\n%%EOF"


def pdf_hidden_text() -> bytes:
    """A real one-page PDF whose content stream uses text render mode 3."""
    try:
        import pikepdf
    except ImportError:
        return b"%PDF-1.7\nBT 3 Tr (x) Tj ET\n%%EOF"  # degraded fixture
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pikepdf.Stream(pdf, b"BT 3 Tr (hidden) Tj ET"),
            )
        )
    )
    return _det.save_pdf_deterministic(pdf)


# -- Office fixture ----------------------------------------------------------- #


def xlsx_dde() -> bytes:
    """A .xlsx whose cell contains a classic DDE launch formula."""

    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "=cmd|'/C calc.exe'!A0"
    return _det.save_workbook_deterministic(wb)


# -- PE fixtures -------------------------------------------------------------- #


def _minimal_pe(
    section_name: bytes = b".text",
    raw_size: int = 16,
    virtual_size: int = 16,
    dll_chars: int = 0,
    section_data: bytes = b"",
) -> bytes:
    """Structurally parseable minimal PE (see tests/test_pe_pipeline.py)."""
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack(
        "<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022
    )
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
    raw = section_data or b"\x90" * raw_size
    return dos + b"PE\x00\x00" + coff + opt + sec + b"\x00" * (0x200 - headers_len) + raw


def pe_packed() -> bytes:
    return _minimal_pe(section_name=b"UPX0", raw_size=0, virtual_size=0x4000)


def pe_weak_mitigations() -> bytes:
    return _minimal_pe(dll_chars=0)


def pe_high_entropy_sections() -> bytes:
    """Two sections with genuinely random content (high entropy each)."""
    # Fresh instance per call: the module-level RNG advances between calls, so
    # two builds of the same fixture produced different bytes and broke the
    # "deterministic across runs" promise in the module docstring. Same fix as
    # _entropy_blob in make_test_corpus_extended.
    blob = random.Random(0xE17A0).randbytes(1024)
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0x00F0, 0x0022)
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0, 0x800, 0x800, 0, 0x1000, 0x1000, 0x140000000,
        0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0x4000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"\x00" * 128
    sec1 = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 1024, 0x1000, 1024, 0x200, 0, 0, 0, 0, 0x60000020
    )
    sec2 = b".data".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 1024, 0x2000, 1024, 0x600, 0, 0, 0, 0, 0xC0000040
    )
    return dos + b"PE\x00\x00" + coff + opt + sec1 + sec2 + blob + blob


def pe_overlay() -> bytes:
    # Seeded generator instead of os.urandom: urandom cannot be reproduced, so
    # two builds differed and broke the module's determinism promise.
    return _minimal_pe() + b"\x00" * 512 + random.Random(0xE17A0).randbytes(512)


# -- generic fixtures --------------------------------------------------------- #


def high_entropy_bin() -> bytes:
    # Fresh instance per call — see pe_high_entropy_sections for why.
    return random.Random(0xE17A0).randbytes(64 * 1024)


def zipslip_zip() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        _det.zip_write(zf, "../evil.txt", b"x")
        _det.zip_write(zf, "ok.txt", b"ok")
    return buf.getvalue()


def bomb_zip() -> bytes:
    """20 MB of zeros -> compression ratio far above the bomb threshold."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _det.zip_write(zf, "zeros.bin", b"\x00" * (20 * 1024 * 1024))
    return buf.getvalue()


def tar_gz_with_evil_pdf() -> bytes:
    import io

    buf = io.BytesIO()
    with _det.open_tar_gz(buf) as tf:
        _det.tar_write(tf, "evil.pdf", pdf_launch())
    return buf.getvalue()


def eml_with_evil_pdf() -> bytes:
    import email.message
    import email.policy

    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg["Subject"] = "Rechnung"
    msg["Message-ID"] = "<corpus-1@example.com>"
    msg.set_content("Rechnung anbei.")
    msg.add_attachment(
        pdf_launch(),
        maintype="application",
        subtype="pdf",
        filename="rechnung.pdf",
    )
    # set_content/add_attachment generate a random MIME boundary; pinning it
    # keeps the "deterministic across runs" promise from the module docstring.
    _det.pin_mime_boundary(msg)
    return msg.as_bytes()


def rtf_with_ole() -> bytes:
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 128
    return b"{\\rtf1\\object\\objdata " + ole.hex().encode() + b" }"


def swf_cws() -> bytes:
    payload = b"FWS\x09" + b"\x00" * 10 + b"powershell -encodedcommand downloadstring"
    return b"CWS\x09" + b"\x00" * 4 + zlib.compress(payload)


def png_with_pe_payload() -> bytes:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    stub = (
        b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
        + b"\x00" * 0x40 + b"PE\x00\x00"
    )
    return png + b"\x00" * 32 + stub


def double_extension_name() -> bytes:
    return b"MZ" + b"\x90" * 512  # filename matters, content is inert


def plain_text() -> bytes:
    return b"vollkommen harmloser Klartext.\n"


# -- corpus table -------------------------------------------------------------- #

# (filename, builder, expected rule_ids) — the corpus contract tested by
# tests/test_corpus.py. Expected rules are *minimum* requirements; additional
# findings are allowed.
CORPUS: list[tuple[str, object, tuple[str, ...]]] = [
    ("obfuscated.pdf", pdf_obfuscated, ("PDF_KW_JavaScript_OBF", "PDF_KW_OpenAction_OBF")),
    ("launch.pdf", pdf_launch, ("PDF_KW_Launch",)),
    ("incremental.pdf", pdf_incremental, ("PDF_INCREMENTAL",)),
    ("hidden_text.pdf", pdf_hidden_text, ("PDF_INVISIBLE_TEXT",)),
    ("dde.xlsx", xlsx_dde, ("OFFICE_FORMULA",)),
    ("packed.exe", pe_packed, ("PE_PACKED",)),
    ("weak_mitigations.exe", pe_weak_mitigations, ("PE_WEAK_MITIGATIONS",)),
    ("high_entropy_sections.exe", pe_high_entropy_sections, ("PE_HIGH_ENTROPY_SECTIONS",)),
    ("overlay.exe", pe_overlay, ("PE_OVERLAY",)),
    ("high_entropy.bin", high_entropy_bin, ("GEN_ENTROPY",)),
    ("zipslip.zip", zipslip_zip, ("ARCH_ZIPSLIP",)),
    ("bomb.zip", bomb_zip, ("ARCH_BOMB_RATIO",)),
    ("evil_in_tar.tar.gz", tar_gz_with_evil_pdf, ("PDF_KW_Launch",)),
    ("mail.eml", eml_with_evil_pdf, ("PDF_KW_Launch",)),
    ("object.rtf", rtf_with_ole, ("name:embedded_ole_1.bin", "type:ole")),
    ("flash.swf", swf_cws, ("GEN_SUSPICIOUS_STRINGS",)),
    ("image.png", png_with_pe_payload, ("GEN_EMBEDDED",)),
    ("rechnung.pdf.exe", double_extension_name, ("GEN_FILENAME_IOC",)),
    ("note.txt", plain_text, ()),
]


def build_corpus(target_dir: Path) -> list[Path]:
    """Write every fixture into ``target_dir``; returns the created paths."""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, builder, _expected in CORPUS:
        data = builder()
        path = target_dir / filename
        path.write_bytes(data)
        written.append(path)
    return written


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/data/corpus")
    files = build_corpus(target)
    print(f"{len(files)} Fixtures nach {target} geschrieben:")
    for path in files:
        print(f"  {path.name} ({path.stat().st_size} Bytes)")
