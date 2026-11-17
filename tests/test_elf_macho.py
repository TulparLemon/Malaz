"""AP12: ELF and Mach-O structure tests with minimal, deterministic fixtures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import AnalysisContext
from malaz.pipelines.elf_pipeline import ElfPipeline
from malaz.pipelines.macho_pipeline import MachoPipeline


def _ctx(data: bytes, ftype: str, name: str) -> AnalysisContext:
    return AnalysisContext(
        path=Path(name), data=data, detected_type=ftype, size=len(data), depth=0
    )


def _ids(indicators) -> dict[str, object]:
    return {indicator.rule_id: indicator for indicator in indicators}


def _elf64(*, wx: bool = False, exec_stack: bool = False, overlay: bytes = b"") -> bytes:
    header_size = 64
    phoff = header_size
    phnum = 2
    ph_size = 56
    shoff = phoff + phnum * ph_size
    shnum = 3
    sh_size = 64
    data_off = shoff + shnum * sh_size
    text = b"\x90" * 32
    names = b"\x00.text\x00.shstrtab\x00"
    names_off = data_off + len(text)
    total = names_off + len(names)

    ehdr = (
        b"\x7fELF\x02\x01\x01\x00"
        + b"\x00" * 8
        + struct.pack(
            "<HHIQQQIHHHHHH",
            2, 0x3E, 1, 0x401000, phoff, shoff, 0,
            header_size, ph_size, phnum, sh_size, shnum, 2,
        )
    )
    load = struct.pack(
        "<IIQQQQQQ",
        1, 7 if wx else 5, 0, 0x400000, 0x400000, total, total, 0x1000,
    )
    stack = struct.pack(
        "<IIQQQQQQ",
        0x6474E551, 7 if exec_stack else 6, 0, 0, 0, 0, 0, 16,
    )
    null = b"\x00" * sh_size
    text_sh = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 0x6, 0x401000, data_off, len(text), 0, 0, 16, 0
    )
    names_sh = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, names_off, len(names), 0, 0, 1, 0
    )
    return ehdr + load + stack + null + text_sh + names_sh + text + names + overlay


def _elf32_be_header() -> bytes:
    return (
        b"\x7fELF\x01\x02\x01\x00"
        + b"\x00" * 8
        + struct.pack(
            ">HHIIIIIHHHHHH",
            2, 0x14, 1, 0x10000000, 52, 0, 0, 52, 32, 0, 40, 0, 0,
        )
    )


def test_elf_zero_section_entry_size_does_not_crash():
    """BUG-030: e_shentsize=0 made the parser unpack 64 bytes at EOF."""
    from malaz.core.elf import parse_elf

    data = bytearray(_elf64())
    struct.pack_into("<Q", data, 40, len(data) - 8)  # e_shoff near EOF
    struct.pack_into("<H", data, 58, 0)  # e_shentsize = 0

    info = parse_elf(bytes(data))

    assert info.valid is True
    assert "Section-Header-Tabelle" in info.error, info.error


def test_elf_header_caps_are_reported():
    """BUG-032: silently capped PHDR/SHDR tables must surface as a warning."""
    from malaz.core.elf import parse_elf

    data = bytearray(_elf64())
    struct.pack_into("<H", data, 56, 300)  # e_phnum > _MAX_PHDRS (256)
    struct.pack_into("<H", data, 60, 600)  # e_shnum > _MAX_SHDRS (512)

    info = parse_elf(bytes(data))

    assert info.valid is True
    assert "Program-Header-Tabelle gekappt: 300" in info.error, info.error
    assert "Section-Header-Tabelle gekappt: 600" in info.error, info.error


def _macho64(*, code_signature: bool = True, overlay: bytes = b"") -> bytes:
    header_size = 32
    dylib_name = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_size = (24 + len(dylib_name) + 7) // 8 * 8
    dylib = (
        struct.pack("<IIIIII", 0xC, dylib_size, 24, 2, 0x10000, 0x10000)
        + dylib_name
        + b"\x00" * (dylib_size - 24 - len(dylib_name))
    )
    uuid = struct.pack("<II", 0x1B, 24) + bytes(range(16))
    code = struct.pack("<IIII", 0x1D, 16, 0x1000, 0x100) if code_signature else b""
    commands_without_segment = dylib + uuid + code
    sizeofcmds = 72 + len(commands_without_segment)
    total = header_size + sizeofcmds
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19, 72, b"__TEXT", 0x100000000, 0x1000, 0, total, 5, 5, 0, 0,
    )
    header = (
        b"\xcf\xfa\xed\xfe"
        + struct.pack(
            "<IIIIII", 0x01000007, 3, 2, 4, sizeofcmds, 0
        )
        + struct.pack("<I", 0)
    )
    return header + segment + commands_without_segment + overlay


def _macho32() -> bytes:
    return (
        b"\xce\xfa\xed\xfe"
        + struct.pack("<IIIIII", 7, 3, 2, 0, 0, 0)
    )


def _fat_macho() -> bytes:
    slice_data = _macho64()
    offset = 0x100
    entry = struct.pack(
        ">IIIII", 0x01000007, 3, offset, len(slice_data), 0
    )
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1) + entry
    return header.ljust(offset, b"\x00") + slice_data


def test_elf_header_sections_and_nx():
    inds = _ids(ElfPipeline().analyze(_ctx(_elf64(), "elf", "a.elf")))
    assert "ELF_HEADER" in inds
    assert "ELF_SECTIONS" in inds
    assert "ELF_PARSE_WARN" not in inds
    assert "ELF_NO_NX" not in inds
    assert "ELF_WX_SEGMENT" not in inds
    assert inds["ELF_HEADER"].weight == 0


def test_elf_wx_exec_stack_and_overlay():
    inds = _ids(
        ElfPipeline().analyze(
            _ctx(
                _elf64(wx=True, exec_stack=True, overlay=b"APPENDED" * 8),
                "elf",
                "a.elf",
            )
        )
    )
    assert "ELF_WX_SEGMENT" in inds
    assert "ELF_NO_NX" in inds
    assert "ELF_OVERLAY" in inds
    assert all(inds[name].weight == 0 for name in ("ELF_WX_SEGMENT", "ELF_NO_NX", "ELF_OVERLAY"))


def test_elf32_big_endian_header_is_parsed():
    inds = _ids(ElfPipeline().analyze(_ctx(_elf32_be_header(), "elf", "a.elf")))
    assert "ELF_HEADER" in inds
    assert "ELF32 big-endian" in inds["ELF_HEADER"].title


def test_truncated_elf_is_not_clean():
    inds = _ids(ElfPipeline().analyze(_ctx(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8, "elf", "a.elf")))
    assert "ELF_PARSE_WARN" in inds
    assert inds["ELF_PARSE_WARN"].weight == 5


def test_macho_header_segments_dylib_and_signature():
    inds = _ids(MachoPipeline().analyze(_ctx(_macho64(), "macho", "a.macho")))
    assert "MACHO_HEADER" in inds
    assert "MACHO_SEGMENTS" in inds
    assert "MACHO_DYLIB" in inds
    assert "MACHO_NO_CODE_SIGNATURE" not in inds
    assert "MACHO_OVERLAY" not in inds
    assert inds["MACHO_HEADER"].weight == 0


def test_macho_without_signature_and_overlay():
    inds = _ids(
        MachoPipeline().analyze(
            _ctx(_macho64(code_signature=False, overlay=b"X" * 64), "macho", "a.macho")
        )
    )
    assert "MACHO_NO_CODE_SIGNATURE" in inds
    assert "MACHO_OVERLAY" in inds
    assert inds["MACHO_NO_CODE_SIGNATURE"].weight == 0
    assert inds["MACHO_OVERLAY"].weight == 0


def test_macho32_and_fat_header():
    inds = _ids(MachoPipeline().analyze(_ctx(_macho32(), "macho", "a.macho")))
    assert "MACHO_HEADER" in inds
    fat = _ids(MachoPipeline().analyze(_ctx(_fat_macho(), "macho", "fat.macho")))
    assert "MACHO_HEADER" in fat
    assert "Fat-Binary mit 1" in fat["MACHO_HEADER"].detail


def test_truncated_macho_is_not_clean():
    inds = _ids(MachoPipeline().analyze(_ctx(b"\xcf\xfa\xed\xfe" + b"\x00" * 8, "macho", "a.macho")))
    assert "MACHO_PARSE_WARN" in inds
    assert inds["MACHO_PARSE_WARN"].weight == 5


@pytest.mark.parametrize(
    ("name", "data", "ftype", "rule"),
    [
        ("a.elf", _elf64(), "elf", "ELF_HEADER"),
        ("a.macho", _macho64(), "macho", "MACHO_HEADER"),
    ],
)
def test_dispatcher_attaches_structure_pipeline(tmp_path, name, data, ftype, rule):
    path = tmp_path / name
    path.write_bytes(data)
    result = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(path)
    assert result.detected_type == ftype
    assert rule in {i.rule_id for i in result.indicators}
