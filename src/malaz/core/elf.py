"""Defensive ELF structure parsing (AP12).

Only headers, program headers and section headers are read — no disassembly and
no execution. Every count/offset is bounded because the input is hostile; a
truncated or malformed structure yields ``valid=False`` or a bounded partial
result, never an exception.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .entropy import shannon_entropy

_ELF_MAGIC = b"\x7fELF"
_MAX_PHDRS = 256
_MAX_SHDRS = 512
_MAX_NAME_BYTES = 64 * 1024
_MAX_NAME_LEN = 80
_MAX_SECTION_ENTROPY_BYTES = 1 * 1024 * 1024

PT_LOAD = 1
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2

ET_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACHINE_NAMES = {
    0x03: "x86",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0xF3: "RISC-V",
}


@dataclass(frozen=True)
class ElfSegment:
    type: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int
    align: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)

    @property
    def writable(self) -> bool:
        return bool(self.flags & PF_W)


@dataclass(frozen=True)
class ElfSection:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    entsize: int
    entropy: float = 0.0


@dataclass(frozen=True)
class ElfInfo:
    valid: bool
    bits: int = 0
    endian: str = ""
    e_type: int = 0
    machine: int = 0
    entry: int = 0
    segments: tuple[ElfSegment, ...] = ()
    sections: tuple[ElfSection, ...] = ()
    interpreter: str = ""
    overlay: int = 0
    error: str = ""


def _unpack(endian: str, fmt: str, data: bytes, offset: int):
    return struct.unpack_from(endian + fmt, data, offset)


def parse_elf(data: bytes) -> ElfInfo:
    """Parse the ELF header and bounded program/section header tables."""
    if len(data) < 16 or data[:4] != _ELF_MAGIC:
        return ElfInfo(valid=False, error="kein ELF-Magic")
    bits = data[4]
    encoding = data[5]
    if bits not in (1, 2):
        return ElfInfo(valid=False, error=f"ungültige ELF-Klasse {bits}")
    if encoding not in (1, 2):
        return ElfInfo(valid=False, error=f"ungültige Byte-Order {encoding}")
    endian = "<" if encoding == 1 else ">"
    header_size = 52 if bits == 1 else 64
    if len(data) < header_size:
        return ElfInfo(
            valid=False, bits=32 if bits == 1 else 64,
            endian="little" if endian == "<" else "big",
            error="ELF-Header abgeschnitten",
        )

    if bits == 1:
        (
            e_type, e_machine, _version, e_entry, e_phoff, e_shoff, _e_flags,
            _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
        ) = _unpack(endian, "HHIIIIIHHHHHH", data, 16)
        ph_fmt, ph_size = "IIIIIIII", 32
        sh_fmt, sh_size = "IIIIIIIIII", 40
    else:
        (
            e_type, e_machine, _version, e_entry, e_phoff, e_shoff, _e_flags,
            _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
        ) = _unpack(endian, "HHIQQQIHHHHHH", data, 16)
        ph_fmt, ph_size = "IIQQQQQQ", 56
        sh_fmt, sh_size = "IIQQQQIIQQ", 64

    fehler: list[str] = []
    segments: list[ElfSegment] = []
    phnum_gesamt = int(e_phnum)
    phnum = min(phnum_gesamt, _MAX_PHDRS)
    if phnum_gesamt > _MAX_PHDRS:
        # BUG-032: silently cutting the table made a structure look complete
        # that was only partially parsed. The cap stays (bounded work), but the
        # pipeline must be able to say so via ELF_STRUCTURE_WARN.
        fehler.append(
            f"Program-Header-Tabelle gekappt: {phnum_gesamt} Einträge, nur "
            f"{_MAX_PHDRS} gelesen"
        )
    if phnum and (e_phentsize < ph_size or e_phoff + phnum * e_phentsize > len(data)):
        fehler.append("Program-Header-Tabelle abgeschnitten")
    else:
        for index in range(phnum):
            pos = e_phoff + index * e_phentsize
            # BUG-030: the table guard above is arithmetic on attacker-
            # controlled fields; check the actual unpack window as well so a
            # zero/malformed entry size can never raise struct.error.
            if pos < 0 or pos + ph_size > len(data):
                fehler.append("Program-Header-Tabelle abgeschnitten")
                break
            values = _unpack(endian, ph_fmt, data, pos)
            if bits == 1:
                p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = values
            else:
                p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = values
            segments.append(
                ElfSegment(
                    type=int(p_type), offset=int(p_offset), vaddr=int(p_vaddr),
                    filesz=int(p_filesz), memsz=int(p_memsz), flags=int(p_flags),
                    align=int(p_align),
                )
            )

    sections: list[ElfSection] = []
    shnum_gesamt = int(e_shnum)
    shnum = min(shnum_gesamt, _MAX_SHDRS)
    if shnum_gesamt > _MAX_SHDRS:
        fehler.append(
            f"Section-Header-Tabelle gekappt: {shnum_gesamt} Einträge, nur "
            f"{_MAX_SHDRS} gelesen"
        )
    names = b""
    table_ok = bool(shnum) and (
        e_shentsize >= sh_size and e_shoff + shnum * e_shentsize <= len(data)
    )
    if table_ok and e_shstrndx < shnum:
        str_pos = e_shoff + e_shstrndx * e_shentsize
        # BUG-030: check the full 64-byte window BEFORE unpacking. The old
        # guard accepted e_shentsize=0 (table fits "by arithmetic") and then
        # unpacked 64 bytes at e_shoff=len-8 -> struct.error.
        if str_pos >= 0 and str_pos + sh_size <= len(data):
            str_values = _unpack(endian, sh_fmt, data, str_pos)
            str_offset, str_size = int(str_values[4]), int(str_values[5])
            if 0 <= str_offset < len(data):
                names = data[str_offset : str_offset + min(str_size, _MAX_NAME_BYTES)]
    if shnum and not table_ok:
        fehler.append("Section-Header-Tabelle abgeschnitten")
    else:
        for index in range(shnum):
            pos = e_shoff + index * e_shentsize
            if pos < 0 or pos + sh_size > len(data):
                fehler.append("Section-Header-Tabelle abgeschnitten")
                break
            values = _unpack(endian, sh_fmt, data, pos)
            (
                name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                _link, _info, _align, sh_entsize,
            ) = values
            name = _section_name(names, int(name_off))
            entropy = 0.0
            size = int(sh_size)
            if 0 < size <= _MAX_SECTION_ENTROPY_BYTES and 0 <= sh_offset < len(data):
                entropy = shannon_entropy(data[sh_offset : sh_offset + size])
            sections.append(
                ElfSection(
                    name=name, type=int(sh_type), flags=int(sh_flags),
                    addr=int(sh_addr), offset=int(sh_offset), size=size,
                    entsize=int(sh_entsize), entropy=entropy,
                )
            )

    interpreter = ""
    for segment in segments:
        if segment.type == PT_INTERP and segment.offset < len(data):
            raw = data[segment.offset : segment.offset + min(segment.filesz, 400)]
            interpreter = raw.split(b"\x00", 1)[0].decode("latin-1", "replace")[:120]
            break

    load_ends = [
        segment.offset + segment.filesz
        for segment in segments
        if segment.type == PT_LOAD and 0 <= segment.offset < len(data)
    ]
    overlay = max(0, len(data) - max(load_ends)) if load_ends else 0
    return ElfInfo(
        valid=True,
        bits=32 if bits == 1 else 64,
        endian="little" if endian == "<" else "big",
        e_type=int(e_type),
        machine=int(e_machine),
        entry=int(e_entry),
        segments=tuple(segments),
        sections=tuple(sections),
        interpreter=interpreter,
        overlay=overlay,
        error="; ".join(fehler),
    )


def _section_name(table: bytes, offset: int) -> str:
    if not table or offset <= 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("latin-1", "replace")[:_MAX_NAME_LEN]
