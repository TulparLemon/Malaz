"""Defensive Mach-O structure parsing (AP12).

Handles thin 32/64-bit binaries (both endiannesses) and fat/universal files.
Only headers, load commands and segment metadata are read — no code, no
disassembly. Every count and offset is bounded; malformed input degrades to
``valid=False`` or a partial result.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_MAGIC_THIN = {
    b"\xfe\xed\xfa\xce": (False, 32),
    b"\xce\xfa\xed\xfe": (True, 32),
    b"\xfe\xed\xfa\xcf": (False, 64),
    b"\xcf\xfa\xed\xfe": (True, 64),
}
_MAGIC_FAT = {
    b"\xca\xfe\xba\xbe": False,  # FAT_MAGIC (big endian)
    b"\xbe\xba\xfe\xca": True,   # FAT_CIGAM
}

LC_SEGMENT = 0x1
LC_LOAD_DYLIB = 0xC
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19

_MAX_COMMANDS = 256
_MAX_DYLIB_NAME = 120
_VM_PROT_WRITE = 0x2
_VM_PROT_EXECUTE = 0x4

CPU_NAMES = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "ARM64",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}
FILETYPE_NAMES = {
    1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD",
    6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE", 9: "DYLIB_STUB", 10: "DSYM",
    11: "KEXT_BUNDLE",
}


@dataclass(frozen=True)
class MachoSegment:
    name: str
    fileoff: int
    filesize: int
    initprot: int
    nsects: int

    @property
    def executable(self) -> bool:
        return bool(self.initprot & _VM_PROT_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.initprot & _VM_PROT_WRITE)


@dataclass(frozen=True)
class MachoArch:
    cputype: int
    cpusubtype: int
    offset: int
    size: int


@dataclass(frozen=True)
class MachoInfo:
    valid: bool
    bits: int = 0
    endian: str = ""
    filetype: int = 0
    cputype: int = 0
    ncmds: int = 0
    segments: tuple[MachoSegment, ...] = ()
    dylibs: tuple[str, ...] = ()
    uuid: str = ""
    code_signature: bool = False
    overlay: int = 0
    fat_arches: tuple[MachoArch, ...] = ()
    error: str = ""


def parse_macho(data: bytes) -> MachoInfo:
    """Parse a thin or fat Mach-O with bounded command walking."""
    if len(data) < 4:
        return MachoInfo(valid=False, error="Datei zu kurz")
    magic = data[:4]
    if magic in _MAGIC_FAT:
        return _parse_fat(data, _MAGIC_FAT[magic])
    return _parse_thin(data, 0, len(data))


def _parse_fat(data: bytes, little: bool) -> MachoInfo:
    endian = "<" if little else ">"
    if len(data) < 8:
        return MachoInfo(valid=False, error="Fat-Header abgeschnitten")
    nfat = struct.unpack_from(endian + "I", data, 4)[0]
    if nfat == 0 or nfat > 32 or 8 + nfat * 20 > len(data):
        return MachoInfo(valid=False, error="ungültige Fat-Arch-Anzahl")
    arches = []
    for index in range(nfat):
        offset, size = struct.unpack_from(
            endian + "II", data, 8 + index * 20 + 8
        )
        cputype, cpusubtype = struct.unpack_from(
            endian + "II", data, 8 + index * 20
        )
        arches.append(MachoArch(int(cputype), int(cpusubtype), int(offset), int(size)))
    first = arches[0]
    if first.offset + first.size > len(data):
        return MachoInfo(
            valid=False, fat_arches=tuple(arches),
            error="Fat-Arch zeigt über das Dateiende",
        )
    info = _parse_thin(data, first.offset, first.offset + first.size)
    return MachoInfo(
        valid=info.valid,
        bits=info.bits,
        endian=info.endian,
        filetype=info.filetype,
        cputype=info.cputype,
        ncmds=info.ncmds,
        segments=info.segments,
        dylibs=info.dylibs,
        uuid=info.uuid,
        code_signature=info.code_signature,
        overlay=info.overlay,
        fat_arches=tuple(arches),
        error=info.error,
    )


def _parse_thin(data: bytes, start: int, limit: int) -> MachoInfo:
    magic = data[start : start + 4]
    if magic not in _MAGIC_THIN:
        return MachoInfo(valid=False, error="kein Mach-O-Magic")
    little, bits = _MAGIC_THIN[magic]
    endian = "<" if little else ">"
    header_size = 32 if bits == 64 else 28
    if start + header_size > limit:
        return MachoInfo(
            valid=False, bits=bits,
            endian="little" if little else "big",
            error="Mach-O-Header abgeschnitten",
        )
    cputype, _cpusubtype, filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(
        endian + "IIIIII", data, start + 4
    )
    commands_end = min(start + header_size + int(sizeofcmds), limit)
    pos = start + header_size
    segments: list[MachoSegment] = []
    dylibs: list[str] = []
    uuid = ""
    code_signature = False
    error = ""
    declared_commands = int(ncmds)
    count = min(declared_commands, _MAX_COMMANDS)
    if declared_commands > _MAX_COMMANDS:
        # BUG-032: a silently trimmed table makes NX/WX/overlay statements
        # look complete. The caller turns this into MACHO_STRUCTURE_WARN.
        error = (
            f"Load-Command-Tabelle gekürzt "
            f"({_MAX_COMMANDS} von {declared_commands})"
        )
    for _index in range(count):
        if pos + 8 > commands_end:
            error = "Load-Command-Tabelle abgeschnitten"
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, pos)
        if cmdsize < 8 or pos + cmdsize > commands_end:
            error = "ungültige Load-Command-Größe"
            break
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            expected = 56 if cmd == LC_SEGMENT else 72
            if cmdsize >= expected:
                name_raw = data[pos + 8 : pos + 24]
                name = name_raw.split(b"\x00", 1)[0].decode("latin-1", "replace")[:32]
                if cmd == LC_SEGMENT:
                    fileoff, filesize, initprot, nsects = struct.unpack_from(
                        endian + "IIII", data, pos + 32
                    )
                else:
                    fileoff, filesize, initprot, nsects = struct.unpack_from(
                        endian + "QQII", data, pos + 40
                    )
                segments.append(
                    MachoSegment(
                        name=name, fileoff=int(fileoff), filesize=int(filesize),
                        initprot=int(initprot), nsects=int(nsects),
                    )
                )
        elif cmd == LC_LOAD_DYLIB:
            if cmdsize >= 12:
                name_off = struct.unpack_from(endian + "I", data, pos + 8)[0]
                if 8 <= name_off < cmdsize:
                    raw = data[pos + name_off : pos + cmdsize]
                    dylibs.append(
                        raw.split(b"\x00", 1)[0].decode("latin-1", "replace")[
                            :_MAX_DYLIB_NAME
                        ]
                    )
        elif cmd == LC_UUID and cmdsize >= 24:
            uuid = data[pos + 8 : pos + 24].hex()
        elif cmd == LC_CODE_SIGNATURE:
            code_signature = True
        pos += cmdsize

    ends = [
        segment.fileoff + segment.filesize
        for segment in segments
        if segment.filesize > 0
    ]
    overlay = max(0, (limit - start) - max(ends)) if ends else 0
    return MachoInfo(
        valid=True,
        bits=bits,
        endian="little" if little else "big",
        filetype=int(filetype),
        cputype=int(cputype),
        ncmds=int(ncmds),
        segments=tuple(segments),
        dylibs=tuple(dylibs),
        uuid=uuid,
        code_signature=code_signature,
        overlay=overlay,
        error=error,
    )
