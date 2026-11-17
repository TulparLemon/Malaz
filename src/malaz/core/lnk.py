"""Minimal Windows Shell Link (.lnk / MS-SHLLINK) parser.

Extracts the human-relevant strings (target, relative path, working directory,
command-line arguments, icon location) and the set LinkFlags. This is enough to
surface the classic LNK abuse pattern (a shortcut whose target/arguments launch
a script or LOLBin) without pulling in a heavy dependency. The parser is
defensive: any structural problem yields whatever was collected so far.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_LNK_MAGIC = b"\x4c\x00\x00\x00"
_LNK_CLSID = (
    b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
)

_FLAG_NAMES = {
    0: "HasLinkTargetIDList",
    1: "HasLinkInfo",
    2: "HasName",
    3: "HasRelativePath",
    4: "HasWorkingDir",
    5: "HasArguments",
    6: "HasIconLocation",
    7: "IsUnicode",
}


@dataclass
class LnkInfo:
    valid: bool = False
    flags: int = 0
    flag_names: list[str] = field(default_factory=list)
    description: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""

    @property
    def has_arguments(self) -> bool:
        return bool(self.arguments)

    def interesting_strings(self) -> list[str]:
        out = []
        for label, value in (
            ("Ziel/Relativpfad", self.relative_path),
            ("Arbeitsverzeichnis", self.working_dir),
            ("Argumente", self.arguments),
            ("Icon", self.icon_location),
            ("Beschreibung", self.description),
        ):
            if value:
                out.append(f"{label}: {value}")
        return out


def _read_string(data: bytes, pos: int, unicode: bool) -> tuple[str, int]:
    """Read one prefixed string; on truncation, stop at the buffer end.

    Returning ``len(data)`` as the position (instead of a mid-buffer offset)
    makes all FOLLOW-UP string reads empty — a truncated LNK must never be
    parsed from shifted offsets, that would produce garbage strings.
    """
    if pos + 2 > len(data):
        return "", len(data)
    count = int.from_bytes(data[pos : pos + 2], "little")
    pos += 2
    if unicode:
        nbytes = count * 2
        if pos + nbytes > len(data):
            return "", len(data)
        text = data[pos : pos + nbytes].decode("utf-16-le", errors="replace")
    else:
        if pos + count > len(data):
            return "", len(data)
        text = data[pos : pos + count].decode("cp1252", errors="replace")
    pos += nbytes if unicode else count
    return text, min(pos, len(data))


def parse_lnk(data: bytes) -> LnkInfo:
    """Parse a .lnk blob. Returns an (possibly empty) :class:`LnkInfo`."""
    info = LnkInfo()
    if len(data) < 76 or data[:4] != _LNK_MAGIC or data[4:20] != _LNK_CLSID:
        return info
    info.valid = True
    info.flags = int.from_bytes(data[20:24], "little")
    info.flag_names = [name for bit, name in _FLAG_NAMES.items() if info.flags & (1 << bit)]

    unicode = bool(info.flags & (1 << 7))
    pos = 76  # end of fixed header

    # Optional LinkTargetIDList: 2-byte size prefix, then that many bytes.
    # Clamp every skip to the buffer end so a lying size field cannot push
    # subsequent reads past the data.
    if (info.flags & (1 << 0)) and pos + 2 <= len(data):
        size = int.from_bytes(data[pos : pos + 2], "little")
        pos = min(pos + 2 + size, len(data))

    # Optional LinkInfo: 4-byte size prefix, then that many bytes (inclusive).
    if (info.flags & (1 << 1)) and pos + 4 <= len(data):
        size = int.from_bytes(data[pos : pos + 4], "little")
        pos = min(pos + size, len(data))

    # StringData in the documented order, gated by their flags.
    order = (
        ("description", 2),
        ("relative_path", 3),
        ("working_dir", 4),
        ("arguments", 5),
        ("icon_location", 6),
    )
    for attr, bit in order:
        if info.flags & (1 << bit):
            text, pos = _read_string(data, pos, unicode)
            setattr(info, attr, text)
    return info
