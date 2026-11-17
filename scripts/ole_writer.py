"""Minimal OLE2 / Compound File Binary (CFB) writer — test fixtures only.

Why this exists: ``olefile`` (and every other library available offline) can
only *read* OLE2 containers. To exercise the real VBA path of the Office
pipeline, the test corpus needs a genuine CFB whose ``VBA/dir`` module stream is
compressed per MS-OVBA. Without this writer the corpus could only test the
text fallback — which is not what a real .doc hits.

Scope: exactly what the fixtures need.
  * one FAT sector chain per stream, sized 4096 bytes (>= the mini-stream
    cutoff, so everything lives in the main FAT and no mini-FAT is required),
  * a two-level directory tree with the storages VBA is expected in,
  * MS-OVBA 2.4.1.3.6 compression for module streams.

Not a general-purpose writer: no mini streams, no DIFAT extension, no
red-black rebalancing. The output is validated against ``olefile`` in
``tests/test_corpus_extended.py``, which is the contract that matters — if
olefile can read it, oletools can too.

Reference: MS-CFB (compound file binary format), MS-OVBA (VBA compression).
"""

from __future__ import annotations

import struct

SECTOR_SIZE = 512
_MINI_CUTOFF = 4096  # streams >= this live in the main FAT (no mini stream)

_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF

_DIR_ENTRY_SIZE = 128
_STGTY_STORAGE = 1
_STGTY_STREAM = 2
_STGTY_ROOT = 5


# -- MS-OVBA compression (2.4.1.3.6) ---------------------------------------- #


def compress_vba(data: bytes) -> bytes:
    """Wrap ``data`` as an MS-OVBA CompressedContainer (uncompressed chunks).

    MS-OVBA 2.4.1.3.3 describes a *RawChunk*: exactly 4096 payload bytes
    behind a 2-byte header whose flag bit (15) is 0 and whose size field is
    fixed at 4098. Declaring raw chunks keeps the writer trivial and correct —
    and ``decompress_stream`` copies them verbatim, so the analyser sees the
    exact source we put in. Real compression would test our encoder, not the
    pipeline.
    """
    out = bytearray([0x01])  # CompressedContainer signature
    for pos in range(0, len(data), 4096):
        chunk = data[pos : pos + 4096]
        # Header: size field 0x0FFF + 3 = 4098, signature bits 0b011 (0x3000),
        # flag bit 15 cleared -> raw chunk.
        out += struct.pack("<H", 0x3000 | 0x0FFF)
        out += chunk
        out += b"\x00" * (4096 - len(chunk))  # raw chunks are always 4096 bytes
    return bytes(out)


# -- CFB directory helper ---------------------------------------------------- #


class _Entry:
    __slots__ = ("child", "data", "etype", "index", "left", "name", "right", "size", "start")

    def __init__(self, name: str, etype: int, data: bytes = b"") -> None:
        self.name = name
        self.etype = etype
        self.data = data
        self.child = _NOSTREAM
        self.left = _NOSTREAM
        self.right = _NOSTREAM
        self.start = _ENDOFCHAIN
        self.size = 0
        self.index = -1


def _dir_entry_bytes(entry: _Entry) -> bytes:
    name_utf16 = entry.name.encode("utf-16-le") + b"\x00\x00"
    name_len = len(name_utf16)
    raw = bytearray(_DIR_ENTRY_SIZE)
    raw[0:name_len] = name_utf16
    struct.pack_into("<H", raw, 64, name_len)
    raw[66] = entry.etype
    raw[67] = 1  # color: black
    struct.pack_into("<I", raw, 68, entry.left)
    struct.pack_into("<I", raw, 72, entry.right)
    struct.pack_into("<I", raw, 76, entry.child)
    # CLSID (16) zero, state bits (4) zero, timestamps (16) zero
    struct.pack_into("<I", raw, 116, entry.start)
    struct.pack_into("<Q", raw, 120, entry.size)
    return bytes(raw)


def write_ole(streams: dict[str, bytes], root_name: str = "Root Entry") -> bytes:
    """Build a CFB containing ``streams`` (paths like ``"VBA/Module1"``).

    Storages are created implicitly for every path component. All streams are
    padded to at least ``_MINI_CUTOFF`` so they are stored in the main FAT.
    """
    # 1. Flatten the path tree into directory entries.
    entries: dict[str, _Entry] = {}
    root = _Entry(root_name, _STGTY_ROOT)
    entries[""] = root
    ordered: list[_Entry] = [root]

    # Create every storage mentioned by a path prefix, then the streams.
    for path in sorted(streams):
        parent_path, _, _name = path.rpartition("/")
        while parent_path and parent_path not in entries:
            grandparent, _, part = parent_path.rpartition("/")
            entries[parent_path] = _Entry(part, _STGTY_STORAGE)
            ordered.append(entries[parent_path])
            parent_path = grandparent

    for path, data in sorted(streams.items()):
        _parent_path, _, name = path.rpartition("/")
        stream = _Entry(name, _STGTY_STREAM, data)
        stream.size = len(data)
        entries[path] = stream
        ordered.append(stream)

    for i, entry in enumerate(ordered):
        entry.index = i

    # 2. Link each entry into its parent's child chain (a plain linked list:
    #    readers require a consistent structure, not a balanced tree).
    for path in sorted(p for p in entries if p):
        parent_path, _, _ = path.rpartition("/")
        parent = entries[parent_path]
        entry = entries[path]
        if parent.child == _NOSTREAM:
            parent.child = entry.index
        else:
            sibling_index = parent.child
            while ordered[sibling_index].right != _NOSTREAM:
                sibling_index = ordered[sibling_index].right
            ordered[sibling_index].right = entry.index

    # 3. Lay out the data sectors.
    #
    # Small streams (< the mini-stream cutoff) live in the *mini stream*, a
    # single ordinary stream owned by the root entry and addressed in 64-byte
    # mini sectors via the mini FAT. olefile picks the storage by comparing the
    # entry's DECLARED size against the cutoff, so padding a small stream and
    # storing it in the main FAT does not work — the mini path is mandatory.
    sectors: list[bytes] = []
    fat: list[int] = []
    mini_sectors: list[bytes] = []
    minifat: list[int] = []

    def add_chain(payload: bytes) -> int:
        """Append ``payload`` in 512-byte sectors; returns the first sector id."""
        padded = payload + b"\x00" * ((-len(payload)) % SECTOR_SIZE)
        n = max(len(padded) // SECTOR_SIZE, 1)
        first = len(sectors)
        for i in range(n):
            sectors.append(padded[i * SECTOR_SIZE : (i + 1) * SECTOR_SIZE])
            fat.append(first + i + 1 if i + 1 < n else _ENDOFCHAIN)
        return first

    def add_mini_chain(payload: bytes) -> int:
        """Append ``payload`` in 64-byte mini sectors; returns the first id."""
        padded = payload + b"\x00" * ((-len(payload)) % 64)
        n = max(len(padded) // 64, 1)
        first = len(mini_sectors)
        for i in range(n):
            mini_sectors.append(padded[i * 64 : (i + 1) * 64])
            minifat.append(first + i + 1 if i + 1 < n else _ENDOFCHAIN)
        return first

    small: list[_Entry] = []
    for entry in ordered:
        if entry.etype != _STGTY_STREAM:
            continue
        if len(entry.data) < _MINI_CUTOFF:
            small.append(entry)
        else:
            entry.start = add_chain(entry.data)

    # The mini stream itself: concatenated mini sectors, stored in the main FAT
    # and owned by the root entry (which must point at it).
    if small:
        for entry in small:
            entry.start = add_mini_chain(entry.data)
        mini_stream = b"".join(mini_sectors)
        root.start = add_chain(mini_stream)
        root.size = len(mini_stream)
        mini_fat_data = struct.pack(
            "<" + "I" * len(minifat), *minifat
        ) + struct.pack("<I", _FREESECT) * (SECTOR_SIZE // 4 - len(minifat))
        minifat_first = add_chain(mini_fat_data)
    else:
        minifat_first = _ENDOFCHAIN

    # Directory sectors (each holds 4 entries = 512/128).
    per_sector = SECTOR_SIZE // _DIR_ENTRY_SIZE
    dir_count = max((len(ordered) + per_sector - 1) // per_sector, 1)
    dir_first = len(sectors)
    for i in range(dir_count):
        block = bytearray()
        for j in range(per_sector):
            idx = i * per_sector + j
            if idx < len(ordered):
                block += _dir_entry_bytes(ordered[idx])
            else:
                block += _dir_entry_bytes(_Entry("", 0))
        sectors.append(bytes(block))
        fat.append(dir_first + i + 1 if i + 1 < dir_count else _ENDOFCHAIN)

    # 4. Header + FAT sector.
    total_sectors = len(sectors) + 1  # + the FAT sector itself
    fat.append(_FATSECT)
    fat += [_FREESECT] * (SECTOR_SIZE // 4 - len(fat))

    header = bytearray(SECTOR_SIZE)
    header[0:8] = _MAGIC
    struct.pack_into("<H", header, 24, 0x003E)   # minor version
    struct.pack_into("<H", header, 26, 0x0003)   # major version
    struct.pack_into("<H", header, 28, 0xFFFE)   # little endian
    struct.pack_into("<H", header, 30, 9)        # 512-byte sectors
    struct.pack_into("<H", header, 32, 6)        # 64-byte mini sectors
    struct.pack_into("<I", header, 44, 1)        # one FAT sector
    struct.pack_into("<I", header, 48, dir_first)
    struct.pack_into("<I", header, 56, _MINI_CUTOFF)
    struct.pack_into("<I", header, 60, minifat_first)
    # num_mini_fat_sectors counts 512-byte SECTORS, not entries. The mini FAT
    # always occupies at least one sector once it exists.
    struct.pack_into("<I", header, 64, 1 if minifat else 0)
    struct.pack_into("<I", header, 68, _ENDOFCHAIN)  # no DIFAT extension
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<I", header, 76, total_sectors - 1)  # DIFAT[0] -> FAT
    for i in range(1, 109):
        struct.pack_into("<I", header, 76 + i * 4, _FREESECT)

    body = b"".join(sectors) + struct.pack("<" + "I" * (SECTOR_SIZE // 4), *fat)
    return bytes(header) + body


def _dir_stream(module_name: str, module_text_offset: int = 0) -> bytes:
    """Build the uncompressed ``VBA/dir`` stream for one procedural module.

    Record layout per MS-OVBA 2.3.4.2: the fixed project records (SYSKIND,
    LCID, LCIDINVOKE, CODEPAGE, PROJECTNAME…), then PROJECTMODULES with the
    module count, then one module record carrying the name and the
    MODULEOFFSET — the byte offset of the compressed source inside the module
    stream. ``oletools`` validates each ID and size, so the order and the
    constants matter.
    """
    import struct as _struct

    d = bytearray()

    def rec(rec_id: int, payload: bytes) -> None:
        d.extend(_struct.pack("<H", rec_id))
        d.extend(_struct.pack("<I", len(payload)))
        d.extend(payload)

    rec(0x0001, _struct.pack("<I", 0x01))            # PROJECTSYSKIND: 32-bit
    rec(0x0002, _struct.pack("<I", 0x0409))          # PROJECTLCID: en-US
    rec(0x0014, _struct.pack("<I", 0x0409))          # PROJECTLCIDINVOKE
    rec(0x0003, _struct.pack("<H", 1252))            # PROJECTCODEPAGE
    rec(0x0004, module_name.encode("latin-1"))       # PROJECTNAME
    # PROJECTDOCSTRING: id, ANSI size+text, reserved marker 0x0040, then the
    # UTF-16 size+text (the parser validates the reserved value).
    doc = b""
    d.extend(_struct.pack("<H", 0x0005))
    d.extend(_struct.pack("<I", len(doc)))           # SizeOfDocString (ANSI)
    d.extend(doc)
    d.extend(_struct.pack("<H", 0x0040))             # mandated reserved marker
    d.extend(_struct.pack("<I", len(doc) * 2))       # SizeOfDocStringUnicode
    # PROJECTHELPFILEPATH: HelpFile1, reserved 0x003D, HelpFile2 (identical).
    d.extend(_struct.pack("<H", 0x0006))
    d.extend(_struct.pack("<I", 0))
    d.extend(_struct.pack("<H", 0x003D))             # mandated reserved marker
    d.extend(_struct.pack("<I", 0))
    rec(0x0007, _struct.pack("<I", 0))               # PROJECTHELPCONTEXT
    rec(0x0008, _struct.pack("<I", 0))               # PROJECTLIBFLAGS
    # PROJECTVERSION: reserved 0x0004, MajorVersion, MinorVersion.
    d.extend(_struct.pack("<H", 0x0009))
    d.extend(_struct.pack("<I", 0x0004))
    d.extend(_struct.pack("<I", 1))                  # MajorVersion
    d.extend(_struct.pack("<H", 0))                  # MinorVersion
    # PROJECTCONSTANTS: ANSI size+text, reserved 0x003C, UTF-16 size+text.
    # MS-OVBA 2.3.4.3 mandates 0x003C (the 0x003D marker belongs to
    # PROJECTHELPFILEPATH above).
    d.extend(_struct.pack("<H", 0x000C))
    d.extend(_struct.pack("<I", 0))
    d.extend(_struct.pack("<H", 0x003C))             # mandated reserved marker
    d.extend(_struct.pack("<I", 0))

    # PROJECTMODULES: count + cookie, then the module records themselves.
    modules = bytearray()
    modules.extend(_struct.pack("<H", 1))            # module count
    modules.extend(_struct.pack("<H", 0x0013))       # PROJECTCOOKIE id
    modules.extend(_struct.pack("<I", 0x0002))
    modules.extend(_struct.pack("<H", 0xFFFF))       # cookie

    m = bytearray()
    # MS-OVBA 2.3.4.2.3.2: MODULENAME and MODULESTREAMNAME are MBCS (the
    # project code page is 1252 here); the matching *_UNICODE fields are
    # UTF-16. The size fields therefore count BYTES of the encoded names,
    # not Python characters (BUG-100).
    name_ansi = module_name.encode("cp1252", errors="replace")
    name_utf16 = module_name.encode("utf-16-le")

    def mrec(rec_id: int, payload: bytes) -> None:
        m.extend(_struct.pack("<H", rec_id))
        m.extend(_struct.pack("<I", len(payload)))
        m.extend(payload)

    mrec(0x0019, name_ansi)                          # MODULENAME (MBCS)
    mrec(0x0047, name_utf16)                         # MODULENAMEUNICODE
    # MODULESTREAMNAME: SizeOfModuleStreamName counts ONLY the ANSI name;
    # Reserved 0x0032 and the unicode size/name follow outside that length
    # (MS-OVBA 2.3.4.2.3.2.3). A generic payload-length prefix made oletools
    # consume the reserved marker as part of the name.
    m.extend(_struct.pack("<HI", 0x001A, len(name_ansi)))
    m.extend(name_ansi)
    m.extend(_struct.pack("<H", 0x0032))
    m.extend(_struct.pack("<I", len(name_utf16)))
    m.extend(name_utf16)
    # MODULEDOCSTRING: SizeOfDocString counts only the ANSI text (empty),
    # then reserved 0x0048 and the empty unicode text follow.
    m.extend(_struct.pack("<HI", 0x001C, 0))
    m.extend(_struct.pack("<H", 0x0048))
    m.extend(_struct.pack("<I", 0))
    mrec(0x0031, _struct.pack("<I", module_text_offset))  # MODULEOFFSET
    mrec(0x001E, _struct.pack("<I", 0))              # MODULEHELPCONTEXT
    mrec(0x002C, _struct.pack("<H", 0xFFFF))         # MODULECOOKIE
    # MODULETYPE and MODULETERMINATOR carry four reserved bytes, not a
    # length-prefixed payload.
    m.extend(_struct.pack("<HI", 0x0021, 0))         # MODULETYPE: procedural
    m.extend(_struct.pack("<HI", 0x002B, 0))         # MODULETERMINATOR

    modules.extend(m)
    d.extend(_struct.pack("<H", 0x000F))             # PROJECTMODULES id
    d.extend(_struct.pack("<I", 0x0002))             # size (reserved constant)
    d.extend(modules)
    # Trailing strings block (ignored by the parser).
    d.extend(_struct.pack("<H", 0x0010))
    d.extend(_struct.pack("<I", 0))
    return bytes(d)


def make_vba_doc(module_source: str, module_name: str = "Module1") -> bytes:
    """A Word-97-shaped CFB carrying one VBA module (the analyser's target).

    Layout required by oletools: the root storage holds ``PROJECT``, and its
    ``VBA`` storage holds ``_VBA_PROJECT``, ``dir`` and the module stream. The
    ``dir`` stream is itself MS-OVBA compressed (the parser decompresses it
    before reading the records), which is easy to miss.
    """
    source = module_source.encode("latin-1")
    project = (
        'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
        "Document=ThisDocument/&H00000000\r\n"
        f"Module={module_name}\r\n"
        'Name="VBAProject"\r\n'
        'HelpContextID="0"\r\n'
        'VersionCompatible32="393222000"\r\n'
        "\r\n"
        "[Host Extender Info]\r\n"
        "[Workspace]\r\n"
    ).encode("latin-1")
    return write_ole(
        {
            # The dir stream itself is a CompressedContainer (parser detail).
            "Macros/VBA/dir": compress_vba(_dir_stream(module_name)),
            "Macros/VBA/_VBA_PROJECT": b"\xcc\x61" + b"\x00" * 30,
            "Macros/VBA/" + module_name: compress_vba(source),
            "Macros/PROJECT": project,
            "WordDocument": b"\xec\xa5" + b"\x00" * 1020,
        }
    )
