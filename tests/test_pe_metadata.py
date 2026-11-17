"""AP10: PE metadata depth (resources, manifest, version, exports, delay, .NET, Rich, RWX)."""

from __future__ import annotations

import struct
from pathlib import Path

from malaz.models import AnalysisContext
from malaz.pipelines.pe_pipeline import PePipeline


def _align(value: int, alignment: int = 0x200) -> int:
    return (value + alignment - 1) // alignment * alignment


def _build_pe(
    sections: list[tuple[bytes, int, int, bytes]],
    directories: dict[int, tuple[int, int]] | None = None,
    *,
    pe_offset: int = 0x40,
    dll_chars: int = 0x0140,
    rich_key: int = 0,
) -> bytes:
    """Minimal PE32+ builder. Sections are ``(data, rva, characteristics, name)``."""
    dos = bytearray(pe_offset)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)
    if rich_key:
        block = (
            struct.pack("<I", 0x536E6144 ^ rich_key)
            + struct.pack("<III", rich_key, rich_key, rich_key)
            + struct.pack("<II", 0x00010001 ^ rich_key, 3 ^ rich_key)
            + struct.pack("<II", 0x00010002 ^ rich_key, 1 ^ rich_key)
            + b"Rich"
            + struct.pack("<I", rich_key)
        )
        dos[0x80 : 0x80 + len(block)] = block

    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 0x00F0, 0x0022)
    dirs = bytearray(16 * 8)
    for index, (rva, size) in (directories or {}).items():
        dirs[index * 8 : index * 8 + 8] = struct.pack("<II", rva, size)
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
    table_size = 40 * len(sections)
    headers_end = _align(pe_offset + 4 + 20 + len(opt) + table_size)
    table = b""
    raw_ptr = headers_end
    payload = b""
    for data, rva, characteristics, name in sections:
        raw_size = _align(len(data))
        table += (
            name.ljust(8, b"\x00")
            + struct.pack(
                "<IIIIIIHHI",
                len(data),
                rva,
                raw_size,
                raw_ptr,
                0,
                0,
                0,
                0,
                characteristics,
            )
        )
        payload += data.ljust(raw_size, b"\x00")
        raw_ptr += raw_size
    return (
        bytes(dos)
        + b"PE\x00\x00"
        + coff
        + opt
        + table
        + b"\x00" * (headers_end - (pe_offset + 4 + 20 + len(opt) + table_size))
        + payload
    )


def _ctx(data: bytes, name: str = "fixture.exe") -> AnalysisContext:
    return AnalysisContext(
        path=Path(name), data=data, detected_type="pe", size=len(data), depth=0
    )


def _wstr(value: str) -> bytes:
    return value.encode("utf-16-le") + b"\x00\x00"


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _version_block(key: str, value: bytes, value_len: int, wtype: int = 1) -> bytes:
    key_bytes = _wstr(key)
    body = _pad4(struct.pack("<HHH", 0, value_len, wtype) + key_bytes) + value
    body = _pad4(body)
    return struct.pack("<H", len(body)) + body[2:]


def _version_blob(strings: dict[str, str]) -> bytes:
    fixed = struct.pack(
        "<IIIIIIIIIIIII",
        0xFEEF04BD,
        0x00010000,
        0x00010000,
        0x00010000,
        0x00010000,
        0x00010000,
        0x00010000,
        0,
        0x3F,
        0,
        0x40004,
        1,
        0,
    )
    entries = b"".join(
        _version_block(key, _wstr(value), len(value) + 1)
        for key, value in strings.items()
    )
    table = _version_block("040904B0", entries, 0)
    string_file_info = _version_block("StringFileInfo", table, 0)
    root = _pad4(struct.pack("<HHH", 0, 52, 0) + _wstr("VS_VERSION_INFO")) + fixed
    root = _pad4(root) + string_file_info
    return struct.pack("<H", len(root)) + root[2:]


def _resource_section(payloads: dict[int, bytes]) -> bytes:
    root_entries = len(payloads)
    offset = 16 + 8 * root_entries
    type_offsets = {}
    for type_id in payloads:
        type_offsets[type_id] = offset
        offset += 24
    lang_offsets = {}
    for type_id in payloads:
        lang_offsets[type_id] = offset
        offset += 24
    data_entry_offsets = {}
    for type_id in payloads:
        data_entry_offsets[type_id] = offset
        offset += 16
    blob_offsets = {}
    for type_id, blob in payloads.items():
        offset = (offset + 7) // 8 * 8
        blob_offsets[type_id] = offset
        offset += len(blob)

    data = bytearray(max(offset, 0x200))
    struct.pack_into("<IIHHHH", data, 0, 0, 0, 0, 0, 0, root_entries)
    for index, type_id in enumerate(payloads):
        struct.pack_into("<II", data, 16 + 8 * index, type_id, 0x80000000 | type_offsets[type_id])
    for type_id in payloads:
        base = type_offsets[type_id]
        struct.pack_into("<IIHHHH", data, base, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", data, base + 16, 1, 0x80000000 | lang_offsets[type_id])
        lang = lang_offsets[type_id]
        struct.pack_into("<IIHHHH", data, lang, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", data, lang + 16, 0x0409, data_entry_offsets[type_id])
        struct.pack_into(
            "<IIII",
            data,
            data_entry_offsets[type_id],
            0x2000 + blob_offsets[type_id],
            len(payloads[type_id]),
            0,
            0,
        )
        data[
            blob_offsets[type_id] : blob_offsets[type_id] + len(payloads[type_id])
        ] = payloads[type_id]
    return bytes(data)


def _resource_pe(manifest: bytes | None, version: bytes | None) -> bytes:
    payloads = {}
    if manifest is not None:
        payloads[24] = manifest
    if version is not None:
        payloads[16] = version
    return _build_pe(
        [
            (bytes(range(256)), 0x1000, 0x60000020, b".text"),
            (_resource_section(payloads), 0x2000, 0x40000040, b".rsrc"),
        ],
        {2: (0x2000, 0x800)},
    )


def _manifest(level: str = "requireAdministrator", ui: str = "true", auto: bool = True) -> bytes:
    return (
        '<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
        "<trustInfo><security><requestedPrivileges>"
        f'<requestedExecutionLevel level="{level}" uiAccess="{ui}"/>'
        "</requestedPrivileges></security></trustInfo>"
        + ("<autoElevate>true</autoElevate>" if auto else "")
        + "</assembly>"
    ).encode()


def _export_pe() -> bytes:
    rdata = bytearray(0x200)
    struct.pack_into(
        "<IIHHIIIIIII",
        rdata,
        0,
        0,
        0,
        0,
        0,
        0x2100,
        1,
        1,
        1,
        0x2040,
        0x2048,
        0x204C,
    )
    struct.pack_into("<I", rdata, 0x40, 0x2100)
    struct.pack_into("<I", rdata, 0x48, 0x2120)
    struct.pack_into("<H", rdata, 0x4C, 0)
    rdata[0x100 : 0x100 + 12] = b"fixture.dll\x00"
    rdata[0x120 : 0x120 + 9] = b"Exported\x00"
    return _build_pe(
        [
            (bytes(range(256)), 0x1000, 0x60000020, b".text"),
            (bytes(rdata), 0x2000, 0x40000040, b".rdata"),
        ],
        {0: (0x2000, 0x40)},
    )


def _delay_pe() -> bytes:
    rdata = bytearray(0x200)
    struct.pack_into(
        "<IIIIIIII",
        rdata,
        0,
        1,
        0x2080,
        0,
        0x20A0,
        0x20C0,
        0,
        0,
        0,
    )
    rdata[0x80:0x80 + 13] = b"KERNEL32.dll\x00"
    struct.pack_into("<QQQ", rdata, 0xA0, 0x20E0, 0x2100, 0)
    struct.pack_into("<QQQ", rdata, 0xC0, 0x20E0, 0x2100, 0)
    struct.pack_into("<H", rdata, 0xE0, 0)
    rdata[0xE2:0xE2 + 19] = b"URLDownloadToFileW\x00"
    struct.pack_into("<H", rdata, 0x100, 0)
    rdata[0x102:0x102 + 8] = b"WinExec\x00"
    return _build_pe(
        [
            (bytes(range(256)), 0x1000, 0x60000020, b".text"),
            (bytes(rdata), 0x2000, 0x40000040, b".rdata"),
        ],
        {13: (0x2000, 0x40)},
    )


def _dotnet_pe() -> bytes:
    header = struct.pack("<IHHIIII", 0x48, 2, 5, 0, 0, 1, 0) + b"\x00" * 24
    return _build_pe(
        [(header, 0x2000, 0x40000040, b".text")],
        {14: (0x2000, len(header))},
    )


def test_resources_manifest_and_version_are_reported():
    data = _resource_pe(
        _manifest(),
        _version_blob(
            {
                "CompanyName": "Malaz Fixture GmbH",
                "ProductName": "Malaz Test",
                "OriginalFilename": "fixture.exe",
            }
        ),
    )
    inds = {i.rule_id: i for i in PePipeline().analyze(_ctx(data))}
    assert "PE_RESOURCES" in inds
    assert "1033" in inds["PE_RESOURCES"].detail
    assert "24 (1)" in inds["PE_RESOURCES"].detail
    manifest = inds["PE_MANIFEST"]
    assert "requireAdministrator" in manifest.detail
    assert "uiAccess=true" in manifest.detail
    assert "autoElevate=true" in manifest.detail
    version = inds["PE_VERSION_INFO"]
    assert "CompanyName=Malaz Fixture GmbH" in version.detail
    assert "OriginalFilename=fixture.exe" in version.detail
    assert manifest.weight == version.weight == 0


def test_benign_manifest_is_a_note_not_a_verdict():
    data = _resource_pe(_manifest("asInvoker", "false", False), None)
    inds = {i.rule_id: i for i in PePipeline().analyze(_ctx(data))}
    assert inds["PE_MANIFEST"].weight == 0
    assert "requireAdministrator" not in inds["PE_MANIFEST"].detail


def test_exports_are_reported_without_score():
    inds = {i.rule_id: i for i in PePipeline().analyze(_ctx(_export_pe()))}
    assert "PE_EXPORTS" in inds
    assert "Exported" in inds["PE_EXPORTS"].detail
    assert inds["PE_EXPORTS"].weight == 0


def test_delay_imports_feed_the_import_matcher_once():
    inds = list(PePipeline().analyze(_ctx(_delay_pe())))
    by_id = {i.rule_id: i for i in inds}
    assert "PE_DELAY_IMPORTS" in by_id
    assert "KERNEL32.dll" in by_id["PE_DELAY_IMPORTS"].detail
    # Delay imports are still imports: they must feed the same pattern
    # matcher (download + execute), not a second family of PE_IMPORT_* rows.
    patterns = [i for i in inds if i.rule_id == "PE_IMPORT_DOWNLOAD_EXEC"]
    assert len(patterns) == 1, "Delay-Importe wurden nicht in die Heuristik übernommen"
    assert "PE_NO_IMPORTS" not in by_id
    assert by_id["PE_DELAY_IMPORTS"].weight == 0


def test_dotnet_header_is_reported():
    inds = {i.rule_id: i for i in PePipeline().analyze(_ctx(_dotnet_pe()))}
    assert "PE_DOTNET" in inds
    assert "2.5" in inds["PE_DOTNET"].detail
    assert inds["PE_DOTNET"].weight == 0


def test_rich_header_is_decoded():
    data = _build_pe(
        [(bytes(range(256)), 0x1000, 0x60000020, b".text")],
        pe_offset=0x100,
        rich_key=0x12345678,
    )
    inds = {i.rule_id: i for i in PePipeline().analyze(_ctx(data))}
    assert "PE_RICH_HEADER" in inds
    assert "0x12345678" in inds["PE_RICH_HEADER"].detail
    assert inds["PE_RICH_HEADER"].weight == 0


def test_rwx_section_is_reported():
    data = _build_pe(
        [(bytes(range(256)), 0x1000, 0xE0000020, b".rwx")]
    )
    inds = {i.rule_id: i for i in PePipeline().analyze(_ctx(data))}
    assert "PE_RWX_SECTION" in inds
    assert ".rwx" in inds["PE_RWX_SECTION"].detail
    assert inds["PE_RWX_SECTION"].weight == 0
