"""Tests for the PE analysis pipeline (pefile, Authenticode, DIE)."""

import struct
from pathlib import Path
from unittest import mock

import pytest

from malaz.analysis.die import _parse_die_output
from malaz.models import AnalysisContext
from malaz.pipelines.pe_pipeline import (
    PePipeline,
    match_import_patterns,
)


def _ctx(data: bytes, name="a.exe", ftype="pe", depth=0) -> AnalysisContext:
    return AnalysisContext(
        path=Path(name), data=data, detected_type=ftype, size=len(data), depth=depth
    )


def _opt_header(dll_chars: int = 0) -> bytes:
    """A well-formed PE32+ optional header (240 bytes + 16 data dirs)."""
    return struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,          # Magic: PE32+
        0, 0,           # linker versions
        0x1000,         # SizeOfCode
        0x200,          # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        0x1000,         # AddressOfEntryPoint
        0x1000,         # BaseOfCode
        0x140000000,    # ImageBase
        0x1000,         # SectionAlignment
        0x200,          # FileAlignment
        0, 0, 0, 0, 0, 0,  # OS/image/subsystem versions
        0,              # Win32VersionValue
        0x20000,        # SizeOfImage
        0x200,          # SizeOfHeaders
        0,              # CheckSum
        3,              # Subsystem: CONSOLE
        dll_chars,      # DllCharacteristics
        0x100000, 0x1000,  # stack reserve/commit
        0x100000, 0x1000,  # heap reserve/commit
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    ) + b"\x00" * (16 * 8)  # 16 empty data directories


def _minimal_pe(
    section_name: bytes = b".text",
    raw_size: int = 16,
    virtual_size: int = 16,
    dll_chars: int = 0,
    extra: bytes = b"",
    raw_content: bytes | None = None,
) -> bytes:
    """Build a structurally parseable minimal PE (DOS + COFF + optional header
    + one section). Enough for pefile to walk headers and sections."""
    import pefile  # noqa: F401  (pefile must be installed)

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)  # e_lfanew = 0x40
    pe_sig = b"PE\x00\x00"
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,          # Machine: AMD64
        1,               # NumberOfSections
        0,               # TimeDateStamp
        0,               # PointerToSymbolTable
        0,               # NumberOfSymbols
        0x00F0,          # SizeOfOptionalHeader (PE32+ with 16 dirs)
        0x0022,          # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    opt = _opt_header(dll_chars)
    sec = (
        section_name.ljust(8, b"\x00")
        + struct.pack(
            "<IIIIIIHHI",
            virtual_size,  # VirtualSize
            0x1000,        # VirtualAddress
            raw_size,      # SizeOfRawData
            0x200,         # PointerToRawData
            0,             # PointerToRelocations
            0,             # PointerToLinenumbers
            0,             # NumberOfRelocations
            0,             # NumberOfLinenumbers
            0x60000020,    # Characteristics: CODE | EXECUTE | READ
        )
    )
    headers_len = len(dos) + len(pe_sig) + len(coff) + len(opt) + len(sec)
    raw = (
        b"\x90" * raw_size
        if raw_content is None
        else raw_content[:raw_size].ljust(raw_size, b"\x00")
    )
    return dos + pe_sig + coff + opt + sec + b"\x00" * (0x200 - headers_len) + raw + extra


def _pe_with_debug_entries(pdb_names: list[bytes]) -> bytes:
    """Minimal PE whose Debug directory carries the given CODEVIEW PDB names."""
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022)
    opt = bytearray(_opt_header(0))
    section_ptr = 0x200
    dirs_len = 28 * len(pdb_names)
    dirs = b""
    blobs = b""
    offset = 0
    for name in pdb_names:
        codeview = b"RSDS" + b"\x00" * 16 + struct.pack("<I", 1) + name + b"\x00"
        dirs += struct.pack(
            "<IIHHIIII",
            0, 0, 0, 0, 2, len(codeview),
            0x1000 + dirs_len + offset,
            section_ptr + dirs_len + offset,
        )
        blobs += codeview
        offset += len(codeview)
    raw = dirs + blobs
    # Data directory 6 = IMAGE_DIRECTORY_ENTRY_DEBUG (112 bytes into PE32+ opt).
    struct.pack_into("<II", opt, 112 + 6 * 8, 0x1000, dirs_len)
    section = (
        b".text".ljust(8, b"\x00")
        + struct.pack(
            "<IIIIIIHHI",
            len(raw), 0x1000, len(raw), section_ptr, 0, 0, 0, 0, 0x60000020
        )
    )
    headers_len = len(dos) + len(pe_sig) + len(coff) + len(opt) + len(section)
    return (
        dos + pe_sig + coff + bytes(opt) + section
        + b"\x00" * (section_ptr - headers_len) + raw
    )


def test_non_pe_returns_empty():
    assert PePipeline().analyze(_ctx(b"hello", ftype="text")) == []


def test_minimal_pe_parses():
    data = _minimal_pe()
    inds = PePipeline().analyze(_ctx(data))
    ids = {i.rule_id for i in inds}
    assert "PE_HEADER" in ids
    assert "PE_PARSE_WARN" not in ids


def test_packer_section_detected():
    data = _minimal_pe(section_name=b"UPX0", raw_size=0, virtual_size=0x4000)
    inds = PePipeline().analyze(_ctx(data))
    assert any(i.rule_id == "PE_PACKED" for i in inds)


def test_high_entropy_sections_flagged():
    import os

    # Two sections with genuinely random (high-entropy) content.
    blob = os.urandom(1024)
    sec1 = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 1024, 0x1000, 1024, 0x200, 0, 0, 0, 0, 0x60000020
    )
    sec2 = b".data".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 1024, 0x2000, 1024, 0x600, 0, 0, 0, 0, 0xC0000040
    )
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack(
        "<HHIIIHH", 0x8664, 2, 0, 0, 0, 0x00F0, 0x0022
    )
    opt = _opt_header(0)
    data = dos + b"PE\x00\x00" + coff + opt + sec1 + sec2 + blob + blob
    inds = PePipeline().analyze(_ctx(data))
    assert any(i.rule_id == "PE_HIGH_ENTROPY_SECTIONS" for i in inds)


def test_overlay_detected():
    data = _minimal_pe(extra=b"\x00" * 64)
    inds = PePipeline().analyze(_ctx(data))
    assert any(i.rule_id == "PE_OVERLAY" and "64" in i.detail for i in inds)


def test_missing_mitigations_flagged():
    data = _minimal_pe(dll_chars=0)
    inds = PePipeline().analyze(_ctx(data))
    assert any(i.rule_id == "PE_WEAK_MITIGATIONS" for i in inds)


def test_mitigations_present_no_flag():
    # DYNAMIC_BASE | NX_COMPAT | GUARD_CF -> nothing to flag.
    data = _minimal_pe(dll_chars=0x0140 | 0x4000)
    inds = PePipeline().analyze(_ctx(data))
    assert not any(i.rule_id == "PE_WEAK_MITIGATIONS" for i in inds)


def test_malformed_pe_degrades_gracefully():
    inds = PePipeline().analyze(_ctx(b"MZ" + b"garbage" * 50))
    warn = next(i for i in inds if i.rule_id == "PE_PARSE_WARN")
    # "Nicht analysierbar" darf nicht wie "sauber" aussehen (Audit-Fund):
    # ohne parsbaren Header entfallen Sektionen/Importe/Mitigationen
    # komplett, also darf der Befund nicht bei Gewicht 0 stehen bleiben.
    assert warn.weight > 0
    assert warn.severity.name == "LOW"
    assert "nicht als 'sauber'" in warn.detail


def test_import_patterns():
    assert match_import_patterns({"winexec"}) == []
    hits = match_import_patterns(
        {"virtualallocex", "writeprocessmemory", "createremotethread"}
    )
    assert any(rule == "PE_IMPORT_INJECTION" for rule, _, _ in hits)
    hits = match_import_patterns({"urldownloadtofilew", "winexec"})
    assert any(rule == "PE_IMPORT_DOWNLOAD_EXEC" for rule, _, _ in hits)
    hits = match_import_patterns({"setwindowshookexa", "getasynckeystate"})
    assert any(rule == "PE_IMPORT_KEYLOG" for rule, _, _ in hits)


def test_authenticode_parses_status(monkeypatch):
    if not hasattr(Path("."), "resolve"):
        pytest.skip("no pathlib")
    fake_proc = mock.Mock(
        returncode=0,
        stdout=(
            b'{"Status": "HashMismatch", "Message": "bad", '
            b'"Issuer": "CN=Test CA", "NotBefore": "2026-01-01", '
            b'"NotAfter": "2027-01-01", "Thumbprint": "ABC123"}\n'
        ),
        stderr=b"",
    )
    import malaz.pipelines.pe_pipeline as module

    monkeypatch.setattr(module, "which_absolute", lambda name: "C:/fake/powershell.exe")
    monkeypatch.setattr(
        module, "run_tool", lambda *a, **k: (0, fake_proc.stdout, fake_proc.stderr)
    )
    # _authenticode needs a real file on disk.
    fd, path = __import__("tempfile").mkstemp(suffix=".exe")
    import os

    os.write(fd, b"MZ" * 4)
    os.close(fd)
    try:
        ctx = _ctx(Path(path).read_bytes(), name=path)
        inds = PePipeline()._authenticode(ctx)
    finally:
        os.unlink(path)
    treffer = next(
        i for i in inds if i.rule_id == "PE_SIGNATURE_INVALID"
    )
    assert treffer.severity.name == "HIGH"
    assert "Aussteller: CN=Test CA" in treffer.detail
    assert "Gültig: 2026-01-01 bis 2027-01-01" in treffer.detail
    assert "Fingerabdruck: ABC123" in treffer.detail


def test_truncated_signature_output_stays_unknown(monkeypatch, tmp_path):
    """SEC-023: a cut-off status JSON must never be parsed as a signature.

    The fake output is a complete, valid "Valid" document *plus* the truncation
    flag: exactly the danger case (the flag is the only evidence the rest was
    dropped). The status stays unknown -> no PE_SIGNED/PE_UNSIGNED indicator.
    """
    import malaz.pipelines.pe_pipeline as module
    from malaz.procio import ToolResult

    sample = tmp_path / "sig-sample.exe"
    sample.write_bytes(b"MZ" * 4)
    monkeypatch.setattr(
        module, "which_absolute", lambda name: "C:/fake/powershell.exe"
    )
    monkeypatch.setattr(
        module,
        "run_tool",
        lambda *a, **k: ToolResult(
            0, b'{"Status": "Valid", "Message": "ok"}', b"", truncated=True
        ),
    )

    ctx = _ctx(sample.read_bytes(), name=str(sample))
    assert PePipeline()._authenticode(ctx) == []


def test_die_parse_real_format():
    output = (
        '{\n "detects": [\n  {\n   "filetype": "PE64",\n   "offset": "0",\n'
        '   "values": [\n    {"type": "linker", "name": "Microsoft Linker",'
        ' "version": "14.43.34808"},\n    {"type": "compiler",'
        ' "name": "Microsoft Visual C/C++", "version": "19.43"}\n   ]\n  }\n ]\n}'
    )
    findings = _parse_die_output(output)
    assert findings == [
        {"type": "linker", "name": "Microsoft Linker", "version": "14.43.34808"},
        {"type": "compiler", "name": "Microsoft Visual C/C++", "version": "19.43"},
    ]


def test_die_parse_garbage():
    assert _parse_die_output("not json at all") == []
    assert _parse_die_output("") == []
    assert _parse_die_output('{"detects": []}') == []


def test_die_truncated_output_is_not_a_result(tmp_path, monkeypatch):
    """SEC-023: half an output is not a scan result.

    The visible prefix is even valid JSON naming a packer; the rest (possibly
    the real protector entry) is gone. Parsing it would report a finding from
    an incomplete document — instead the stage must say "not checked".
    """
    from malaz.analysis import die as die_module
    from malaz.procio import ToolResult

    fake = tmp_path / "diec.exe"
    fake.write_bytes(b"MZ")
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    scanner = die_module.DieScanner.__new__(die_module.DieScanner)
    scanner.enabled = True
    scanner.timeout = 5
    scanner.binary = fake
    partial = (
        b'{"detects": [{"values": [{"type": "packer", "name": "UPX"}]}]}'
    )
    monkeypatch.setattr(
        die_module,
        "run_tool",
        lambda *a, **k: ToolResult(0, partial, b"", truncated=True),
    )

    result = scanner.scan_path(target)

    assert result.scanned is False
    assert result.findings == []
    assert "abgeschnitten" in (result.skipped_reason or "")


def test_die_stufenausfall_wird_sichtbar(monkeypatch):
    """BEISSPROBE fuer DIE_SKIPPED — der Nutzer-Grundsatz in einer Zusicherung.

    Die Meldung traegt Gewicht 0, damit eine fehlende Bibliothek die Datei
    nicht belastet. Genau deshalb merkt niemand, wenn sie still wegfaellt:
    ohne diesen Test bleibt ein nicht geprueftes PE ununterscheidbar von
    einem geprueften. Das Projekt hat den Verlust selbst gemessen
    ("packed sample drops from score 50/RED to 20/YELLOW").
    """
    from malaz.analysis.die import DieResult
    from malaz.pipelines import pe_pipeline

    class _Uebersprungen:
        available = True

        def scan_path(self, _p):
            return DieResult(
                scanned=False, skipped_reason="Zeitueberschreitung nach 20 Sekunden"
            )

    monkeypatch.setattr(pe_pipeline, "DieScanner", lambda: _Uebersprungen())
    inds = PePipeline().analyze(_ctx(_minimal_pe()))
    treffer = [i for i in inds if i.rule_id == "DIE_SKIPPED"]

    assert treffer, "der Ausfall der DIE-Stufe blieb unsichtbar"
    assert treffer[0].weight == 0, "die Stufe ist der Datei nicht anzulasten"
    assert "Zeitueberschreitung" in treffer[0].detail, "der Grund fehlt"


# -- AP9: bounded string extraction ---------------------------------------- #


def test_strings_stage_reports_section_and_stays_weightless():
    payload = b"\x90" * 8 + b"powershell -nop -w hidden -enc SQBFAFgA"
    data = _minimal_pe(
        raw_size=len(payload), virtual_size=len(payload), raw_content=payload
    )
    inds = PePipeline().analyze(_ctx(data))
    hit = next(i for i in inds if i.rule_id == "PE_STRINGS_SUSPICIOUS")
    assert hit.weight == 0, "AP9 startet mit Gewicht 0 bis zur Kalibrierung"
    assert hit.severity.name == "INFO"
    assert "powershell" in hit.detail
    # The section table is what makes the finding actionable.
    assert ".text" in hit.detail
    assert "0x208" in hit.detail


def test_benign_pe_strings_do_not_trigger_the_suspicious_rule():
    payload = b"ordinary text for a harmless program"
    data = _minimal_pe(
        raw_size=len(payload), virtual_size=len(payload), raw_content=payload
    )
    ids = {i.rule_id for i in PePipeline().analyze(_ctx(data))}
    assert "PE_STRINGS_SUSPICIOUS" not in ids


def test_address_strings_are_not_reported_twice(monkeypatch):
    """No duplicate statement: addresses belong to binary_iocs, not here."""
    payload = b"http://198.51.100.10/payload"
    data = _minimal_pe(
        raw_size=len(payload), virtual_size=len(payload), raw_content=payload
    )
    ids = {i.rule_id for i in PePipeline().analyze(_ctx(data))}
    assert "PE_STRINGS_SUSPICIOUS" not in ids


def test_string_cap_is_visible(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "STRINGS_MAX_SCAN_BYTES", 64)
    data = _minimal_pe(raw_size=256)
    inds = PePipeline().analyze(_ctx(data))
    summary = next(i for i in inds if i.rule_id == "PE_STRINGS_SUMMARY")
    assert summary.weight == 0
    assert "Byte-Limit" in summary.detail
    assert "NICHT" in summary.detail


def test_utf16le_strings_are_found_in_a_pe():
    payload = "C:\\Windows\\System32\\calc.exe".encode("utf-16-le")
    data = _minimal_pe(
        raw_size=len(payload), virtual_size=len(payload), raw_content=payload
    )
    inds = PePipeline().analyze(_ctx(data))
    assert "PE_STRINGS_SUSPICIOUS" not in {i.rule_id for i in inds}

    from malaz.core.strings_extract import extract_strings

    extracted = extract_strings(data)
    assert any(
        entry.encoding == "utf-16le" and "calc.exe" in entry.value
        for entry in extracted.strings
    )


def test_length_only_cap_is_not_reported_as_partial_scan(monkeypatch):
    """A truncated VALUE does not mean the file was only partly searched."""
    from malaz import config

    monkeypatch.setattr(config, "STRINGS_MAX_STRING_LEN", 50)
    payload = b"A" * 200
    data = _minimal_pe(
        raw_size=len(payload), virtual_size=len(payload), raw_content=payload
    )
    summary = next(
        i
        for i in PePipeline().analyze(_ctx(data))
        if i.rule_id == "PE_STRINGS_SUMMARY"
    )
    assert "vollständig durchsucht" in summary.detail
    assert "NICHT nach Strings durchsucht" not in summary.detail


# -- BUG-031 / SEC-019 / SEC-020: attacker-controlled header budgets --------- #


def test_oversized_size_of_raw_data_is_reported():
    """BUG-031: a forged SizeOfRawData must not hide that it reaches past EOF."""
    data = bytearray(_minimal_pe(extra=b"\x00" * 64))
    section = data.index(b".text")
    struct.pack_into("<I", data, section + 16, 0x9000)  # SizeOfRawData

    inds = PePipeline().analyze(_ctx(bytes(data)))
    ids = {i.rule_id for i in inds}
    oob = next(i for i in inds if i.rule_id == "PE_SECTION_RAW_OOB")
    assert oob.weight > 0
    assert "36864" in oob.detail  # 0x9000, the declared size
    assert "PE_SECTION_PARSE_WARN" not in ids


def test_section_entropy_bytes_budget_is_visible(monkeypatch):
    """SEC-020: per-section entropy work is capped and the cut is reported."""
    from malaz.pipelines import pe_pipeline as mod

    monkeypatch.setattr(mod, "_SECTION_ENTROPY_MAX_BYTES", 8)
    inds = PePipeline().analyze(_ctx(_minimal_pe(raw_size=64)))
    marker = next(i for i in inds if i.rule_id == "PE_SECTION_ENTROPY_LIMIT")
    assert "8 Bytes" in marker.detail
    assert marker.weight == 0


def test_section_count_budget_is_visible(monkeypatch):
    """SEC-020: sections beyond the count budget are skipped visibly."""
    from malaz.pipelines import pe_pipeline as mod

    monkeypatch.setattr(mod, "_SECTION_ENTROPY_MAX_SECTIONS", 0)
    inds = PePipeline().analyze(_ctx(_minimal_pe()))
    marker = next(i for i in inds if i.rule_id == "PE_SECTION_ENTROPY_LIMIT")
    assert "0 von 1" in marker.detail
    assert "übersprungen" in marker.detail


def test_pdb_long_names_are_clipped_in_the_report():
    """SEC-019 end-to-end: neither title nor detail may carry a full PDB name."""
    from malaz.pipelines.pe_pipeline import _PDB_NAME_MAX

    pdb_name = b"X" * (_PDB_NAME_MAX + 200) + b".pdb"
    data = _pe_with_debug_entries([pdb_name] * 17)
    inds = PePipeline().analyze(_ctx(data))
    pdb = next(i for i in inds if i.rule_id == "PE_PDB")
    assert len(pdb.title) <= len("PDB-Pfad vorhanden: ") + _PDB_NAME_MAX
    assert "gekürzt" in pdb.detail
    assert "weitere Debug-Einträge" in pdb.detail


def test_pdb_entries_and_names_are_capped():
    """SEC-019: debug entries and PDB names are attacker-controlled."""
    from types import SimpleNamespace

    from malaz.pipelines.pe_pipeline import _PDB_MAX_ENTRIES, _PDB_NAME_MAX, _pdb_paths

    entries = [
        SimpleNamespace(
            entry=SimpleNamespace(PdbFileName=b"X" * (_PDB_NAME_MAX + 100))
        )
        for _ in range(_PDB_MAX_ENTRIES + 4)
    ]
    paths, dropped, clipped = _pdb_paths(
        SimpleNamespace(DIRECTORY_ENTRY_DEBUG=entries)
    )
    assert len(paths) == _PDB_MAX_ENTRIES
    assert dropped == 4
    assert clipped == _PDB_MAX_ENTRIES
    assert all(len(path) <= _PDB_NAME_MAX for path in paths)
