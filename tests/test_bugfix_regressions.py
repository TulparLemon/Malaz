"""Regression tests for the bugs found in the pre-ship bug hunt.

Each test pins one concrete defect so it cannot silently come back:

1. xlsx formula scan vs. inflated sheet dimension (DoS / worker hang).
2. 7-Zip extraction must not follow symlinks out of the temp dir.
3. MpCmdRun discovery must prefer the newest platform version.
4. IOC extraction must not materialise millions of regex matches.
"""

import io
import os
import time
import zipfile
from pathlib import Path

import pytest

from malaz import config
from malaz.models import AnalysisContext

# -- 1) xlsx formula scan: inflated <dimension> must not hang --------------- #

def _crafted_xlsx() -> bytes:
    """Minimal xlsx whose sheet claims A1:XFD1048576 (~1.7e10 cells).

    The dangerous formula sits in the very last cell, so the 25-hit early stop
    does not help — only the cell budget does.
    """
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType='
        '"application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType='
        '"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType='
        '"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Tabelle1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<dimension ref="A1:XFD1048576"/>'
        "<sheetData>"
        '<row r="1048576"><c r="XFD1048576" t="str"><f>cmd|"/C calc"!A0</f><v>0</v></c></row>'
        "</sheetData></worksheet>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()


def test_formula_scan_terminates_on_inflated_dimension(monkeypatch):
    pytest.importorskip("openpyxl")
    from malaz.pipelines.office_pipeline import OfficePipeline

    # Small budget so the test stays fast; production default is 250_000.
    monkeypatch.setattr(config, "MAX_FORMULA_CELLS", 2_000)
    data = _crafted_xlsx()
    ctx = AnalysisContext(
        path=Path("crafted.xlsx"), data=data, detected_type="zip", size=len(data)
    )
    started = time.perf_counter()
    indicators = OfficePipeline()._formula_analysis(ctx)  # must not raise
    elapsed = time.perf_counter() - started

    # Der Vertrag ist "das Budget greift UND wird gemeldet" — geprueft wird das
    # Signal, nicht die Uhr. Vorher war der Abbruch stumm: die Analyse brach
    # ab und lieferte 0 Indikatoren, also optisch dasselbe wie "keine
    # gefaehrliche Formel". Jetzt meldet sie OFFICE_FORMULA_STOP.
    ids = [i.rule_id for i in indicators]
    assert "OFFICE_FORMULA_STOP" in ids, (
        f"Zell-Budget-Abbruch wurde nicht gemeldet: {ids}"
    )
    # Die Formel im Fixture liegt bei XFD1048576, also HINTER dem Limit — sie
    # darf nicht gefunden werden. Waere das Budget wirkungslos, liefe der Test
    # in Milliarden Zellen und die Zeitschranke unten faengt das ab.
    assert "OFFICE_FORMULA" not in ids, ids
    # Zeitschranke bleibt als zweiter, eigenstaendiger Vertrag: das Signal
    # belegt das Greifen des Budgets, nicht dass der Lauf nicht pathologisch
    # langsam wird. Grosse Reserve (gemessen 0,9 s; ohne Budget >130 s).
    assert elapsed < 60, f"Analyse dauerte {elapsed:.1f}s"


def test_formula_scan_still_detects_dangerous_formula():
    openpyxl = pytest.importorskip("openpyxl")
    from malaz.pipelines.office_pipeline import OfficePipeline

    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = '=cmd|"/C calc"!A0'
    buf = io.BytesIO()
    wb.save(buf)
    data = buf.getvalue()
    ctx = AnalysisContext(
        path=Path("normal.xlsx"), data=data, detected_type="zip", size=len(data)
    )
    indicators = OfficePipeline()._formula_analysis(ctx)
    assert any(i.rule_id == "OFFICE_FORMULA" for i in indicators)


# -- 2) 7-Zip extraction must ignore symlinks -------------------------------- #

def test_sevenzip_skips_symlinks(monkeypatch, tmp_path):
    """TEST-038: the test SKIPPED on every Windows host without the symlink
    privilege — i.e. the only regression guard for the 7-Zip symlink filter
    was not running at all.

    A real symlink is still used wherever the OS allows it. On hosts without
    SeCreateSymbolicLinkPrivilege the extractor writes a regular file and
    reports it as a symlink through ``Path.is_symlink`` — the exact predicate
    the production filter asks (``not p.is_symlink() and p.is_file()``). The
    test therefore runs everywhere instead of skipping, and still fails if the
    filter is dropped.
    """
    from pathlib import Path as _Path

    from malaz.core import sevenzip

    outside = tmp_path / "outside_secret.txt"
    outside.write_text("secret")
    simulated_link = {"active": False}

    def fake(binary, archive_path, out_dir, password, timeout):
        out = _Path(out_dir)
        (out / "good.txt").write_bytes(b"content")
        link = out / "link.txt"
        try:
            os.symlink(str(outside), str(link))
        except (OSError, NotImplementedError):
            link.write_bytes(b"secret")
            simulated_link["active"] = True
        return 0, "Everything is Ok"

    real_is_symlink = _Path.is_symlink

    def fake_is_symlink(self):
        if real_is_symlink(self):
            return True
        return simulated_link["active"] and self.name == "link.txt"

    monkeypatch.setattr(_Path, "is_symlink", fake_is_symlink)
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(sevenzip, "_extract", fake)

    def fake_listing(binary, archive_path, timeout, password=None):
        return 0, [("good.txt", 7), ("link.txt", 6)], ""

    monkeypatch.setattr(sevenzip, "_list_members", fake_listing)
    members = {name: err for name, _data, err in sevenzip.iter_7z_members(b"x", ".rar")}
    assert "good.txt" in members and members["good.txt"] is None
    assert "link.txt" not in members  # symlink must not be scanned


# -- 3) MpCmdRun discovery prefers the newest platform version --------------- #

def test_mpcmdrun_prefers_newest_platform(tmp_path, monkeypatch):
    from malaz.analysis.windows_av import WindowsDefenderScanner

    base = tmp_path / "Platform"
    old = base / "4.18.24090.11"
    new = base / "4.18.25010.2"
    for d in (old, new):
        d.mkdir(parents=True)
        (d / "MpCmdRun.exe").write_bytes(b"MZ")
    monkeypatch.setattr(
        config, "AV_MPCMDRUN_CANDIDATES", (str(base / "*" / "MpCmdRun.exe"),)
    )
    scanner = WindowsDefenderScanner()
    assert scanner.mpcmdrun == new / "MpCmdRun.exe"


# -- 4) IOC extraction stops early instead of materialising all matches ------ #

def test_ioc_collection_stops_early():
    from malaz.pipelines.generic_pipeline import _URL_RE, _collect

    # 20 distinct URLs, each repeated 1000x; the first 20 matches already
    # contain every distinct value, so a capped scan must stop almost at once.
    raw = b" ".join(
        f"http://evil{i}.com/x".encode() for i in range(20)
    ) * 1000
    consumed = 0

    def counting():
        nonlocal consumed
        for m in _URL_RE.finditer(raw):
            consumed += 1
            yield m

    urls = _collect(counting(), None, 8)
    assert len(urls) == 8
    assert consumed < 200  # would be 20_000 without the early stop
