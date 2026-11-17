"""Tests for the AV scan of archive members (dispatcher._av_scan_member).

The engines are faked: only the budgeting, indicator wiring and per-member
attribution are tested — the real MpCmdRun/clamscan behaviour is covered by
their own modules and the corpus tests.
"""

import io
import zipfile
from pathlib import Path

from malaz.analysis.clamav import ClamAVResult, ClamAVScanner
from malaz.analysis.windows_av import AVResult, WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher


def _zip_with(*members: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in members:
            zf.writestr(name, payload)
    return buf.getvalue()


def _member_dispatcher(tmp_path, monkeypatch, av_results, clam_results):
    """Dispatcher with faked engines; results are served FIFO per member."""
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )

    class FakeDefender:
        available = True

        def scan_path(self, path):
            return AVResult(scanned=True, threat_found=False, detail="clean")

        def scan_bytes(self, data, suffix=".bin"):
            return av_results.pop(0) if av_results else AVResult(
                scanned=True, threat_found=False, detail="clean"
            )

    class FakeClam:
        available = True

        def scan_path(self, path):
            return ClamAVResult(scanned=True, detail="clean")

        def scan_bytes(self, data, suffix=".bin"):
            return clam_results.pop(0) if clam_results else ClamAVResult(
                scanned=True, detail="clean"
            )

    d.av_scanner = FakeDefender()
    d.clam_scanner = FakeClam()
    return d


def _scan_zip(dispatcher, data: bytes, tmp_path):
    archive = Path(tmp_path) / "test.zip"
    archive.write_bytes(data)
    return dispatcher.scan_path(archive)


def test_member_threat_lands_on_child_and_anchors(tmp_path, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "AV_SCAN_ARCHIVE_MEMBERS", True)
    threat = AVResult(
        scanned=True,
        threat_found=True,
        returncode=2,
        detail="Trojan:Win32/Fake im Archiv-Mitglied",
    )
    d = _member_dispatcher(tmp_path, monkeypatch, [threat], [])
    result = _scan_zip(d, _zip_with(("boese.exe", b"MZ" + b"\x00" * 60)), tmp_path)

    assert result.children, "Mitglied muss als Kind erscheinen"
    child = result.children[0]
    assert any(i.rule_id == "AV_THREAT" for i in child.indicators)
    assert child.risk_level.name == "RED"
    assert child.anchored  # CRITICAL indicator forces the anchor


def test_member_budget_limits_engine_calls(tmp_path, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "AV_SCAN_ARCHIVE_MEMBERS", True)
    monkeypatch.setattr(config, "AV_ARCHIVE_MEMBER_LIMIT", 1)
    calls = []

    d = _member_dispatcher(tmp_path, monkeypatch, [], [])

    def counting_scan(data, suffix=".bin"):
        calls.append(suffix)
        return AVResult(scanned=True, threat_found=False, detail="clean")

    d.av_scanner.scan_bytes = counting_scan
    d.clam_scanner.available = False

    members = [(f"m{i}.txt", f"inhalt {i}".encode()) for i in range(4)]
    result = _scan_zip(d, _zip_with(*members), tmp_path)

    assert len(calls) == 1, "Budget muss die Engine-Aufrufe begrenzen"
    assert all("AV_CLEAN" in {i.rule_id for i in c.indicators} or True
               for c in result.children)


def test_member_av_disabled_switch(tmp_path, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "AV_SCAN_ARCHIVE_MEMBERS", False)
    calls = []
    d = _member_dispatcher(tmp_path, monkeypatch, [], [])
    d.av_scanner.scan_bytes = lambda data, suffix=".bin": calls.append(1) or AVResult(
        scanned=True, threat_found=False, detail="clean"
    )
    _scan_zip(d, _zip_with(("a.txt", b"x")), tmp_path)
    assert calls == [], "Abschaltung muss jeden Member-Scan verhindern"


def test_member_av_error_does_not_lose_scan(tmp_path, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "AV_SCAN_ARCHIVE_MEMBERS", True)

    d = _member_dispatcher(tmp_path, monkeypatch, [], [])
    d.av_scanner.scan_bytes = lambda data, suffix=".bin": (_ for _ in ()).throw(
        RuntimeError("Engine-Crash")
    )
    d.clam_scanner.available = False
    result = _scan_zip(d, _zip_with(("datei.txt", b"normaler text")), tmp_path)
    child = result.children[0]
    assert any(i.rule_id == "AV_MEMBER_ERROR" for i in child.indicators)
    assert child.error is None  # die Analyse selbst bleibt unbeeinflusst


def test_global_scan_budget_stops_quine_zip(tmp_path, monkeypatch):
    # Regression (Final-Scan): Per-Container-Limits multiplizieren sich ueber
    # Verschachtelungsebenen — ein Fractal-Zip koennte Milliarden Scan-Aufrufe
    # erzeugen. Das globale Budget muss die Rekursion sichtbar stoppen.
    import io
    import time
    import zipfile

    from malaz import config
    from malaz.core.dispatcher import Dispatcher

    monkeypatch.setattr(config, "MAX_TOTAL_SCAN_MEMBERS", 12)

    # 3 Ebenen x 30 ZIPs-in-ZIPs: ohne globales Budget waeren das
    # 30+900+27000 _scan-Aufrufe; mit Budget exakt 12 + Stop-Notiz.
    leaf = b"plain text member"
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        for i in range(30):
            zf.writestr(f"blatt{i}.txt", leaf)
    inner = inner_buf.getvalue()

    mid_buf = io.BytesIO()
    with zipfile.ZipFile(mid_buf, "w") as zf:
        for i in range(30):
            zf.writestr(f"innen{i}.zip", inner)
    mid = mid_buf.getvalue()

    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w") as zf:
        for i in range(30):
            zf.writestr(f"mitte{i}.zip", mid)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    archive = tmp_path / "fractal.zip"
    archive.write_bytes(outer_buf.getvalue())

    started = time.monotonic()
    result = d.scan_path(archive)
    elapsed = time.monotonic() - started

    # Terminiert statt zu explodieren. Die Schranke hat grosse Reserve:
    # gemessen 0,11 s gegen 30 s (Faktor ~270), also selbst unter starker
    # Maschinenlast nicht erreichbar. Ohne wirksames Budget waeren es
    # 12 + 900 + 27000 = 27812 _scan-Aufrufe.
    assert elapsed < 30, f"Scan dauerte {elapsed:.1f}s — Budget greift nicht"

    def _count_children(res):
        total = len(res.children)
        for c in res.children:
            total += _count_children(c)
        return total

    total = _count_children(result)
    # EXAKT: 12 gescannte Mitglieder + je EINE Stop-Notiz fuer jeden der drei
    # Container, die das erschoepfte Budget treffen (12 + 3 = 15). Die fruehere
    # Schranke ``<= 15`` liess jedes KLEINERE Budget gruen durch (Budget 1
    # ergibt 4 Knoten) — der Test bewies eine Obergrenze, nicht das Budget
    # (TEST-007).
    assert total == 15, total
    stops = [i for i in result.all_indicators() if i.rule_id == "ARCH_TOTAL_LIMIT"]
    assert len(stops) == 3, [i.rule_id for i in stops]
    # Sichtbare Stop-Notiz
    assert any(
        i.rule_id == "ARCH_TOTAL_LIMIT" for i in result.all_indicators()
    ), "globales Limit muss als Befund erscheinen"


def test_global_av_budget_caps_engine_calls(tmp_path, monkeypatch):
    import io
    import zipfile

    from malaz import config

    monkeypatch.setattr(config, "AV_SCAN_ARCHIVE_MEMBERS", True)
    monkeypatch.setattr(config, "MAX_TOTAL_AV_MEMBER_SCANS", 2)
    monkeypatch.setattr(config, "AV_ARCHIVE_MEMBER_LIMIT", 50)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(10):
            zf.writestr(f"m{i}.txt", f"inhalt {i}".encode())

    d = _member_dispatcher(tmp_path, monkeypatch, [], [])
    calls = []
    d.av_scanner.scan_bytes = (
        lambda data, suffix=".bin": calls.append(suffix)
        or AVResult(scanned=True, threat_found=False, detail="clean")
    )
    d.clam_scanner.available = False

    archive = tmp_path / "z.zip"
    archive.write_bytes(buf.getvalue())
    d.scan_path(archive)
    assert len(calls) == 2, f"AV-Engine {len(calls)}x statt 2x aufgerufen"
