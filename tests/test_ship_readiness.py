from pathlib import Path

from malaz import config
from malaz.core import binary_iocs, domain_blocklist, hashlist, ipblocklist
from malaz.models import CAT_AV, AnalysisContext, Indicator, ScanResult, Severity
from malaz.pipelines.generic_pipeline import GenericPipeline


def _incomplete_result() -> ScanResult:
    result = ScanResult(path="probe.bin", detected_type="text")
    result.indicators = [
        Indicator(
            rule_id="AV_SKIPPED",
            title="Windows Defender: Scan übersprungen",
            severity=Severity.INFO,
            category=CAT_AV,
            weight=0,
        )
    ]
    return result


def test_unreadable_hash_list_reports_status_without_raising(tmp_path):
    unreadable = tmp_path / "hashlist"
    unreadable.mkdir()
    entries, errors = hashlist.load_blocklist_status(unreadable)
    assert entries == frozenset()
    assert errors


def test_unreadable_domain_and_ip_lists_report_status(tmp_path):
    unreadable = tmp_path / "blocklist"
    unreadable.mkdir()
    domains, domain_error = domain_blocklist.load_domain_blocklist_or_error(unreadable)
    networks, ip_error = ipblocklist.load_ip_blocklist_or_error(unreadable)
    assert domains == frozenset()
    assert networks == []
    assert domain_error
    assert ip_error


def test_generic_hash_stage_marks_unreadable_list_incomplete(tmp_path, monkeypatch):
    unreadable = tmp_path / "hashlist"
    unreadable.mkdir()
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", unreadable)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "missing")
    hashlist._load_blocklist.cache_clear()
    ctx = AnalysisContext(path=Path("probe.bin"), data=b"probe", detected_type="text", size=5)
    indicators = GenericPipeline()._hash_blocklist(ctx)
    assert "HASH_BLOCKLIST_UNAVAILABLE" in {item.rule_id for item in indicators}
    assert all(item.weight == 0 for item in indicators)


def test_binary_ioc_split_reports_each_unreadable_list(monkeypatch):
    monkeypatch.setattr(
        binary_iocs,
        "load_domain_blocklist_or_error",
        lambda: (frozenset(), "Domain-Blockliste nicht lesbar"),
    )
    monkeypatch.setattr(
        binary_iocs,
        "load_ip_blocklist_or_error",
        lambda _path: ([], "IP-Blockliste nicht lesbar"),
    )
    monkeypatch.setattr(
        binary_iocs,
        "load_blocklist_or_error",
        lambda _path: (frozenset(), "URL-Hash-Blockliste nicht lesbar"),
    )
    blocked, plain, unavailable = binary_iocs.split_blocked_iocs(
        [("domain", "evil.example")]
    )
    assert blocked == []
    assert plain == [("domain", "evil.example")]
    # Only lists actually consulted for these hit kinds are reported.
    # A domain hit can match a domain or an IP literal (nets), never the URL
    # hash list; claiming the URL list failed would be a false incomplete note.
    assert {item[0] for item in unavailable} == {
        "DOMAIN_BLOCKLIST_UNAVAILABLE",
        "IP_BLOCKLIST_UNAVAILABLE",
    }

    blocked, plain, unavailable = binary_iocs.split_blocked_iocs(
        [("url", "http://evil.example/x")]
    )
    assert {item[0] for item in unavailable} == {
        "DOMAIN_BLOCKLIST_UNAVAILABLE",
        "IP_BLOCKLIST_UNAVAILABLE",
        "URL_BLOCKLIST_UNAVAILABLE",
    }

    blocked, plain, unavailable = binary_iocs.split_blocked_iocs(
        [("ipv4", "203.0.113.9")]
    )
    assert {item[0] for item in unavailable} == {"IP_BLOCKLIST_UNAVAILABLE"}


def test_unavailable_blocklist_ids_are_incomplete_rules():
    from malaz.models import _INCOMPLETE_RULES

    assert {
        "HASH_BLOCKLIST_UNAVAILABLE",
        "DOMAIN_BLOCKLIST_UNAVAILABLE",
        "IP_BLOCKLIST_UNAVAILABLE",
        "URL_BLOCKLIST_UNAVAILABLE",
    } <= set(_INCOMPLETE_RULES)


def test_html_report_marks_incomplete_result_before_advice():
    from malaz.reporting.html_report import generate_report

    html = generate_report([_incomplete_result()])
    assert "(unvollständig)" in html
    assert "Nicht geprüft" in html
    assert html.index("Nicht geprüft") < html.index("Empfehlung")


def test_verdict_card_marks_incomplete_result(qapp):
    from malaz.gui.verdict_card import VerdictCard

    card = VerdictCard()
    card.show_result(_incomplete_result())
    assert "unvollständig" in card.headline.text()
    assert "nicht vollständig geprüft" in card.advice.text().lower()


def test_csv_and_json_include_completeness_fields(tmp_path):
    import csv
    import json

    from malaz.reporting.export import write_csv, write_json

    result = _incomplete_result()
    csv_path = write_csv([result], tmp_path / "result.csv")
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle, delimiter=";"))
    assert row["Vollständig"] == "nein"
    assert "AV_SKIPPED" in row["Nicht_geprüfte_Stufen"]

    json_path = write_json([result], tmp_path / "result.json")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["files"][0]["complete"] is False
    assert data["files"][0]["incomplete_stages"] == ["AV_SKIPPED"]


def test_cli_returns_three_for_incomplete_green_result(tmp_path, monkeypatch):
    import malaz.__main__ as cli

    class FakeDispatcher:
        def scan_path(self, path):
            return _incomplete_result()

    monkeypatch.setattr(cli, "Dispatcher", FakeDispatcher)
    monkeypatch.setattr(cli, "_print_engines", lambda _dispatcher: None)
    target = tmp_path / "probe.bin"
    target.write_bytes(b"probe")
    assert cli.run_cli([str(target)], None) == 3


def test_gui_path_expansion_preserves_truncation(monkeypatch):
    from PySide6.QtCore import QUrl

    from malaz.gui import main_window

    monkeypatch.setattr(
        main_window,
        "expand_scan_paths",
        lambda _paths: ([Path("kept.bin")], True),
    )
    paths, truncated = main_window._urls_to_paths(
        [QUrl.fromLocalFile(str(Path("dropped.bin")))]
    )
    assert paths == ["kept.bin"]
    assert truncated is True


def test_yara_load_error_reaches_the_result(monkeypatch):
    from malaz.core.yara_engine import YaraEngine

    engine = YaraEngine.__new__(YaraEngine)
    engine._rules = []
    engine._disabled = frozenset()
    engine.load_error = "defekte Regel"
    engine.available = True
    pipeline = GenericPipeline(yara=engine)
    indicators = pipeline._yara(
        AnalysisContext(path=Path("probe.bin"), data=b"probe", detected_type="text", size=5)
    )
    assert "YARA_LOAD_ERROR" in {item.rule_id for item in indicators}
    assert next(item for item in indicators if item.rule_id == "YARA_LOAD_ERROR").weight == 25


def test_yara_total_budget_is_reported(monkeypatch):
    from malaz.core.yara_engine import YaraEngine

    class _Rule:
        def match(self, **_kwargs):
            return []

    engine = YaraEngine.__new__(YaraEngine)
    engine._rules = [_Rule()]
    engine._disabled = frozenset()
    engine.load_error = None
    engine.available = True
    monkeypatch.setattr(config, "YARA_SCAN_BUDGET_SECONDS", 0)
    outcome = engine.scan_with_status(b"probe")
    assert outcome.matches == []
    assert "Gesamtbudget" in (outcome.scan_error or "")


def test_concurrent_clamd_loss_scans_every_file(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from malaz.analysis import clamav as clamav_module

    clamdscan = tmp_path / "clamdscan.exe"
    clamscan = tmp_path / "clamscan.exe"
    clamdscan.write_bytes(b"MZ")
    clamscan.write_bytes(b"MZ")
    scanner = clamav_module.ClamAVScanner.__new__(clamav_module.ClamAVScanner)
    scanner.enabled = True
    scanner.timeout = 5
    scanner.binary = clamdscan
    scanner._clamscan = clamscan
    scanner._clamd_conf_used = None
    scanner.database = None
    scanner._fallback_done = False
    targets = []
    for name in ("a.bin", "b.bin"):
        target = tmp_path / name
        target.write_bytes(b"x")
        targets.append(target)

    entered = threading.Barrier(2)
    clamd_calls = []

    def fake_run(args, timeout=None):
        binary = str(args[0])
        target = str(args[-1])
        if binary.endswith("clamdscan.exe"):
            clamd_calls.append(target)
            entered.wait(timeout=5)
            return 2, b"", b"ERROR: Could not connect to clamd: Connection refused"
        return 0, f"{target}: OK\n".encode(), b""

    monkeypatch.setattr(clamav_module, "run_tool", fake_run)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(scanner.scan_path, targets))
    assert len(clamd_calls) == 2
    assert all(result.scanned for result in results), results



def test_feed_update_replaces_stale_source_entries_without_losing_siblings(
    tmp_path, monkeypatch
):
    from malaz.core import feed_import, feeds, hashlist

    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "hashes.sha256")
    target = tmp_path / "urls.sha256"
    manual = "f" * 64
    target.write_text(manual + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", target)
    first, second = feeds.FEEDS[0], feeds.FEEDS[1]
    raw_first = tmp_path / "first.txt"
    raw_second = tmp_path / "second.txt"
    raw_first.write_text("http://first.example/a\n", encoding="utf-8")
    raw_second.write_text("http://second.example/b\n", encoding="utf-8")
    feed_import.import_feed(first, raw_first)
    feed_import.import_feed(second, raw_second)
    raw_first.write_text("http://first.example/new\n", encoding="utf-8")
    feed_import.import_feed(first, raw_first)
    hashlist._load_blocklist.cache_clear()
    entries = hashlist.load_blocklist(target)
    assert feed_import.url_hash("http://first.example/new") in entries
    assert feed_import.url_hash("http://second.example/b") in entries
    assert feed_import.url_hash("http://first.example/a") not in entries
    assert manual in entries


def test_domain_feed_update_preserves_manual_entries(tmp_path, monkeypatch):
    from malaz.core import feed_import, feeds

    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "hashes.sha256")
    target = tmp_path / "domains.txt"
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", target)
    target.write_text("manual.example\n", encoding="utf-8")
    feed = feeds.FEEDS[2]
    raw = tmp_path / "domains-feed.txt"
    raw.write_text("phishing.example\n", encoding="utf-8")

    feed_import.import_feed(feed, raw)

    text = target.read_text(encoding="utf-8")
    assert "manual.example" in text
    assert "phishing.example" in text


def test_manual_entries_survive_repeated_feed_refreshes(tmp_path, monkeypatch):
    """refresh1 -> merge -> refresh2 -> merge -> refresh3 (BUG-008).

    Der Legacy-Bestand wurde nur EINMAL gesichert; danach schrieb jeder
    Refresh das Ziel ausschliesslich aus den Feed-Snapshots plus diesem alten
    Legacy. Manuelle Importe nach dem ersten Refresh verschwanden damit beim
    naechsten automatischen Update — dieselbe Datei war vorher ROT (50) und
    danach GRUEN (0), ohne dass der Nutzer etwas geaendert haette.
    """
    from malaz.core import feed_import, feeds, hashlist

    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "hashes.sha256")
    target = tmp_path / "urls.sha256"
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", target)
    manual_one, manual_two, manual_three = ("1" * 64, "2" * 64, "3" * 64)
    target.write_text(manual_one + "\n", encoding="utf-8")
    feed = feeds.FEEDS[0]
    raw = tmp_path / "feed.txt"

    def refresh(url: str) -> None:
        raw.write_text(f"{url}\n", encoding="utf-8")
        feed_import.import_feed(feed, raw)
        hashlist._load_blocklist.cache_clear()

    def manual(token: str) -> None:
        hashlist._load_blocklist.cache_clear()
        hashlist.merge_blocklist([token], source_label="test", path=target)
        hashlist._load_blocklist.cache_clear()

    refresh("http://feed.example/a")
    manual(manual_two)
    refresh("http://feed.example/b")
    manual(manual_three)
    refresh("http://feed.example/c")

    entries = hashlist.load_blocklist(target)
    assert feed_import.url_hash("http://feed.example/a") not in entries
    assert feed_import.url_hash("http://feed.example/b") not in entries
    assert feed_import.url_hash("http://feed.example/c") in entries
    assert manual_one in entries
    assert manual_two in entries
    assert manual_three in entries


def test_failed_feed_source_cannot_be_hidden_by_fresh_target(tmp_path, monkeypatch):
    from malaz.core import feeds

    for attr, name in (
        ("USER_HASH_BLOCKLIST_FILE", "hashes.txt"),
        ("URL_BLOCKLIST_FILE", "urls.txt"),
        ("DOMAIN_BLOCKLIST_FILE", "domains.txt"),
        ("IP_BLOCKLIST_FILE", "ips.txt"),
    ):
        path = tmp_path / name
        path.write_text("fresh", encoding="utf-8")
        monkeypatch.setattr(config, attr, path)
    feeds.record_source_status(feeds.FEEDS[0], ok=False, error="HTTP 503")
    _name, state, tooltip = feeds.state_badge(7)
    assert state == "warn"
    assert "urlhaus" in tooltip
    assert "FEHLGESCHLAGEN" in tooltip


