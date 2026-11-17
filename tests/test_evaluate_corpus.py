"""Tests für die Korpus-Auswertung (malaz.evaluation + CLI-Flag --evaluate)."""

import contextlib
import io
import sys
from pathlib import Path

from malaz import evaluation as ev
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.evaluation import evaluate
from malaz.models import RiskLevel, ScanResult

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_test_corpus as corpus  # noqa: E402


class _NoAvDispatcher(Dispatcher):
    """Dispatcher ohne AV-Subprozesse: deterministisch und schnell."""

    def __init__(self):
        super().__init__(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )


def _dispatcher():
    return _NoAvDispatcher()


def test_scan_dir_collects_results(tmp_path):
    d = _dispatcher()
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "launch.pdf").write_bytes(corpus.pdf_launch())
    results, truncated = ev._scan_dir(d, tmp_path / "bad")
    assert len(results) == 1
    assert truncated is False
    assert results[0].risk_level == RiskLevel.RED


def test_rates_and_verdict():
    green = ScanResult(path="g", detected_type="text")
    yellow = ScanResult(path="y", detected_type="pdf", score=30,
                        risk_level=RiskLevel.YELLOW)
    red = ScanResult(path="r", detected_type="pe", score=80,
                     risk_level=RiskLevel.RED)
    assert ev._verdict(RiskLevel.RED) == "ROT"
    stats = ev._section_stats([green, yellow, red])
    assert stats.rate_yellow == 2 / 3
    assert stats.rate_red == 1 / 3
    assert ev._section_stats([]).rate_red == 0.0
    assert ev._type_of(red) == "pe"


def test_scan_failed():
    assert ev._scan_failed(ScanResult(path="x", error="OSError: [Errno 22] Invalid argument"))
    assert not ev._scan_failed(ScanResult(path="x"))


def test_skipped_engine_reason_lands_in_csv_cell():
    """CLAMAV_SKIPPED muss seinen Grund (fehlende DB, Timeout, …) direkt
    in die CSV-Zelle schreiben — sonst bleibt ein toter Engine unsichtbar
    (VM-Befund: ClamAV lief nie, die CSV zeigte nur 'CLAMAV_SKIPPED')."""
    from malaz.models import Indicator, Severity

    result = ScanResult(
        path="x", detected_type="text",
        indicators=[
            Indicator(
                rule_id="CLAMAV_SKIPPED", title="ClamAV: Scan übersprungen",
                detail="ClamAV-Scan nicht aussagekräftig (Returncode 2)",
                severity=Severity.INFO, weight=0, source="clamav",
            )
        ],
    )
    cells = ev._top_findings(result)
    assert cells
    assert "Returncode 2" in cells[0]
    # Regel-IDs ohne Skip tragen weiter KEIN Detail (CSV bleibt kompakt).
    clean = ScanResult(
        path="y", detected_type="text",
        indicators=[
            Indicator(
                rule_id="AV_CLEAN", title="ok", detail=" Defender sagt sauber",
                severity=Severity.INFO, weight=0, source="windows_av",
            )
        ],
    )
    assert ev._top_findings(clean) == ["AV_CLEAN(windows_av)"]


def test_failed_scan_is_fehler_not_gruen():
    failed = ScanResult(
        path="blocked.exe", detected_type="pe",
        error="OSError: [Errno 22] Invalid argument",
    )
    ok = ScanResult(path="ok.pdf", detected_type="pdf",
                    score=0, risk_level=RiskLevel.GREEN)
    rows: list[list[str]] = []
    ev._print_section("TEST", [failed, ok], rows, "bad")
    fehler_rows = [r for r in rows if r[0] == "bad" and r[3] == "FEHLER"]
    assert len(fehler_rows) == 1
    assert fehler_rows[0][1] == "blocked.exe"
    # Die fehlerhafte Datei darf nicht als GRÜN durchrutschen
    assert not any(r[1] == "blocked.exe" and r[3] == "GRÜN" for r in rows)
    # ok.pdf bleibt GRÜN
    assert any(r[1] == "ok.pdf" and r[3] == "GRÜN" for r in rows)


def test_evaluate_writes_csv_and_returns_zero(tmp_path, monkeypatch):
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    (bad / "launch.pdf").write_bytes(corpus.pdf_launch())
    (good / "note.txt").write_bytes(b"harmloser Text")
    monkeypatch.setattr(ev, "Dispatcher", _NoAvDispatcher)

    csv_path = tmp_path / "out.csv"
    with contextlib.redirect_stdout(io.StringIO()):
        rc = evaluate(bad, good, csv_path=csv_path)
    assert rc == 0
    assert csv_path.exists()
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 3  # header + 2 Dateien
    assert any("bad" in r and "ROT" in r for r in rows)
    assert any("good" in r and "GRÜN" in r for r in rows)


def test_evaluate_rejects_missing_dirs_and_traversal(tmp_path, capsys):
    # Die Validierung muss VOR der Arbeit laufen. Vorher stand die
    # ../-Pruefung hinter beiden Scans: ein ungueltiger Ausgabepfad kostete
    # erst die volle Messung (gemessen 31,5 s fuer zwei Ein-Byte-Dateien,
    # auf einem echten Korpus Minuten) und wurde dann abgelehnt. Dieser Test
    # belegt die Reihenfolge ohne Dispatcher — wuerde hier ein echter
    # ClamAV-Aufruf starten, waere er sofort sichtbar langsam.
    assert evaluate(tmp_path / "fehlt", tmp_path, csv_path=tmp_path / "x.csv") == 1
    bad = tmp_path / "bad"
    bad.mkdir()
    good = tmp_path / "good"
    good.mkdir()
    (bad / "x.txt").write_bytes(b"x")
    (good / "y.txt").write_bytes(b"y")
    # ../ im CSV-Pfad muss abgelehnt werden (Ausgabe bleibt, wo der
    # Bediener sie haben will - nicht darueber hinaus) — und zwar bevor
    # gescannt wird.
    assert evaluate(bad, good, csv_path=tmp_path / ".." / "out.csv") == 1
    assert not (tmp_path.parent / "out.csv").exists()
    # Der laufende Fall braucht den Dispatcher, damit kein echtes AV startet.
    assert evaluate(bad, good, csv_path=tmp_path / "out.csv", dispatcher=_NoAvDispatcher()) == 0


def test_cli_evaluate_flag(tmp_path, monkeypatch):
    """Malaz.exe --evaluate BAD GOOD --csv … nimmt exakt den Pfad durch."""
    from malaz import __main__

    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    (bad / "launch.pdf").write_bytes(corpus.pdf_launch())
    (good / "note.txt").write_bytes(b"harmloser Text")
    monkeypatch.setattr(ev, "Dispatcher", _NoAvDispatcher)
    monkeypatch.setattr(__main__, "Dispatcher", _NoAvDispatcher)
    monkeypatch.setattr(__main__, "_print_engines", lambda d: None)

    csv_path = tmp_path / "cli.csv"
    rc = __main__.main(["--evaluate", str(bad), str(good), "--csv", str(csv_path)])
    assert rc == 0
    assert csv_path.exists()
    assert "ROT" in csv_path.read_text(encoding="utf-8")


def test_cli_evaluate_conflicts_with_cli():
    import pytest

    from malaz import __main__

    with pytest.raises(SystemExit) as excinfo, contextlib.redirect_stderr(io.StringIO()):
        __main__.main(["--cli", "x", "--evaluate", "a", "b"])
    assert excinfo.value.code == 2  # argparse-Nutzungsfehler


# -- AP4: unchecked trennen, statische Messung, JSON ------------------------
#
# Ein GRÜN mit CORE_READ_TRUNCATED oder *_SKIPPED ist kein sauberes Negativ.
# Die Messung muss solche Zeilen aus dem Nenner nehmen und separat ausweisen —
# sonst sinkt die Trefferquote scheinbar, und ein harmloser Korpus sieht
# sauberer aus, als er geprüft wurde.

import json  # noqa: E402

import pytest  # noqa: E402

from malaz.models import Indicator, Severity  # noqa: E402


def _indicator(rule_id: str) -> Indicator:
    return Indicator(
        rule_id=rule_id,
        title=rule_id,
        detail="Detail",
        severity=Severity.INFO,
        weight=0,
        source="test",
    )


def _result(name: str, level: RiskLevel, *rules: str, error: str = "") -> ScanResult:
    return ScanResult(
        path=name,
        detected_type="text",
        score={RiskLevel.GREEN: 0, RiskLevel.YELLOW: 30, RiskLevel.RED: 60}[level],
        risk_level=level,
        indicators=[_indicator(rule) for rule in rules],
        error=error,
    )


def test_section_stats_excludes_unchecked_and_errors():
    results = [
        _result("clean.txt", RiskLevel.GREEN),
        _result("truncated.tar", RiskLevel.GREEN, "CORE_READ_TRUNCATED"),
        _result("clamav-skip.pdf", RiskLevel.GREEN, "CLAMAV_SKIPPED"),
        _result("hit.pdf", RiskLevel.RED, "PDF_LAUNCH_ACTION"),
        _result("blocked.exe", RiskLevel.GREEN, error="OSError: gesperrt"),
    ]
    stats = ev._section_stats(results)
    assert stats.total == 5
    assert stats.evaluated == 2
    assert stats.unchecked == 2
    assert stats.errors == 1
    assert stats.green == 1
    assert stats.red == 1
    assert stats.rate_yellow == 0.5
    assert stats.rate_red == 0.5
    assert stats.unchecked_rules == ("CLAMAV_SKIPPED", "CORE_READ_TRUNCATED")


def test_static_only_treats_av_skip_as_configuration():
    """--static-only: Engine-aus ist eine Einstellung, keine ungeprüfte Datei.

    Content-Marker (CORE_READ_TRUNCATED) bleiben ungeprüft — nur die beiden
    Engines, die der Bediener ausdrücklich abgeschaltet hat, fallen heraus.
    """
    results = [
        _result("clean.txt", RiskLevel.GREEN, "AV_SKIPPED", "CLAMAV_SKIPPED"),
        _result(
            "truncated.tar", RiskLevel.GREEN, "CORE_READ_TRUNCATED", "AV_SKIPPED"
        ),
    ]
    strict = ev._section_stats(results)
    assert strict.total == 2
    assert strict.unchecked == 2
    assert strict.evaluated == 0

    static = ev._section_stats(results, ev._AV_SKIP_RULES)
    assert static.total == 2
    assert static.evaluated == 1
    assert static.unchecked == 1
    assert static.unchecked_rules == ("CORE_READ_TRUNCATED",)


def test_short_read_and_changed_file_are_unchecked():
    """CORE_READ_SHORT/CORE_FILE_CHANGED sind dieselbe Klasse wie TRUNCATED."""
    for rule in ("CORE_READ_SHORT", "CORE_FILE_CHANGED"):
        stats = ev._section_stats([_result("x.bin", RiskLevel.GREEN, rule)])
        assert stats.unchecked == 1, rule
        assert stats.unchecked_rules == (rule,)


def test_detection_with_skipped_marker_still_counts_as_detected():
    """GELB/ROT + Skip ist ein Befund; nur ein GRÜN wird unbrauchbar."""
    stats = ev._section_stats([
        _result("yellow.pdf", RiskLevel.YELLOW, "CLAMAV_SKIPPED"),
    ])
    assert stats.evaluated == 1
    assert stats.unchecked == 0
    assert stats.yellow == 1


def test_static_only_builds_disabled_engines(monkeypatch):
    seen: list[dict] = []

    class _Recorder(Dispatcher):
        def __init__(self, **kwargs):
            seen.append(kwargs)
            super().__init__(**kwargs)

    monkeypatch.setattr(ev, "Dispatcher", _Recorder)
    dispatcher = ev.build_dispatcher(with_av=False)
    assert isinstance(dispatcher, Dispatcher)
    assert dispatcher.av_scanner.enabled is False
    assert dispatcher.clam_scanner.enabled is False
    assert seen and set(seen[0]) == {"av_scanner", "clam_scanner"}

    ev.build_dispatcher(with_av=True)
    assert seen[-1] == {}


def _fake_dispatcher(mapping):
    class _Fake:
        def scan_path(self, path):
            return mapping[Path(path).name]

    return _Fake()


def test_unchecked_row_is_visible_in_csv_and_separately_counted(tmp_path):
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    (bad / "truncated.tar").write_bytes(b"x")
    (bad / "hit.pdf").write_bytes(b"y")
    (good / "note.txt").write_bytes(b"z")
    dispatcher = _fake_dispatcher({
        "truncated.tar": _result("truncated.tar", RiskLevel.GREEN, "CORE_READ_TRUNCATED"),
        "hit.pdf": _result("hit.pdf", RiskLevel.RED, "PDF_LAUNCH_ACTION"),
        "note.txt": _result("note.txt", RiskLevel.GREEN),
    })
    csv_path = tmp_path / "out.csv"
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = evaluate(bad, good, csv_path=csv_path, dispatcher=dispatcher)
    assert rc == 0
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    # Die Spalte bleibt (AP4), die Identitaetsspalte kommt dahinter (BUG-039).
    assert "Ungeprueft" in rows[0] and "Datei_ID" in rows[0], rows[0]
    assert any(
        "truncated.tar" in row and "CORE_READ_TRUNCATED" in row for row in rows
    )
    # 1 von 2 bösartigen Dateien ist ausgewertet und ROT -> 100 %; die
    # abgeschnittene Datei senkt die Quote NICHT, sie wird separat gezählt.
    assert "ausgewertet: 1  (nicht geprüft: 1, Fehler: 0)" in out.getvalue()
    assert ">= ROT 100.0%" in out.getvalue()


def test_json_report_contains_unchecked_bucket(tmp_path):
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    (bad / "truncated.tar").write_bytes(b"x")
    (bad / "hit.pdf").write_bytes(b"y")
    (good / "note.txt").write_bytes(b"z")
    dispatcher = _fake_dispatcher({
        "truncated.tar": _result("truncated.tar", RiskLevel.GREEN, "CORE_READ_TRUNCATED"),
        "hit.pdf": _result("hit.pdf", RiskLevel.RED, "PDF_LAUNCH_ACTION"),
        "note.txt": _result("note.txt", RiskLevel.GREEN),
    })
    json_path = tmp_path / "out.json"
    with contextlib.redirect_stdout(io.StringIO()):
        assert evaluate(
            bad, good, dispatcher=dispatcher, json_path=json_path, with_av=False
        ) == 0
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["schema"] == "malaz.evaluation/1"
    assert document["mode"] == {
        "with_av": False,
        "ignored_skips": ["AV_SKIPPED", "CLAMAV_SKIPPED"],
    }
    assert document["bad"]["total"] == 2
    assert document["bad"]["evaluated"] == 1
    assert document["bad"]["unchecked"] == 1
    assert document["bad"]["unchecked_rules"] == ["CORE_READ_TRUNCATED"]
    assert document["good"] == {
        "total": 1, "evaluated": 1, "unchecked": 0, "errors": 0,
        "green": 1, "yellow": 0, "red": 0,
        "yellow_or_higher": 0, "rate_yellow": 0.0, "rate_red": 0.0,
        "unchecked_rules": [], "by_type": {"text": {
            "total": 1, "evaluated": 1, "unchecked": 0, "errors": 0,
            "green": 1, "yellow": 0, "red": 0,
            "yellow_or_higher": 0, "rate_yellow": 0.0, "rate_red": 0.0,
            "unchecked_rules": [], "by_type": {},
        }},
    }
    truncated = next(row for row in document["files"] if row["name"] == "truncated.tar")
    assert truncated["unchecked"] == ["CORE_READ_TRUNCATED"]
    assert truncated["verdict"] == "GRÜN"


def test_json_path_traversal_is_rejected_before_scanning(tmp_path):
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert evaluate(
            bad, good, json_path=tmp_path / ".." / "escape.json",
            dispatcher=_fake_dispatcher({}),
        ) == 1
    assert not (tmp_path.parent / "escape.json").exists()


def test_cli_evaluate_static_only_and_mutual_exclusion(tmp_path, monkeypatch):
    from malaz import __main__

    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    (bad / "launch.pdf").write_bytes(corpus.pdf_launch())
    (good / "note.txt").write_bytes(b"harmloser Text")

    class _Recorder(Dispatcher):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)

    monkeypatch.setattr(ev, "Dispatcher", _Recorder)
    monkeypatch.setattr(__main__, "_print_engines", lambda d: None)
    json_path = tmp_path / "cli.json"
    rc = __main__.main([
        "--evaluate", str(bad), str(good), "--static-only", "--json", str(json_path),
    ])
    assert rc == 0
    assert json.loads(json_path.read_text(encoding="utf-8"))["mode"] == {
        "with_av": False,
        "ignored_skips": ["AV_SKIPPED", "CLAMAV_SKIPPED"],
    }

    with pytest.raises(SystemExit) as excinfo, contextlib.redirect_stderr(io.StringIO()):
        __main__.main(["--evaluate", str(bad), str(good), "--static-only", "--with-av"])
    assert excinfo.value.code == 2


# -- Fixrunde Medium: Messintegritaet und Identitaet ------------------------
#
# Drei Zusagen der Messung, die vorher nur im Docstring standen:
#   * ein abgeschnittener Korpus ist eine Teilmenge, keine Messung (BUG-038),
#   * die CSV-Zeile muss ueber den Dateinamen wiederauffindbar sein (BUG-039),
#   * ein --static-only-MISS ist ein Fehlschlag, nicht "ungeprueft" (BUG-081),
#   * ungueltige Ausgabepfade werden VOR jedem Scan abgelehnt (TEST-031).


def _corpus(tmp_path, names=("a.txt",)):
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    for name in names:
        (bad / name).write_bytes(b"x")
    (good / "sauber.txt").write_bytes(b"y")
    return bad, good


def test_corpus_truncation_is_warned_json_and_nonzero(tmp_path, monkeypatch, capsys):
    """BUG-038: das Batch-Limit kappte den Lauf, ohne jede Spur.

    Gemessen (Limit 2, 3 Dateien): 2 gescannt, keine Warnung, Exit 0 — der
    Bediener hielt die Teilmenge fuer den Korpus. Jetzt: Warnung auf stderr,
    ``truncated`` im JSON, Exit 2 (Messung unvollstaendig).
    """
    from malaz import config as cfg

    monkeypatch.setattr(cfg, "MAX_BATCH_FILES", 2)
    bad, good = _corpus(tmp_path, names=("a.txt", "b.txt", "c.txt"))
    mapping = {
        name: _result(name, RiskLevel.GREEN)
        for name in ("a.txt", "b.txt", "c.txt", "sauber.txt")
    }
    json_path = tmp_path / "out.json"
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        rc = evaluate(bad, good, dispatcher=_fake_dispatcher(mapping), json_path=json_path)

    assert rc == 2, "eine abgeschnittene Messung darf nicht als 0 gelten"
    assert "Korpus-Limit" in err.getvalue(), err.getvalue()
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["truncated"] == {"bad": True, "good": False}


def test_corpus_without_truncation_stays_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(ev.config, "MAX_BATCH_FILES", 2)
    bad, good = _corpus(tmp_path, names=("a.txt", "b.txt"))
    mapping = {
        name: _result(name, RiskLevel.GREEN)
        for name in ("a.txt", "b.txt", "sauber.txt")
    }
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert evaluate(bad, good, dispatcher=_fake_dispatcher(mapping)) == 0


def test_csv_keeps_the_exact_file_name_for_its_readers(tmp_path):
    """BUG-039: die Entschaerfung zerstoerte die Namensidentitaet.

    ``safe_cell`` schreibt fuer "-report.pdf" ein "'-report.pdf" und fuer
    Bidi/NUL ein \\uXXXX. ``lab.report`` matcht Manifest-Eintraege ueber genau
    diesen Namen — gemessen: matched 0, missing 1, unexpected 1. Die
    Identitaetsspalte "Datei_ID" wird deshalb unveraendert geschrieben und von
    den Lesern bevorzugt; die Anzeige-Spalte bleibt entschaerft.
    """
    import csv as _csv

    from malaz.lab.report import load_results

    names = ("-report.pdf", "=cmd.xls", "harmlos.txt")
    bad = tmp_path / "bad"
    bad.mkdir()
    good = tmp_path / "good"
    good.mkdir()
    for name in names:
        (bad / name).write_bytes(b"x")
    (good / "sauber.txt").write_bytes(b"y")
    mapping = {name: _result(name, RiskLevel.GREEN) for name in names}
    mapping["sauber.txt"] = _result("sauber.txt", RiskLevel.GREEN)

    csv_path = tmp_path / "out.csv"
    with contextlib.redirect_stdout(io.StringIO()):
        assert evaluate(bad, good, csv_path=csv_path, dispatcher=_fake_dispatcher(mapping)) == 0

    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(_csv.DictReader(handle))
    assert "Datei_ID" in rows[0], rows[0].keys()
    # Die Anzeige-Spalte bleibt entschaerft (Formel-Schutz) ...
    display = {row["Datei_ID"]: row["Datei"] for row in rows}
    assert display["-report.pdf"].startswith("'"), display
    # ... die Identitaetsspalte ist der exakte Name.
    assert sorted(display) == sorted((*names, "sauber.txt"))
    # Und der gemeinsame Leser sieht wieder die Dateinamen.
    assert sorted(row.name for row in load_results(csv_path)) == sorted(
        (*names, "sauber.txt")
    )


def test_static_only_miss_counts_as_miss_not_unchecked(tmp_path):
    """BUG-081: mit --static-only wurde jeder MISS als "ungeprueft" gezaehlt.

    ``_top_findings`` schrieb AV_SKIPPED/CLAMAV_SKIPPED ungefiltert in die
    Zelle, obwohl derselbe Lauf sie als Konfiguration behandelt (Ungeprueft-
    Spalte leer). ``lab.report``/``triage_misses`` mischen beide Zellen und
    rekonstruieren die Marker aus den Regel-IDs — gemessen: detected 0,
    misses 0, unchecked 1, die Detektionsluecke verschwand.
    """
    import triage_misses as triage

    from malaz.lab.report import load_results

    bad, good = _corpus(tmp_path)
    mapping = {
        "a.txt": _result("a.txt", RiskLevel.GREEN, "AV_SKIPPED", "CLAMAV_SKIPPED"),
        "sauber.txt": _result("sauber.txt", RiskLevel.GREEN, "AV_SKIPPED", "CLAMAV_SKIPPED"),
    }
    csv_path = tmp_path / "static.csv"
    with contextlib.redirect_stdout(io.StringIO()):
        assert evaluate(
            bad,
            good,
            csv_path=csv_path,
            dispatcher=_fake_dispatcher(mapping),
            with_av=False,
        ) == 0

    for row in csv_path.read_text(encoding="utf-8-sig").splitlines():
        assert "AV_SKIPPED" not in row, row

    report = triage.triage(load_results(csv_path))
    assert report["total_malicious"] == 1
    assert report["misses"] == 1, report
    assert report["unchecked"] == 0, report


def test_all_output_paths_are_validated_before_any_scan(tmp_path, monkeypatch):
    """TEST-031: die Reihenfolge "Validierung VOR dem Scan" war nicht geprueft.

    Der bisherige Test rief ``evaluate`` ohne Dispatcher auf; ein Scan waere
    zwar langsam gewesen, aber nicht sichtbar. Hier wirft der Aufbau des
    Dispatchers, sobald er ueberhaupt erreicht wird — und der HTML-Pfad
    (BUG-041) gehoert zu denselben Ausgabepfaden.
    """
    bad, good = _corpus(tmp_path)

    def verboten(**_kwargs):
        raise AssertionError("Dispatcher wurde VOR der Validierung gebaut")

    monkeypatch.setattr(ev, "build_dispatcher", verboten)
    stderr = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
        assert evaluate(tmp_path / "fehlt", good) == 1
        assert evaluate(bad, good, csv_path=tmp_path / ".." / "a.csv") == 1
        assert evaluate(bad, good, json_path=tmp_path / ".." / "a.json") == 1
        assert evaluate(bad, good, report_path=tmp_path / ".." / "a.html") == 1

    assert "HTML" in stderr.getvalue()
    assert not (tmp_path.parent / "a.html").exists()
