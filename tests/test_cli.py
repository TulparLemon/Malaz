"""Tests für den CLI/GUI-Einstieg (__main__): Argumente, Exit-Codes, Reports."""

import sys
from pathlib import Path
from unittest import mock

import pytest

import malaz.__main__ as cli
from malaz.models import RiskLevel, ScanResult


def _result(path="a.txt", level=RiskLevel.GREEN) -> ScanResult:
    r = ScanResult(path=path, size=1, depth=0)
    r.risk_level = level
    r.detected_type = "text"
    r.duration_ms = 1
    return r


@pytest.fixture()
def fake_dispatcher(monkeypatch):
    """Dispatcher-Klasse im CLI-Modul durch Fake ersetzen (keine echten Engines)."""
    created = []

    class FakeDisp:
        def __init__(self):
            self.av_scanner = mock.Mock(available=False)
            self.clam_scanner = mock.Mock(available=False)
            self.external_scanners = []
            self.yara = mock.Mock(available=False, load_error=None)

            class _Status:
                probed = False
                error = None

            self.defender_status = _Status()
            created.append(self)

        def scan_path(self, path):
            return _result(Path(path).name)

    monkeypatch.setattr(cli, "Dispatcher", FakeDisp)
    monkeypatch.setattr(cli, "_print_engines", lambda dispatcher: None)
    return created


# -- run_cli ---------------------------------------------------------------- #

def test_run_cli_scans_and_exits_green(fake_dispatcher, tmp_path, capsys):
    f = tmp_path / "gut.txt"
    f.write_text("ok")
    rc = cli.run_cli([str(f)], None)
    assert rc == 0
    out = capsys.readouterr().out
    assert "[GRÜN]" in out and "gut.txt" in out


def test_run_cli_red_result_exits_two(fake_dispatcher, tmp_path, monkeypatch):
    f = tmp_path / "boese.txt"
    f.write_text("x")

    def bad(self, path):
        r = _result(Path(path).name, RiskLevel.RED)
        r.score = 80
        return r

    monkeypatch.setattr(sys.modules["malaz.__main__"].Dispatcher, "scan_path", bad)
    rc = cli.run_cli([str(f)], None)
    assert rc == 2


def test_run_cli_missing_file_reports_and_exits_one(fake_dispatcher, tmp_path, capsys):
    rc = cli.run_cli([str(tmp_path / "gibtsnicht.bin")], None)
    assert rc == 1
    assert "Nicht gefunden" in capsys.readouterr().err


def test_run_cli_returns_three_for_incomplete_member(tmp_path, monkeypatch):
    """BUG-040: derselbe nicht gelaufene Schritt als KIND ergab Exit 0.

    ``is_incomplete`` sieht nur die eigenen Indikatoren (models.py). Ein
    Archiv, dessen Mitglied die Größenlimit-Stufe von ClamAV nicht lief,
    meldete damit 0 = „vollständig geprüft", obwohl ``_log_stages`` dieselbe
    Datei ueber ``_walk_results`` als UNVOLLSTÄNDIG protokollierte. Der
    Exit-Code muss dieselbe Menge sehen wie das Protokoll — sonst haelt CI
    eine unvollstaendige Pruefung fuer eine saubere.
    """
    from malaz.models import Indicator, Severity

    class FakeDispatcher:
        def scan_path(self, path):
            parent = _result("archiv.zip")
            child = _result("mitglied.bin")
            child.indicators = [
                Indicator(
                    rule_id="CLAMAV_SIZE_LIMIT",
                    title="ClamAV: Datei wegen Größenlimit nicht geprüft",
                    severity=Severity.MEDIUM,
                    weight=25,
                )
            ]
            parent.children = [child]
            return parent

    monkeypatch.setattr(cli, "Dispatcher", FakeDispatcher)
    monkeypatch.setattr(cli, "_print_engines", lambda _dispatcher: None)
    target = tmp_path / "archiv.zip"
    target.write_bytes(b"PK\x05\x06")
    assert cli.run_cli([str(target)], None) == 3


def test_run_cli_writes_html_report(fake_dispatcher, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("ok")
    report = tmp_path / "bericht.html"
    rc = cli.run_cli([str(f)], str(report))
    assert rc == 0
    assert report.exists()
    assert report.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_run_cli_report_write_failure_exits_four(fake_dispatcher, tmp_path, capsys):
    """BUG-044: ein unschreibbarer Report-Pfad ist ein Bedienfehler.

    Vorher lief der ``OSError`` aus ``save_report`` als Traceback durch: kein
    definierter Exitcode, keine lesbare Meldung. Ein Verzeichnis an der
    Zielstelle erzeugt den Fehler ohne Rechte-Tricks.
    """
    f = tmp_path / "a.txt"
    f.write_text("ok")
    ziel = tmp_path / "bericht.html"
    ziel.mkdir()

    rc = cli.run_cli([str(f)], str(ziel))
    assert rc == 4
    err = capsys.readouterr().err
    assert "Report konnte nicht geschrieben werden" in err
    assert "Traceback" not in err


def test_cli_summary_masks_bidi_and_control_characters(capsys):
    """SEC-026: Namen/Fehler sind angreiferkontrolliert und gehen roh an print.

    Ein U+202E stellt den Namen im Terminal anders dar; ESC beginnt eine
    ANSI-Sequenz, ein Zeilenumbruch faelscht eine weitere Ergebniszeile.
    """
    r = _result("rechnung\u202egpj.exe")
    cli._print_summary(r)
    out = capsys.readouterr().out
    assert "\u202e" not in out
    assert "\\u202e" in out

    failed = ScanResult(
        path="x.txt",
        detected_type="text",
        error="kaputt\x1b[31mrot\n[ROT] gefaelscht",
    )
    cli._print_summary(failed)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\\x1b" in out
    assert "\n[ROT] gefaelscht" not in out
    assert "\\x0a" in out


# -- main(): Argument-Verarbeitung ------------------------------------------ #

def test_main_cli_routing(fake_dispatcher, monkeypatch, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("x")
    called = {}
    monkeypatch.setattr(cli, "run_cli", lambda paths, report: called.setdefault("rc", 7))
    assert cli.main(["--cli", str(f)]) == 7
    assert called["rc"] == 7


def test_main_gui_ignores_report_with_warning(monkeypatch, capsys):
    calls = {}

    def fake_gui(paths):
        calls["paths"] = paths
        return 0

    monkeypatch.setattr(cli, "run_gui", fake_gui)
    rc = cli.main(["datei.pdf", "--report", "out.html"])
    assert rc == 0
    assert calls["paths"] == ["datei.pdf"]
    assert "--report gilt nur im --cli/--evaluate-Modus" in capsys.readouterr().err


def test_main_warns_about_report_without_files(monkeypatch, capsys):
    """BUG-045: --report ohne Dateien war im GUI-Start stumm."""
    calls = {}

    def fake_gui(paths):
        calls["paths"] = paths
        return 0

    monkeypatch.setattr(cli, "run_gui", fake_gui)
    assert cli.main(["--report", "out.html"]) == 0
    assert calls["paths"] is None
    assert "--report gilt nur im --cli/--evaluate-Modus" in capsys.readouterr().err


def test_main_warns_that_csv_and_engine_flags_need_evaluate(monkeypatch, capsys):
    """BUG-045: --csv/--json/--static-only wirken nur mit --evaluate."""
    monkeypatch.setattr(cli, "run_gui", lambda paths: 0)
    assert cli.main(["--csv", "out.csv", "--json", "out.json", "--static-only"]) == 0
    err = capsys.readouterr().err
    assert "--csv gilt nur im --evaluate-Modus" in err
    assert "--json gilt nur im --evaluate-Modus" in err
    assert "--static-only/--with-av" in err


def test_main_warns_about_positional_files_in_cli_mode(monkeypatch, capsys):
    """BUG-045: Dateien vor ``--cli`` landen in ``files`` und wurden nie gescannt.

    ``malaz a.txt --cli b.txt`` scannte nur b.txt und sagte nichts ueber a.txt.
    """
    called = {}

    def fake_cli(paths, report):
        called["paths"] = paths
        return 0

    monkeypatch.setattr(cli, "run_cli", fake_cli)
    assert cli.main(["a.txt", "--cli", "b.txt"]) == 0
    assert called["paths"] == ["b.txt"]
    assert "DATEI-Positionalargumente" in capsys.readouterr().err


def test_main_gui_default_without_args(monkeypatch):
    monkeypatch.setattr(cli, "run_gui", lambda paths: 0 if paths is None else 9)
    assert cli.main([]) == 0


def test_main_version_exits(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_main_unknown_argument_exits(monkeypatch):
    with pytest.raises(SystemExit):
        cli.main(["--gibtsnicht"])


def test_setup_logging_never_raises(monkeypatch, tmp_path):
    # Echtes Fehlerszenario: MALAZ_LOG_DIR zeigt auf eine regulaere Datei,
    # sodass mkdir(parents=True) OSError wirft — App-Start darf nie crashen,
    # und im aktuellen Arbeitsverzeichnis darf kein malaz.log entstehen.
    blocker = tmp_path / "kein_ordner"
    blocker.write_text("datei", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MALAZ_LOG_DIR", str(blocker))
    cli._setup_logging()  # kein raise
    assert not (tmp_path / "malaz.log").exists()


def test_setup_logging_uses_localappdata_not_cwd(monkeypatch, tmp_path):
    import logging

    cwd = tmp_path / "untrusted_cwd"
    cwd.mkdir()
    appdata = tmp_path / "appdata_local"
    home_dir = tmp_path / "fake_home"
    home_dir.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("MALAZ_LOG_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata))
    try:
        cli._setup_logging()
        assert (appdata / "Malaz" / "logs" / "malaz.log").is_file()
        assert not (cwd / "malaz.log").exists()

        monkeypatch.setenv("LOCALAPPDATA", "")
        monkeypatch.setenv("USERPROFILE", str(home_dir))
        monkeypatch.setenv("HOME", str(home_dir))
        cli._setup_logging()
        assert (home_dir / ".malaz" / "logs" / "malaz.log").is_file()
        assert not (cwd / "malaz.log").exists()
    finally:
        root_logger = logging.getLogger()
        for h in list(root_logger.handlers):
            if getattr(h, "_malaz_privacy_handler", False):
                root_logger.removeHandler(h)
                h.close()


def test_cli_static_only_disables_av_engines(monkeypatch, tmp_path, capsys):
    sample = tmp_path / "probe.txt"
    sample.write_text("harmlos", encoding="utf-8")
    seen = {}

    def fake_scan(self, path):
        seen["av"] = self.av_scanner.available
        seen["clam"] = self.clam_scanner.available
        return _result(Path(path).name)

    monkeypatch.setattr("malaz.core.dispatcher.Dispatcher.scan_path", fake_scan)
    rc = cli.main(["--cli", str(sample), "--static-only"])
    captured = capsys.readouterr()
    assert rc == 0
    assert seen == {"av": False, "clam": False}
    assert "--static-only" not in captured.err


def test_enable_utf8_console_never_raises():
    cli._enable_utf8_console()


def test_frozen_app_dir_markers(monkeypatch):
    """Nuitka-Builds ohne sys.frozen muessen ueber __compiled__ erkannt
    werden, sonst landet malaz.log im Arbeitsverzeichnis (z.B. System32
    bei Admin-Start) statt neben der exe."""
    import sys as _sys
    from pathlib import Path

    from malaz import __main__ as m

    monkeypatch.setattr(_sys, "frozen", False, raising=False)
    monkeypatch.delattr(m, "__compiled__", raising=False)
    assert m._frozen_app_dir() is None

    monkeypatch.setattr(m, "__compiled__", {"backend": "nuitka"}, raising=False)
    assert m._frozen_app_dir() == Path(_sys.executable).resolve().parent

    monkeypatch.delattr(m, "__compiled__", raising=False)
    monkeypatch.setattr(_sys, "frozen", True, raising=False)
    assert m._frozen_app_dir() == Path(_sys.executable).resolve().parent


def test_print_summary_marks_failed_scan(capcs=None):
    """CORE_ERROR (AV-Lock, unlesbar) darf im CLI nie als [GRÜN] score=0
    daherkommen — Live-Befund EICAR-Demo: Defender sperrt open(), der
    Fehler muss sichtbar [FEHLER] markieren."""
    import io
    from contextlib import redirect_stdout

    from malaz import __main__ as m
    from malaz.models import ScanResult

    failed = ScanResult(path="blocked.txt", detected_type="text",
                        error="OSError: [Errno 22] Invalid argument")
    buf = io.StringIO()
    with redirect_stdout(buf):
        m._print_summary(failed)
    out = buf.getvalue()
    assert "[FEHLER]" in out
    assert "GRÜN" not in out
    assert "Errno 22" in out
