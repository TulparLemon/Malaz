"""Tests für das freshclam-Update-Modul (GUI-Knopf / Script)."""

import sys
from pathlib import Path

import pytest

from malaz.analysis import clamav_update
from malaz.analysis.clamav_update import (
    FreshclamResult,
    build_command,
    find_freshclam,
    run_freshclam,
    update_due,
    user_conf_path,
)


@pytest.fixture
def fake_binary(tmp_path, monkeypatch):
    """A freshclam 'binary': a tiny stub that prints lines and exits 0."""
    if sys.platform == "win32":
        stub = tmp_path / "freshclam.exe"
        # Real execution only happens in run_freshclam tests; for the pure
        # helpers existence is all that matters.
        stub.write_bytes(b"MZ")
    else:
        stub = tmp_path / "freshclam"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    return stub


def test_find_freshclam_from_config(tmp_path, monkeypatch, fake_binary):
    monkeypatch.setattr(clamav_update.config, "CLAMAV_FRESHCLAM_CANDIDATES", (str(fake_binary),))
    assert find_freshclam() == fake_binary


def test_find_freshclam_missing(monkeypatch, tmp_path):
    nowhere = str(tmp_path / "gibtsnicht.exe")
    monkeypatch.setattr(clamav_update.config, "CLAMAV_FRESHCLAM_CANDIDATES", (nowhere,))
    monkeypatch.setattr(clamav_update, "which_absolute", lambda _name: None)
    assert find_freshclam() is None


def test_build_command_none_when_missing(monkeypatch):
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: None)
    assert build_command() is None


def test_build_command_creates_user_conf(fake_binary, monkeypatch):
    """Ohne vorhandene Nutzer-Config wird sie angelegt (adminlos, Variante B)
    und immer per --config-file genutzt — sonst stirbt freshclam auf dem
    nicht-beschreibbaren Program-Files-Standardpfad mit rc 10 (Feld-Report)."""
    conf = fake_binary.parent / "freshclam.conf"
    monkeypatch.setattr(clamav_update, "user_conf_path", lambda: conf)
    cmd = build_command(fake_binary)
    assert cmd[-2:] == ["--config-file", str(conf)]
    raw = conf.read_bytes()
    assert b"\r\r" not in raw, "Doppel-CR wuerde freshclam die Config ablehnen (rc 2)"
    text = conf.read_text(encoding="utf-8")
    assert f"DatabaseDirectory {conf.parent / 'db'}" in text
    assert "DatabaseMirror database.clamav.net" in text
    assert (conf.parent / "db").is_dir()


def test_build_command_with_user_conf(fake_binary, monkeypatch, tmp_path):
    conf = tmp_path / "freshclam.conf"
    conf.write_text("DatabaseDirectory x\n", encoding="utf-8")
    monkeypatch.setattr(clamav_update, "user_conf_path", lambda: conf)
    cmd = build_command(fake_binary)
    assert cmd[-2:] == ["--config-file", str(conf)]


def test_ensure_user_conf_does_not_overwrite(fake_binary, monkeypatch):
    """Eine existierende (ggf. hand-editierte) Config bleibt unangetastet."""
    conf = fake_binary.parent / "freshclam.conf"
    conf.write_text("DatabaseMirror internal.example\n", encoding="utf-8")
    monkeypatch.setattr(clamav_update, "user_conf_path", lambda: conf)
    assert clamav_update.ensure_user_conf() == conf
    assert conf.read_text(encoding="utf-8") == "DatabaseMirror internal.example\n"


def test_ensure_user_conf_failure_falls_back_plain(fake_binary, monkeypatch):
    conf = fake_binary.parent / "freshclam.conf"
    monkeypatch.setattr(clamav_update, "user_conf_path", lambda: conf)

    def boom(*_args, **_kwargs):
        raise OSError("read-only")

    monkeypatch.setattr("pathlib.Path.write_text", boom)
    assert clamav_update.ensure_user_conf() is None
    assert build_command(fake_binary) == [str(fake_binary)]


def test_run_freshclam_streams_lines(tmp_path):
    """End-to-end gegen ein echtes Kommando (cmd echo) mit Line-Callback."""
    lines = []
    result = run_freshclam(
        line_callback=lines.append,
        command=["cmd", "/c", "echo first & echo second"],
    )
    assert result.ran
    assert result.rc == 0
    assert "first" in lines
    assert "second" in result.output


def test_run_freshclam_collapses_progress_repaints():
    """freshclam-Fortschrittsbalken nutzen \\r-Ruecklaeufe: nur der Endstand
    darf als Zeile ankommen, nicht jeder Zwischenstand."""
    import sys

    lines = []
    result = run_freshclam(
        line_callback=lines.append,
        command=[
            sys.executable, "-c",
            (
                "import sys; sys.stdout.buffer.write(b'tick1\\rtick2\\rtick3\\r\\n'); "
                "sys.stdout.buffer.flush()"
            ),
        ],
    )
    assert result.rc == 0
    assert lines == ["tick3"]
    assert result.output == "tick3"


def test_run_freshclam_reports_a_timer_kill_as_timeout():
    """BUG-036: the kill timer ended the pipe, so EOF hid the timeout.

    ``readline`` returned EOF as soon as the timer killed the process and
    ``wait`` then returned rc=1 — ``timed_out`` stayed False and the GUI said
    "Update fehlgeschlagen (Code 1)" without the timeout hint. A genuine hang
    and a normal failure must stay distinguishable.
    """
    import sys
    import time

    started = time.monotonic()
    result = run_freshclam(
        command=[
            sys.executable, "-c",
            "import time; print('tick', flush=True); time.sleep(10)",
        ],
        timeout=0.7,
    )
    elapsed = time.monotonic() - started

    assert result.ran
    assert result.timed_out is True
    assert "Timeout" in result.output
    assert "abgebrochen" in result.output
    assert elapsed < 5, f"der Timer hat den Prozess nicht beendet ({elapsed:.1f}s)"


def test_run_freshclam_not_started(monkeypatch):
    monkeypatch.setattr(clamav_update, "build_command", lambda: None)
    result = run_freshclam()
    assert isinstance(result, FreshclamResult)
    assert not result.ran
    assert "nicht gefunden" in result.error


def test_user_conf_path_expands_env():
    path = user_conf_path()
    assert "%" not in str(path)  # %LocalAppData% expanded to a real path


@pytest.fixture()
def _quiet_window(monkeypatch):
    """MainWindow whose dispatcher builds no SUBPROCESS engines.

    ``MainWindow()`` probes ClamAV in its constructor (~2.2 s); these tests
    exercise button visibility, not detection. The scanner is built normally
    and then made to skip the probe: some tests here need
    ``clam.available is True`` (the button only appears for an installed
    engine), so ``enabled=False`` would change what is being tested.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    # Stub the engine probe, as tests/test_gui.py does: it otherwise runs on a
    # thread, finishes after the constructor returns and calls
    # _refresh_engine_status() -> _refresh_update_buttons() behind the test's
    # back. With the local DB here being over two weeks old that would flip
    # btn_clam_update to visible and race every "hidden" expectation below.
    monkeypatch.setattr("malaz.gui.main_window._EngineProbe.run", lambda self: None)
    monkeypatch.setattr(ClamAVScanner, "_choose_binary", lambda self: None)
    monkeypatch.setattr(
        ClamAVScanner, "_clamd_reachable", lambda self: (False, None)
    )
    scanner = ClamAVScanner()
    # present it as an installed engine without touching the filesystem
    monkeypatch.setattr(type(scanner), "available", property(lambda _s: True))
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=scanner,
    )


def test_gui_update_button_starts_hidden(qapp, monkeypatch, _quiet_window):
    # Contract: a HEALTHY engine shows no manual update button — it only
    # appears for the stale/missing cases (covered by
    # test_gui_button_shown_when_update_due).
    #
    # Everything that would make this machine-dependent is pinned:
    #  * `_EngineProbe.run` is stubbed by the fixture, otherwise the real probe
    #    runs on a thread, finishes ~2 s later and calls
    #    _refresh_update_buttons() behind the assertion's back (measured: it
    #    would flip the button to visible here, because this machine's DB is
    #    16 days old).
    #  * `update_due` / `read_db_dates` are forced to "healthy", since both
    #    read the local signature database.
    #  * `isVisibleTo`, not `isVisible()` — the latter is always False for a
    #    window that was never shown, which would make this test vacuous.
    from malaz.gui.main_window import MainWindow

    monkeypatch.setattr(
        "malaz.analysis.clamav_update.update_due", lambda **_k: (False, "aktuell")
    )
    monkeypatch.setattr(
        "malaz.analysis.clamav_status.read_db_dates", lambda: {"daily": object()}
    )
    window = MainWindow(dispatcher=_quiet_window)
    try:
        assert window.options_view.btn_clam_now.text() == "ClamAV"
        assert window.chk_clam_auto is not None  # opt-in switch present
    finally:
        window.close()


def test_gui_button_shown_when_update_due(qapp, monkeypatch, _quiet_window):
    # Stale signatures + opted-in auto-update must dispatch _AutoUpdateJob via
    # update_due(), while opt-in OFF starts zero jobs (offline-by-default).
    from malaz.gui.main_window import MainWindow, _AutoUpdateJob

    started: list[object] = []

    def fake_due(*, enabled=None, **_k):
        if not enabled:
            return False, "Auto-Update ist ausgeschaltet."
        return True, "Signaturen sind 9 Tag(e) alt — wird aktualisiert."

    monkeypatch.setattr("malaz.analysis.clamav_update.update_due", fake_due)
    window = MainWindow(dispatcher=_quiet_window)
    try:
        monkeypatch.setattr(window.thread_pool, "start", lambda job: started.append(job))
        window.chk_clam_auto.setChecked(False)
        window._maybe_auto_update_clamav()
        assert started == [], "opt-in OFF darf keinen Auto-Update-Job starten"

        window.chk_clam_auto.setChecked(True)
        window._maybe_auto_update_clamav()
        assert any(isinstance(j, _AutoUpdateJob) for j in started), (
            "faelliges ClamAV-Auto-Update muss _AutoUpdateJob starten"
        )
        assert window.options_view.btn_clam_now.isVisibleTo(window.options_view)
    finally:
        window.close()


def test_gui_button_hidden_when_clamav_absent(qapp, monkeypatch, _quiet_window):
    # Without freshclam/ClamAV, _maybe_auto_update_clamav() must never start a
    # background job even when the opt-in toggle is enabled.
    from malaz.gui.main_window import MainWindow

    started: list[object] = []
    monkeypatch.setattr("malaz.analysis.clamav_update.find_freshclam", lambda: None)
    window = MainWindow(dispatcher=_quiet_window)
    try:
        monkeypatch.setattr(window.thread_pool, "start", lambda job: started.append(job))
        window.chk_clam_auto.setChecked(True)
        window._maybe_auto_update_clamav()
        assert started == [], "ohne freshclam darf kein Auto-Update-Job starten"
    finally:
        window.close()


def test_gui_update_button_without_freshclam_shows_hint(
    qapp, monkeypatch, _quiet_window
):
    from PySide6.QtWidgets import QMessageBox

    from malaz.gui import main_window as mw

    calls = []
    monkeypatch.setattr(
        QMessageBox, "information",
        lambda *args, **kwargs: calls.append(args) or QMessageBox.StandardButton.Ok,
    )
    monkeypatch.setattr(
        "malaz.analysis.clamav_update.find_freshclam", lambda: None
    )
    window = mw.MainWindow(dispatcher=_quiet_window)
    try:
        window._on_update_clamav()
        assert len(calls) == 1
        assert "freshclam" in calls[0][2]
    finally:
        window.close()


def test_clam_update_dialog_finish_paths(qapp):
    from malaz.gui.main_window import _freshclam_runner, _StreamUpdateDialog

    dialog = _StreamUpdateDialog(
        title="ClamAV-Signaturen aktualisieren",
        hint="Test",
        runner=_freshclam_runner,
    )
    try:
        dialog._finish(0, "")
        assert "abgeschlossen" in dialog.output.toPlainText()
        dialog._finish(-1, "freshclam.exe nicht gefunden")
        assert "nicht gestartet" in dialog.output.toPlainText()
        dialog._finish(2, "")
        assert "Code 2" in dialog.output.toPlainText()
    finally:
        dialog.deleteLater()


# -- update_due: Startup-Entscheidung (opt-in, altersgesteuert) -------------- #


def _stub_dates(monkeypatch, dates):
    """Patch the DB-date reader used by update_due."""
    from malaz.analysis import clamav_status

    monkeypatch.setattr(clamav_status, "read_db_dates", lambda *_a, **_k: dates)


def test_update_due_disabled_is_never_due(monkeypatch):
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: object())
    due, reason = update_due(enabled=False)
    assert due is False
    assert "aus" in reason.lower()


def test_update_due_without_freshclam_is_not_due(monkeypatch):
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: None)
    due, reason = update_due(enabled=True)
    assert due is False
    assert "freshclam" in reason


def test_update_due_without_database_is_due(monkeypatch):
    # A missing DB means every ClamAV scan is skipped — this is THE case the
    # startup update exists for, regardless of age thresholds.
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: object())
    _stub_dates(monkeypatch, {})
    due, reason = update_due(enabled=True)
    assert due is True
    assert "Keine Signatur-Datenbank" in reason


def test_update_due_fresh_database_is_not_due(monkeypatch):
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: object())
    from datetime import UTC, datetime, timedelta

    fresh = datetime.now(UTC) - timedelta(hours=2)
    _stub_dates(monkeypatch, {"daily": fresh})
    due, reason = update_due(enabled=True, min_age_days=1)
    assert due is False
    assert "aktuell" in reason


def test_update_due_stale_database_is_due(monkeypatch):
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: object())
    from datetime import UTC, datetime, timedelta

    old = datetime.now(UTC) - timedelta(days=5)
    _stub_dates(monkeypatch, {"daily": old})
    due, reason = update_due(enabled=True, min_age_days=1)
    assert due is True
    assert "5 Tag" in reason


def test_update_due_threshold_is_configurable(monkeypatch):
    monkeypatch.setattr(clamav_update, "find_freshclam", lambda: object())
    from datetime import UTC, datetime, timedelta

    two_days = datetime.now(UTC) - timedelta(days=2)
    _stub_dates(monkeypatch, {"daily": two_days})
    assert update_due(enabled=True, min_age_days=1)[0] is True
    assert update_due(enabled=True, min_age_days=3)[0] is False


# -- clamd: der Unterschied zwischen 19 Sekunden und 0,2 ------------------- #


def test_start_clamd_merkt_wenn_er_schon_laeuft(monkeypatch):
    """Laeuft der Daemon, wird KEIN zweiter gestartet.

    Zwei clamd-Prozesse auf demselben Port: der zweite stirbt mit einer
    Fehlermeldung, aber der Nutzer saehe sie nie — und ein Startversuch, der
    nur scheitern kann, kostet beim Programmstart Sekunden.
    """
    from malaz.analysis import clamav_update as cu

    monkeypatch.setattr(cu, "clamd_port_offen", lambda *a, **k: True)
    gestartet = []
    monkeypatch.setattr(cu.subprocess, "Popen", lambda *a, **k: gestartet.append(a))
    ok, grund = cu.start_clamd()
    assert ok is True
    assert "laeuft bereits" in grund
    assert gestartet == [], "es darf kein zweiter Daemon gestartet werden"


def test_start_clamd_ohne_binary_sagt_warum(monkeypatch):
    """Ohne clamd.exe muss die Meldung sagen, was fehlt."""
    from malaz.analysis import clamav_update as cu

    monkeypatch.setattr(cu, "clamd_port_offen", lambda *a, **k: False)
    monkeypatch.setattr(cu, "find_clamd", lambda: None)
    ok, grund = cu.start_clamd(timeout=1)
    assert ok is False
    assert "nicht gefunden" in grund


def test_start_clamd_gibt_nach_der_frist_auf(monkeypatch):
    """Ein Daemon, der sich nicht meldet, darf den Start nicht blockieren."""
    from malaz.analysis import clamav_update as cu

    monkeypatch.setattr(cu, "clamd_port_offen", lambda *a, **k: False)
    monkeypatch.setattr(cu, "find_clamd", lambda: Path("C:/gibt/es/nicht/clamd.exe"))
    monkeypatch.setattr(cu, "clamd_conf_path", lambda: "C:/tmp/clamd.conf")
    monkeypatch.setattr(cu.subprocess, "Popen", lambda *a, **k: None)
    ok, grund = cu.start_clamd(timeout=0.3)
    assert ok is False
    assert "binnen" in grund


class _Signal:
    """Doppelgaenger des Qt-Signals: `ready` ist ein Objekt mit `.emit`."""

    def __init__(self, sammlung):
        self._sammlung = sammlung

    def emit(self, *args):
        self._sammlung.append(args)


class _Signale:
    def __init__(self):
        self.meldungen: list = []
        self.ready = _Signal(self.meldungen)


def test_der_startjob_erreicht_start_clamd_wirklich(monkeypatch):
    """Der Job muss start_clamd AUFRUFEN — nicht nur so aussehen.

    Die erste Fassung baute den Scanner mit ``enabled=False`` und pruefte
    ``_clamdscan``. Weil der Konstruktor die Binaries nur sucht, wenn er
    aktiviert ist (``if self.enabled:`` in clamav.py), war das IMMER None:
    der Job stieg ausnahmslos aus, und der Autostart lief in der Anwendung
    nie. Aufgefallen ist das nicht, weil ``start_clamd()`` direkt getestet
    war — der Weg DORTHIN war es nicht.

    Deshalb prueft dieser Test den Aufruf selbst, nicht seine Wirkung.
    """
    from malaz.gui.main_window import _ClamdStartJob

    gerufen: list = []

    # start_clamd/clamd_port_offen an der QUELLE ersetzen, damit der Job sie
    # ueber seinen lokalen Import findet.
    import malaz.analysis.clamav_update as cu

    monkeypatch.setattr(cu, "clamd_port_offen", lambda *a, **k: False)
    monkeypatch.setattr(cu, "start_clamd", lambda *a, **k: (gerufen.append(1), (True, "gestartet"))[1])

    from malaz import config

    monkeypatch.setattr(config, "CLAMAV_ENABLED", True)
    # clamdscan muss "da" sein — sonst steigt der Job zu Recht aus.
    import malaz.analysis.clamav as ca

    monkeypatch.setattr(
        ca.ClamAVScanner, "_locate_binaries",
        lambda self: (Path("C:/x/clamscan.exe"), Path("C:/x/clamdscan.exe")),
    )
    job = _ClamdStartJob(_Signale())
    job.run()
    assert gerufen, (
        "der Job hat start_clamd NICHT gerufen — der Autostart ist wirkungslos "
        f"(Meldung war: {job.signals.meldungen})"
    )


def test_der_startjob_startet_nichts_bei_ausgeschalteter_stufe(monkeypatch):
    """Ist die ClamAV-Stufe aus, hat ein 170-MB-Daemon keinen Zweck."""
    import malaz.analysis.clamav as ca
    import malaz.analysis.clamav_update as cu
    from malaz import config
    from malaz.gui.main_window import _ClamdStartJob

    gerufen: list = []

    monkeypatch.setattr(config, "CLAMAV_SCAN_CANDIDATES", ())
    monkeypatch.setattr(ca, "which_absolute", lambda _n: None)
    monkeypatch.setattr(
        ca.ClamAVScanner,
        "_locate_binaries",
        lambda self: (Path("C:/x/clamscan.exe"), Path("C:/x/clamdscan.exe")),
    )
    monkeypatch.setattr(ca.ClamAVScanner, "_choose_binary", lambda self: None)
    monkeypatch.setattr(cu, "clamd_port_offen", lambda *a, **k: False)
    monkeypatch.setattr(cu, "start_clamd", lambda *a, **k: (gerufen.append(1), (True, ""))[1])
    monkeypatch.setattr(config, "CLAMAV_ENABLED", False)

    job = _ClamdStartJob(_Signale())
    job.run()
    assert gerufen == [], "bei ausgeschalteter Stufe darf kein Daemon starten"


def test_fehler_im_startjob_entkommt_nicht(monkeypatch):
    """Eine Ausnahme darf den Threadpool nicht verlassen.

    Ein Runnable kennt keinen Aufrufer: ohne den Fang wandert die Ausnahme in
    die Qt-Ereignisschleife. Gemessen im vollen Suite-Lauf — sie schlug beim
    NAECHSTEN Testaufbau durch ("Exceptions caught in Qt event loop" bei einem
    voellig anderen Test), und die Ursache lag drei Tests vorher.

    Der Test prueft ``run()``, nicht eine Zwischenmethode: genau diese Huelle
    war ungeprueft, als conftest noch den Job statt des Ausloesers stilllegte.
    """
    import malaz.analysis.clamav as ca
    import malaz.analysis.clamav_update as cu
    from malaz import config
    from malaz.gui.main_window import _ClamdStartJob

    platzt_gerufen = False

    def platzt(*_a, **_k):
        nonlocal platzt_gerufen
        platzt_gerufen = True
        raise RuntimeError("absichtlich")

    monkeypatch.setattr(config, "CLAMAV_ENABLED", True)
    monkeypatch.setattr(config, "CLAMAV_SCAN_CANDIDATES", ())
    monkeypatch.setattr(ca, "which_absolute", lambda _n: None)
    monkeypatch.setattr(
        ca.ClamAVScanner,
        "_locate_binaries",
        lambda self: (Path("C:/x/clamscan.exe"), Path("C:/x/clamdscan.exe")),
    )
    monkeypatch.setattr(ca.ClamAVScanner, "_choose_binary", lambda self: None)
    # Mitten im Entscheidungsweg, nicht am Rand: sonst wird ein Zweig
    # geprueft, der ohnehin vorher aussteigt (mit laufendem Daemon kam der
    # Test so bis "clamd laeuft." und die Huelle blieb unberuehrt).
    monkeypatch.setattr(cu, "clamd_port_offen", platzt)

    sammlung: list = []

    class _Signal:
        def emit(self, *args):
            sammlung.append(args)

    class _Signale:
        def __init__(self):
            self.ready = _Signal()

    job = _ClamdStartJob(_Signale())
    job.run()  # darf NICHT werfen

    assert platzt_gerufen, "clamd_port_offen wurde gar nicht erreicht"
    assert sammlung, "der Fehlschlag muss gemeldet werden, nicht stumm bleiben"
    assert "uebersprungen" in sammlung[0][0], sammlung
