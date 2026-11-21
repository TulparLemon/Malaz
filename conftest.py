"""Pytest bootstrap: make the ``src`` layout importable without installation.

Also pins the user-writable threat-intel lists to non-existent paths: tests
must not depend on what the developer has imported into
``%LocalAppData%\\Malaz\\hashes\\``. Without this the suite would pass or fail
depending on the machine's blocklist content (measured: a populated URL list
made the "reputation is off by default" contract test fail).
"""

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def pytest_configure(config):
    """Create the PARENT of ``--basetemp`` so a fresh checkout can run the suite.

    pytest creates the basetemp directory itself, but without ``parents=True``.
    CI and the docs call ``--basetemp=.pytest-tmp/ci``; on a fresh clone
    ``.pytest-tmp`` does not exist (it is gitignored), and every test errored
    with FileNotFoundError before running (measured: 1911 errors on GitHub
    Actions, 1916 on a freshly cloned C:\\Malaz). Only the parent is created;
    the basetemp itself stays pytest's job, so its clean-up semantics are
    unchanged.
    """
    basetemp = getattr(config.option, "basetemp", None)
    if basetemp:
        Path(basetemp).resolve().parent.mkdir(parents=True, exist_ok=True)


@pytest.fixture(autouse=True)
def _isolate_user_threat_intel(tmp_path_factory, monkeypatch):
    """Point both imported-list config values at empty temp paths.

    ``config.USER_HASH_BLOCKLIST_FILE`` and ``config.URL_BLOCKLIST_FILE`` live
    in the user profile by design; a test run must observe the project's
    defaults, not the developer's imports. The files are never created, so the
    loaders see "missing" — exactly the state of a fresh install.

    Tests that need content set these values themselves (they run after this
    fixture and win).
    """
    from malaz import config

    empty = tmp_path_factory.mktemp("no_user_threat_intel")
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", empty / "hashes.sha256")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", empty / "urls.sha256")
    # Die beiden in dieser Sitzung hinzugekommenen Listen fehlten hier — der
    # Testlauf las damit die ECHTEN Nutzerdaten des Entwicklers (gemessen
    # 385 895 Domains und 1 715 Netze). Das ist nicht nur langsamer: ein
    # Fixture, dessen Absenderdomain zufaellig in der importierten Liste steht,
    # bekaeme MAIL_SENDER_DOMAIN_BLOCKED (CRITICAL/50) und kippte von GRUEN auf
    # ROT — das Ergebnis haenge dann davon ab, wer die Suite laufen laesst.
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", empty / "domains.txt")
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", empty / "netze.txt")


@pytest.fixture(scope="session", autouse=True)
def _production_recursion_limit():
    """Die Tests muessen unter dem Limit laufen, unter dem das Produkt laeuft.

    ``core/ole_depth.ensure_walk_limit()`` setzt das Prozesslimit beim
    MODUL-IMPORT auf ``HARD_MAX_FRAMES``. Das ist die Begruendung des
    .eml-Tiefen-Guards: die Parse-Kosten des stdlib-Parsers wachsen quadratisch,
    und sichtbar wird das erst oberhalb der Rekursionsgrenze — mit dem
    Standardlimit 1000 bricht der Parser bei ~1600 Ebenen ab und die Kurve sieht
    linear aus. Genau daran ist in Runde 11 eine Messung gescheitert: sie lief
    unterhalb der Grenze und liess den Guard kurzzeitig wie unnoetig aussehen.

    Wandert ``ensure_walk_limit()`` je aus dem Import heraus, messen alle
    Parser-Tests still unterhalb des Produktionszustands, und der Docstring in
    ``tests/test_email_rtf.py`` wird falsch, ohne dass ein Test rot wird. Diese
    Zusicherung macht daraus einen Fehlschlag.
    """
    import sys

    from malaz.core import ole_depth

    limit = sys.getrecursionlimit()
    assert limit >= ole_depth.HARD_MAX_FRAMES, (
        f"Prozesslimit ist {limit}, erwartet >= {ole_depth.HARD_MAX_FRAMES}: "
        "die Tests messen unterhalb des Produktionszustands "
        "(ensure_walk_limit laeuft beim Import von core/ole_depth)"
    )


@pytest.fixture(autouse=True)
def _isolate_settings(tmp_path, monkeypatch):
    """Die Fenster-Einstellungen in eine Temp-INI umbiegen.

    ``MainWindow`` liest beim Aufbau seine Haken aus den Einstellungen, und
    der capa-Haken SCHREIBT sie auch. Ohne diese Kapselung gilt:

    * Wer den Haken in der App einmal gesetzt hat, bekommt im Testprozess
      ``config.CAPA_ENABLED = True`` — global, fuer alle folgenden Tests.
      ``test_capa_is_opto…`` prueft genau ``is False`` und haelt damit nur,
      solange test_capa.py vor test_gui.py laeuft.
    * Ein Test, der den Haken klickt, schreibt in die Registry des
      Entwicklers. Gemessen stand ``capa_enabled`` danach in
      ``HKCU\\Software\\Malaz``.

    Umgesetzt ueber die Naht ``gui.settings.app_settings`` statt ueber
    ``QSettings.setDefaultFormat(IniFormat)``: letzteres liess ``fileName()``
    im Versuch weiter auf die Registry zeigen, die Umleitung greift in
    PySide6 nicht.
    """
    from PySide6.QtCore import QSettings

    from malaz.gui import settings as settings_module

    ini = tmp_path / "malaz_settings.ini"
    monkeypatch.setattr(
        settings_module,
        "app_settings",
        lambda: QSettings(str(ini), QSettings.Format.IniFormat),
    )
    # Und den Namen, den main_window importiert hat, mit umbiegen.
    import malaz.gui.main_window as mw

    monkeypatch.setattr(
        mw, "app_settings", lambda: QSettings(str(ini), QSettings.Format.IniFormat)
    )


@pytest.fixture(autouse=True)
def _kein_echter_clamd(monkeypatch):
    """Kein Test startet einen clamd-Daemon auf der Maschine des Entwicklers.

    Stillgelegt wird der AUSLOESER, nicht die Arbeit. ``_start_clamd_if_needed``
    ist der einzige Weg, auf dem ein Test an einen Daemonstart geraten kann —
    jedes ``MainWindow`` plant ihn ein, und ohne laufenden Daemon ruft der Job
    ``start_clamd()``, einen echten Prozess mit rund 170 MB, der den Testlauf
    ueberlebt.

    Warum nicht eine Ebene tiefer (der Job, oder gar ``start_clamd``): dann
    waere die VERDRAHTUNG ungeprueft — und genau die hat heute zugeschlagen
    ("die Funktion geht, der Aufruf nicht": der Waechter stieg immer aus, und
    weil ich nur ``start_clamd`` direkt getestet hatte, merkte es niemand).
    So bleiben ``run()`` samt Fehlerisolation und die Entscheidung darin echt
    und pruefbar.
    """
    monkeypatch.setattr(
        "malaz.gui.main_window.MainWindow._start_clamd_if_needed", lambda self: None
    )


@pytest.fixture()
def window(qtbot, monkeypatch):
    """Ein echtes MainWindow mit abgeschalteten AV-Engines.

    Steht hier und nicht in test_gui.py, weil mehrere Testdateien sie
    brauchen (die Anzeige-Randfaelle ebenso wie die GUI-Tests). Eine Fixture
    in einer Testdatei ist fuer die anderen unsichtbar — genau daran
    scheiterten die Randfall-Tests zuerst.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import MainWindow

    # The engine probe (PowerShell/clamscan, off-thread) is not what these
    # tests exercise; disabling it keeps the global thread pool quiet so the
    # scan workers finish deterministically between tests.
    monkeypatch.setattr("malaz.gui.main_window._EngineProbe.run", lambda self: None)
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    # Pass it IN rather than overwriting afterwards: the window's default is a
    # live Dispatcher whose constructor probes ClamAV — measured 2.2 s, paid
    # once per test and discarded again here.
    win = MainWindow(dispatcher=dispatcher)
    qtbot.addWidget(win)
    win.show()
    return win


@pytest.fixture(autouse=True)
def _isolate_log_dir(tmp_path_factory, monkeypatch):
    """Redirect runtime diagnostics away from %LOCALAPPDATA%/Malaz/logs during tests."""
    import logging

    log_dir = tmp_path_factory.mktemp("malaz_logs")
    monkeypatch.setenv("MALAZ_LOG_DIR", str(log_dir))
    yield
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if getattr(handler, "_malaz_privacy_handler", False):
            root_logger.removeHandler(handler)
            handler.close()


@pytest.fixture(autouse=True)
def _isolate_language():
    """Keep active UI language deterministically pinned to ``de`` between tests."""
    from contextlib import suppress

    from malaz import i18n

    i18n.set_language("de")
    with suppress(ImportError):
        from malaz.gui import settings as gui_settings

        gui_settings._ACTIVE_LANG_PREF = None
    yield
    i18n.set_language("de")
    with suppress(ImportError):
        from malaz.gui import settings as gui_settings

        gui_settings._ACTIVE_LANG_PREF = None
