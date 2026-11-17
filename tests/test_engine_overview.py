"""Tests für die Engine-Diagnose im Log („warum geht Defender/ClamAV nicht?")."""

import logging

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.defender_status import probe
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher


def test_mpcmdrun_missing_logs_candidates(monkeypatch, caplog):
    from malaz import config

    monkeypatch.setattr(
        config, "AV_MPCMDRUN_CANDIDATES", (r"C:\gibt_es_nicht\MpCmdRun.exe",)
    )
    with caplog.at_level(logging.WARNING):
        scanner = WindowsDefenderScanner()
    assert not scanner.available
    assert any(
        "MpCmdRun nicht gefunden" in r.message and "gibt_es_nicht" in r.message
        for r in caplog.records
    ), "Der Log muss nennen, WO gesucht wurde"


def test_mpcmdrun_found_logs_path(caplog):
    with caplog.at_level(logging.INFO):
        scanner = WindowsDefenderScanner()
    if scanner.available:  # Host mit Defender
        assert any("MpCmdRun gefunden" in r.message for r in caplog.records)
    else:
        # TEST-036: Ohne Defender gab es GAR KEINE Assertion — der Test war
        # gruen, ohne etwas zu pruefen. Der Kontrakt gilt in beide Richtungen:
        # ein Pfad, der nicht gefunden wurde, darf NICHT als gefunden geloggt
        # werden, und bei aktiver Stufe muss der Grund im Log stehen.
        assert not any("MpCmdRun gefunden" in r.message for r in caplog.records)
        if scanner.enabled:
            assert any("MpCmdRun nicht gefunden" in r.message for r in caplog.records)


def test_engine_overview_once_per_run(tmp_path, monkeypatch, caplog):
    from malaz import config

    monkeypatch.setattr(
        config, "AV_MPCMDRUN_CANDIDATES", (r"C:\gibt_es_nicht\MpCmdRun.exe",)
    )
    target = tmp_path / "datei.txt"
    target.write_bytes(b"harmlos")
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    with caplog.at_level(logging.INFO):
        d.scan_path(target)
        d.scan_path(target)
    defender_lines = [r for r in caplog.records if "[Engines] Defender" in r.message]
    assert len(defender_lines) == 1, "Überblick muss genau EINMAL pro Lauf stehen"
    assert "nicht verfügbar" in defender_lines[0].message
    assert any("ClamAV: deaktiviert" in r.message for r in caplog.records)


def test_defender_status_probe_logs_failure(monkeypatch, caplog):
    monkeypatch.setattr(
        "malaz.analysis.defender_status.which_absolute", lambda name: None
    )
    with caplog.at_level(logging.WARNING):
        status = probe()
    assert not status.probed
    assert any("nicht abrufbar" in r.message for r in caplog.records)


def test_datenbank_wird_nach_dem_nachladen_erkannt(tmp_path, monkeypatch):
    """DIE Ursache vom 22.09.2026: Abzeichen blieb rot bis zum Neustart.

    Der Scanner bestimmt Binary und Signatur-DB EINMALIG beim Bau. Wird die
    Datenbank danach ueber Malaz nachgeladen, benutzt der Statusabgleich
    dieselbe Instanz — und sieht sie nie. Der Nutzer laedt nach, das
    Abzeichen bleibt rot, erst ein Neustart hilft.

    Hier wird genau dieser Ablauf nachgestellt: bauen OHNE Datenbank
    (-> ``error``), Datenbank anlegen, Abgleich, erneut pruefen (-> ``ok``).
    """
    from malaz import config
    from malaz.gui.main_window import _engine_badges

    db_dir = tmp_path / "db"
    db_dir.mkdir()
    monkeypatch.setattr(config, "CLAMAV_DB_CANDIDATES", (db_dir,))
    # Ein Binary muss "da" sein, sonst greift der Rot-Zweig gar nicht.
    fake_bin = tmp_path / "clamscan.exe"
    fake_bin.write_bytes(b"MZ")

    scanner = ClamAVScanner(enabled=True)
    scanner._clamscan = fake_bin
    scanner._clamdscan = None
    scanner.binary = fake_bin
    scanner.database = None          # wie unmittelbar nach dem Start ohne DB

    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=scanner,
    )
    vorher = dict((n, s) for n, s, _t in _engine_badges(dispatcher))
    assert vorher["ClamAV"] == "error", "Vorbedingung: ohne DB ist es rot"

    # JETZT laedt der Nutzer die Signaturen nach.
    (db_dir / "main.cvd").write_bytes(b"CVD" + b"\0" * 64)

    # Ohne den Abgleich bliebe es rot — genau der gemeldete Fehler.
    unveraendert = dict((n, s) for n, s, _t in _engine_badges(dispatcher))
    assert unveraendert["ClamAV"] == "error", (
        "Vorbedingung: ohne refresh_state() sieht der Status die neue DB nicht"
    )

    scanner.refresh_state()
    nachher = dict((n, s) for n, s, _t in _engine_badges(dispatcher))
    assert nachher["ClamAV"] == "ok", (
        "nach dem Nachladen muss das Abzeichen gruen werden, ohne Neustart"
    )


def test_refresh_state_pingt_den_daemon_nicht_erneut(tmp_path, monkeypatch):
    """Der Abgleich darf keinen zusaetzlichen Prozessstart kosten.

    ``_choose_binary`` pingt clamd. Laeuft das bei jeder Statusabfrage,
    kostet jede Abfrage einen Prozessstart — fuer eine Information, die sich
    nicht geaendert hat.
    """
    from malaz import config

    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "main.cvd").write_bytes(b"CVD" + b"\0" * 64)
    monkeypatch.setattr(config, "CLAMAV_DB_CANDIDATES", (db_dir,))

    fake_bin = tmp_path / "clamscan.exe"
    fake_bin.write_bytes(b"MZ")
    scanner = ClamAVScanner(enabled=True)
    scanner._clamscan = fake_bin
    scanner.binary = fake_bin          # Binary ist bekannt

    import malaz.analysis.clamav as modul

    def verboten(*_a, **_k):
        raise AssertionError("_locate_binaries darf hier nicht laufen")

    monkeypatch.setattr(modul.ClamAVScanner, "_locate_binaries", verboten)
    scanner.refresh_state()
    assert scanner.database == db_dir, "die Datenbank muss trotzdem gefunden werden"


def test_badges_distinguish_deactivated_clamav_and_empty_yara(tmp_path, monkeypatch):
    """BUG-037/BUG-079: 'deaktiviert' und 'keine Regeln' sind nicht 'nicht installiert'/'ok'."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.core.yara_engine import YaraEngine
    from malaz.gui.main_window import _engine_badges

    clam = ClamAVScanner(enabled=False)
    yara = YaraEngine()
    yara._rules = []
    yara.available = True
    yara.load_error = None
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=clam,
        yara=yara,
    )
    badges = {n: (s, t) for n, s, t in _engine_badges(dispatcher)}
    assert badges["ClamAV"][0] == "off"
    assert "Deaktiviert" in badges["ClamAV"][1]
    assert badges["YARA"][0] == "warn"
    assert "Keine Regeln" in badges["YARA"][1]
