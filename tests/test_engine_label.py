"""Tests für die Engine-Statuszeile der GUI (Wahrheit statt Binary-Existenz).

Feld-Befund: Auf einem Rechner mit totem Defender-Dienst und ClamAV ohne
Signatur-DB zeigte die GUI „Windows Defender bereit · ClamAV bereit" —
während jede Datei AV_SKIPPED/CLAMAV_SKIPPED produzierte. „Bereit" heißt
ab jetzt: kann wirklich scannen.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def _fake_dispatcher(*, av_available, defender_probed, can_scan,
                     clam_available, clam_binary, clam_db):
    av = SimpleNamespace(available=av_available)
    clam = SimpleNamespace(available=clam_available, binary=clam_binary,
                           database=clam_db)
    yara = SimpleNamespace(available=True, load_error=None)
    status = SimpleNamespace(
        probed=defender_probed, can_scan=can_scan, error=None,
        summary="Modus: not running | On-Demand NICHT möglich"
        if not can_scan else "Modus: normal | On-Demand möglich",
    )
    return SimpleNamespace(
        av_scanner=av, clam_scanner=clam, yara=yara,
        external_scanners=[], defender_status=status,
    )


def _line(d):
    from malaz.gui.main_window import _build_engine_line

    with mock.patch("malaz.analysis.clamav_status.collect_status") as collect, \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        collect.return_value = SimpleNamespace(
            binary_version="ClamAV 1.5.3", db_dates={}, db_dir="",
            remote_dates=None, error=None)
        die.return_value = SimpleNamespace(available=False)
        return _build_engine_line(d)


def test_dead_defender_service_is_not_ready():
    d = _fake_dispatcher(
        av_available=True, defender_probed=True, can_scan=False,
        clam_available=False, clam_binary=None, clam_db=None)
    line = _line(d)
    assert "nicht bereit (Dienst aus" in line
    assert "Defender bereit" not in line


def test_defender_without_binary_is_unavailable():
    d = _fake_dispatcher(
        av_available=False, defender_probed=False, can_scan=False,
        clam_available=False, clam_binary=None, clam_db=None)
    assert "Windows Defender nicht verfügbar" in _line(d)


def test_clamav_without_database_says_freshclam():
    d = _fake_dispatcher(
        av_available=False, defender_probed=False, can_scan=False,
        clam_available=True, clam_binary=Path(r"C:\ClamAV\clamscan.exe"),
        clam_db=None)
    line = _line(d)
    assert "Signatur-DB fehlt" in line and "freshclam" in line
    assert "ClamAV bereit" not in line


def test_clamav_with_database_or_daemon_is_ready():
    d = _fake_dispatcher(
        av_available=False, defender_probed=False, can_scan=False,
        clam_available=True, clam_binary=Path(r"C:\ClamAV\clamscan.exe"),
        clam_db=Path(r"C:\db"))
    assert "ClamAV bereit" in _line(d)

    d2 = _fake_dispatcher(
        av_available=False, defender_probed=False, can_scan=False,
        clam_available=True, clam_binary=Path(r"C:\ClamAV\clamdscan.exe"),
        clam_db=None)  # Daemon nutzt seine eigene DB — Pfad hier egal
    assert "bereit (clamd-Daemon)" in _line(d2)


def test_healthy_defender_still_says_ready():
    d = _fake_dispatcher(
        av_available=True, defender_probed=True, can_scan=True,
        clam_available=False, clam_binary=None, clam_db=None)
    line = _line(d)
    assert "Windows Defender bereit" in line
    assert "nicht bereit" not in line


# ---- Ampel (Traffic-Light) --------------------------------------------------

def _health(d):
    from malaz.gui.main_window import _engine_health

    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: None), \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        die.return_value = SimpleNamespace(available=False)
        return _engine_health(d)


def _fd(*, av_ok=True, probed=True, can_scan=True,
        clam_on=True, clam_bin=r"C:\ClamAV\clamscan.exe", clam_db=r"C:\db",
        yara_on=True, yara_err=None):
    return SimpleNamespace(
        av_scanner=SimpleNamespace(available=av_ok),
        clam_scanner=SimpleNamespace(
            available=clam_on, binary=Path(clam_bin) if clam_bin else None,
            database=Path(clam_db) if clam_db else None),
        yara=SimpleNamespace(available=yara_on, load_error=yara_err),
        external_scanners=[],
        defender_status=SimpleNamespace(probed=probed, can_scan=can_scan,
                                        error=None, summary="x"),
    )


def test_ampel_red_when_no_av_engine_works():
    d = _fd(av_ok=True, can_scan=False,          # Defender-Dienst tot
            clam_on=True, clam_db=None)          # ClamAV ohne DB
    level, short = _health(d)
    assert level == "error" and "Kein funktionsfähiger AV" in short


def test_ampel_red_when_yara_missing():
    d = _fd(yara_on=False)
    assert _health(d)[0] == "error"


def test_ampel_yellow_when_only_second_engine_down():
    d = _fd(av_ok=True, can_scan=True, clam_on=True, clam_db=None)
    level, short = _health(d)
    assert level == "warn" and "Signatur-DB" in short


def test_ampel_yellow_when_defender_dead_but_clam_works():
    d = _fd(av_ok=True, can_scan=False, clam_on=True, clam_db=r"C:\db")
    level, short = _health(d)
    assert level == "warn" and "Defender" in short


def test_ampel_green_when_all_ready():
    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: "C:/7z.exe"):
        from malaz.gui.main_window import _engine_health

        d = _fd()
        level, short = _engine_health(d)
    assert level == "ok" and "Alle Schutz-Engines bereit" in short


def test_ampel_daemon_without_db_path_still_usable():
    # clamd-Daemon nutzt seine eigene DB — der gefundene Pfad ist egal.
    d = _fd(av_ok=False, clam_bin=r"C:\ClamAV\clamdscan.exe", clam_db=None)
    level, short = _health(d)
    assert level == "warn" and "Defender" in short  # nicht "kein AV"


# ---- Badge-Reihe (eine Ampel je Engine) -------------------------------------

def _badges(d):
    from malaz.gui.main_window import _engine_badges

    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: None), \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        die.return_value = SimpleNamespace(available=False)
        return {name: (state, tip) for name, state, tip in _engine_badges(d)}


def test_badges_reflect_field_finding():
    # Feld-Befund: Defender-Dienst tot + ClamAV ohne DB -> zwei ROTE Badges.
    d = _fd(av_ok=True, can_scan=False, clam_on=True, clam_db=None)
    b = _badges(d)
    assert b["Defender"][0] == "error" and "Dienst" in b["Defender"][1]
    assert b["ClamAV"][0] == "error" and "freshclam" in b["ClamAV"][1]
    assert b["YARA"][0] == "ok"
    assert b["7-Zip"][0] == "warn"      # nicht installiert -> GELB (Luecke)
    assert b["DIE"][0] == "off"         # optional -> GRAU, kein Alarm


def test_badges_all_ok_when_everything_ready():
    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: "C:/7z.exe"), \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        die.return_value = SimpleNamespace(available=True)
        from malaz.gui.main_window import _engine_badges

        b = {n: s for n, s, _t in _engine_badges(_fd())}
    assert b == {"Defender": "ok", "ClamAV": "ok", "YARA": "ok",
                 "7-Zip": "ok", "DIE": "ok"}


def test_badges_daemon_mode_is_ok_without_db_path():
    d = _fd(av_ok=False, clam_bin=r"C:\ClamAV\clamdscan.exe", clam_db=None)
    assert _badges(d)["ClamAV"][0] == "ok"


def test_badges_missing_clamav_is_off_not_red():
    # Fehlendes ClamAV ist KEIN Fehler: Defender deckt die AV-Spalte ab.
    d = _fd(clam_on=False, clam_bin=None, clam_db=None)
    assert _badges(d)["ClamAV"][0] == "off"


def test_badges_yara_rule_error_is_warn():
    d = _fd(yara_err="bad.yar: syntax error")
    assert _badges(d)["YARA"][0] == "warn"


# ---- 7-Zip-Stufe: Binary vorhanden heisst nicht Abdeckung --------------------

def _sevenzip_badge(*, binary="C:/7z.exe"):
    """Badge-Tupel fuer 7-Zip mit gestubbtem Binary und echter config."""
    from malaz.gui.main_window import _engine_badges

    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: binary), \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        die.return_value = SimpleNamespace(available=True)
        return {n: (s, t) for n, s, t in _engine_badges(_fd())}["7-Zip"]


def test_badge_sevenzip_disabled_stage_does_not_promise_coverage(monkeypatch):
    """Regression (malaz/core/dispatcher/sevenzip-disabled-stage-reports-green).

    Der Badge las nur ``find_7z_binary()``: mit installiertem 7-Zip meldete er
    in BEIDEN Zustaenden „RAR/7z/deb/rpm-Inhalte werden entpackt und gescannt"
    — auch wenn ``config.SEVENZIP_ENABLED=False`` die Stufe abschaltet und der
    Inhalt nie entpackt wird (je Datei ARCH_7Z_DISABLED).
    """
    from malaz import config

    monkeypatch.setattr(config, "SEVENZIP_ENABLED", False)
    state, tip = _sevenzip_badge()
    assert state != "ok", "abgeschaltete Stufe darf nicht gruen leuchten"
    assert "werden entpackt und gescannt" not in tip
    assert "ungeprüft" in tip

    # Und die Abdeckungszusage gilt weiter, wenn die Stufe laeuft.
    monkeypatch.setattr(config, "SEVENZIP_ENABLED", True)
    state, tip = _sevenzip_badge()
    assert state == "ok" and "werden entpackt und gescannt" in tip


def test_engine_line_reports_disabled_sevenzip_stage(monkeypatch):
    """Die Statuszeile behauptete „7-Zip bereit" auch bei abgeschalteter Stufe."""
    from malaz import config

    monkeypatch.setattr(config, "SEVENZIP_ENABLED", False)
    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: "C:/7z.exe"), \
         mock.patch("malaz.analysis.clamav_status.collect_status") as collect, \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        collect.return_value = SimpleNamespace(
            binary_version="ClamAV 1.5.3", db_dates={}, db_dir="",
            remote_dates=None, error=None)
        die.return_value = SimpleNamespace(available=False)
        from malaz.gui.main_window import _build_engine_line

        line = _build_engine_line(_fd())
    assert "7-Zip bereit" not in line
    assert "7-Zip abgeschaltet" in line


def test_ampel_warns_when_sevenzip_stage_disabled(monkeypatch):
    """Ein gefundenes Binary bei abgeschalteter Stufe ist keine gruene Ampel."""
    from malaz import config

    monkeypatch.setattr(config, "SEVENZIP_ENABLED", False)
    with mock.patch("malaz.core.sevenzip.find_7z_binary", lambda: "C:/7z.exe"), \
         mock.patch("malaz.analysis.die.DieScanner") as die:
        die.return_value = SimpleNamespace(available=False)
        from malaz.gui.main_window import _engine_health

        level, short = _engine_health(_fd())
    assert level == "warn" and "abgeschaltet" in short


def test_badge_shows_age_of_external_yara_rules(monkeypatch, tmp_path):
    """AP6: Update-Alter muss sichtbar sein, nicht nur 'Regeln geladen'."""
    import os
    import time

    from malaz import config

    rules = tmp_path / "external"
    rules.mkdir()
    bundle = rules / "bundle.yarc"
    bundle.write_bytes(b"x")
    old = time.time() - 40 * 86400 - 3600
    os.utime(bundle, (old, old))
    monkeypatch.setattr(config, "YARA_EXTERNAL_DIR", rules)

    state, tip = _badges(_fd())["YARA"]
    assert state == "ok"
    assert "Externe YARA-Regeln" in tip
    assert "40 Tag" in tip
