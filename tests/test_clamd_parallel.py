"""Tests für clamd-Daemon-Bevorzugung und parallele AV-Engines.

Hintergrund (Messung): ein frischer clamscan-Prozess lädt bei jedem Start
die komplette Signatur-DB (~15+ s); der clamd-Daemon hält sie im Speicher
(Millisekunden pro Scan). Defender + ClamAV laufen dafür pro Datei
parallel statt sequenziell.
"""

import threading
from pathlib import Path
from unittest import mock

from malaz.analysis.clamav import ClamAVResult, ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import ScanResult

# ---- clamd-Auswahl ---------------------------------------------------------

def _fake_binaries(tmp_path):
    (tmp_path / "clamscan.exe").write_bytes(b"MZ")
    (tmp_path / "clamdscan.exe").write_bytes(b"MZ")
    return tmp_path


def _patch_candidates(monkeypatch, tmp_path):
    from malaz import config

    monkeypatch.setattr(
        config,
        "CLAMAV_SCAN_CANDIDATES",
        (str(tmp_path / "clamscan.exe"), str(tmp_path / "clamdscan.exe")),
    )


def test_prefers_clamdscan_when_daemon_answers(tmp_path, monkeypatch):
    _patch_candidates(monkeypatch, _fake_binaries(tmp_path))
    monkeypatch.setattr(ClamAVScanner, "_clamd_reachable", lambda self: (True, None))
    s = ClamAVScanner()
    assert s.available
    assert s.binary.name == "clamdscan.exe"


def test_falls_back_to_clamscan_when_daemon_silent(tmp_path, monkeypatch):
    _patch_candidates(monkeypatch, _fake_binaries(tmp_path))
    monkeypatch.setattr(ClamAVScanner, "_clamd_reachable", lambda self: (False, None))
    s = ClamAVScanner()
    assert s.available
    assert s.binary.name == "clamscan.exe"


def test_ping_invocation_and_rc_mapping(monkeypatch):
    s = ClamAVScanner.__new__(ClamAVScanner)
    s._clamdscan = Path(r"C:\fake\clamdscan.exe")
    for rc, expected in ((0, True), (2, False)):
        with mock.patch(
            "malaz.analysis.clamav.run_tool",
            return_value=(rc, b"", b""),
        ) as run:
            reachable, _conf = s._clamd_reachable()
            assert reachable is expected
        args = run.call_args[0][0]
        assert "--ping=1" in args
        assert "1" not in args[2:]  # Inline-Syntax: nie als Scan-Ziel interpretierbar


def test_ping_exception_means_unreachable():
    s = ClamAVScanner.__new__(ClamAVScanner)
    s._clamdscan = Path(r"C:\fake\clamdscan.exe")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        side_effect=OSError("boom"),
    ):
        reachable, _conf = s._clamd_reachable()
        assert reachable is False


def test_no_clamdscan_means_no_ping(tmp_path, monkeypatch):
    from malaz import config

    only = tmp_path / "clamscan.exe"
    only.write_bytes(b"MZ")
    monkeypatch.setattr(config, "CLAMAV_SCAN_CANDIDATES", (str(only),))
    # The host may have a real ClamAV install; `_locate_binaries` falls back to
    # shutil.which. This test is about "no daemon client at all", so the PATH
    # fallback has to be neutralised explicitly (otherwise it is machine-
    # dependent and fails only in the full suite after a real clamd starts).
    monkeypatch.setattr("malaz.analysis.clamav.which_absolute", lambda _name: None)
    with mock.patch("malaz.analysis.clamav.run_tool") as run:
        s = ClamAVScanner()
    assert s.binary == only
    run.assert_not_called()  # kein Daemon-Kliente -> kein Ping-Subprozess


def test_clamdscan_gets_no_clamscan_flags(tmp_path):
    # clamdscan versteht --no-summary/--database nicht zuverlässig über
    # Versionen hinweg — der Daemon nutzt ohnehin seine konfigurierte DB.
    # --no-summary bringt hier auch nichts: _FOUND_RE matcht die
    # "…: <name> FOUND"-Zeile unabhängig von der Abschluss-Zusammenfassung.
    fake = tmp_path / "clamdscan"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = fake
    s._clamd_conf_used = None  # Default-Suche hat gereicht
    s.database = tmp_path  # vorhanden, muss dennoch NICHT durchgereicht werden
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(0, b"/f.bin: OK\n", b""),
    ) as run:
        r = s.scan_path(target)
    assert r.scanned and r.clean
    args = run.call_args[0][0]
    assert "--no-summary" not in args
    assert "--database" not in args
    assert args[-1] == str(target.resolve())


# ---- parallele Engines -----------------------------------------------------

class _OverlapAv:
    """Blockiert, bis ClamAV gestartet ist — nur bei echtem Parallelismus
    löst sich das ohne Timeout auf (sequenziell: detail='sequenziell')."""

    available = True

    def __init__(self):
        self._clam_started = threading.Event()
        self.overlapped = None

    def scan_path(self, path):
        self.overlapped = self._clam_started.wait(2.0)
        from malaz.analysis.windows_av import AVResult

        return AVResult(
            scanned=True,
            detail="parallel" if self.overlapped else "sequenziell",
        )


class _OverlapClam:
    available = True

    def __init__(self, gate: _OverlapAv):
        self._gate = gate

    def scan_path(self, path):
        self._gate._clam_started.set()
        return ClamAVResult(scanned=True, detail="clam")

    def scan_bytes(self, data, suffix=".bin"):
        self._gate._clam_started.set()
        return ClamAVResult(scanned=True, detail="clam")


class _OverlapAvBytes(_OverlapAv):
    def scan_bytes(self, data, suffix=".bin"):
        return self.scan_path(None)


def test_top_level_av_engines_run_in_parallel(tmp_path):
    av = _OverlapAv()
    clam = _OverlapClam(av)
    d = Dispatcher(av_scanner=av, clam_scanner=clam)
    target = tmp_path / "datei.txt"
    target.write_bytes(b"harmlos")
    result = d.scan_path(target)
    ids = [i.rule_id for i in result.indicators]
    assert "AV_CLEAN" in ids
    assert "CLAMAV_CLEAN" in ids
    assert av.overlapped is True, (
        "Defender lief nicht parallel zu ClamAV (sequenzieller Pfad?)"
    )


def test_member_av_engines_run_in_parallel(tmp_path):
    av = _OverlapAvBytes()
    clam = _OverlapClam(av)
    d = Dispatcher(av_scanner=av, clam_scanner=clam)
    child = ScanResult(path="(Archiv)/boese.exe", depth=1)
    d._av_scan_member(child, b"MZ" + b"\x00" * 60)
    ids = [i.rule_id for i in child.indicators]
    assert "AV_CLEAN" in ids and "CLAMAV_CLEAN" in ids
    assert av.overlapped is True


def test_disabled_av_still_yields_skip_indicators(tmp_path):
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    target = tmp_path / "datei.txt"
    target.write_bytes(b"harmlos")
    result = d.scan_path(target)
    ids = [i.rule_id for i in result.indicators]
    assert "AV_SKIPPED" in ids and "CLAMAV_SKIPPED" in ids


def test_clamd_ping_tries_default_lookup_first(tmp_path, monkeypatch):
    """Ein funktionierender Default-Lookup darf NICHT ueberschrieben werden.

    Liegt clamd.conf im ClamAV-Installationsverzeichnis (normaler Dienst-
    Setup), findet clamdscan sie selbst. Wuerde Malaz dort bedingungslos seine
    Nutzer-Config vorschieben, zeigt die auf einen anderen Socket/Port — der
    Ping faellt aus und eine zuvor funktionierende Installation greift
    ploetzlich auf den langsamen clamscan-Weg zurueck.
    """
    from malaz import config

    conf = tmp_path / "clamd.conf"
    conf.write_text("TCPSocket 3310\n", encoding="utf-8")
    monkeypatch.setattr(config, "CLAMAV_CLAMD_USER_CONF", str(conf))
    fake = tmp_path / "clamdscan"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s._clamdscan = fake
    with mock.patch(
        "malaz.analysis.clamav.run_tool", return_value=(0, b"PONG", b"")
    ) as run:
        reachable, used = s._clamd_reachable()
    assert reachable is True
    assert used is None, "Default-Lookup hat gereicht -> keine Config vorschreiben"
    args = run.call_args[0][0]
    assert not any(a.startswith("--config-file=") for a in args), args


def test_clamd_ping_falls_back_to_user_config(tmp_path, monkeypatch):
    """Scheitert der Default-Lookup, wird die Nutzer-Config nachgereicht.

    Regression aus dem Nutzerkontext-Setup: `clamdscan --ping=1` endet dort
    rc=2 (Config liegt nicht im Installationsverzeichnis), mit
    `--config-file` rc=0. Ohne den zweiten Versuch fiel die Engine still auf
    ~16 s pro Datei zurueck, obwohl der Daemon lief.

    Der Port muss real lauschen: die Vorpruefung (`_tcp_reachable`) ueberspringt
    den Config-Ping sonst korrekt — eine Config auf einen toten Port bedeutet
    „kein Daemon", und genau dafuer ist die Vorpruefung da.
    """
    import socket

    from malaz import config

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        conf = tmp_path / "clamd.conf"
        conf.write_text(f"TCPSocket {port}\nTCPAddr 127.0.0.1\n", encoding="utf-8")
        monkeypatch.setattr(config, "CLAMAV_CLAMD_USER_CONF", str(conf))
        fake = tmp_path / "clamdscan"
        fake.write_bytes(b"MZ")
        s = ClamAVScanner.__new__(ClamAVScanner)
        s._clamdscan = fake

        calls: list[list[str]] = []

        def fake_run(args, timeout=None):
            calls.append(list(args))
            # Erster Versuch (Default): rc=2 -> zweiter Versuch mit Config: rc=0
            return (2, b"", b"ERROR") if len(calls) == 1 else (0, b"PONG", b"")

        with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
            reachable, used = s._clamd_reachable()
    finally:
        srv.close()

    assert reachable is True
    assert used == str(conf), "der erfolgreiche Weg muss zurueckgemeldet werden"
    assert len(calls) == 2, calls
    assert not any(a.startswith("--config-file=") for a in calls[0]), calls[0]
    assert any(a.startswith("--config-file=") for a in calls[1]), calls[1]


def test_clamd_conf_lookup_has_no_side_effects(tmp_path, monkeypatch):
    """Fehlt die Config, wird keine gesetzt — und nichts erzeugt.

    Ein Pfad auf eine nicht existierende Datei laesst clamdscan genauso
    scheitern wie gar keiner. Wichtiger: Der Aufruf darf die Datei NICHT
    anlegen. Das Anlegen ist eine bewusste Nutzeraktion
    (scripts/start_clamd.bat -> ensure_clamd_conf).
    """
    from malaz import config

    conf = tmp_path / "gibtsnicht.conf"
    monkeypatch.setattr(config, "CLAMAV_CLAMD_USER_CONF", str(conf))
    fake = tmp_path / "clamdscan"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s._clamdscan = fake
    with mock.patch(
        "malaz.analysis.clamav.run_tool", return_value=(2, b"", b"ERROR")
    ) as run:
        reachable, used = s._clamd_reachable()
    assert reachable is False and used is None
    for call in run.call_args_list:
        args = call[0][0]
        assert not any(a.startswith("--config-file=") for a in args), args
    assert not conf.exists(), "Lookup darf keine Config anlegen"


def test_clamdscan_scan_passes_config_file(tmp_path, monkeypatch):
    """Auch der SCAN-Aufruf braucht die Config — sonst rc=2 beim Scannen."""
    from malaz import config

    conf = tmp_path / "clamd.conf"
    conf.write_text("TCPSocket 3310\n", encoding="utf-8")
    monkeypatch.setattr(config, "CLAMAV_CLAMD_USER_CONF", str(conf))

    fake = tmp_path / "clamdscan"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = fake
    s._clamd_conf_used = str(conf)
    s.database = None
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool", return_value=(0, b"/f.bin: OK\n", b"")
    ) as run:
        s.scan_path(target)
    args = run.call_args[0][0]
    assert any(a.startswith("--config-file=") for a in args), args


def test_clamdscan_scan_omits_config_when_default_worked(tmp_path):
    """Kam der Ping ueber den Default-Lookup, darf der Scan ihn nicht ueberschreiben."""
    fake = tmp_path / "clamdscan"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = fake
    s._clamd_conf_used = None
    s.database = None
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool", return_value=(0, b"/f.bin: OK\n", b"")
    ) as run:
        s.scan_path(target)
    args = run.call_args[0][0]
    assert not any(a.startswith("--config-file=") for a in args), args


def test_lost_daemon_falls_back_to_clamscan(tmp_path):
    """Stirbt der Daemon, muss die Stufe auf clamscan umschalten.

    `_choose_binary` pingt nur EINMAL im __init__. Stirbt clamd danach, bleibt
    `self.binary = clamdscan.exe` stehen; jeder weitere Scan antwortet
    "Could not connect to clamd ... Connection refused" -> rc=2 -> die
    ClamAV-Stufe lieferte fuer den REST DES PROZESSES `scanned=False`
    ("nicht aussagekraeftig"), also gar keine AV-Pruefung mehr. Gemessen vor
    dem Fix: zweiter Scan nach `taskkill /F /IM clamd.exe` -> scanned=False.
    """
    clamdscan = tmp_path / "clamdscan.exe"
    clamscan = tmp_path / "clamscan.exe"
    clamdscan.write_bytes(b"MZ")
    clamscan.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = clamdscan
    s._clamscan = clamscan
    s._clamd_conf_used = None
    s.database = None
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    def fake_run(args, timeout=None):
        if str(args[0]).endswith("clamdscan.exe"):
            # Genau die reale Meldung: sie kommt auf STDERR.
            return (2, b"", b"ERROR: Could not connect to clamd on 127.0.0.1: Connection refused")
        return (0, b"/f.bin: OK\n", b"")

    with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
        r = s.scan_path(target)

    assert r.scanned is True, "nach dem Daemon-Verlust muss clamscan uebernehmen"
    assert r.clean is True
    assert s.binary is clamscan, "die Umschaltung muss dauerhaft sein"


def _daemon_lost_scanner(tmp_path, binary_name, database=None):
    """Scanner mit gesetzten Binaries, ohne Ping/Config-Suche im __init__."""
    clamscan = tmp_path / "clamscan.exe"
    clamdscan = tmp_path / "clamdscan.exe"
    clamscan.write_bytes(b"MZ")
    clamdscan.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = clamdscan if binary_name == "clamdscan" else clamscan
    s._clamscan = clamscan
    s._clamdscan = clamdscan
    s._clamd_conf_used = None
    s.database = database
    return s


def test_reported_target_name_with_daemon_phrase_does_not_recurse(tmp_path):
    """Ein Dateiname mit 'connection refused' darf KEINE Rekursion ausloesen.

    Gemessen vor dem Fix: der Stub lieferte die reale Meldung
    ``WARNING: Can't open file <ziel mit 'connection refused'>: Permission
    denied`` mit rc=2, binary war bereits clamscan — `_daemon_lost` matchte per
    Substring ueber die GESAMTE Ausgabe (inklusive des Pfad-Echos), der
    "Fallback" setzte dasselbe Binary und rief `_run` erneut auf: RecursionError
    nach 494 identischen Aufrufen. Ueber CORE_ERROR (Gewicht 5) galt die Probe
    danach als GRUEN.

    Erwartet: genau EIN Aufruf, ehrliches scanned=False (nicht "sauber").
    """
    s = _daemon_lost_scanner(tmp_path, "clamscan")
    target = tmp_path / "connection refused.pdf"
    target.write_bytes(b"x")
    echoed = str(target.resolve())

    calls = []

    def fake_run(args, timeout=None):
        calls.append(str(args[0]))
        return (
            2,
            b"",
            f"WARNING: Can't open file {echoed}: Permission denied".encode(),
        )

    with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
        r = s.scan_path(target)

    assert len(calls) == 1, f"clamscan->clamscan ist kein Fallback: {calls}"
    assert s.binary is s._clamscan
    assert r.scanned is False, "ungeprueft muss ungeprueft bleiben"
    assert r.clean is False
    assert "Returncode 2" in (r.skipped_reason or "")


def test_stale_fallback_flag_still_switches_to_clamscan(tmp_path):
    """BUG-034: ein altes _fallback_done darf clamdscan nicht in _run halten."""
    s = _daemon_lost_scanner(tmp_path, "clamdscan")
    s._fallback_done = True  # Zustand nach refresh_state-Upgrade
    target = tmp_path / "probe.bin"
    target.write_bytes(b"x")
    calls = []

    def fake_run(args, timeout=None):
        calls.append(str(args[0]))
        if str(args[0]).endswith("clamdscan.exe"):
            return (
                2,
                b"",
                b"ERROR: Could not connect to clamd on 127.0.0.1: Connection refused",
            )
        return (2, b"", b"")

    with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
        s.scan_path(target)

    assert [Path(call).name for call in calls] == [
        "clamdscan.exe",
        "clamscan.exe",
    ]
    assert s.binary is s._clamscan


def test_daemon_fallback_runs_only_once_when_retry_echoes_the_phrase(tmp_path):
    """Der echte Daemon-Verlust schaltet um — danach aber nicht erneut.

    Erster Aufruf: clamdscan meldet den echten Verbindungsverlust -> Fallback
    auf clamscan. Der Zweitversuch scheitert mit rc=2 und traegt den Dateinamen
    ('connection refused.pdf') im Pfad-Echo. Gemessen vor dem Fix: dieser
    Zweitversuch loeste ueber den Substring-Match einen weiteren "Fallback"
    aus und lief bis zum RecursionError.
    """
    s = _daemon_lost_scanner(tmp_path, "clamdscan")
    target = tmp_path / "connection refused.pdf"
    target.write_bytes(b"x")
    echoed = str(target.resolve())

    calls = []

    def fake_run(args, timeout=None):
        calls.append(str(args[0]))
        if str(args[0]).endswith("clamdscan.exe"):
            return (
                2,
                b"",
                b"ERROR: Could not connect to clamd on 127.0.0.1: Connection refused",
            )
        return (
            2,
            b"",
            f"WARNING: Can't open file {echoed}: Permission denied".encode(),
        )

    with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
        r = s.scan_path(target)

    assert len(calls) == 2, f"genau clamdscan + EIN clamscan-Versuch: {calls}"
    assert s.binary is s._clamscan, "die Umschaltung muss dauerhaft sein"
    assert r.scanned is False
    assert r.clean is False
    assert "Returncode 2" in (r.skipped_reason or "")


def test_target_name_with_db_phrase_does_not_claim_db_failure(tmp_path):
    """Auch _db_load_failure darf nicht auf das Pfad-Echo hereinfallen.

    Ein Dateiname wie 'error loading database.pdf' im rc=2-Output des Scanners
    wurde als Signaturbasis-Fehler gemeldet — obwohl in Wahrheit nur das
    Scan-Ziel unlesbar war. Der Nutzer bekam die falsche Diagnose.
    """
    s = _daemon_lost_scanner(tmp_path, "clamscan", database=tmp_path)
    target = tmp_path / "error loading database.pdf"
    target.write_bytes(b"x")
    echoed = str(target.resolve())

    def fake_run(args, timeout=None):
        return (
            2,
            b"",
            f"WARNING: Can't open file {echoed}: Permission denied".encode(),
        )

    with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
        r = s.scan_path(target)

    assert r.scanned is False
    assert "Signaturbasis" not in (r.skipped_reason or ""), r.skipped_reason
    assert "Returncode 2" in (r.skipped_reason or "")


def test_broken_database_does_not_switch_to_clamscan(tmp_path):
    """Gegenprobe: ein rc=2 OHNE Verbindungsfehler darf NICHT umschalten.

    Eine kaputte Signaturbasis ist der andere rc=2-Fall; sie muss als solche
    gemeldet werden. Wuerde sie den Fallback ausloesen, verschluckte die
    Umschaltung genau die Diagnose, die der Nutzer braucht.
    """
    clamdscan = tmp_path / "clamdscan.exe"
    clamscan = tmp_path / "clamscan.exe"
    clamdscan.write_bytes(b"MZ")
    clamscan.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = clamdscan
    s._clamscan = clamscan
    s._clamd_conf_used = None
    s.database = tmp_path
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    calls = []

    def fake_run(args, timeout=None):
        calls.append(str(args[0]))
        return (2, b"", b"ERROR: Can't verify database integrity")

    with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
        r = s.scan_path(target)

    assert r.scanned is False
    assert s.binary is clamdscan, "kein Umschalten ohne Verbindungsverlust"
    assert len(calls) == 1, "kein zweiter Versuch bei DB-Fehler"


def test_tcp_reachable_skips_ping_for_closed_port(tmp_path):
    """Ein geschlossener Port darf keinen 2-s-Ping auslösen.

    `clamdscan --config-file=<conf>` blockiert gegen einen NICHT lauschenden
    Port im Connect-Timeout von ~2 s (gemessen 2075 ms; ClamAVs Default). Jede
    Malaz-Instanz zahlt das beim Start, sobald ClamAV installiert ist und kein
    clamd läuft — die zweistufige Suche erreicht die Config-Stufe bei jedem
    Start. Ein reiner Socket-Connect beantwortet dieselbe Frage in ~250 ms.
    """
    from malaz.analysis.clamav import _tcp_reachable

    # Port 1 lauscht praktisch nie; kein Dienst, kein Privileg noetig.
    conf = tmp_path / "clamd.conf"
    conf.write_text("TCPSocket 1\nTCPAddr 127.0.0.1\n", encoding="utf-8")
    assert _tcp_reachable(str(conf)) is False


def test_tcp_reachable_true_for_open_port(tmp_path):
    """Gegenprobe: ein lauschender Port meldet erreichbar."""
    import socket

    from malaz.analysis.clamav import _tcp_reachable

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        conf = tmp_path / "clamd.conf"
        conf.write_text(f"TCPSocket {port}\nTCPAddr 127.0.0.1\n", encoding="utf-8")
        assert _tcp_reachable(str(conf)) is True
    finally:
        srv.close()


def test_tcp_reachable_without_config_does_not_block(tmp_path):
    """Ohne verwertbare Config wird nicht blockiert (True = Ping entscheidet).

    Eine fehlende oder unlesbare Config darf einen laufenden Daemon nicht
    abschalten — dann muss der Ping die Entscheidung treffen.
    """
    from malaz.analysis.clamav import _tcp_reachable

    assert _tcp_reachable(None) in (True, False)  # kein Absturz, kein Hang
    assert _tcp_reachable(str(tmp_path / "fehlt.conf")) in (True, False)


def test_closed_port_does_not_spawn_the_config_ping(tmp_path, monkeypatch):
    """Bei totem Port entfällt der teure Config-Ping (der ~2 s kostet).

    Der erste Versuch (Default-Suche, ohne --config-file) ist billig (~67 ms)
    und läuft weiterhin; nur der zweite, teure Versuch wird übersprungen.
    """
    from malaz import config

    conf = tmp_path / "clamd.conf"
    conf.write_text("TCPSocket 1\nTCPAddr 127.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(config, "CLAMAV_CLAMD_USER_CONF", str(conf))
    fake = tmp_path / "clamdscan.exe"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s._clamdscan = fake

    with mock.patch(
        "malaz.analysis.clamav.run_tool", return_value=(2, b"", b"ERROR")
    ) as run:
        reachable, used = s._clamd_reachable()

    assert reachable is False and used is None
    # Filter to THIS scanner: a clamd start thread from another test can call
    # run_tool concurrently and would otherwise pollute the call list.
    calls = [
        c[0][0]
        for c in run.call_args_list
        if c[0] and c[0][0] and c[0][0][0] == str(fake)
    ]
    assert len(calls) == 1, f"nur der billige Default-Ping, nicht der Config-Ping: {calls}"
    assert not any(
        a.startswith("--config-file=") for args in calls for a in args
    ), calls


def test_open_port_still_uses_the_config_ping(tmp_path, monkeypatch):
    """Gegenprobe: bei lauschendem Port läuft der Config-Ping wie bisher."""
    import socket

    from malaz import config

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        conf = tmp_path / "clamd.conf"
        conf.write_text(f"TCPSocket {port}\nTCPAddr 127.0.0.1\n", encoding="utf-8")
        monkeypatch.setattr(config, "CLAMAV_CLAMD_USER_CONF", str(conf))
        fake = tmp_path / "clamdscan.exe"
        fake.write_bytes(b"MZ")
        s = ClamAVScanner.__new__(ClamAVScanner)
        s._clamdscan = fake

        calls_made: list[list[str]] = []

        def fake_run(args, timeout=None):
            calls_made.append(list(args))
            return (2, b"", b"") if len(calls_made) == 1 else (0, b"PONG", b"")

        with mock.patch("malaz.analysis.clamav.run_tool", side_effect=fake_run):
            reachable, used = s._clamd_reachable()

        assert reachable is True and used == str(conf)
        assert len(calls_made) == 2, calls_made
        assert any(
            a.startswith("--config-file=") for a in calls_made[1]
        ), calls_made[1]
    finally:
        srv.close()
