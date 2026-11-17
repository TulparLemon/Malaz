import os
import subprocess
import time
from pathlib import Path
from unittest import mock

from malaz.analysis.clamav import _FOUND_RE, ClamAVScanner


def _scanner(tmp_path):
    fake = tmp_path / "clamscan"
    fake.write_bytes(b"MZ")
    s = ClamAVScanner.__new__(ClamAVScanner)
    s.enabled = True
    s.timeout = 5
    s.binary = fake
    s.database = None
    return s


def _db_with_sig(path: Path, age_seconds: float, name: str = "daily.cvd") -> Path:
    """Signature directory whose newest file carries the given age."""
    path.mkdir(parents=True, exist_ok=True)
    sig = path / name
    sig.write_bytes(b"x")
    when = time.time() - age_seconds
    os.utime(sig, (when, when))
    return path


def test_locate_db_prefers_newest(tmp_path, monkeypatch):
    """Nach dem Update-Knopf muss die frische Nutzer-DB gewinnen, nicht die
    alte Admin-Kopie aus Program Files (feste Reihenfolge las sie alt)."""
    from malaz import config as malaz_config

    admin = _db_with_sig(tmp_path / "admin_db", age_seconds=5 * 86400)
    user = _db_with_sig(tmp_path / "user_db", age_seconds=60, name="daily.cld")
    monkeypatch.setattr(malaz_config, "CLAMAV_DB_CANDIDATES", (str(admin), str(user)))
    s = ClamAVScanner.__new__(ClamAVScanner)
    assert s._locate_db() == user


def test_locate_db_tie_goes_to_first(tmp_path, monkeypatch):
    from malaz import config as malaz_config

    admin = _db_with_sig(tmp_path / "admin_db", age_seconds=100)
    user = _db_with_sig(tmp_path / "user_db", age_seconds=100, name="daily.cld")
    # Gleichen Zeitstempel explizit pinnen: zweimal time.time()-100 zu
    # berechnen unterscheidet sich um Mikrosekunden (Flake).
    tie = (admin / "daily.cvd").stat().st_mtime
    os.utime(user / "daily.cld", (tie, tie))
    monkeypatch.setattr(malaz_config, "CLAMAV_DB_CANDIDATES", (str(admin), str(user)))
    s = ClamAVScanner.__new__(ClamAVScanner)
    assert s._locate_db() == admin


def test_locate_db_ignores_empty_and_missing(tmp_path, monkeypatch):
    from malaz import config as malaz_config

    empty = tmp_path / "empty_db"
    empty.mkdir()
    monkeypatch.setattr(
        malaz_config,
        "CLAMAV_DB_CANDIDATES",
        (str(tmp_path / "gibtsnicht"), str(empty)),
    )
    s = ClamAVScanner.__new__(ClamAVScanner)
    assert s._locate_db() is None


def test_disabled_skips():
    s = ClamAVScanner(enabled=False)
    r = s.scan_path(Path("/nope"))
    assert not r.scanned and r.skipped_reason


def test_disabled_engine_still_reports_the_installed_database(tmp_path, monkeypatch):
    """BUG-037: binary/database were only located when the stage was ENABLED.

    A switched-off engine therefore read as "not installed": the GUI badge and
    ``update_due`` claimed no signature database although ``daily.cvd`` was
    right there. "Deactivated" must stay distinguishable from "absent".
    """
    from malaz import config as malaz_config
    from malaz.analysis.clamav_status import read_db_dates

    db = tmp_path / "db"
    db.mkdir()
    (db / "daily.cvd").write_bytes(
        b"ClamAV-VDB:11 Aug 2026 06-25 +00\n" + b"\x00" * 50
    )
    monkeypatch.setattr(malaz_config, "CLAMAV_ENABLED", False)
    monkeypatch.setattr(malaz_config, "CLAMAV_DB_CANDIDATES", (str(db),))
    monkeypatch.setattr(
        ClamAVScanner,
        "_locate_binaries",
        lambda self: (Path("C:/clamav/clamscan.exe"), None),
    )

    scanner = ClamAVScanner()
    assert scanner.enabled is False
    assert scanner.available is False, "deaktiviert darf nicht scannen"
    assert scanner.binary is not None, "Status muss die Installation sehen"
    assert scanner.database == db, "Signatur-DB ist nicht vom Schalter abhaengig"
    assert "daily" in read_db_dates()

    result = scanner.scan_path(tmp_path / "nichts.bin")
    assert not result.scanned and "deaktiviert" in (result.skipped_reason or "")


def test_missing_file_skips(tmp_path):
    s = _scanner(tmp_path)
    r = s.scan_path(tmp_path / "missing.bin")
    assert not r.scanned and r.skipped_reason


def test_clean(tmp_path):
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=0, stdout=b"/tmp/f.bin: OK\n", stderr=b"")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ) as run:
        r = s.scan_path(target)
    assert r.scanned and r.clean
    args = run.call_args[0][0]
    assert "--no-summary" in args
    assert "--remove" not in args  # detection only, never delete


def test_truncated_output_is_skipped_not_clean_or_threat(tmp_path):
    """SEC-023: a capped clamscan output is a PREFIX, not a verdict.

    Both fakes carry what would normally be a clear result (": OK", a FOUND
    line). With the truncation flag set neither may be parsed: CLAMAV_SKIPPED,
    never clean, never a threat.
    """
    from malaz.procio import ToolResult

    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    for rc, output in (
        (0, b"/tmp/f.bin: OK\n"),
        (1, b"/tmp/f.bin: Eicar-Test-Signature FOUND\n"),
    ):
        with mock.patch(
            "malaz.analysis.clamav.run_tool",
            return_value=ToolResult(rc, output, b"", truncated=True),
        ):
            r = s.scan_path(target)

        assert r.scanned is False
        assert r.threat_found is False
        assert r.clean is False
        assert "abgeschnitten" in (r.skipped_reason or "")


def test_clean_detail_strips_libclamav_banner(tmp_path):
    """Der 'database is older than 7 days'-Block ist Engine-Status, kein
    Datei-Befund — im Detail las er sich wie ein Widerspruch direkt nach
    dem Nutzer-Update (Feld-Report)."""
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    out = (
        b"C:\\x\\f.bin: OK\n"
        b"LibClamAV Warning: **************************************************\n"
        b"LibClamAV Warning: ***  The virus database is older than 7 days!  ***\n"
        b"LibClamAV Warning: **************************************************\n"
    )
    fake_proc = mock.Mock(returncode=0, stdout=out, stderr=b"")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ):
        r = s.scan_path(target)
    assert r.scanned and r.clean
    assert "LibClamAV" not in r.detail
    assert "****" not in r.detail
    assert "OK" in r.detail  # das eigentliche Ergebnis bleibt sichtbar


def test_threat_via_output(tmp_path):
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    out = b"/tmp/f.bin: Eicar-Test-Signature FOUND\n"
    fake_proc = mock.Mock(returncode=1, stdout=out, stderr=b"")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ):
        r = s.scan_path(target)
    assert r.scanned and r.threat_found
    assert r.threat_name == "Eicar-Test-Signature"


def test_threat_via_rc_when_no_match_line(tmp_path):
    # rc==1 without a parsable FOUND line (e.g. encoding damage): still
    # flagged as threat_found, but with an explicit "unbestätigt" marker so
    # the dispatcher can downgrade it to MEDIUM instead of a CRITICAL anchor.
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=1, stdout=b"weird output", stderr=b"")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ):
        r = s.scan_path(target)
    assert r.threat_found
    assert r.threat_name.startswith("unbestätigt")


def test_threat_via_rc_with_match_line_is_confirmed(tmp_path):
    # A real FOUND line keeps the full CRITICAL anchor path.
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(
        returncode=1, stdout=b"/tmp/f.bin: Win.Test.Evil FOUND\n", stderr=b""
    )
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ):
        r = s.scan_path(target)
    assert r.threat_found and r.threat_name == "Win.Test.Evil"


def test_engine_error_inconclusive(tmp_path):
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=2, stdout=b"", stderr=b"database error")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ):
        r = s.scan_path(target)
    assert not r.scanned and r.skipped_reason


def test_database_flag_passed_when_db_found(tmp_path):
    # Admin-less ClamAV installs keep signatures outside the install dir; the
    # discovered directory must be handed to clamscan via --database, otherwise
    # the scan aborts with "cl_load: No such file or directory".
    s = _scanner(tmp_path)
    dbdir = tmp_path / "db"
    dbdir.mkdir()
    (dbdir / "daily.cvd").write_bytes(b"x")
    s.database = dbdir
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=0, stdout=b"/f.bin: OK\n", stderr=b"")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ) as run:
        r = s.scan_path(target)
    assert r.scanned and r.clean
    args = run.call_args[0][0]
    assert "--database" in args
    assert str(dbdir) in args


def test_no_database_flag_when_none_found(tmp_path):
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=0, stdout=b"/f.bin: OK\n", stderr=b"")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ) as run:
        r = s.scan_path(target)
    assert r.clean
    args = run.call_args[0][0]
    assert "--database" not in args


def test_locate_db_requires_signatures(tmp_path, monkeypatch):
    from malaz import config

    empty = tmp_path / "empty"
    empty.mkdir()
    filled = tmp_path / "filled"
    filled.mkdir()
    (filled / "main.cvd").write_bytes(b"x")
    monkeypatch.setattr(
        config, "CLAMAV_DB_CANDIDATES", (str(empty), str(filled), str(tmp_path / "nope"))
    )
    s = ClamAVScanner.__new__(ClamAVScanner)
    assert s._locate_db() == filled


def test_timeout_skips(tmp_path):
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        side_effect=subprocess.TimeoutExpired("c", 5),
    ):
        r = s.scan_path(target)
    assert not r.scanned and "Timeout" in r.skipped_reason


def test_found_regex():
    m = _FOUND_RE.search("/path/file.exe: Trojan.Gen FOUND\n")
    assert m and m.group("name") == "Trojan.Gen"


# -- Signaturbasis nicht ladbar (Befund der ClamAV-Dritt-Signatur-Pruefung) -- #

def test_db_load_failure_is_named(tmp_path):
    """Eine unlesbare Signaturbasis muss als solche erkennbar sein.

    Gemessen mit ClamAV 1.5.3: EINE kaputte Signaturdatei im --database-Pfad
    genuegt, damit clamscan gar nichts mehr prueft (rc=2). Das ist besonders
    relevant fuer Dritt-Signaturen (.ndb/.hdb/.ldb), also genau den Fall
    'viele Dateien von woanders'. Vorher verschwand das in einem generischen
    'Returncode 2' - der Nutzer konnte nicht erkennen, dass die Engine blind
    war statt 'sauber'.
    """
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(2, b"", b"LibClamAV Error: Problem parsing database at line 1"),
    ):
        r = s.scan_path(target)
    assert not r.scanned
    assert "Signaturbasis" in r.skipped_reason
    assert "nicht: 'sauber'" in r.skipped_reason
    # Die konkrete LibClamAV-Meldung bleibt sichtbar (diagnostizierbar).
    assert "Problem parsing database" in r.skipped_reason


def test_db_load_failure_variants_detected(tmp_path):
    """Alle gemessenen Fehlerphrasen werden erkannt, nicht nur eine.

    Jede Phrase stammt aus einem echten clamscan-Lauf in der Situation, die
    sie erzeugt. 'Signaturbasis' wird je Fall geprueft - 'assert not scanned'
    allein gilt fuer JEDEN rc=2, also auch fuer den generischen Zweig, und
    koennte 'erkannt' nicht von 'nicht erkannt' unterscheiden.

    Die CVD-Gruppe kam zuletzt dazu: eine Kopie von main.cvd mit EINEM
    gekippten Byte erzeugt andere Meldungen als eine kaputte .ndb, und
    'cli_cvdload:' enthaelt NICHT 'cl_load:'. Ohne sie fiel genau der Anlass
    dieser Pruefung (kaputte Signaturbasis) auf den generischen Text zurueck.
    """
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    for phrase in (
        b"LibClamAV Error: Problem parsing database at line 1",
        b"LibClamAV Error: Empty database file",
        b"LibClamAV Error: cli_loaddbdir: No supported database files found in C:\\x",
        b"LibClamAV Error: cl_load: No such file or directory: C:\\missing",
        # Real gemessen: Kopie von main.cvd, ein Byte bei Offset 100000 gekippt
        (
            b"LibClamAV Warning: Failed to verify CVD with MD5-based RSA digital "
            b"signature: Error verifying signature: MD5 hash does not match"
        ),
        b"LibClamAV Error: cli_cvdload: Can't verify CVD file C:\\t\\main.cvd",
        b"LibClamAV Error: cli_loaddbdir: error loading database C:\\t",
        b"ERROR: Can't verify database integrity",
    ):
        with mock.patch(
            "malaz.analysis.clamav.run_tool", return_value=(2, b"", phrase)
        ):
            r = s.scan_path(target)
        assert not r.scanned
        assert "Signaturbasis" in r.skipped_reason, (
            f"Phrase nicht erkannt: {phrase!r} -> {r.skipped_reason!r}"
        )


def test_generic_engine_error_stays_generic(tmp_path):
    """Gegenprobe: ein NICHT-DB-Fehler bleibt die allgemeine Meldung.

    Sonst wuerde jeder rc=2 als Signaturproblem ausgegeben und die
    Unterscheidung waere wertlos.
    """
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(2, b"", b"irgendein anderer Fehler ohne DB-Bezug"),
    ):
        r = s.scan_path(target)
    assert not r.scanned
    assert "Signaturbasis" not in r.skipped_reason
    assert "Returncode 2" in r.skipped_reason


def test_db_failure_never_reports_clean(tmp_path):
    """Kernvertrag: 'nicht pruefbar' darf NIE als 'clean' durchgehen.

    Ohne diese Zusicherung waere eine blinde Engine unsichtbar - genau der
    Fehler, den der Security-Audit beim DIE-Suffix schon einmal fand.
    """
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(2, b"", b"LibClamAV Error: Problem parsing database at line 1"),
    ):
        r = s.scan_path(target)
    assert not r.threat_found
    assert not r.clean  # der springende Punkt: NICHT clean


def test_third_party_signatures_do_not_win_db_selection(tmp_path, monkeypatch):
    """Dritt-Signaturen duerfen die DB-AUSWAHL nicht beeinflussen.

    Regression gegen einen fast eingebauten Fehler: `_db_signature_time` ist
    nicht nur die Altersanzeige, sondern das Kriterium, mit dem `_locate_db`
    das zu verwendende Verzeichnis waehlt (hoechster Zeitstempel gewinnt).
    Wuerde eine .ndb dort mitzaehlen, koennte ein Verzeichnis OHNE die
    offiziellen Signaturen allein wegen ihres Zeitstempels gewinnen - die
    Engine liefe dann ohne main/daily, ein stiller Erkennungsverlust.
    """
    from malaz import config

    # Verzeichnis mit NUR einer Dritt-Signatur, und zwar NEUER.
    thirdparty = tmp_path / "thirdparty"
    thirdparty.mkdir()
    ndb = thirdparty / "somefeed.ndb"
    ndb.write_bytes(b"Malaz.Test:0:*:41414141\n")

    # Verzeichnis mit den offiziellen Signaturen, aelter.
    official = tmp_path / "official"
    official.mkdir()
    (official / "main.cvd").write_bytes(b"x")
    (official / "daily.cld").write_bytes(b"y")
    old = 1_600_000_000
    os.utime(official / "main.cvd", (old, old))
    os.utime(official / "daily.cld", (old, old))

    monkeypatch.setattr(
        config, "CLAMAV_DB_CANDIDATES", (str(thirdparty), str(official))
    )
    s = ClamAVScanner.__new__(ClamAVScanner)
    assert s._locate_db() == official, (
        "Ein Verzeichnis mit nur Dritt-Signaturen darf die Auswahl nicht "
        "gewinnen - sonst fehlen die offiziellen Signaturen komplett"
    )


def test_ign2_alone_is_not_a_signature_base(tmp_path):
    """Eine .ign2 allein ist keine Signaturbasis.

    .ign2 enthaelt nur Abschaltungen, keine Signaturen. Zaehlte sie als
    Signaturbasis, waehlte _locate_db ein leeres Verzeichnis - clamscan
    bricht dann mit 'No supported database files found' ab.
    """
    d = tmp_path / "only_ign2"
    d.mkdir()
    (d / "whitelist.ign2").write_bytes(b"Some.Signature\n")
    assert ClamAVScanner._db_signature_time(d) == 0.0


def test_broken_ign2_killswitch_is_detected(tmp_path):
    """Eine kaputte .ign2 legt die Engine still - und wird als DB-Fehler erkannt.

    Gemessen mit ClamAV 1.5.3: eine LEERE .ign2 ist harmlos, eine
    unvollstaendig geschriebene (Binaermuell) fuehrt zu
    'cli_loadign: No signature name provided' -> rc=2, nichts wird geprueft.
    Der Kill-Switch gegen FP-Signaturen ist damit selbst ein Risiko fuer
    genau den Ausfall, gegen den er schuetzt. Die Meldung muss als
    Signaturbasis-Fehler durchkommen, nicht als generischer Returncode.
    """
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    output = (
        b"LibClamAV Error: cli_loadign: No signature name provided\n"
        b"LibClamAV Error: cli_loadign: Problem parsing database at line 1\n"
    )
    with mock.patch(
        "malaz.analysis.clamav.run_tool", return_value=(2, b"", output)
    ):
        r = s.scan_path(target)
    assert not r.scanned
    assert not r.clean
    assert "Signaturbasis" in r.skipped_reason


def test_target_access_error_is_not_a_db_failure(tmp_path):
    """Ein gesperrtes SCAN-ZIEL darf nicht als DB-Fehler gemeldet werden.

    Gemessen mit ClamAV 1.5.3: Ist die zu scannende Datei unlesbar (fehlt,
    oder ein AV hat sie gesperrt), meldet clamscan
      'WARNING: <pfad>: Can't access file'  bzw.  'Can't open file <pfad>'
    — die SIGNATURBASIS ist dabei in Ordnung. Wuerde das als DB-Fehler
    durchkommen, laese der Nutzer 'Signaturbasis konnte nicht geladen werden'
    und suchte am falschen Ort: an den Signaturen statt an der Datei bzw. am
    eingreifenden Antivirusprogramm.
    """
    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    for phrase in (
        b"WARNING: C:\\tmp\\f.bin: Can't access file",
        b"LibClamAV Warning: Can't open file C:\\tmp\\f.bin",
    ):
        with mock.patch(
            "malaz.analysis.clamav.run_tool", return_value=(2, b"", phrase)
        ):
            r = s.scan_path(target)
        assert not r.scanned
        assert "Signaturbasis" not in r.skipped_reason, (
            f"Ziel-Problem wurde als DB-Fehler gemeldet: {phrase!r}"
        )


# --------------------------------------------------------------------------- #
# Size limits: clamd reports "OK" for skipped oversized files
# --------------------------------------------------------------------------- #


def test_clamd_size_limit_is_not_clean(tmp_path):
    """A skipped oversized file must not be reported as clean.

    Gemessen mit clamd 1.5.3: MaxFileSize default 100 MB, a 150 MB file
    returns rc=0 and "...: OK" in 0.03 s. The engine did not look at it.
    """
    s = _scanner(tmp_path)
    s.binary = tmp_path / "clamdscan.exe"
    s.clamd_max_file_size = 1024 * 1024
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * (2 * 1024 * 1024))
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        side_effect=AssertionError("engine must not be asked to scan a known-skipped file"),
    ):
        result = s.scan_path(target)
    assert result.limit_exceeded
    assert not result.clean
    assert "Dateilimit" in (result.skipped_reason or "")


def test_clamd_unlimited_size_is_honoured(tmp_path):
    s = _scanner(tmp_path)
    s.binary = tmp_path / "clamdscan.exe"
    s.clamd_max_file_size = 0
    target = tmp_path / "big.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(0, b"/tmp/big.bin: OK\n", b""),
    ):
        result = s.scan_path(target)
    assert result.clean


def test_clamscan_receives_explicit_size_flags(tmp_path):
    """clamscan's default says 'skipped and assumed clean' above 100 MB."""

    s = _scanner(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.clamav.run_tool",
        return_value=(0, b"/tmp/f.bin: OK\n", b""),
    ) as run:
        s.scan_path(target)
    args = run.call_args[0][0]
    assert any(a.startswith("--max-filesize=") for a in args)
    assert any(a.startswith("--max-scansize=") for a in args)
    assert any(a.startswith("--pcre-max-filesize=") for a in args)


def test_parse_size_units():
    assert ClamAVScanner._parse_size("100M") == 100 * 1024 * 1024
    assert ClamAVScanner._parse_size("2G") == 2 * 1024**3
    assert ClamAVScanner._parse_size("0") == 0
    assert ClamAVScanner._parse_size("kaputt") is None


def test_read_clamd_max_file_size(tmp_path):
    conf = tmp_path / "clamd.conf"
    conf.write_text("MaxThreads 4\nMaxFileSize 1536M\n", encoding="utf-8")
    s = _scanner(tmp_path)
    s._clamd_conf_used = str(conf)
    assert s._read_clamd_max_file_size() == 1536 * 1024 * 1024


def test_read_clamd_missing_key_uses_default(tmp_path):
    conf = tmp_path / "clamd.conf"
    conf.write_text("MaxThreads 4\n", encoding="utf-8")
    s = _scanner(tmp_path)
    s._clamd_conf_used = str(conf)
    from malaz import config as malaz_config

    assert s._read_clamd_max_file_size() == malaz_config.CLAMAV_DEFAULT_MAX_FILE_SIZE


def test_refresh_state_upgrades_to_daemon(tmp_path, monkeypatch):
    """GUI: Dispatcher is built before clamd starts; the existing instance
    must switch to clamdscan instead of staying on the 15 s clamscan path."""
    clam = tmp_path / "clamscan.exe"
    clam.write_bytes(b"")
    daemon = tmp_path / "clamdscan.exe"
    daemon.write_bytes(b"")
    monkeypatch.setattr(
        ClamAVScanner, "_locate_binaries", lambda self: (clam, daemon)
    )
    monkeypatch.setattr(ClamAVScanner, "_locate_db", lambda self: None)
    monkeypatch.setattr(ClamAVScanner, "_read_clamd_max_file_size", lambda self: 0)
    monkeypatch.setattr(ClamAVScanner, "_clamd_reachable", lambda self: (False, None))
    s = ClamAVScanner()
    assert s.binary == clam
    monkeypatch.setattr(ClamAVScanner, "_clamd_reachable", lambda self: (True, "conf"))
    s.refresh_state()
    assert s.binary == daemon


def test_default_lookup_uses_conservative_max_file_size(tmp_path, monkeypatch):
    """BUG-035: ohne erreichte Daemon-Config gilt der sichere Default.

    Die Config des Nutzers darf NICHT als Daemon-Limit gelten: sie kann ein
    größeres MaxFileSize nennen als der laufende clamd, der die Datei dann
    überspringt und „OK“ meldet.
    """
    from malaz import config as malaz_config

    conf = tmp_path / "user-clamd.conf"
    conf.write_text("MaxFileSize 2048M\n", encoding="utf-8")
    monkeypatch.setattr(malaz_config, "CLAMAV_CLAMD_USER_CONF", str(conf))
    s = _scanner(tmp_path)
    s._clamd_conf_used = None
    assert s._read_clamd_max_file_size() == malaz_config.CLAMAV_DEFAULT_MAX_FILE_SIZE


def test_reached_daemon_config_wins_over_user_config(tmp_path, monkeypatch):
    """BUG-035: nur die Config, die den Daemon erreicht hat, zählt."""
    from malaz import config as malaz_config

    user_conf = tmp_path / "user.conf"
    user_conf.write_text("MaxFileSize 100M\n", encoding="utf-8")
    used_conf = tmp_path / "daemon.conf"
    used_conf.write_text("MaxFileSize 1536M\n", encoding="utf-8")
    monkeypatch.setattr(malaz_config, "CLAMAV_CLAMD_USER_CONF", str(user_conf))
    s = _scanner(tmp_path)
    s._clamd_conf_used = str(used_conf)
    assert s._read_clamd_max_file_size() == 1536 * 1024 * 1024


def test_refresh_upgrade_resets_fallback_flag(tmp_path, monkeypatch):
    """BUG-034: nach dem Upgrade auf clamdscan ist ein Fallback wieder erlaubt."""
    clam = tmp_path / "clamscan.exe"
    clam.write_bytes(b"MZ")
    daemon = tmp_path / "clamdscan.exe"
    daemon.write_bytes(b"MZ")
    monkeypatch.setattr(ClamAVScanner, "_locate_binaries", lambda self: (clam, daemon))
    monkeypatch.setattr(ClamAVScanner, "_locate_db", lambda self: None)
    monkeypatch.setattr(ClamAVScanner, "_read_clamd_max_file_size", lambda self: 0)
    monkeypatch.setattr(ClamAVScanner, "_clamd_reachable", lambda self: (False, None))
    s = ClamAVScanner()
    assert s.binary == clam
    s._fallback_done = True  # Zustand nach einem früheren Daemon-Verlust

    monkeypatch.setattr(ClamAVScanner, "_clamd_reachable", lambda self: (True, "conf"))
    s.refresh_state()
    assert s.binary == daemon
    assert s._fallback_done is False, "sonst rekurse der nächste Verlust in _run"


def test_tcp_reachable_rejects_remote_endpoint(tmp_path):
    """SEC-022: ein Fremd-Endpunkt aus der Config wird nicht kontaktiert."""
    from malaz.analysis.clamav import _tcp_reachable

    conf = tmp_path / "clamd.conf"
    conf.write_text("TCPAddr 203.0.113.10\nTCPSocket 3310\n", encoding="utf-8")
    assert _tcp_reachable(str(conf)) is False


def test_is_loopback_host_units():
    from malaz.analysis.clamav import _is_loopback_host

    for host in ("127.0.0.1", "127.9.9.9", "::1", "[::1]", "localhost"):
        assert _is_loopback_host(host), host
    for host in ("", "0.0.0.0", "192.0.2.1", "example.com", "fe80::1%eth0"):
        assert not _is_loopback_host(host), host


def test_generated_clamd_conf_has_size_limits(tmp_path, monkeypatch):
    from malaz import config as malaz_config
    from malaz.analysis import clamav_update

    monkeypatch.setattr(
        malaz_config,
        "CLAMAV_CLAMD_USER_CONF",
        str(tmp_path / "ClamAV" / "clamd.conf"),
    )
    conf = clamav_update.ensure_clamd_conf()
    assert conf is not None
    text = conf.read_text(encoding="utf-8")
    assert "MaxFileSize" in text
    assert "StreamMaxLength" in text
    assert "MaxScanSize" in text


def test_old_generated_clamd_conf_is_upgraded(tmp_path, monkeypatch):
    """An old Malaz conf without size limits must not keep hiding 101+ MB files.

    A user-edited config (no Malaz header) stays untouched.
    """
    from malaz.analysis import clamav_update

    old = tmp_path / "ClamAV" / "clamd.conf"
    old.parent.mkdir(parents=True)
    old.write_text(
        "# Erzeugt von Malaz: adminlose clamd-Konfiguration.\n"
        "TCPSocket 3310\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(clamav_update, "clamd_conf_path", lambda: old)
    assert clamav_update.ensure_clamd_conf() == old
    text = old.read_text(encoding="utf-8")
    assert "MaxFileSize" in text

    user = tmp_path / "user" / "clamd.conf"
    user.parent.mkdir()
    user.write_text("# handgeschrieben\nTCPSocket 3310\n", encoding="utf-8")
    monkeypatch.setattr(clamav_update, "clamd_conf_path", lambda: user)
    clamav_update.ensure_clamd_conf()
    assert "MaxFileSize" not in user.read_text(encoding="utf-8")


def test_size_limit_maps_to_incomplete_indicator():
    from malaz.analysis.clamav import ClamAVResult
    from malaz.core.dispatcher import Dispatcher

    dispatcher = Dispatcher.__new__(Dispatcher)
    indicator = Dispatcher._clam_indicator(
        dispatcher,
        ClamAVResult(
            limit_exceeded=True,
            skipped_reason="Dateilimit überschritten",
        ),
    )
    assert indicator.rule_id == "CLAMAV_SIZE_LIMIT"
    assert indicator.weight == 25
    assert not indicator.rule_id.endswith("_CLEAN")


def test_av_timeouts_scale_and_cap():
    from malaz import config

    assert config.av_timeout_for_size(0) == config.AV_TIMEOUT_SECONDS
    assert config.av_timeout_for_size(600 * config.MB) > config.AV_TIMEOUT_SECONDS
    assert config.av_timeout_for_size(100 * 1024 * config.MB) == config.AV_TIMEOUT_MAX_SECONDS
    assert config.clamav_timeout_for_size(0) == config.CLAMAV_TIMEOUT_SECONDS
    assert config.clamav_timeout_for_size(100 * 1024 * config.MB) == config.CLAMAV_TIMEOUT_MAX_SECONDS
