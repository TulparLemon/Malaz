import subprocess
from pathlib import Path
from unittest import mock

from malaz.analysis.windows_av import (
    WindowsDefenderScanner,
    _looks_like_scan_failure,
    _merge_verdicts,
    _remediation_detected,
    _structured_verdict,
    _verdict_from_output,
)


def _scanner_with_fake_binary(tmp_path, disable_remediation=False):
    fake = tmp_path / "MpCmdRun.exe"
    fake.write_bytes(b"MZ")  # existence is enough for the locator
    scanner = WindowsDefenderScanner.__new__(WindowsDefenderScanner)
    scanner.enabled = True
    scanner.timeout = 5
    scanner.disable_remediation = disable_remediation
    scanner.mpcmdrun = fake
    return scanner


def _scan_with(tmp_path, returncode, stdout=b"", stderr=b"", disable_remediation=False):
    scanner = _scanner_with_fake_binary(tmp_path, disable_remediation=disable_remediation)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)
    with mock.patch(
        "malaz.analysis.windows_av.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ) as run:
        result = scanner.scan_path(target)
    return result, run


def test_disabled_scanner_skips():
    s = WindowsDefenderScanner(enabled=False)
    r = s.scan_bytes(b"data")
    assert not r.scanned
    assert r.skipped_reason


def test_missing_file_skips(tmp_path):
    s = _scanner_with_fake_binary(tmp_path)
    r = s.scan_path(Path(tmp_path) / "nope.bin")
    assert not r.scanned
    assert r.skipped_reason


def test_relative_path_is_resolved_before_scan(tmp_path, monkeypatch):
    # MpCmdRun aborts with an engine error (hr = 0x80508023) on relative paths,
    # so scan_path must hand the binary an absolute path even when the caller
    # (CLI, scan.bat) passes one relative to the cwd.
    scanner = _scanner_with_fake_binary(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    monkeypatch.chdir(tmp_path)
    fake_proc = mock.Mock(returncode=0, stdout=b"found no threats", stderr=b"")
    with mock.patch(
        "malaz.analysis.windows_av.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ) as run:
        result = scanner.scan_path("f.bin")
    assert result.scanned and result.clean
    args = run.call_args[0][0]
    file_arg = Path(args[args.index("-File") + 1])
    assert file_arg.is_absolute()
    assert file_arg == target.resolve()


def test_clean_returncode_and_default_args(tmp_path):
    r, run = _scan_with(tmp_path, 0, stdout=b"Scanning f found no threats.")
    assert r.scanned and r.clean and not r.threat_found
    args = run.call_args[0][0]
    # Argument list + custom scan.
    assert "-Scan" in args and "-File" in args
    assert "-ScanType" in args and "3" in args
    # Default: remediation is ALLOWED, so the flag must NOT be present.
    assert "-DisableRemediation" not in args


def test_truncated_output_is_skipped_not_clean_or_threat(tmp_path):
    """SEC-023: a capped MpCmdRun output is not a scan result.

    The visible prefix says "found no threats" / names a Trojan and the return
    code is Defender's own — but the rest of Defender's output is gone. The
    result must be "not checked" (scanned=False), never clean and never a
    threat.
    """
    from malaz.procio import ToolResult

    scanner = _scanner_with_fake_binary(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    for rc, output in (
        (0, b"Scanning f found no threats."),
        (2, b"found Trojan:Win32/Foo. Threats detected."),
    ):
        with mock.patch(
            "malaz.analysis.windows_av.run_tool",
            return_value=ToolResult(rc, output, b"", truncated=True),
        ):
            result = scanner.scan_path(target)

        assert result.scanned is False
        assert result.threat_found is False
        assert result.clean is False
        assert "abgeschnitten" in (result.skipped_reason or "")


def test_subprocess_runs_without_console_window():
    # Die Engines laufen jetzt über procio.run_tool; die Fenster-
    # Unterdrückung (CREATE_NO_WINDOW) wird zentral in tests/test_procio.py
    # per Popen-Kwargs-Check verifiziert. Hier bleibt der Verweis-Check.
    from malaz.procio import no_window_flags

    assert callable(no_window_flags)


def test_analysis_mode_passes_disable_remediation(tmp_path):
    _, run = _scan_with(tmp_path, 0, stdout=b"found no threats", disable_remediation=True)
    args = run.call_args[0][0]
    assert "-DisableRemediation" in args


def test_threat_returncode(tmp_path):
    r, _ = _scan_with(tmp_path, 2, stdout=b"found Trojan:Win32/Foo")
    assert r.scanned and r.threat_found


def test_threat_remediation_detected_and_reported(tmp_path):
    # Defender detected AND quarantined the threat -> remediated flag + detail.
    r, _ = _scan_with(tmp_path, 2, stdout=b"found Trojan:Win32/Foo. File quarantined.")
    assert r.scanned and r.threat_found
    assert r.remediated is True
    assert "bereinigt" in r.detail


def test_threat_not_remediated_in_analysis_mode(tmp_path):
    r, _ = _scan_with(
        tmp_path, 2, stdout=b"found Trojan:Win32/Foo", disable_remediation=True
    )
    assert r.threat_found
    assert r.remediated is False
    assert "verbleibt" in r.detail  # notes the file stays on disk


def test_threat_detected_via_output_even_if_rc_zero(tmp_path):
    # Some builds return 0 but report the threat only in the output text.
    r, _ = _scan_with(tmp_path, 0, stdout=b"Scanning f found Trojan:Win32/Foo. Threats detected.")
    assert r.scanned and r.threat_found


def test_passive_mode_unusual_rc_but_clean_output_not_skipped(tmp_path):
    # Key EDR/passive-mode case: return code is unusual, but the output clearly
    # says no threats -> must be reported clean, NOT skipped.
    r, _ = _scan_with(tmp_path, 1, stdout=b"Scanning f found no threats.")
    assert r.scanned and r.clean
    assert r.skipped_reason is None


def test_unusual_rc_with_threat_output_is_threat(tmp_path):
    r, _ = _scan_with(tmp_path, 1, stdout=b"Threats detected: Trojan")
    assert r.scanned and r.threat_found


def test_disabled_by_edr_message(tmp_path):
    r, _ = _scan_with(tmp_path, 1, stderr=b"Microsoft Defender Antivirus is disabled.")
    assert not r.scanned
    assert r.skipped_reason is not None
    assert "deaktiviert" in r.skipped_reason


def test_inconclusive_returncode(tmp_path):
    r, _ = _scan_with(tmp_path, 1, stdout=b"some unrelated error")
    assert not r.scanned
    assert r.skipped_reason  # generic inconclusive, no score impact


def test_timeout_skips(tmp_path):
    scanner = _scanner_with_fake_binary(tmp_path)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.windows_av.run_tool",
        side_effect=subprocess.TimeoutExpired("cmd", 5),
    ):
        r = scanner.scan_path(target)
    assert not r.scanned
    assert r.skipped_reason and "Timeout" in r.skipped_reason


def test_verdict_from_output():
    assert _verdict_from_output("Scanning x found no threats.") == "clean"
    assert _verdict_from_output("keine Bedrohungen gefunden") == "clean"
    assert _verdict_from_output("keine Bedrohung erkannt") == "clean"  # clean wins over "erkannt"
    assert _verdict_from_output("Threats detected: Foo") == "threat"
    assert _verdict_from_output("Threat detected: Foo") == "threat"  # Singular
    assert _verdict_from_output("Bedrohung gefunden") == "threat"
    assert _verdict_from_output("Bedrohung erkannt: Trojan:Win32/Foo") == "threat"
    assert _verdict_from_output("Virus erkannt") == "threat"
    # Regression: current Defender builds exit 0 but report "found N threats."
    assert _verdict_from_output("Scanning f found 1 threats.") == "threat"
    assert _verdict_from_output("Scanning f found 3 threats.") == "threat"
    assert _verdict_from_output("found 1 threat") == "threat"
    assert _verdict_from_output("found 0 threats") is None
    assert _verdict_from_output("garbage output") is None


def test_remediation_detection():
    assert _remediation_detected("Threat quarantined successfully.")
    assert _remediation_detected("Datei wurde entfernt")
    assert _remediation_detected("in Quarantäne verschoben")
    assert not _remediation_detected("found no threats")
    assert not _remediation_detected("found Trojan:Win32/Foo")


def test_threat_rc_zero_found_count_phrase(tmp_path):
    # Regression (VM-Befund): MpCmdRun on this Defender build exits 0 after a
    # detection + remediation and reports "found 1 threats." — this must be a
    # threat, NOT clean (previously the file was removed but recorded AV_CLEAN).
    out = b"Scanning C:\\x\\eicar.com found 1 threats.\nCleaning started...\nCleaning finished."
    r, _ = _scan_with(tmp_path, 0, stdout=out)
    assert r.scanned
    assert r.threat_found
    assert r.remediated
    assert not r.clean


def test_result_token_is_not_erased_by_a_file_with_the_same_name(tmp_path):
    # SEC-018: the file is named exactly like Defender's result token. The old
    # global bare-name strip deleted both occurrences, so rc=0 + "found 1
    # threats" was reported as AV_CLEAN (a real detection turned green).
    name = "found 1 threats"
    target = (tmp_path / name).resolve()
    output = f"Scanning {target}\nfound 1 threats"
    r = _scan_name_with_output(tmp_path, name, 0, output)
    assert r.scanned and r.threat_found
    assert not r.clean


def test_raw_result_token_survives_echo_stripping():
    # SEC-018 second half: the token is read from the raw output as well. When
    # the echoed name is identical to the result token, strip_scan_target
    # removes BOTH occurrences on the echo line and the stripped text has no
    # verdict left — the raw token must still decide "threat".
    raw = "Scanning found 1 threats found 1 threats"
    stripped = "Scanning "
    assert _verdict_from_output(stripped) is None
    assert _structured_verdict(raw) == "threat"
    assert _merge_verdicts(_structured_verdict(raw), _verdict_from_output(stripped)) == "threat"


def test_verdict_phrase_in_filename_stays_clean(tmp_path):
    # Counter-test: "threat detected.pdf" is data echoed back by the scan, not
    # a verdict. Both Defender's normal result line and a bare echo line must
    # stay clean with rc=0.
    name = "threat detected.pdf"
    target = (tmp_path / name).resolve()
    for output in (
        f"Scanning {target}\nfound no threats.",
        f"Scanning {target}",
    ):
        r = _scan_name_with_output(tmp_path, name, 0, output)
        assert r.scanned and r.clean and not r.threat_found, output


def test_normal_clean_scan_with_path_echo_stays_clean(tmp_path):
    r, _ = _scan_with(
        tmp_path, 0, stdout=b"Scanning C:\\x\\a.pdf ... found no threats."
    )
    assert r.scanned and r.clean and not r.threat_found


def test_remediation_output_without_threat_phrase_is_threat(tmp_path):
    # Safety net: cleaning/remediation output with rc 0 must NOT be recorded
    # as clean even if no threat phrase matches (future phrase gaps would
    # otherwise silently swallow real detections again).
    out = b"Scanning f done.\nRemoving file.\nCleaning finished."
    r, _ = _scan_with(tmp_path, 0, stdout=out)
    assert r.scanned
    assert r.threat_found
    assert r.remediated


def test_clean_phrase_with_remediation_is_still_threat(tmp_path):
    # Conservative by design: a remediated file IS a detected threat, even if
    # the output contradictorily contains "no threats".
    out = b"Scanning f found no threats.\nCleaning finished."
    r, _ = _scan_with(tmp_path, 0, stdout=out)
    assert r.threat_found
    assert r.remediated


def test_scan_failure_rc2_is_not_threat(tmp_path):
    # Regression: MpCmdRun exits 2 when the scan engine fails/aborts, but the
    # output only shows an engine error — this must NOT be a critical threat.
    out = b"Scan starting...CmdTool: Failed with hr = 0x80508023. Check the log."
    r, _ = _scan_with(tmp_path, 2, stdout=out)
    assert not r.scanned
    assert not r.threat_found
    assert r.skipped_reason is not None
    assert "fehlgeschlagen" in r.skipped_reason


def test_scan_failure_with_threat_phrase_is_still_threat(tmp_path):
    # Safety against false negatives: if the output genuinely names a threat, it
    # stays a threat even when a failure fragment is also present.
    out = b"Threats detected: Trojan:Win32/Foo. CmdTool: Failed with hr = 0x80508023"
    r, _ = _scan_with(tmp_path, 2, stdout=out)
    assert r.scanned and r.threat_found


def test_looks_like_scan_failure():
    assert _looks_like_scan_failure("CmdTool: Failed with hr = 0x80508023")
    assert _looks_like_scan_failure("scan aborted")
    assert not _looks_like_scan_failure("Scanning f found no threats.")
    assert not _looks_like_scan_failure("found Trojan:Win32/Foo")


def test_path_echo_remediation_word_is_clean(tmp_path):
    # MpCmdRun echoes the scanned path; a folder named "quarantine" or a file
    # called "removed.docx" must never flip the verdict via its own name.
    folder = tmp_path / "quarantine"
    folder.mkdir()
    target = folder / "removed.docx"
    target.write_bytes(b"x")
    out = f"Scanning {target} found no threats.".encode()
    scanner = _scanner_with_fake_binary(tmp_path)
    with mock.patch(
        "malaz.analysis.windows_av.run_tool", return_value=(0, out, b"")
    ):
        r = scanner.scan_path(target)
    assert r.scanned and r.clean and not r.threat_found and not r.remediated


def test_path_echo_threat_word_is_clean(tmp_path):
    # Same vector, opposite phrase: a file literally named "threat detected.pdf"
    # with a clean rc and no explicit clean phrase must not become CRITICAL.
    target = tmp_path / "threat detected.pdf"
    target.write_bytes(b"x")
    out = f"Scanning {target} ... done.".encode()
    scanner = _scanner_with_fake_binary(tmp_path)
    with mock.patch(
        "malaz.analysis.windows_av.run_tool", return_value=(0, out, b"")
    ):
        r = scanner.scan_path(target)
    assert r.scanned and r.clean and not r.threat_found


def test_oem_encoded_german_remediation_is_recognised(tmp_path):
    # MpCmdRun writes OEM-codepage (cp850) bytes to pipes on German Windows:
    # "Quarantäne" as 0x84 must still match the remediation phrase after the
    # UTF-8-first/OEM-fallback decode.
    out = b"found Trojan:Win32/Foo. Datei unter Quarant\x84ne gestellt."
    r, _ = _scan_with(tmp_path, 2, stdout=out)
    assert r.scanned and r.threat_found and r.remediated


def test_oem_encoded_german_clean_phrase_is_recognised(tmp_path):
    out = b"Keine Bedrohungen gefunden. L\xf6schung nicht erforderlich."
    r, _ = _scan_with(tmp_path, 0, stdout=out)
    assert r.scanned and r.clean and not r.threat_found


def test_bare_filename_echo_is_stripped_with_word_boundaries():
    # Regression (Final-Scan-Verifikation): Zeilen, die nur den DATEINAMEN
    # (ohne Pfad) echoen, muessen ebenfalls von der Phrasen-Analyse befreit
    # werden — aber mit Wortgrenzen, damit eine Datei namens 'threat' nicht
    # 'found 1 threats' zu 'found 1 s' verstuemmelt.
    from malaz.procio import strip_scan_target

    out = strip_scan_target(
        "file: threat detected.pdf found 1 threats.",
        "C:/scan/threat detected.pdf",
    )
    assert "threat detected.pdf" not in out

    out2 = strip_scan_target("x found 1 threats y", "C:/d/threat")
    assert "found 1 threats" in out2


def test_verdict_word_filename_is_not_stripped():
    # Regression (Stopwort-Fix): heißt die Datei selbst wie ein Verdict-Wort
    # ('threat', 'virus', …), darf der Bare-Name-Strip dieses Wort NICHT aus
    # der Ausgabe entfernen — sonst löscht die Datei ihre eigene Fundzeile
    # und die Phrasen-Analyse liefert ein False Negative.
    from malaz.analysis.windows_av import _verdict_from_output
    from malaz.procio import strip_scan_target

    out = strip_scan_target("1 threat found on this machine", "C:/x/threat")
    assert out == "1 threat found on this machine"
    assert _verdict_from_output(out) == "threat"

    # Mit Endung: stem 'virus' ist ebenfalls ein Stopwort.
    out2 = strip_scan_target("1 virus found in archive", "C:/x/virus.pdf")
    assert "virus found" in out2

    # Harmlose Namen werden weiterhin gestrippt (Bestandsvertrag).
    out3 = strip_scan_target("Scanning C:/d/report.pdf ok", "C:/d/report.pdf")
    assert "report.pdf" not in out3


def _oem_echo(target) -> str:
    """MpCmdRun's path echo for a name the OEM code page cannot map.

    U+2713 has no OEM representation and comes back as '?' — exactly the
    mangling that defeats the byte-exact strip in ``procio.strip_scan_target``.
    """
    return str(target).replace("\u2713", "?")


def _scan_name_with_output(tmp_path, name: str, returncode: int, output: str):
    target = tmp_path / name
    target.write_bytes(b"x")
    scanner = _scanner_with_fake_binary(tmp_path)
    with mock.patch(
        "malaz.analysis.windows_av.run_tool",
        return_value=(returncode, output.encode(), b""),
    ):
        return scanner.scan_path(target)


def test_oem_mangled_path_echo_cannot_flip_a_real_detection(tmp_path):
    # Regression (Audit Lauf 2,
    # malaz/procio/strip_scan_target/oem-echo-defeats-path-strip): MpCmdRun
    # echoes the scanned path in the OEM code page; a name that does not map
    # comes back with '?', so the exact-match strip leaves the file name in the
    # analysed text. A name carrying "found no threats" plus "scan aborted"
    # then flipped a genuine detection to AV_CLEAN — the clean phrase won
    # against the rc-2 threat path, and the fake "aborted" suppressed it.
    output = f"Scanning {_oem_echo(tmp_path / 'scan aborted found no threats \u2713.pdf')} found 1 threats."
    r = _scan_name_with_output(
        tmp_path, "scan aborted found no threats \u2713.pdf", 2, output
    )
    assert r.threat_found, "das Pfad-Echo hat den echten Defender-Treffer ueberschrieben"
    assert not r.clean


def test_oem_mangled_path_echo_with_clean_result_stays_clean(tmp_path):
    # Gegenprobe: derselbe Name mit einem tatsaechlich sauberen Scan darf
    # nicht zum Treffer werden.
    output = f"Scanning {_oem_echo(tmp_path / 'scan aborted found no threats \u2713.pdf')} found no threats."
    r = _scan_name_with_output(
        tmp_path, "scan aborted found no threats \u2713.pdf", 0, output
    )
    assert r.scanned and r.clean and not r.threat_found


def test_oem_mangled_path_echo_remediation_word_stays_clean(tmp_path):
    # Gegenprobe zur Echo-Behandlung: ein Name mit Bereinigungswort
    # ("removed") darf keinen Treffer vortaeuschen. Beim exakten Strip deckt
    # das test_path_echo_remediation_word_is_clean ab — hier scheitert der
    # Strip am OEM-Echo, also muss die Auswertung den Echo selbst aussperren.
    output = f"Scanning {_oem_echo(tmp_path / 'removed \u2713.pdf')} found no threats."
    r = _scan_name_with_output(tmp_path, "removed \u2713.pdf", 0, output)
    assert r.scanned and r.clean and not r.threat_found and not r.remediated


def test_clean_phrase_does_not_override_threat_returncode(tmp_path):
    # Eine CLEAN-Phrase darf den Trefferpfad nur schlagen, wenn KEIN
    # Treffer-Returncode vorliegt. Hier ist der rc 2 (Defender meldet einen
    # Treffer) und die Clean-Phrase stammt nachweislich nicht aus einer
    # strukturierten Ergebniszeile, sondern aus dem Pfad-Echo — sie darf das
    # Ergebnis nicht zu "sauber" machen.
    r, _ = _scan_with(
        tmp_path, 2, stdout=b"Scanning C:\\tmp\\harmlos keine Bedrohungen ?.pdf"
    )
    assert not r.clean
    assert r.threat_found  # rc 2 ohne Abbruchsignal bleibt der Treffer

    # Mit einem Abbruchsignal daneben bleibt der Fall unklar: nicht sauber,
    # aber auch kein belegter Treffer.
    r2, _ = _scan_with(
        tmp_path, 2, stdout=b"Scanning C:\\tmp\\scan aborted keine Bedrohungen ?.pdf"
    )
    assert not r2.clean
    assert not r2.threat_found
    assert not r2.scanned


def test_gefaelschter_sauber_token_schlaegt_keinen_echten_treffer():
    """Audit-Befund 1 (high), am Produktionsweg nachgestellt.

    Kommt der gescannte Pfad mit einem Zeichen zurueck, das die OEM-Codepage
    NICHT verstuemmelt, scheitert die Pfad-Ersetzung — und ein Dateiname wie
    "found no threats \u2713.pdf" liefert einen SAUBER-Token, waehrend die
    echte Trefferzeile daneben steht:

        found no threats \u2713.pdf
        found Trojan:Win32/Foo. Threats detected.

    GEMESSEN vor dem Fix: "clean" — ROT waere GRUEN geworden, bei unveraendert
    im Text stehender Trefferphrase. Ein echter sauberer Bericht enthaelt keine
    Trefferphrase; kommen beide vor, stammt der Token aus dem Dateinamen.
    """
    from malaz.analysis.windows_av import _strip_result_echo, _verdict_from_output
    from malaz.procio import strip_scan_target

    # BEIDE RICHTUNGEN, und die des Audits ist die realistische: die Datei
    # heisst MIT U+2713, Defender gibt sie verstaemmelt ("?") zurueck. Dann
    # scheitert der byte-genaue Vergleich, der Echo bleibt stehen — und genau
    # daran scheiterte meine erste Reproduktion, weil ich den verstuemmelten
    # Namen als Ziel uebergab (dann greift die Ersetzung und der Fall tritt
    # gar nicht auf).
    echter_name = "C:\\tmp\\found no threats \u2713.pdf"
    verstuemmelt = "C:\\tmp\\found no threats ?.pdf"
    trefferzeile = "found Trojan:Win32/Foo. Threats detected."

    # NUR die erreichbare Richtung: der uebergebene Pfad ist der echte (so
    # steht er auf der Platte, windows_av.py:390), der Echo kommt verstaemmelt
    # zurueck. Die Umkehrung (Ziel verstaemmelt, Echo echt) wird NICHT
    # geprueft — nicht weil sie unmoeglich waere, sondern weil kein Aufrufer
    # sie herstellt und der Code nicht fuer einen unbegehbaren Fall wachsen
    # soll. Wird spaeter ein Aufrufer mit verstaemmeltem Ziel ergaenzt, gehoert
    # diese Zusicherung hierher.
    #
    # Sie auf "clean" festzuschreiben waere zudem die Aussage, dass ein
    # gefaelschter Sauber-Token gewinnen darf.
    analyse = _strip_result_echo(
        strip_scan_target(f"Scanning {verstuemmelt}\n{trefferzeile}", echter_name)
    )
    assert _verdict_from_output(analyse) == "threat", analyse

    # Und eine echte Saubermeldung unter demselben Namen bleibt sauber.
    sauber = _strip_result_echo(
        strip_scan_target(f"Scanning {verstuemmelt}\nfound no threats", echter_name)
    )
    assert _verdict_from_output(sauber) == "clean"

    # UND DIE UMKEHRUNG: ein Dateiname darf ein Urteil in KEINE Richtung
    # kippen. Der Name traegt hier selbst eine Trefferphrase, der Scan ist
    # aber sauber — der Echo kommt verstaemmelt zurueck, also half die
    # byte-genaue Namensentfernung nicht, und vor der Korrektur kam "threat"
    # heraus. Behoben an der Wurzel: die Echo-Behandlung entfernt den
    # Basisnamen in BEIDEN Formen (roh und verstuemmelt).
    for drohender_name in ("threat detected", "bedrohung gefunden"):
        echt = f"C:\\t\\{drohender_name} \u2713.pdf"
        verst = f"C:\\t\\{drohender_name} ?.pdf"
        for meldung in ("found no threats", "Keine Bedrohungen gefunden."):
            a = _strip_result_echo(strip_scan_target(f"Scanning {verst}\n{meldung}", echt))
            assert _verdict_from_output(a) == "clean", (drohender_name, meldung, a)

    # Deutsche Saubermeldungen ebenfalls (sie tragen keinen Token).
    for deutsch in ("Keine Bedrohungen gefunden.", "Keine Bedrohung gefunden."):
        a = _strip_result_echo(strip_scan_target(f"Scanning {verstuemmelt}\n{deutsch}", echter_name))
        assert _verdict_from_output(a) == "clean", a
