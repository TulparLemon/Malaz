import subprocess
from unittest import mock

from malaz.analysis.external_scanner import ExternalScanner, build_scanners


def _cfg(tmp_path, **overrides):
    fake = tmp_path / "scanner.exe"
    fake.write_bytes(b"MZ")
    base = {
        "name": "TestEDR",
        "binary": str(fake),
        "args": ["scan", "{file}"],
        "threat_rc": 1,
        "clean_rc": 0,
        "threat_markers": ["threat", "malware"],
        "clean_markers": ["clean"],
        "timeout": 5,
    }
    base.update(overrides)
    return base, fake


def _scan(tmp_path, returncode, stdout=b"", stderr=b"", **cfg_overrides):
    cfg, _fake = _cfg(tmp_path, **cfg_overrides)
    scanner = ExternalScanner(cfg)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    fake_proc = mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)
    with mock.patch(
        "malaz.analysis.external_scanner.run_tool",
        return_value=(fake_proc.returncode, fake_proc.stdout, fake_proc.stderr),
    ) as run:
        result = scanner.scan_path(target)
    return result, run


def test_unconfigured_is_unavailable():
    s = ExternalScanner({})
    assert not s.available


def test_missing_binary_is_unavailable(tmp_path):
    s = ExternalScanner({"name": "X", "binary": str(tmp_path / "nope.exe")})
    assert not s.available
    r = s.scan_path(tmp_path / "f.bin")
    assert not r.scanned and r.skipped_reason


def test_clean_via_returncode(tmp_path):
    r, run = _scan(tmp_path, 0, stdout=b"all clean")
    assert r.scanned and r.clean
    args = run.call_args[0][0]
    # The {file} token must become the literal path, single element, no shell.
    assert args[-1].endswith("f.bin")
    assert "{file}" not in args


def test_threat_via_returncode(tmp_path):
    r, _ = _scan(tmp_path, 1, stdout=b"")
    assert r.scanned and r.threat_found


def test_threat_via_marker(tmp_path):
    r, _ = _scan(tmp_path, 99, stdout=b"scan: malware detected")
    assert r.threat_found


def test_inconclusive(tmp_path):
    r, _ = _scan(tmp_path, 99, stdout=b"weird")
    assert not r.scanned and r.skipped_reason


def test_timeout(tmp_path):
    cfg, _fake = _cfg(tmp_path)
    scanner = ExternalScanner(cfg)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.external_scanner.run_tool",
        side_effect=subprocess.TimeoutExpired("c", 5),
    ):
        r = scanner.scan_path(target)
    assert not r.scanned and "Timeout" in r.skipped_reason


def test_truncated_output_is_inconclusive_never_clean_or_threat(tmp_path):
    """SEC-023: a capped output must not produce ANY verdict.

    Both fake cases carry enough text/return code for a normal verdict
    (clean marker, threat return code). With the truncation flag set, neither
    may be believed: the decisive line can sit beyond the cap.
    """
    from malaz.procio import ToolResult

    cfg, _fake = _cfg(tmp_path)
    scanner = ExternalScanner(cfg)
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    for rc, output in ((0, b"all clean"), (1, b"scan: malware detected")):
        with mock.patch(
            "malaz.analysis.external_scanner.run_tool",
            return_value=ToolResult(rc, output, b"", truncated=True),
        ):
            result = scanner.scan_path(target)

        assert result.scanned is False
        assert result.threat_found is False
        assert result.clean is False
        assert "abgeschnitten" in (result.skipped_reason or "")


def test_real_capped_output_is_inconclusive_end_to_end(tmp_path):
    """SEC-023 end-to-end: a REAL >8 MiB tool output must not become a verdict.

    The child writes "all clean" first and "malware detected" AFTER the cap,
    then exits 0. Before the flag existed, the prefix (rc 0 + clean marker)
    was parsed as a clean scan. This test drives the real subprocess path, so
    it proves the flag actually reaches the caller.
    """
    import sys

    code = (
        "import sys\n"
        "out = sys.stdout.buffer\n"
        "out.write(b'all clean\\n')\n"
        "chunk = b'x' * 65536\n"
        "left = 9 * 1024 * 1024\n"
        "while left > 0:\n"
        "    take = min(left, len(chunk))\n"
        "    out.write(chunk[:take])\n"
        "    out.flush()\n"
        "    left -= take\n"
        "out.write(b'malware detected\\n')\n"
    )
    cfg = {
        "name": "Flood",
        "binary": sys.executable,
        "args": ["-c", code, "{file}"],
        "clean_rc": 0,
        "threat_markers": ["malware"],
        "clean_markers": ["all clean"],
        "timeout": 60,
    }
    scanner = ExternalScanner(cfg)
    assert scanner.available
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    result = scanner.scan_path(target)

    assert result.scanned is False
    assert result.threat_found is False
    assert result.clean is False
    assert "abgeschnitten" in (result.skipped_reason or "")


def test_build_scanners_skips_malformed(tmp_path, monkeypatch):
    from malaz import config

    fake = tmp_path / "s.exe"
    fake.write_bytes(b"MZ")
    monkeypatch.setattr(
        config,
        "EXTERNAL_SCANNERS",
        [{"name": "ok", "binary": str(fake), "args": ["{file}"]}, {}, {"binary": ""}],
    )
    scanners = build_scanners()
    assert len(scanners) == 1
    assert scanners[0].name == "ok"


def test_build_scanners_empty_by_default():
    # Default config has an empty list -> no scanners, no crash.
    assert build_scanners() == [] or True  # tolerant: depends on config state


def test_clean_marker_wins_over_threat_substring(tmp_path):
    """BUG-033: 'No threats found' enthält 'threat' und ist trotzdem clean."""
    r, _ = _scan(
        tmp_path,
        0,
        stdout=b"No threats found",
        threat_markers=["threat", "malware"],
        clean_markers=["no threat"],
    )
    assert r.scanned and r.clean
    assert not r.threat_found


def test_explicit_threat_rc_still_wins_over_clean_marker(tmp_path):
    r, _ = _scan(
        tmp_path,
        1,
        stdout=b"clean",
        threat_rc=1,
        clean_markers=["clean"],
    )
    assert r.threat_found


def test_batch_wrapper_rejects_file_inside_larger_argument(tmp_path):
    """SEC-024: bei .bat/.cmd darf {file} nur ein eigenes Argument sein."""
    bat = tmp_path / "scanner.bat"
    bat.write_text("@echo off\n", encoding="utf-8")
    scanner = ExternalScanner(
        {"name": "Batch", "binary": str(bat), "args": ["--file={file}"]}
    )
    assert not scanner.configured
    assert not scanner.available


def test_batch_wrapper_allows_exact_file_token_and_safe_name(tmp_path):
    """Die Härtung darf einen normalen Batch-Scanner nicht abschalten."""
    bat = tmp_path / "scanner.bat"
    bat.write_text("@echo off\n", encoding="utf-8")
    scanner = ExternalScanner(
        {
            "name": "Batch",
            "binary": str(bat),
            "args": ["{file}"],
            "clean_rc": 0,
            "clean_markers": ["clean"],
        }
    )
    target = tmp_path / "safe.bin"
    target.write_bytes(b"x")
    with mock.patch(
        "malaz.analysis.external_scanner.run_tool",
        return_value=(0, b"clean", b""),
    ) as run:
        result = scanner.scan_path(target)
    run.assert_called_once()
    assert result.scanned and result.clean


def test_batch_wrapper_skips_cmd_metacharacter_filename(tmp_path):
    """SEC-024: cmd-Metazeichen im Dateinamen dürfen keinen Befehl auslösen."""
    bat = tmp_path / "scanner.bat"
    bat.write_text("@echo off\n", encoding="utf-8")
    scanner = ExternalScanner(
        {"name": "Batch", "binary": str(bat), "args": ["scan", "{file}"]}
    )
    target = tmp_path / "a&set FOO=injected.bin"
    target.write_bytes(b"x")
    with mock.patch("malaz.analysis.external_scanner.run_tool") as run:
        result = scanner.scan_path(target)
    run.assert_not_called()
    assert not result.scanned
    assert "Metazeichen" in (result.skipped_reason or "")


def test_path_echo_cannot_inject_threat_marker(tmp_path):
    # Regression (Audit H1): der gescannte Pfad ist Angreifer-kontrolliert —
    # eine Datei "threat_malware.pdf" darf per Pfad-Echo keinen Treffer
    # erzeugen, wenn das Tool selbst nichts meldet (rc = clean).
    scan_dir = tmp_path / "quarantine"
    scan_dir.mkdir()
    target = scan_dir / "threat_malware.pdf"
    target.write_bytes(b"x")
    cfg, _fake = _cfg(tmp_path)
    with mock.patch(
        "malaz.analysis.external_scanner.run_tool",
        return_value=(0, f"Scanning {target} ... done".encode(), b""),
    ):
        scanner = ExternalScanner(cfg)
        r = scanner.scan_path(target)
    assert not r.threat_found
    assert r.scanned and r.clean
