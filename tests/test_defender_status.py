import json
from unittest import mock

from malaz.analysis import defender_status as ds


def _run_with(stdout=b"", stderr=b"", returncode=0):
    # run_tool liefert (rc, stdout, stderr) statt eines CompletedProcess.
    return (returncode, stdout, stderr)


def test_no_powershell():
    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value=None):
        s = ds.probe()
    assert not s.probed and s.error


def test_parse_passive_mode():
    payload = json.dumps(
        {
            "AMRunningMode": "Passive Mode",
            "RealTimeProtectionEnabled": False,
            "AntivirusEnabled": True,
            "AMServiceEnabled": True,
            "IsTamperProtected": True,
            "AMProductVersion": "4.18",
            "AntivirusSignatureVersion": "1.4",
        }
    ).encode()
    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value="powershell"), mock.patch(
        "malaz.analysis.defender_status.run_tool", return_value=_run_with(payload)
    ):
        s = ds.probe()
    assert s.probed
    assert s.mode == "passive mode"
    assert s.can_scan is True
    assert "Passivmodus" in s.summary


def test_parse_not_running_cannot_scan():
    payload = json.dumps(
        {"AMRunningMode": "Not Running", "AMServiceEnabled": False}
    ).encode()
    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value="powershell"), mock.patch(
        "malaz.analysis.defender_status.run_tool", return_value=_run_with(payload)
    ):
        s = ds.probe()
    assert s.probed
    assert s.can_scan is False


def test_truncated_status_is_unknown_not_normal():
    """SEC-023: a cut-off status document must not be parsed as a mode.

    The visible prefix is complete JSON claiming "Normal Mode" — only the
    truncation flag proves the rest is missing. Unknown, not "can scan".
    """
    from malaz.procio import ToolResult

    payload = json.dumps(
        {"AMRunningMode": "Normal", "AMServiceEnabled": True}
    ).encode()
    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value="powershell"), mock.patch(
        "malaz.analysis.defender_status.run_tool",
        return_value=ToolResult(0, payload, b"", truncated=True),
    ):
        s = ds.probe()
    assert not s.probed
    assert "abgeschnitten" in (s.error or "")


def test_empty_output_is_error():
    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value="powershell"), mock.patch(
        "malaz.analysis.defender_status.run_tool", return_value=_run_with(b"", b"denied", 1)
    ):
        s = ds.probe()
    assert not s.probed and s.error


def test_timeout_is_error():
    import subprocess

    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value="powershell"), mock.patch(
        "malaz.analysis.defender_status.run_tool",
        side_effect=subprocess.TimeoutExpired("pwsh", 1),
    ):
        s = ds.probe()
    assert not s.probed and "Timeout" in s.error


def test_tamper_protection_is_visible_in_summary():
    """Ohne Tamper Protection ist das Defender-Verdikt weniger belastbar.

    Der Wert wurde vom Probe gelesen und gespeichert, aber nirgends angezeigt:
    eine Meldung "On-Demand-Scan möglich" stand damit für eine
    Defender-Konfiguration, die Schadcode hätte verändern können. Der Scan
    bleibt möglich — die Einschränkung gehört sichtbar daneben, nicht in eine
    stille Gewichtung.
    """
    payload = json.dumps(
        {
            "AMRunningMode": "Normal",
            "AMServiceEnabled": True,
            "IsTamperProtected": False,
            "AMProductVersion": "4.18.24090.11",
        }
    ).encode()
    with mock.patch("malaz.analysis.defender_status.which_absolute", return_value="powershell"), mock.patch(
        "malaz.analysis.defender_status.run_tool", return_value=_run_with(payload)
    ):
        s = ds.probe()
    assert s.tamper_protected is False
    assert "Tamper Protection AUS" in s.summary
    assert "4.18.24090.11" in s.summary
    assert s.can_scan is True
