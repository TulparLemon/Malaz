"""Windows .url shortcuts: benign intranet targets vs dangerous ones.

AP8 requires a content-based type (``[InternetShortcut]`` + ``URL=``) and a
parser that *names* the dangerous target classes without resolving or opening
anything: ``file:``, UNC, ``javascript:``, IP literal and credentials.

The benign counterexample is the other half of the contract: a normal intranet
shortcut must stay GREEN, otherwise every company bookmark becomes a finding.
"""

from __future__ import annotations

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.scoring import BASE_WEIGHTS


def _scan(tmp_path, name: str, target: bytes | None, *, extra: bytes = b""):
    data = b"[InternetShortcut]\r\n"
    if target is not None:
        data += b"URL=" + target + b"\r\n"
    data += extra
    path = tmp_path / name
    path.write_bytes(data)
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(path)


def test_benign_intranet_shortcut_stays_green(tmp_path):
    result = _scan(
        tmp_path,
        "intranet.url",
        b"https://intranet.example.local/wiki",
        extra=b"IconFile=%SystemRoot%\\system32\\shell32.dll\r\nIconIndex=13\r\n",
    )
    ids = {i.rule_id for i in result.all_indicators()}
    assert result.detected_type == "url"
    assert "URL_SHORTCUT_TARGET" in ids
    assert "URL_SHORTCUT_SUSPICIOUS" not in ids
    assert result.risk_level.name == "GREEN", f"{result.risk_level.name}/{result.score}"


@pytest.mark.parametrize(
    ("name", "target", "reason"),
    [
        ("file.url", b"file:///C:/Windows/System32/calc.exe", "file:-Schema"),
        ("path.url", b"C:\\Windows\\System32\\calc.exe", "Laufwerkspfad"),
        ("unc.url", b"\\\\fileserver\\share\\setup.exe", "UNC-Pfad"),
        ("javascript.url", b"javascript:alert(document.domain)", "javascript:-Schema"),
        ("ip.url", b"http://203.0.113.10/payload", "IP-Adresse"),
        (
            "credentials.url",
            b"https://user:pass@example.com/login",
            "Zugangsdaten",
        ),
    ],
)
def test_dangerous_shortcut_targets_are_named(tmp_path, name, target, reason):
    result = _scan(tmp_path, name, target)
    treffer = [
        i for i in result.all_indicators() if i.rule_id == "URL_SHORTCUT_SUSPICIOUS"
    ]
    assert treffer, f"{name} blieb unauffällig"
    assert treffer[0].effective_weight(BASE_WEIGHTS) == 25
    assert reason in treffer[0].detail
    # The rule must score without the OPTIONAL signature_base feed (the
    # snapshot/CI runs shipped rules only). If signature_base is installed,
    # its YARA Methodology rules can add 30 — then the file is RED; the
    # contract here is "at least YELLOW".
    assert result.risk_level.name in ("YELLOW", "RED"), (
        f"{result.risk_level.name}/{result.score}"
    )
    # The target is shown defanged; nothing is opened or resolved.
    target_note = next(
        i for i in result.all_indicators() if i.rule_id == "URL_SHORTCUT_TARGET"
    )
    assert "Ziel:" in target_note.detail
    assert "http://" not in target_note.detail
    assert "https://" not in target_note.detail
    assert "wird nicht geöffnet" in treffer[0].detail


def test_shortcut_without_section_header_is_plain_text(tmp_path):
    """The extension alone is not evidence — the section header is required."""
    path = tmp_path / "nur_url.url"
    path.write_bytes(b"URL=https://example.invalid/\r\n")
    result = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(path)
    assert result.detected_type == "text"


def test_padded_shortcut_beyond_the_preview_is_still_detected(tmp_path):
    """Comments must not push [InternetShortcut] out of the probe window.

    REPORTED: the type check only saw the first 1024 bytes, so a .url with
    ~1 KB of leading comment lines became "text" and its dangerous target was
    never parsed (while the extension triggered GEN_FORMAT_MISMATCH).
    """
    path = tmp_path / "gepolstert.url"
    path.write_bytes(
        b"; padding line\r\n" * 100
        + b"[InternetShortcut]\r\nURL=file:///C:/Windows/System32/calc.exe\r\n"
    )
    assert path.stat().st_size > 1024
    result = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(path)
    assert result.detected_type == "url"
    treffer = [
        i for i in result.all_indicators() if i.rule_id == "URL_SHORTCUT_SUSPICIOUS"
    ]
    assert treffer, "der gefährliche Zielpfad wurde hinter dem Padding nicht gesehen"
    assert treffer[0].effective_weight(BASE_WEIGHTS) == 25


def test_defang_handles_uppercase_schemes():
    from malaz.core.url_view import defang_url

    assert defang_url("HTTPS://Example.invalid/x") == "hxxps://Example.invalid/x"
    assert defang_url("http://example.invalid") == "hxxp://example.invalid"
