from malaz.models import Indicator, RiskLevel, ScanResult, Severity
from malaz.reporting.html_report import generate_report, save_report


def _result():
    r = ScanResult(
        path="C:/t/<b>evil</b>.pdf",
        size=10,
        sha256="ab" * 32,
        md5="cd" * 16,
        detected_type="pdf",
        mime_hint="application/pdf",
    )
    r.indicators = [
        Indicator(
            "XSS",
            'Titel <script>alert(1)</script>',
            detail='Detail <img src=x onerror=alert(1)> & "q"',
            severity=Severity.CRITICAL,
        )
    ]
    r.score = 50
    r.risk_level = RiskLevel.RED
    r.anchored = True
    return r


def test_xss_neutralised():
    html = generate_report([_result()])
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;evil&lt;/b&gt;" in html


def test_no_javascript_or_external_resources():
    html = generate_report([_result()])
    lowered = html.lower()
    assert "<script" not in lowered
    assert "http://" not in lowered and "https://" not in lowered


def test_self_contained_has_css():
    html = generate_report([_result()])
    assert "<style>" in html


def test_empty_report():
    html = generate_report([])
    assert "Keine Dateien" in html


def test_save_report(tmp_path):
    out = save_report([_result()], tmp_path / "r.html")
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_report_names_the_av_discount():
    """Regression (malaz/reporting/html_report/av-discount-missing-in-reports).

    models.ScanResult.av_discount existiert, damit Berichte zeigen koennen,
    WARUM ein Score unter der Summe seiner Befunde liegt; die CLI druckt das
    Feld, der Bericht tat es nicht: zwei saubere AV-Stimmen setzen 55 Rohpunkte
    (ROT) auf 47 (GELB) herab — der Leser sah nur "47/100" und ein Gelb ohne
    Begruendung.
    """
    import re

    r = _result()
    r.score, r.risk_level, r.anchored = 47, RiskLevel.YELLOW, False
    r.av_discount = 8
    html = generate_report([r])
    assert "Score: 47/100" in html
    assert re.search(r"8[^<]{0,40}AV-ohne-Fund", html), "die Herabsetzung fehlt"


def test_report_without_discount_has_no_discount_line():
    """Gegenrichtung: ohne AV-Rabatt keine erfundene Begruendung."""
    html = generate_report([_result()])
    assert "AV-ohne-Fund" not in html
