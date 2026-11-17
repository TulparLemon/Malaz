"""Engine verdicts: score-adjacent truth without parsing indicator text."""

from __future__ import annotations

from malaz.core.engine_verdicts import build_engine_verdicts
from malaz.models import CAT_AV, CAT_CLAMAV, Indicator, RiskLevel, ScanResult, Severity


def _result(*indicators: Indicator) -> ScanResult:
    return ScanResult(path="x.bin", indicators=list(indicators), score=0)


def test_clean_engines_are_labelled_clean():
    result = _result(
        Indicator("AV_CLEAN", "Defender sauber", category=CAT_AV),
        Indicator("CLAMAV_CLEAN", "ClamAV sauber", category=CAT_CLAMAV),
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["Defender"].state == "clean"
    assert verdicts["ClamAV"].state == "clean"
    assert verdicts["YARA"].state == "clean"


def test_skipped_is_never_clean():
    result = _result(
        Indicator("AV_SKIPPED", "Defender übersprungen", category=CAT_AV),
        Indicator(
            "CLAMAV_SIZE_LIMIT",
            "ClamAV Größenlimit",
            category=CAT_CLAMAV,
        ),
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["Defender"].state == "skipped"
    assert verdicts["ClamAV"].state == "skipped"
    assert verdicts["ClamAV"].label == "Größenlimit"


def test_threats_win_over_clean_indicators():
    result = _result(
        Indicator("AV_CLEAN", "sauber", category=CAT_AV),
        Indicator("AV_THREAT", "Bedrohung", category=CAT_AV, weight=50),
        Indicator("CLAMAV_THREAT", "Bedrohung", category=CAT_CLAMAV, weight=50),
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["Defender"].state == "threat"
    assert verdicts["ClamAV"].state == "threat"


def test_yara_hits_and_errors():
    hit = _result(
        Indicator("YARA_TestRule", "Treffer", severity=Severity.HIGH, weight=20)
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(hit)}
    assert verdicts["YARA"].state == "threat"
    assert "Treffer" in verdicts["YARA"].label

    error = _result(Indicator("YARA_SCAN_ERROR", "kaputt"))
    verdicts = {v.engine: v for v in build_engine_verdicts(error)}
    assert verdicts["YARA"].state == "error"


def test_external_engines_with_underscored_names_stay_separate():
    """BUG-007: ``split('_')[1]`` merged CYNET_1 and CYNET_2 into one vote."""
    result = _result(
        Indicator(
            "EXT_CYNET_1_CLEAN", "Cynet 1: keine Bedrohung",
            weight=0, source="cynet 1",
        ),
        Indicator(
            "EXT_CYNET_2_THREAT", "Cynet 2: Fund", weight=50, source="cynet 2",
        ),
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["Cynet 1"].state == "clean"
    assert verdicts["Cynet 2"].state == "threat"
    assert len(verdicts) == 6, sorted(verdicts)  # 4 built-in + 2 external


def test_external_skipped_is_not_rendered_as_clean():
    result = _result(
        Indicator(
            "EXT_CYNET_THREAT", "Cynet: Fund", weight=50, source="cynet",
        ),
        Indicator(
            "EXT_GUARD_SKIPPED", "Guard: nicht verfügbar",
            weight=0, source="guard",
        ),
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["Guard"].state == "skipped"
    assert verdicts["Guard"].label == "nicht geprüft"


def test_static_verdict_reflects_risk_and_incomplete():
    green = ScanResult(path="x", score=0, risk_level=RiskLevel.GREEN)
    assert {v.engine: v for v in build_engine_verdicts(green)}["Statisch"].state == "clean"

    yellow = ScanResult(path="x", score=25, risk_level=RiskLevel.YELLOW)
    static = {v.engine: v for v in build_engine_verdicts(yellow)}["Statisch"]
    assert static.state == "threat"
    assert "25/100" in static.label


def test_external_engine_is_grouped():
    result = _result(
        Indicator("EXT_CYNET_THREAT", "Cynet: Fund", weight=50, source="cynet")
    )
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["Cynet"].state == "threat"


def test_generic_pipeline_error_marks_yara_not_checked():
    """GENERIC_ERROR means the YARA stage may never have run."""
    result = _result(Indicator("GENERIC_ERROR", "Generic pipeline failed", weight=25))
    verdicts = {v.engine: v for v in build_engine_verdicts(result)}
    assert verdicts["YARA"].state == "error"
    assert "geprüft" in verdicts["YARA"].label
