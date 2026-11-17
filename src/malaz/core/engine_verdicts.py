"""One structured verdict per engine, for display next to the score.

The scoring indicators already say WHAT fired. They do not answer the question
a user asks first: "what did Defender say, what did ClamAV say, and did YARA
find anything?" This module turns the existing indicators into a small,
stable list of engine verdicts. It intentionally does not change the score.

States:
* ``threat``  — the engine reported a detection
* ``clean``   — the engine ran and found nothing
* ``skipped`` — the engine did not inspect the file (missing, timeout, limit)
* ``error``   — the engine ran but failed
* ``off``     — the engine is not installed/configured

``skipped`` is never rendered as ``clean``. That distinction is the project's
central rule ("was nicht geprüft wurde, darf nicht wie geprüft aussehen").
"""

from __future__ import annotations

from ..models import EngineVerdict, Indicator, RiskLevel, ScanResult


def _first(indicators: list[Indicator], *rule_ids: str) -> Indicator | None:
    wanted = set(rule_ids)
    for indicator in indicators:
        if indicator.rule_id in wanted:
            return indicator
    return None


def _verdict(
    engine: str,
    state: str,
    label: str,
    indicator: Indicator | None = None,
) -> EngineVerdict:
    return EngineVerdict(
        engine=engine,
        state=state,
        label=label,
        detail=indicator.detail if indicator else "",
    )


def _defender(indicators: list[Indicator]) -> EngineVerdict:
    threat = _first(indicators, "AV_THREAT")
    if threat is not None:
        return _verdict("Defender", "threat", "Bedrohung", threat)
    error = _first(indicators, "AV_ERROR")
    if error is not None:
        return _verdict("Defender", "error", "Fehler", error)
    clean = _first(indicators, "AV_CLEAN")
    if clean is not None:
        return _verdict("Defender", "clean", "sauber", clean)
    skipped = _first(indicators, "AV_SKIPPED", "AV_MEMBER_ERROR")
    if skipped is not None:
        state = "error" if skipped.rule_id == "AV_MEMBER_ERROR" else "skipped"
        return _verdict("Defender", state, "nicht geprüft", skipped)
    return _verdict("Defender", "off", "nicht gelaufen")


def _clamav(indicators: list[Indicator]) -> EngineVerdict:
    threat = _first(indicators, "CLAMAV_THREAT")
    if threat is not None:
        return _verdict("ClamAV", "threat", "Bedrohung", threat)
    error = _first(indicators, "CLAMAV_ERROR")
    if error is not None:
        return _verdict("ClamAV", "error", "Fehler", error)
    clean = _first(indicators, "CLAMAV_CLEAN")
    if clean is not None:
        return _verdict("ClamAV", "clean", "sauber", clean)
    limit = _first(indicators, "CLAMAV_SIZE_LIMIT")
    if limit is not None:
        return _verdict("ClamAV", "skipped", "Größenlimit", limit)
    skipped = _first(indicators, "CLAMAV_SKIPPED")
    if skipped is not None:
        return _verdict("ClamAV", "skipped", "nicht geprüft", skipped)
    return _verdict("ClamAV", "off", "nicht gelaufen")


def _yara(indicators: list[Indicator], available: bool) -> EngineVerdict:
    error = _first(indicators, "YARA_SCAN_ERROR", "YARA_LOAD_ERROR")
    if error is not None:
        return _verdict("YARA", "error", "Fehler", error)
    # The generic pipeline contains the YARA stage. If it threw, YARA may
    # never have run; "keine Treffer" would be a false all-clear.
    generic_error = _first(indicators, "GENERIC_ERROR")
    if generic_error is not None:
        return _verdict("YARA", "error", "nicht geprüft", generic_error)
    # A file that was never read (CORE_ERROR) or only stat'ed (CORE_LIMIT,
    # above MAX_FILE_SIZE) cannot have been scanned by YARA either. Without
    # this the engine strip showed a green "YARA: keine Treffer" for a file
    # the pipeline never looked at — the one thing the module docstring
    # forbids ("skipped is never rendered as clean").
    never_read = _first(indicators, "CORE_ERROR", "CORE_LIMIT")
    if never_read is not None:
        return _verdict("YARA", "error", "nicht geprüft", never_read)
    hits = [
        indicator
        for indicator in indicators
        if indicator.rule_id.startswith("YARA_")
        and indicator.rule_id not in ("YARA_SCAN_ERROR", "YARA_LOAD_ERROR")
    ]
    if hits:
        most_severe = max(
            hits,
            key=lambda item: (item.severity, item.effective_weight({})),
        )
        return _verdict(
            "YARA",
            "threat",
            f"{len(hits)} Treffer" if len(hits) != 1 else "1 Treffer",
            most_severe,
        )
    if not available:
        return _verdict("YARA", "off", "nicht verfügbar")
    return _verdict("YARA", "clean", "keine Treffer")


def _static(result: ScanResult) -> EngineVerdict:
    level = result.risk_level
    label = f"{level.short} · {result.score}/100"
    state = "threat" if level >= RiskLevel.YELLOW else "clean"
    if result.is_incomplete:
        label += " (unvollständig)"
    return EngineVerdict(
        engine="Statisch",
        state=state,
        label=label,
        detail=result.incompleteness_note() if result.is_incomplete else "",
    )


def _external_rule_tag(rule_id: str) -> str | None:
    """Return the full scanner tag of ``EXT_<tag>_<STATE>``.

    ``split("_")[1]`` cut the tag at the first underscore, so ``CYNET_1`` and
    ``CYNET_2`` (or any name containing an underscore) collapsed into one
    engine verdict and one state silently replaced the other (BUG-007).
    Strip only the known state suffix instead.
    """
    if not rule_id.startswith("EXT_"):
        return None
    for suffix in ("_THREAT", "_CLEAN", "_SKIPPED", "_ERROR"):
        if rule_id.endswith(suffix):
            tag = rule_id[len("EXT_"):-len(suffix)]
            return tag or None
    return None


def _external(indicators: list[Indicator]) -> list[EngineVerdict]:
    """Group ``EXT_<TAG>_THREAT/CLEAN/SKIPPED/ERROR`` into one verdict each."""
    groups: dict[tuple[str, str], list[Indicator]] = {}
    for indicator in indicators:
        tag = _external_rule_tag(indicator.rule_id)
        if tag is None:
            continue
        # The configured source is the scanner's identity (lower-space name);
        # the tag is its rule-id spelling. Keying on BOTH keeps two scanners
        # that normalise to the same tag ("Cynet 1" and "Cynet-1") apart and
        # still separates CYNET_1/CYNET_2 without any split("_") truncation.
        groups.setdefault((indicator.source, tag), []).append(indicator)
    out: list[EngineVerdict] = []
    for (source, tag), items in groups.items():
        threat = next((i for i in items if i.rule_id.endswith("_THREAT")), None)
        error = next((i for i in items if i.rule_id.endswith("_ERROR")), None)
        clean = next((i for i in items if i.rule_id.endswith("_CLEAN")), None)
        skipped = next((i for i in items if i.rule_id.endswith("_SKIPPED")), None)
        engine = (source or tag).replace("_", " ").title()
        if threat is not None:
            out.append(_verdict(engine, "threat", "Bedrohung", threat))
        elif error is not None:
            out.append(_verdict(engine, "error", "Fehler", error))
        elif clean is not None:
            out.append(_verdict(engine, "clean", "sauber", clean))
        elif skipped is not None:
            out.append(_verdict(engine, "skipped", "nicht geprüft", skipped))
    return out


def build_engine_verdicts(
    result: ScanResult,
    *,
    yara_available: bool = True,
) -> list[EngineVerdict]:
    """Build the stable per-engine view for one result (no child recursion)."""
    indicators = list(result.indicators)
    verdicts = [
        _defender(indicators),
        _clamav(indicators),
        _yara(indicators, yara_available),
        _static(result),
    ]
    verdicts.extend(_external(indicators))
    return verdicts
