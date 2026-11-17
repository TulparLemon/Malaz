"""Multi-layer risk scoring.

Weighted additive model with a clean-vote discount and an anchor rule:

* ``raw = sum(effective_weight(indicator))``
* every AV engine that scanned the file WITHOUT a finding reduces the
  score (``config.AV_CLEAN_DISCOUNT_PER_ENGINE``, capped at
  ``config.AV_CLEAN_DISCOUNT_MAX``) — weak exculpatory evidence, bounded
  so it cannot mask signature hits.
* if any indicator is CRITICAL, the score is forced to at least
  ``config.ANCHOR_CRITICAL_SCORE`` (50 -> RED); the anchor is applied
  AFTER the discount.
* the score is capped to ``[0, config.SCORE_CAP]``.

See docs/ARCHITECTURE.md for the full specification.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import config
from ..models import Indicator, RiskLevel, Severity

# Base weight per severity, used when an indicator does not carry an explicit
# weight of its own.
BASE_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


@dataclass
class ScoreBreakdown:
    raw: int
    score: int
    risk_level: RiskLevel
    anchored: bool
    discount: int = 0  # score reduction from clean AV votes (>= 0)


# Rule ids whose presence means "an AV engine actually scanned this file
# and found nothing". AV_SKIPPED / error notes deliberately do NOT count —
# "not analysed" must never be worth more than "not suspicious".
_AV_CLEAN_RULE_IDS = frozenset({"AV_CLEAN", "CLAMAV_CLEAN"})


def _is_av_clean_rule(rule_id: str) -> bool:
    if rule_id in _AV_CLEAN_RULE_IDS:
        return True
    # External scanners emit EXT_<TAG>_CLEAN.
    return rule_id.startswith("EXT_") and rule_id.endswith("_CLEAN")


def av_clean_discount(indicators: list[Indicator]) -> int:
    """Bounded score reduction for clean AV verdicts (one vote per engine)."""
    votes = len({i.rule_id for i in indicators if _is_av_clean_rule(i.rule_id)})
    if votes <= 0:
        return 0
    return min(votes * config.AV_CLEAN_DISCOUNT_PER_ENGINE, config.AV_CLEAN_DISCOUNT_MAX)


def classify(score: int) -> RiskLevel:
    """Map a numeric score to a risk level."""
    if score <= config.SCORE_GREEN_MAX:
        return RiskLevel.GREEN
    if score <= config.SCORE_YELLOW_MAX:
        return RiskLevel.YELLOW
    return RiskLevel.RED


def compute_score(indicators: list[Indicator]) -> ScoreBreakdown:
    """Compute the aggregated score and risk level for a set of indicators."""
    # EIN MERKMAL, EINE WERTUNG — je rule_id zaehlt der hoechste Einzelwert,
    # nicht die Summe der Vorkommen.
    #
    # GEMESSEN, und zwar an drei Stellen unabhaengig voneinander:
    #   ARCH_MEMBER_ERROR  25 je nicht entpackbarem Mitglied; zwei davon
    #                      ergaben 50 und damit ROT fuer ein Archiv, das
    #                      Malaz schlicht nicht lesen konnte.
    #   GEN_ENTROPY         5 je Bild-Stream; 11 Bilder in einer echten
    #                      PowerPoint ergaben 55 -> ROT.
    #   GEN_IOC             5 je Mitglied; eine echte Praesentation mit
    #                      Hyperlinks ergab 60 -> ROT.
    # In allen drei Faellen war der EINZELNE Befund richtig und seine
    # Wiederholung das Problem. Ein Archiv mit zwei kaputten Mitgliedern ist
    # nicht doppelt so verdaechtig wie eines mit einem.
    #
    # Verschiedene rule_ids summieren weiterhin (mehrere YARA-Regeln, ein
    # Anker plus Begleitbefunde) — dort ist die Summe gewollt.
    hoechste: dict[str, int] = {}
    anchored = False
    for indicator in indicators:
        gewicht = indicator.effective_weight(BASE_WEIGHTS)
        vorher = hoechste.get(indicator.rule_id)
        if vorher is None or gewicht > vorher:
            hoechste[indicator.rule_id] = gewicht
        if indicator.severity == Severity.CRITICAL:
            anchored = True
    raw = sum(hoechste.values())

    discount = av_clean_discount(indicators)
    score = max(0, raw - discount)
    if raw > config.SCORE_GREEN_MAX:
        # Weak exculpatory evidence must not CREATE a clean verdict. The
        # engines only judged the bytes they were handed; a note that says
        # "this part was NOT examined" is not answered by them, so the discount
        # may lower a verdict, never lift one over the GREEN line. Measured: a
        # file whose ONLY finding was an "ungeprüft" note (25 = YELLOW) became
        # GREEN 17 with two clean AV votes (discount 8) — and that applies to
        # every such note the audit rounds added (ARCH_MEMBER_SKIP,
        # ARCH_MEMBER_STOP, CORE_ERROR, CORE_READ_TRUNCATED, MAIL_CONTAINER_WARN,
        # ARCH_TAR_ERROR), so the whole "not examined must be score-effective"
        # work was undone whenever the engines were enabled — i.e. in the
        # normal case. The discount keeps its purpose below this line: 55 -> 47
        # (RED -> YELLOW) is unchanged.
        score = max(score, config.SCORE_GREEN_MAX + 1)
    if anchored:
        # Applied AFTER the clean-vote discount: weak positive evidence must
        # never water down a hard CRITICAL signature hit.
        score = max(score, config.ANCHOR_CRITICAL_SCORE)
    score = max(0, min(config.SCORE_CAP, score))

    return ScoreBreakdown(
        raw=raw,
        score=score,
        risk_level=classify(score),
        anchored=anchored,
        discount=discount,
    )
