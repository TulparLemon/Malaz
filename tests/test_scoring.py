from malaz.core.scoring import classify, compute_score
from malaz.models import Indicator, RiskLevel, Severity


def _ind(sev, weight=None, rule_id="R"):
    """Ein Befund.

    ``rule_id`` ist ein Parameter, weil die Wertung seit dem
    "ein Merkmal, eine Wertung"-Umbau JE rule_id einmal zaehlt: derselbe
    Befund auf mehreren Mitgliedern soll nicht mehrfach wirken
    (ARCH_MEMBER_ERROR, GEN_ENTROPY und GEN_IOC taten genau das). Wo ein Test
    das SUMMIEREN pruefen will, braucht er also verschiedene rule_ids —
    sonst prueft er versehentlich die Entdopplung.
    """
    return Indicator(rule_id, "t", severity=sev, weight=weight)


def test_green_range():
    b = compute_score([_ind(Severity.MEDIUM)])  # 15
    assert b.score == 15
    assert b.risk_level == RiskLevel.GREEN


def test_yellow_range():
    b = compute_score([_ind(Severity.HIGH, rule_id="A"), _ind(Severity.MEDIUM, rule_id="B")])  # 45
    assert b.score == 45
    assert b.risk_level == RiskLevel.YELLOW


def test_anchor_forces_red():
    b = compute_score([_ind(Severity.CRITICAL)])
    assert b.anchored
    assert b.score >= 50
    assert b.risk_level == RiskLevel.RED


def test_anchor_overrides_low_sum():
    # A single low indicator plus a critical one must still be red.
    b = compute_score([_ind(Severity.LOW), _ind(Severity.CRITICAL, weight=1)])
    assert b.anchored
    assert b.score == 50
    assert b.risk_level == RiskLevel.RED


def test_score_capped_at_100():
    # TEST-008: both indicators used the DEFAULT rule_id "R", so the
    # per-rule dedup produced raw 100 and ``min(SCORE_CAP, …)`` never fired —
    # deleting the cap line stayed green. Distinct rules give raw 200.
    b = compute_score([
        _ind(Severity.CRITICAL, weight=100, rule_id="A"),
        _ind(Severity.CRITICAL, weight=100, rule_id="B"),
    ])
    assert b.raw == 200
    assert b.score == 100


def test_explicit_weight_overrides_base():
    b = compute_score([_ind(Severity.INFO, weight=25)])
    assert b.score == 25
    assert b.risk_level == RiskLevel.YELLOW


def test_classify_boundaries():
    assert classify(0) == RiskLevel.GREEN
    assert classify(19) == RiskLevel.GREEN
    assert classify(20) == RiskLevel.YELLOW
    assert classify(49) == RiskLevel.YELLOW
    assert classify(50) == RiskLevel.RED
    assert classify(100) == RiskLevel.RED


# -- AV clean-vote discount ------------------------------------------------ #

def _clean(rule_id):
    return Indicator(rule_id, "keine Bedrohung", severity=Severity.INFO)


def test_two_clean_engines_reduce_score():
    b = compute_score([_ind(Severity.MEDIUM), _clean("AV_CLEAN"), _clean("CLAMAV_CLEAN")])
    assert b.discount == 8
    assert b.score == 7  # 15 - 8
    assert b.risk_level == RiskLevel.GREEN


def test_single_clean_engine_discounts_less():
    b = compute_score([_ind(Severity.MEDIUM), _clean("AV_CLEAN")])
    assert b.discount == 4
    assert b.score == 11


def test_clean_discount_capped():
    b = compute_score([
        _ind(Severity.MEDIUM),
        _clean("AV_CLEAN"), _clean("CLAMAV_CLEAN"), _clean("EXT_TOOLX_CLEAN"),
    ])
    assert b.discount == 8  # cap, despite three engines
    assert b.score == 7


def test_clean_votes_deduplicated_across_members():
    # Parent and archive member both carry CLAMAV_CLEAN — one vote per engine.
    b = compute_score([_ind(Severity.MEDIUM), _clean("CLAMAV_CLEAN"), _clean("CLAMAV_CLEAN")])
    assert b.discount == 4


def test_critical_anchor_survives_clean_discount():
    b = compute_score([
        _ind(Severity.CRITICAL), _clean("AV_CLEAN"), _clean("CLAMAV_CLEAN"),
    ])
    assert b.anchored
    assert b.score == 50  # anchor applied AFTER the discount
    assert b.risk_level == RiskLevel.RED


def test_skipped_engine_never_discounts():
    skipped = Indicator("AV_SKIPPED", "übersprungen", severity=Severity.INFO)
    b = compute_score([_ind(Severity.MEDIUM), skipped])
    assert b.discount == 0
    assert b.score == 15


def test_discount_floors_at_zero():
    b = compute_score([_clean("AV_CLEAN"), _clean("CLAMAV_CLEAN")])
    assert b.score == 0
    assert b.risk_level == RiskLevel.GREEN


def test_clean_av_votes_cannot_create_a_green_verdict():
    """Der AV-Rabatt darf „ungeprüft" nicht in „sauber" verwandeln.

    Regression (Runde 10, am echten Artefakt gefunden): eine Datei, deren
    EINZIGE Meldung eine „ungeprüft"-Notiz mit Gewicht 25 ist, wurde durch zwei
    saubere AV-Stimmen (Rabatt 8) auf 17 = GRÜN gedrueckt. Die Engines haben
    nur die Bytes beurteilt, die sie bekommen haben — eine Aussage „dieser Teil
    wurde NICHT geprueft" beantworten sie nicht. Das traf JEDE solche Notiz
    (ARCH_MEMBER_SKIP, ARCH_MEMBER_STOP, CORE_ERROR, CORE_READ_TRUNCATED,
    MAIL_CONTAINER_WARN, ARCH_TAR_ERROR), also die gesamte Arbeit der Runden
    2-9, sobald die Engines aktiv waren — im Normalfall des Nutzers.

    Der Rabatt darf ein Urteil senken, aber nicht heben: unterhalb der
    GRÜN-Schwelle wirkt er unveraendert (gemessen 55 -> 47, ROT -> GELB).
    """
    from malaz import config
    from malaz.core.scoring import compute_score
    from malaz.models import CAT_ARCHIVE, CAT_AV, CAT_MACRO, Indicator, RiskLevel, Severity

    def av_clean() -> list[Indicator]:
        return [
            Indicator(
                rule_id=rid, title="", detail="",
                severity=Severity.INFO, category=CAT_AV, weight=0,
            )
            for rid in ("AV_CLEAN", "CLAMAV_CLEAN")
        ]

    def note(weight: int) -> list[Indicator]:
        return [
            Indicator(
                rule_id="ARCH_MEMBER_SKIP", title="", detail="",
                severity=Severity.MEDIUM, category=CAT_ARCHIVE, weight=weight,
            )
        ]

    unexamined = compute_score(note(25))
    assert unexamined.risk_level == RiskLevel.YELLOW
    with_votes = compute_score(note(25) + av_clean())
    assert with_votes.risk_level != RiskLevel.GREEN, (
        f"zwei saubere AV-Stimmen haben 'ungeprueft' zu GRUEN gemacht "
        f"(score={with_votes.score}, Rabatt={with_votes.discount})"
    )
    assert with_votes.discount > 0, "der Rabatt soll weiterhin wirken"
    assert with_votes.score <= unexamined.score

    # Gegenrichtung: der Rabatt senkt weiterhin, und echte Grün-Faelle bleiben grün.
    heavy = compute_score(
        [
            Indicator(
                rule_id="OFFICE_SUSPICIOUS_API", title="", detail="",
                severity=Severity.HIGH, category=CAT_MACRO, weight=60,
            ),
            *av_clean(),
        ]
    )
    assert heavy.score == 52, heavy.score  # 60 - 8, unveraendert
    assert compute_score(note(10) + av_clean()).risk_level == RiskLevel.GREEN
    assert compute_score(av_clean()).risk_level == RiskLevel.GREEN
    assert config.SCORE_GREEN_MAX == 19  # die Schwelle, gegen die hier gerechnet wird


def test_derselbe_befund_zaehlt_einmal():
    """Ein Merkmal, eine Wertung — je rule_id der hoechste Einzelwert.

    GEMESSEN an drei Stellen unabhaengig voneinander:
      ARCH_MEMBER_ERROR  25 je nicht entpackbarem Mitglied; zwei davon ergaben
                         50 und damit ROT fuer ein Archiv, das Malaz schlicht
                         nicht lesen konnte.
      GEN_ENTROPY         5 je Bild-Stream; 11 Bilder in einer echten
                         PowerPoint ergaben 55 -> ROT.
      GEN_IOC             5 je Mitglied; eine echte Praesentation mit
                         Hyperlinks ergab 60 -> ROT.
    Der einzelne Befund war jedes Mal richtig; seine Wiederholung war der
    Fehler. Ein Archiv mit zwei kaputten Mitgliedern ist nicht doppelt so
    verdaechtig wie eines mit einem.
    """
    zwei = compute_score([
        _ind(Severity.MEDIUM, weight=25, rule_id="ARCH_MEMBER_ERROR"),
        _ind(Severity.MEDIUM, weight=25, rule_id="ARCH_MEMBER_ERROR"),
    ])
    assert zwei.score == 25, "derselbe Befund darf sich nicht aufsummieren"
    assert zwei.risk_level == RiskLevel.YELLOW

    # Verschiedene Befunde summieren weiterhin — mehrere YARA-Regeln oder ein
    # Anker mit Begleitbefunden sind der Normalfall.
    verschieden = compute_score([
        _ind(Severity.MEDIUM, weight=25, rule_id="A"),
        _ind(Severity.MEDIUM, weight=25, rule_id="B"),
    ])
    assert verschieden.score == 50
