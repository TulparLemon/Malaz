"""„Nicht geprüft" muss man SEHEN — in der Ampel, im Protokoll, im Bericht.

Der Nutzer hat es so verlangt: *"die ampel anzeige erweitern"*, *"die logs"*,
*"auch … den pdf den die kunden am ende bekommen"*. Der gemeinsame Nenner ist
der Grundsatz aus `docs/SECURITY_MODEL.md`:

    Was wir nicht geprüft haben, darf nicht wie geprüft aussehen.

Alle Stufenmeldungen tragen **Gewicht 0** — eine fehlende Bibliothek ist der
Datei nicht anzulasten. Genau deshalb ändern sie den Score nicht, und ohne
diese Anzeigen wäre eine unvollständig geprüfte Datei von einer sauberen nicht
zu unterscheiden.
"""

from __future__ import annotations

import logging

import pytest

from malaz.models import CAT_AV, Indicator, RiskLevel, ScanResult, Severity


def _ergebnis(rule_ids: list[str]) -> ScanResult:
    r = ScanResult(path="probe.bin")
    r.score = 0
    r.indicators = [
        Indicator(
            rule_id=rid,
            title=f"Stufe {rid}",
            detail="",
            severity=Severity.INFO,
            category=CAT_AV,
            weight=0,
        )
        for rid in rule_ids
    ]
    return r


def test_sauberes_ergebnis_ist_nicht_unvollstaendig():
    """Die Gegenprobe: ohne Stufenmeldung darf nichts markiert werden."""
    r = _ergebnis([])
    assert r.is_incomplete is False
    assert r.incomplete_stages == []
    assert r.incompleteness_note() == ""


def test_stufenmeldung_macht_das_ergebnis_unvollstaendig():
    r = _ergebnis(["AV_SKIPPED"])
    assert r.is_incomplete is True
    assert "AV_SKIPPED" in [i.rule_id for i in r.incomplete_stages]
    assert "UNVOLLSTÄNDIG" in r.incompleteness_note()


def test_prefix_scan_is_incomplete_not_complete():
    """BUG-005: only a prefix was analysed -> never "vollständig geprüft"."""
    for rule_id in ("CORE_READ_TRUNCATED", "CORE_READ_SHORT", "CORE_FILE_CHANGED"):
        r = _ergebnis([rule_id])
        assert r.is_incomplete is True, rule_id
        assert "UNVOLLSTÄNDIG" in r.incompleteness_note()


def test_kinder_zaehlen_nicht_in_das_elternteil():
    """Ein sauberes Elternteil darf wegen eines Kindes nicht unvollständig
    heißen — sonst steht der Zusatz an jedem Archiv, das ein ungeprüftes
    Mitglied enthält, und wird nach zwei Wochen ignoriert."""
    aussen = _ergebnis([])
    kind = _ergebnis(["OFFICE_LIB_MISSING"])
    aussen.children = [kind]

    assert aussen.is_incomplete is False, "das Kind faerbte das Elternteil"
    assert kind.is_incomplete is True
    # `all_indicators` zieht die Kinder mit herein — genau deshalb wird es
    # hier NICHT benutzt.
    assert any(i.rule_id == "OFFICE_LIB_MISSING" for i in aussen.all_indicators())


def test_ampelszelle_traegt_den_zusatz():
    """Ohne den Zusatz liest sich ein Grün wie ein Freispruch."""
    from malaz.gui.main_window import _verdict_cell

    sauber = _ergebnis([])
    sauber.score = 0
    assert _verdict_cell(sauber) == sauber.risk_level.short

    luecke = _ergebnis(["DIE_SKIPPED"])
    luecke.score = 0
    zelle = _verdict_cell(luecke)
    assert "unvollständig" in zelle, zelle
    assert zelle.startswith(luecke.risk_level.short)


def test_ampel_stufe_bleibt_dreiwertig():
    """Kein vierter Zustand im Modell: die Bewertung darf sich nicht ändern.

    Ein `RiskLevel.UNKNOWN` haette jeden Vergleich im Scoring beruehrt. Der
    Zustand wird deshalb ABGELEITET, nicht eingeordnet.
    """
    assert [int(x) for x in RiskLevel] == [0, 1, 2]


def test_protokoll_nennt_die_luecke(caplog):
    """Wer hinterher nachvollziehen will, ob ein Grün ein Freispruch war."""
    from malaz.core.dispatcher import Dispatcher

    d = Dispatcher.__new__(Dispatcher)
    with caplog.at_level(logging.INFO, logger="malaz.core.dispatcher"):
        d._log_stages(_ergebnis(["YARA_SCAN_ERROR"]))
    text = caplog.text
    assert "UNVOLLSTÄNDIG" in text
    assert "YARA_SCAN_ERROR" in text or "Stufe YARA_SCAN_ERROR" in text


def test_protokoll_nennt_auch_den_vollstaendigen_fall(caplog):
    """Eine LÜCKE ist in einem Protokoll nur erkennbar, wenn die
    vollständigen Fälle danebenstehen — ein fehlender Eintrag sähe aus wie
    ein Scan, der nie stattfand."""
    from malaz.core.dispatcher import Dispatcher

    d = Dispatcher.__new__(Dispatcher)
    with caplog.at_level(logging.INFO, logger="malaz.core.dispatcher"):
        d._log_stages(_ergebnis([]))
    assert "vollständig geprüft" in caplog.text


def test_jede_stufenmeldung_ist_entweder_gemeldet_oder_bewusst_ausgenommen():
    """Die Liste darf nicht wieder zu kurz werden.

    GEMESSEN war sie es: `OFFICE_VBA_WARN`, `OFFICE_DDE_PARSE_WARN`,
    `OFFICE_XLM_PARSE_WARN`, `OFFICE_FORMULA_PARSE_WARN`, `OFFICE_STAGE_WARN`,
    `PDF_PARSE_WARN`, `PDF_JS_PARSE_WARN`, `CAPA_ERROR`, `CAPA_UNAVAILABLE`,
    `MAIL_PARSE_WARN` und `AV_MEMBER_ERROR` fehlten. Eine Datei, deren
    Makro- oder JS-Stufe fehlschlug, las sich danach als vollständig geprüft —
    das Gegenteil des Grundsatzes.
    """
    from malaz.models import _INCOMPLETE_RULES

    # TEST-012: this used to be a SUBSET check (``muss_drin - set(...)``), so
    # removing an entry stayed green and the older gaps (CORE_TIME_BUDGET,
    # CLAMAV_SIZE_LIMIT, YARA_LOAD_ERROR, …) were never pinned. Equality is the
    # contract: growing the list is a deliberate edit here, shrinking it fails.
    muss_drin = {
        "AV_SKIPPED",
        "AV_ERROR",
        "AV_MEMBER_ERROR",
        "CLAMAV_SKIPPED",
        "CLAMAV_ERROR",
        "CLAMAV_SIZE_LIMIT",
        "CAPA_SKIPPED",
        "CAPA_UNAVAILABLE",
        "CAPA_ERROR",
        "DIE_SKIPPED",
        "DIE_ERROR",
        "YARA_SCAN_ERROR",
        "YARA_LOAD_ERROR",
        "PDF_LIB_MISSING",
        "PDF_PARSE_WARN",
        "PDF_JS_PARSE_WARN",
        "PDF_LINK_CAPPED",
        "WEB_PARSE_LIMIT",
        "ONENOTE_PARSE_ERROR",
        "ONENOTE_OBJ_ERROR",
        "QR_SCAN_INCOMPLETE",
        "OFFICE_LIB_MISSING",
        "OFFICE_STAGE_WARN",
        "OFFICE_DDE_PARSE_WARN",
        "OFFICE_XLM_PARSE_WARN",
        "OFFICE_XLM_PRESENT",
        "OFFICE_FORMULA_PARSE_WARN",
        "MAIL_PARSE_WARN",
        "MAIL_PARTS_TRUNCATED",
        "MAIL_REPUTATION_WARN",
        "MAIL_AUTH_DNS_UNKNOWN",
        "CORE_ERROR",
        "CORE_TIME_BUDGET",
        # A file above MAX_FILE_SIZE is only stat'ed, and ARCH_NOTE_UNREAD is
        # the summary note behind an unread tail — both say "a stage did not
        # run", so both belong to the closed set.
        "CORE_LIMIT",
        "ARCH_NOTE_UNREAD",
        "CORE_READ_TRUNCATED",
        "CORE_READ_SHORT",
        "CORE_FILE_CHANGED",
        "HASH_BLOCKLIST_UNAVAILABLE",
        "DOMAIN_BLOCKLIST_UNAVAILABLE",
        "IP_BLOCKLIST_UNAVAILABLE",
        "URL_BLOCKLIST_UNAVAILABLE",
    }
    assert set(_INCOMPLETE_RULES) == muss_drin


def test_regel_mit_doppelbedeutung_bleibt_draussen():
    """`OFFICE_VBA_WARN` heisst NICHT nur "die Stufe lief nicht".

    Zwei Titel unter einer ID: "Makro-Projekt erkannt, aber kein Quelltext
    ausgelesen" ist eine Aussage ueber die DATEI (und sogar ein Verdacht),
    "VBA-Analyse fehlerhaft" ist die Stufe. Nach der ID allein ist das nicht
    zu trennen — stuende die Regel in der Liste, hiesse jede Datei mit einem
    Makro-Projekt "unvollstaendig geprueft", und der Zusatz waere Rauschen.
    """
    from malaz.models import _INCOMPLETE_RULES

    assert "OFFICE_VBA_WARN" not in _INCOMPLETE_RULES


def test_pdf_parse_warn_ist_drin_weil_alle_titel_dasselbe_sagen():
    """Die Gegenprobe: drei Titel, aber ALLE heissen "Stufe lief nicht"."""
    from malaz.models import _INCOMPLETE_RULES

    assert "PDF_PARSE_WARN" in _INCOMPLETE_RULES


def test_bericht_mit_vielen_luecken_bleibt_lesbar(tmp_path, qapp):
    """Der Chip und der Abschnitt dürfen bei vielen Lücken nicht überlaufen.

    Der Chip ist eine feste Fläche; ein zu langer Text darin wird
    abgeschnitten oder schiebt den Score aus dem Bild. Geprüft wird deshalb,
    dass der Bericht mit 20 Lücken überhaupt entsteht und der Abschnitt die
    Stufen NENNT — nicht nur "unvollständig" sagt.
    """
    from PySide6.QtGui import QFontDatabase

    from malaz.models import CAT_AV, Indicator, RiskLevel, ScanResult, Severity

    # OHNE QApplication BRICHT Qt HART AB — GEMESSEN: Exit 9, keine Ausgabe,
    # kein Traceback. Die qapp-Fixture (pytest-qt) stellt sie bereit; der
    # bestehende PDF-Test macht es genauso (tests/test_pdf_report.py).
    if not QFontDatabase().families():
        pytest.skip("keine Fonts verfügbar — Bericht nicht renderbar")

    from malaz.reporting.pdf_report import save_pdf_report

    r = ScanResult(path="probe.bin")
    r.score = 0
    r.risk_level = RiskLevel.GREEN
    r.indicators = [
        Indicator(
            rule_id=rid,
            title=f"Stufe {rid} nicht gelaufen",
            detail="",
            severity=Severity.INFO,
            category=CAT_AV,
            weight=0,
        )
        for rid in ["AV_SKIPPED", "DIE_SKIPPED", "CAPA_ERROR", "PDF_PARSE_WARN"]
        * 5
    ]
    ziel = tmp_path / "bericht.pdf"
    save_pdf_report([r], ziel)
    assert ziel.is_file()
    assert ziel.stat().st_size > 1000, "der Bericht ist leer"
    assert r.is_incomplete
    # Der Abschnitt nennt die Stufen — ein nacktes "unvollständig" zwänge den
    # Leser zu raten, was fehlt.
    notiz = r.incompleteness_note()
    assert "Stufe" in notiz
