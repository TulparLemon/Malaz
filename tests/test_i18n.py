"""Comprehensive tests for DE/EN/TR localization (Spec 011 / UI-006)."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from types import SimpleNamespace

from malaz import i18n
from malaz.core.engine_verdicts import build_engine_verdicts
from malaz.design_tokens import format_short_type, format_size, state_label
from malaz.i18n_catalog import (
    CATEGORY_EN_EXPLANATIONS,
    CATEGORY_EN_LABELS,
    ENGINE_EN_LABELS,
    INCOMPLETE_REASON_EN,
    RULE_EN_DETAILS,
    RULE_EN_TITLES,
    STRINGS_DE,
    STRINGS_EN,
    TYPE_EN_LABELS,
)
from malaz.i18n_catalog_tr import (
    CATEGORY_TR_EXPLANATIONS,
    CATEGORY_TR_LABELS,
    ENGINE_TR_LABELS,
    INCOMPLETE_REASON_TR,
    RULE_TR_DETAILS,
    RULE_TR_TITLES,
    STRINGS_TR,
    TYPE_TR_LABELS,
)
from malaz.models import (
    CATEGORY_EXPLANATIONS,
    TYPE_LABELS,
    Indicator,
    RiskLevel,
    ScanResult,
    Severity,
    type_label,
)
from malaz.reporting.export import write_csv, write_json
from malaz.reporting.html_report import generate_report
from malaz.reporting.pdf_report import generate_pdf

_ROOT = Path(__file__).resolve().parents[1]
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")
_RULE_LITERAL_RE = re.compile(
    r'["\']((?:(?:ARCH|AV|BINARY_IOC|CAPA|CLAMAV|CORE|DIE|ELF|GEN|HEIC|IMG|JPEG|LNK|'
    r'MACHO|MAIL|OFFICE|PDF|PE|PNG|SCRIPT|SWF|URL|YARA|HASH_BLOCKLIST|'
    r'DOMAIN_BLOCKLIST|IP_BLOCKLIST)_[A-Z0-9_]+)|BINARY_IOC)["\']'
)
_CONFIG_SUFFIXES = (
    "_ENABLED",
    "_TIMEOUT",
    "_SECONDS",
    "_LIMIT_MB",
    "_MAX_LOOKUPS",
    "_ENDPOINT",
    "_FILE",
    "_PATH",
    "_DIR",
)


def _sample_result(
    *,
    name: str = "secret.zip",
    detected_type: str = "zip",
    score: int = 0,
    risk: RiskLevel = RiskLevel.GREEN,
    indicators: list[Indicator] | None = None,
    children: list[ScanResult] | None = None,
) -> ScanResult:
    res = ScanResult(
        path=f"C:/samples/{name}",
        size=2048,
        sha256="a" * 64,
        md5="b" * 32,
        detected_type=detected_type,
        duration_ms=17,
        score=score,
        risk_level=risk,
        indicators=list(indicators or []),
        children=list(children or []),
    )
    res.engine_verdicts = build_engine_verdicts(res, yara_available=True)
    return res


def test_catalog_key_and_placeholder_parity() -> None:
    """DE, EN, and TR string catalogs must share identical keys and placeholders."""
    de_keys = set(STRINGS_DE)
    en_keys = set(STRINGS_EN)
    tr_keys = set(STRINGS_TR)
    assert en_keys == de_keys, f"EN/DE mismatch: missing={de_keys - en_keys}, extra={en_keys - de_keys}"
    assert tr_keys == de_keys, f"TR/DE mismatch: missing={de_keys - tr_keys}, extra={tr_keys - de_keys}"

    for key, de_val in STRINGS_DE.items():
        de_ph = set(_PLACEHOLDER_RE.findall(de_val))
        en_ph = set(_PLACEHOLDER_RE.findall(STRINGS_EN[key]))
        tr_ph = set(_PLACEHOLDER_RE.findall(STRINGS_TR[key]))
        assert en_ph == de_ph, f"EN placeholder mismatch for {key}: {en_ph} != {de_ph}"
        assert tr_ph == de_ph, f"TR placeholder mismatch for {key}: {tr_ph} != {de_ph}"
        assert STRINGS_EN[key].strip(), f"Empty EN value for {key}"
        assert STRINGS_TR[key].strip(), f"Empty TR value for {key}"


def test_all_codebase_rule_ids_have_en_and_tr_translation() -> None:
    """Every canonical rule_id in src/malaz/ and golden_snapshot.json has EN & TR entries."""
    discovered: set[str] = set()
    for py_file in (_ROOT / "src" / "malaz").rglob("*.py"):
        if py_file.name in ("i18n_catalog.py", "i18n_catalog_tr.py", "i18n.py"):
            continue
        txt = py_file.read_text(encoding="utf-8")
        for m in _RULE_LITERAL_RE.finditer(txt):
            rid = m.group(1)
            if rid.endswith(_CONFIG_SUFFIXES):
                continue
            if rid.startswith("YARA_") and rid not in ("YARA_LOAD_ERROR", "YARA_SCAN_ERROR"):
                continue
            discovered.add(rid)

    snap_path = _ROOT / "tests" / "data" / "golden_snapshot.json"
    if snap_path.exists():
        snap = json.loads(snap_path.read_text(encoding="utf-8"))
        for entry in (snap.get("files") or {}).values():
            for ind in entry.get("indicators", []):
                rid = ind.get("rule_id", "")
                if rid and not rid.startswith(("YARA_", "EXT_", "PDF_KW_")):
                    discovered.add(rid)

    assert len(discovered) >= 200
    assert set(RULE_EN_DETAILS) >= set(RULE_EN_TITLES)
    assert set(RULE_TR_DETAILS) >= set(RULE_TR_TITLES)

    missing_en_t = discovered - set(RULE_EN_TITLES)
    missing_en_d = discovered - set(RULE_EN_DETAILS)
    missing_tr_t = discovered - set(RULE_TR_TITLES)
    missing_tr_d = discovered - set(RULE_TR_DETAILS)
    assert not missing_en_t, f"Missing EN titles: {sorted(missing_en_t)}"
    assert not missing_en_d, f"Missing EN details: {sorted(missing_en_d)}"
    assert not missing_tr_t, f"Missing TR titles: {sorted(missing_tr_t)}"
    assert not missing_tr_d, f"Missing TR details: {sorted(missing_tr_d)}"


def test_type_category_engine_incomplete_catalog_parity() -> None:
    assert set(TYPE_EN_LABELS) >= set(TYPE_LABELS)
    assert set(TYPE_TR_LABELS) >= set(TYPE_LABELS)
    assert set(CATEGORY_EN_LABELS) >= set(CATEGORY_EXPLANATIONS)
    assert set(CATEGORY_TR_LABELS) >= set(CATEGORY_EXPLANATIONS)
    assert set(CATEGORY_EN_EXPLANATIONS) >= set(CATEGORY_EXPLANATIONS)
    assert set(CATEGORY_TR_EXPLANATIONS) >= set(CATEGORY_EXPLANATIONS)
    assert set(ENGINE_TR_LABELS) == set(ENGINE_EN_LABELS)
    assert set(INCOMPLETE_REASON_TR) == set(INCOMPLETE_REASON_EN)

    assert type_label("pdf", lang="de") == "PDF-Dokument"
    assert type_label("pdf", lang="en") == "PDF document"
    assert type_label("pdf", lang="tr") == "PDF belgesi"
    assert format_short_type("zip", "report.docx", lang="tr") == "Word (.docx)"
    assert format_size(1536, lang="en") == "1.5 KB"
    assert format_size(1536, lang="de") == "1,5 KB"
    assert format_size(1536, lang="tr") == "1,5 KB"


def test_resolve_language_windows_and_fallback(monkeypatch) -> None:
    # Explicit preferences
    assert i18n.resolve_language("de") == "de"
    assert i18n.resolve_language("en") == "en"
    assert i18n.resolve_language("tr") == "tr"
    assert i18n.resolve_language("tr_TR") == "tr"
    assert i18n.resolve_language("de-AT") == "de"
    assert i18n.resolve_language("unknown_xx") == "en"

    # Mock Windows GetUserDefaultUILanguage LCIDs
    def _mock_lcid(val: int) -> None:
        fake_windll = SimpleNamespace(
            kernel32=SimpleNamespace(GetUserDefaultUILanguage=lambda: val)
        )
        monkeypatch.setattr(i18n.ctypes, "windll", fake_windll, raising=False)

    _mock_lcid(0x0407)  # de-DE
    assert i18n.resolve_language("system") == "de"
    _mock_lcid(0x0807)  # de-CH
    assert i18n.resolve_language("system") == "de"
    _mock_lcid(0x041F)  # tr-TR
    assert i18n.resolve_language("system") == "tr"
    _mock_lcid(0x0409)  # en-US
    assert i18n.resolve_language("system") == "en"
    _mock_lcid(0x040C)  # fr-FR -> fallback en
    assert i18n.resolve_language("system") == "en"

    # Fallback via locale.getlocale() when ctypes.windll unavailable
    monkeypatch.setattr(i18n.ctypes, "windll", None, raising=False)
    monkeypatch.setattr(i18n.locale, "getlocale", lambda: ("German_Germany", "1252"))
    assert i18n.resolve_language("system") == "de"
    monkeypatch.setattr(i18n.locale, "getlocale", lambda: ("Turkish_Turkey", "1254"))
    assert i18n.resolve_language("system") == "tr"
    monkeypatch.setattr(i18n.locale, "getlocale", lambda: ("French_France", "1252"))
    assert i18n.resolve_language("system") == "en"


def test_language_context_thread_isolation() -> None:
    """ContextVar overrides must not leak across concurrent threads."""
    i18n.set_language("de")
    observed: dict[str, list[str]] = {"en": [], "tr": [], "de": []}
    barrier = threading.Barrier(3)

    def _worker(lang: str) -> None:
        if lang == "de":
            barrier.wait()
            for _ in range(15):
                observed["de"].append(i18n.get_language())
        else:
            with i18n.language_context(lang):
                barrier.wait()
                for _ in range(15):
                    observed[lang].append(i18n.get_language())

    threads = [threading.Thread(target=_worker, args=(lg,)) for lg in ("en", "tr", "de")]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert observed["en"] == ["en"] * 15
    assert observed["tr"] == ["tr"] * 15
    assert observed["de"] == ["de"] * 15
    assert i18n.get_language() == "de"


def test_json_csv_invariant_under_en_and_tr(tmp_path) -> None:
    """JSON and CSV schemas/values remain 100 % invariant (incl. incomplete stages & children)."""
    child_inc = _sample_result(
        name="embedded.zip",
        detected_type="zip",
        score=0,
        risk=RiskLevel.GREEN,
        indicators=[
            Indicator(
                rule_id="ARCH_ENCRYPTED",
                title="Archiv ist passwortgeschützt",
                detail="Inhalt konnte nicht entpackt werden",
                severity=Severity.MEDIUM,
                weight=0,
            )
        ],
    )
    res = _sample_result(
        name="invoice.pdf",
        detected_type="pdf",
        score=35,
        risk=RiskLevel.YELLOW,
        indicators=[
            Indicator(
                rule_id="PDF_LINK",
                title="Links im PDF (1)",
                detail="hxxps://example.invalid/login",
                severity=Severity.INFO,
                weight=0,
            ),
            Indicator(
                rule_id="AV_SKIPPED",
                title="Windows Defender: Scan übersprungen",
                detail="MpCmdRun nicht verfügbar",
                severity=Severity.MEDIUM,
                weight=0,
            ),
        ],
        children=[child_inc],
    )

    outputs_json: dict[str, str] = {}
    outputs_csv: dict[str, str] = {}
    for lang in ("de", "en", "tr"):
        i18n.set_language(lang)
        jp = write_json([res], tmp_path / f"out_{lang}.json")
        cp = write_csv([res], tmp_path / f"out_{lang}.csv")
        outputs_json[lang] = jp.read_text(encoding="utf-8")
        outputs_csv[lang] = cp.read_text(encoding="utf-8")

    assert outputs_json["en"] == outputs_json["de"]
    assert outputs_json["tr"] == outputs_json["de"]
    assert outputs_csv["en"] == outputs_csv["de"]
    assert outputs_csv["tr"] == outputs_csv["de"]


def test_no_html_entities_in_i18n_plain_text_and_format_resilience() -> None:
    """i18n.py returns un-escaped, Bidi-stripped plain text and never crashes on bad format args."""
    # Bidi marks stripped, no HTML entity escaping
    raw = "a & b <script>\u202egpj.exe"
    out = i18n.t("verdict.bad.reason_summary", lang="en", reason=raw)
    assert "&amp;" not in out
    assert "&lt;" not in out
    assert "\u202e" not in out
    assert "a & b <script>gpj.exe" in out

    # Missing placeholder never raises
    resilient = i18n.t("verdict.bad.reason_summary", lang="en")
    assert "{reason}" in resilient
    # Unknown key returns key verbatim
    assert i18n.t("nonexistent.key.xyz", lang="tr") == "nonexistent.key.xyz"
    # tn singular/plural
    assert i18n.tn("sidebar.count_one", "sidebar.count_other", 1, lang="en") == "1 file"
    assert i18n.tn("sidebar.count_one", "sidebar.count_other", 3, lang="en") == "3 files"
    assert i18n.tn("sidebar.count_one", "sidebar.count_other", 3, lang="tr") == "3 dosya"


def test_listener_dedup_and_exception_isolation() -> None:
    calls: list[str] = []

    def bad_cb(_lang: str) -> None:
        raise RuntimeError("boom")

    def good_cb(lang: str) -> None:
        calls.append(lang)

    i18n.register_language_listener(bad_cb)
    i18n.register_language_listener(good_cb)
    i18n.register_language_listener(good_cb)  # duplicate ignored
    try:
        i18n.set_language("en")
        i18n.set_language("en")  # no-op
        i18n.set_language("tr")
        assert calls == ["en", "tr"]
    finally:
        i18n.unregister_language_listener(bad_cb)
        i18n.unregister_language_listener(good_cb)
        i18n.unregister_language_listener(good_cb)  # safe no-op


def test_en_and_tr_completeness_invariant_gui_and_html(qapp) -> None:
    """Encrypted/incomplete file must render Unchecked / Turkish unchecked — NEVER Clean / Temiz."""
    from malaz.gui.verdict_card import VerdictCard

    enc_res = _sample_result(
        name="locked.zip",
        detected_type="zip",
        score=0,
        risk=RiskLevel.GREEN,
        indicators=[
            Indicator(
                rule_id="ARCH_ENCRYPTED",
                title="Passwortgeschützte Einträge (2)",
                detail="2 verschlüsselte Dateien",
                severity=Severity.MEDIUM,
                weight=0,
            ),
            Indicator(
                rule_id="AV_SKIPPED",
                title="Windows Defender: Scan übersprungen",
                detail="Defender deaktiviert",
                severity=Severity.INFO,
                weight=0,
            ),
        ],
    )

    # English check
    assert state_label("unk", lang="en") == "Unchecked"
    assert state_label("unk", lang="en") != "Clean"
    i18n.set_language("en")
    card = VerdictCard()
    card.show_result(enc_res)
    assert "Unchecked" in card.headline.text()
    assert "Clean" not in card.headline.text()
    assert "Ungeprüft" not in card.headline.text()

    html_en = generate_report([enc_res], lang="en")
    assert '<html lang="en">' in html_en
    assert "Unchecked:" in html_en
    assert "Nicht geprüft:" not in html_en
    assert "Passwortgeschützte" not in html_en

    # Turkish check
    assert state_label("unk", lang="tr") == "Taranamadı"
    assert state_label("unk", lang="tr") != "Temiz"
    i18n.set_language("tr")
    card.retranslate()
    assert "Taranamadı" in card.headline.text()
    assert "Temiz" not in card.headline.text()
    assert "Ungeprüft" not in card.headline.text()

    html_tr = generate_report([enc_res], lang="tr")
    assert '<html lang="tr">' in html_tr
    assert "Taranamadı:" in html_tr
    assert "Nicht geprüft:" not in html_tr


def test_live_gui_retranslate_de_en_tr_populated(window) -> None:
    """Switching de -> en -> tr -> de live updates menus, summary, detail, options, and tree."""
    res_bad = _sample_result(
        name="invoice.pdf.exe",
        detected_type="pe",
        score=85,
        risk=RiskLevel.RED,
        indicators=[
            Indicator(
                rule_id="PE_DISGUISED_EXT",
                title="Ausführbare Datei getarnt",
                detail="PE-Header trotz .pdf-Endung",
                severity=Severity.HIGH,
                weight=45,
            )
        ],
    )
    window._on_result(res_bad)

    # German initial
    assert window.btn_options.text() == "Optionen"
    assert "Gefährlich" in window.detail_view.verdict.headline.text()

    # Live switch to English
    i18n.set_language("en")
    assert window.btn_options.text() == "Options"
    assert "Dangerous" in window.detail_view.verdict.headline.text()
    assert window._menu_file.title() == "&File"
    assert window.summary._title_lbl.text() == "Folder Overview"
    assert window.options_view._hdr_title is not None
    assert window.options_view._hdr_title.text() == "Options & Auto-Update"

    # Live switch to Turkish
    i18n.set_language("tr")
    assert window.btn_options.text() == "Ayarlar"
    assert "Tehlikeli" in window.detail_view.verdict.headline.text()
    assert window._menu_file.title() == "&Dosya"
    assert window.summary._title_lbl.text() == "Klasör Özeti"
    assert window.options_view._hdr_title.text() == "Ayarlar ve Otomatik Güncelleme"

    # Live switch back to German
    i18n.set_language("de")
    assert window.btn_options.text() == "Optionen"
    assert "Gefährlich" in window.detail_view.verdict.headline.text()


def test_english_and_turkish_html_and_pdf_reports(qapp, tmp_path) -> None:
    """HTML & PDF reports render cleanly in EN and TR with zero leaked German headers."""
    res = _sample_result(
        name="offer.pdf",
        detected_type="pdf",
        score=30,
        risk=RiskLevel.YELLOW,
        indicators=[
            Indicator(
                rule_id="BINARY_IOC_BLOCKED",
                title="Bekannte Schad-Adresse auf lokaler Sperrliste (1)",
                detail="hxxps://evil.invalid/steal",
                severity=Severity.HIGH,
                weight=30,
            )
        ],
    )

    html_en = generate_report([res], lang="en")
    assert '<html lang="en">' in html_en
    assert "Security report" in html_en
    assert "Recommendation:" in html_en
    assert "hxxps://evil.invalid/steal" in html_en
    assert "Analysebericht" not in html_en
    assert "Empfehlung:" not in html_en

    html_tr = generate_report([res], lang="tr")
    assert '<html lang="tr">' in html_tr
    assert "Güvenlik raporu" in html_tr
    assert "Öneri:" in html_tr
    assert "hxxps://evil.invalid/steal" in html_tr
    assert "Analysebericht" not in html_tr
    assert "Empfehlung:" not in html_tr

    pdf_en = generate_pdf([res], tmp_path / "report_en.pdf", lang="en")
    pdf_tr = generate_pdf([res], tmp_path / "report_tr.pdf", lang="tr")
    assert pdf_en.is_file() and pdf_en.stat().st_size > 1500
    assert pdf_tr.is_file() and pdf_tr.stat().st_size > 1500
    assert pdf_en.read_bytes().startswith(b"%PDF-")
    assert pdf_tr.read_bytes().startswith(b"%PDF-")


def test_score_ring_footer_and_engine_capsule_trilingual(qapp) -> None:
    """ScoreRingWidget, build_footer_summary, and _EngineCapsule stay localized and visible."""
    from malaz.gui.detail_view import build_footer_summary
    from malaz.gui.main_window import MainWindow
    from malaz.gui.score_ring import ScoreRingWidget
    from malaz.i18n import set_language
    from malaz.models import RiskLevel, ScanResult

    ring = ScoreRingWidget()
    set_language("en")
    ring.set_score(88, "bad")
    assert ring._cap_lbl.text() == "Risk"
    assert ring._level_lbl.text() == "High"
    set_language("tr")
    ring.retranslate()
    assert ring._cap_lbl.text() == "Risk"
    assert ring._level_lbl.text() == "Yüksek"
    ring.set_score(0, "unk")
    assert ring._level_lbl.text() == "Taranamadı"
    ring.set_score(0, "ok")
    assert ring._level_lbl.text() == "Düşük"

    pe_res = ScanResult(path="sample.exe", detected_type="pe", risk_level=RiskLevel.RED, score=90)
    pdf_res = ScanResult(path="clean.pdf", detected_type="pdf", risk_level=RiskLevel.GREEN, score=0)
    set_language("en")
    assert "Signature: None" in build_footer_summary(pe_res)
    assert "Scripts: None" in build_footer_summary(pdf_res)
    set_language("tr")
    pe_footer_tr = build_footer_summary(pe_res)
    pdf_footer_tr = build_footer_summary(pdf_res)
    assert "İmza: Yok" in pe_footer_tr and "Signatur" not in pe_footer_tr
    assert "Betik: Yok" in pdf_footer_tr and "Skripte" not in pdf_footer_tr

    win = MainWindow(fixed_size=(1060, 740))
    win.show()
    qapp.processEvents()
    win._on_engine_status(
        "",
        [
            ("Defender", "ok", "ok"),
            ("ClamAV", "ok", "ok"),
            ("YARA", "ok", "ok"),
            ("7-Zip", "ok", "ok"),
        ],
    )
    qapp.processEvents()
    assert len(win.status_capsule._items) == 4
    assert all(lbl.isVisible() for _, lbl in win.status_capsule._items)
    win.close()
    set_language("de")


def test_localize_engine_status_line_never_flips_unavailable_to_available() -> None:
    """B1 & r2-M1 regression: disabled/inactive/failing engines must NEVER flip to active/ready."""
    from malaz.gui.options_view import _localize_engine_status_line, _localize_feed_badge
    from malaz.reporting.mail_section import localize_mail_score_label

    for phrase in (
        "Nicht verfügbar",
        "ClamAV nicht verfügbar",
        "7-Zip nicht verfügbar",
        "MpCmdRun nicht verfuegbar",
    ):
        assert _localize_engine_status_line(phrase, "en", avail=False) == "Unavailable"
        assert _localize_engine_status_line(phrase, "tr", avail=False) == "Kullanılamıyor"

    for disabled_phrase in ("Defender deaktiviert", "Windows Defender inaktiv", "Defender nicht aktiv"):
        en_out = _localize_engine_status_line(disabled_phrase, "en", avail=False)
        tr_out = _localize_engine_status_line(disabled_phrase, "tr", avail=False)
        assert "active" not in en_out.lower() and "available" not in en_out.lower(), en_out
        assert "aktif" not in tr_out.lower() and "hazır" not in tr_out.lower(), tr_out

    for err_phrase in ("clamd nicht erreichbar", "clamd Fehler", "Dienst läuft nicht"):
        en_err = _localize_engine_status_line(err_phrase, "en", avail=False)
        tr_err = _localize_engine_status_line(err_phrase, "tr", avail=False)
        assert "ready" not in en_err.lower(), en_err
        assert "hazır" not in tr_err.lower(), tr_err

    assert _localize_engine_status_line("Verfügbar", "en", avail=True) == "Available"
    assert _localize_engine_status_line("Verfügbar", "tr", avail=True) == "Kullanılabilir"

    # r2-N2: feed badge negations and non-aging words
    assert _localize_feed_badge("nicht aktuell", "en") == "Blocklists aging"
    assert _localize_feed_badge("enthalten", "en") == "enthalten"

    # r2-M2: 'unauffaellig' and 'nicht prüfbar' must NOT be shadowed by 'auffaellig'/'prüf'
    assert localize_mail_score_label("unauffaellig", lang="en") == "Unremarkable"
    assert localize_mail_score_label("unauffaellig", lang="tr") == "Normal"
    assert localize_mail_score_label("nicht prüfbar", lang="en") == "Unverifiable"
    assert localize_mail_score_label("nicht prüfbar", lang="tr") == "Doğrulanamadı"
    assert localize_mail_score_label("auffaellig", lang="en") == "Needs review"
    assert localize_mail_score_label("auffaellig", lang="tr") == "İnceleme gerekli"


def test_engine_strip_routes_non_archive_with_children_to_child_cards(qapp) -> None:
    """B2 regression: PDF/OLE containers with extracted children must show child risk, not leaf Clean."""
    from malaz.gui.engine_strip import EngineStrip

    bad_child = _sample_result(
        name="payload.exe",
        detected_type="pe",
        score=95,
        risk=RiskLevel.RED,
        indicators=[
            Indicator(
                rule_id="AV_THREAT",
                title="Windows Defender: Trojan:Win32/Test",
                detail="Trojan:Win32/Test",
                severity=Severity.CRITICAL,
                weight=100,
            )
        ],
    )
    pdf_container = _sample_result(
        name="wrapper.pdf",
        detected_type="pdf",
        score=95,
        risk=RiskLevel.RED,
        indicators=[],
        children=[bad_child],
    )
    i18n.set_language("en")
    strip = EngineStrip()
    strip.show_result(pdf_container)
    from PySide6.QtWidgets import QLabel

    texts = [lbl.text() for c in strip.chips for lbl in c.findChildren(QLabel)]
    assert any("dangerous" in txt.lower() for txt in texts), texts
    assert not any(txt == "Clean" for txt in texts), texts


def test_html_and_pdf_incomplete_green_badges_never_say_clean_or_temiz(qapp, tmp_path) -> None:
    """M1 regression: incomplete GREEN results in EN/TR HTML & PDF must show unchecked badge."""
    from malaz.reporting.html_report import generate_report
    from malaz.reporting.pdf_report import save_pdf_report

    inc_green = _sample_result(
        name="mystery.bin",
        detected_type="unknown",
        score=0,
        risk=RiskLevel.GREEN,
        indicators=[
            Indicator(
                rule_id="AV_SKIPPED",
                title="Windows Defender: Scan übersprungen",
                detail="MpCmdRun nicht verfügbar",
                severity=Severity.MEDIUM,
                weight=0,
            )
        ],
    )

    html_en = generate_report([inc_green], lang="en")
    assert "Unchecked (incomplete)" in html_en
    assert "Clean (Unchecked" not in html_en

    html_tr = generate_report([inc_green], lang="tr")
    assert "Taranamadı (eksik)" in html_tr
    assert "Temiz (eksik)" not in html_tr
    assert "Temiz (Taranamadı" not in html_tr
    assert "Puan:" in html_tr
    assert "<th>Ayrıntı</th>" in html_tr

    chips_seen: list[str] = []
    for lang in ("en", "tr"):
        pdf_out = tmp_path / f"inc_{lang}.pdf"
        save_pdf_report([inc_green], pdf_out, lang=lang)
        assert pdf_out.is_file() and pdf_out.stat().st_size > 1000

    # Direct chip-label check on _render_result by monkeypatching chip capture
    import malaz.reporting.pdf_report as pr_mod

    orig_chip = pr_mod._PdfRenderer.chip

    def _capture_chip(self, label: str, *args, **kwargs):
        chips_seen.append(f"{self.lang}:{label}")
        return orig_chip(self, label, *args, **kwargs)

    pr_mod._PdfRenderer.chip = _capture_chip  # type: ignore[method-assign]
    try:
        save_pdf_report([inc_green], tmp_path / "spy_en.pdf", lang="en")
        save_pdf_report([inc_green], tmp_path / "spy_tr.pdf", lang="tr")
    finally:
        pr_mod._PdfRenderer.chip = orig_chip  # type: ignore[method-assign]

    assert "en:Unchecked" in chips_seen
    assert not any(c.startswith("en:Clean") for c in chips_seen), chips_seen
    assert "tr:Taranamadı" in chips_seen
    assert not any(c.startswith("tr:Temiz") for c in chips_seen), chips_seen


def test_cli_lang_ephemeral_and_options_language_persistence(qapp, monkeypatch, tmp_path) -> None:
    """M3 Spec §4: --cli --lang never touches QSettings; OptionsView._cycle_language persists."""
    from malaz import __main__ as cli
    from malaz.gui import settings as gui_settings
    from malaz.gui.options_view import OptionsView

    sample = tmp_path / "plain.txt"
    sample.write_text("hello world", encoding="utf-8")

    # Seed QSettings with 'de', then invoke --cli --lang tr -> QSettings stays untouched
    gui_settings.apply_language("de", persist=True)
    assert gui_settings.saved_language_preference() == "de"

    called_langs: list[str] = []

    def _fake_cli(files, report_path=None, *, static_only=False):
        called_langs.append(i18n.get_language())
        return 0

    monkeypatch.setattr(cli, "run_cli", _fake_cli)
    rc = cli.main(["--cli", str(sample), "--lang", "tr"])
    assert rc == 0
    assert called_langs == ["tr"]
    # QSettings preference was NEVER overwritten by CLI --lang
    assert gui_settings.saved_language_preference() == "de"

    # Ephemeral GUI override (persist=False) also leaves QSettings intact
    gui_settings.apply_language("en", persist=False)
    assert i18n.get_language() == "en"
    assert gui_settings.saved_language_preference() == "de"

    # OptionsView._cycle_language persists explicitly
    ov = OptionsView({})
    ov._cycle_language()
    assert gui_settings.saved_language_preference() in ("system", "de", "en", "tr")
    assert gui_settings.saved_language_preference() == gui_settings.active_language_preference()


def test_dynamic_helpers_threat_order_url_dedup_and_mail_reasons() -> None:
    """N1 & M2: threat detail preserved, duplicate URLs deduplicated, mail link reasons localized."""
    from malaz.core.eml_analysis import LinkFacts
    from malaz.reporting.mail_section import mail_lines

    # Threat detail never rewritten even if signature text contains an incomplete phrase
    assert (
        i18n.localized_engine_detail("threat", "Trojan:Win32/Timeout.A", lang="en")
        == "Trojan:Win32/Timeout.A"
    )
    assert (
        i18n.localized_engine_detail("threat", "Trojan:Win32/Timeout.A", lang="tr")
        == "Trojan:Win32/Timeout.A"
    )

    # Dynamic rule titles (AV, ClamAV, YARA, EXT)
    av_ind = Indicator(
        rule_id="AV_THREAT",
        title="Windows Defender: Trojan:Win32/AgentTesla",
        detail="",
        severity=Severity.CRITICAL,
        weight=100,
    )
    assert i18n.localized_indicator_title(av_ind, lang="en") == "Windows Defender: Trojan:Win32/AgentTesla"
    assert i18n.localized_indicator_title(av_ind, lang="tr") == "Windows Defender: Trojan:Win32/AgentTesla"

    yara_ind = Indicator(
        rule_id="YARA_SuspiciousDropper",
        title="YARA-Treffer: SuspiciousDropper",
        detail="",
        severity=Severity.MEDIUM,
        weight=40,
    )
    assert i18n.localized_indicator_title(yara_ind, lang="en") == "YARA match: SuspiciousDropper"
    assert i18n.localized_indicator_title(yara_ind, lang="tr") == "YARA eşleşmesi: SuspiciousDropper"

    ext_ind = Indicator(
        rule_id="EXT_ESET_THREAT",
        title="ESET: Win32/Kryptik",
        detail="",
        severity=Severity.CRITICAL,
        weight=90,
    )
    assert i18n.localized_indicator_title(ext_ind, lang="en") == "Eset: Win32/Kryptik"
    assert i18n.localized_indicator_title(ext_ind, lang="tr") == "Eset: Win32/Kryptik"

    # Deduplicated URL overflow count (3 unique URLs repeated -> NO "+N more")
    dup_detail = " ".join(["hxxps://a.example/1", "hxxps://a.example/1", "hxxps://b.example/2"] * 4)
    snip = i18n._extract_evidence_snippets(dup_detail, "en")
    assert "+ " not in snip and "(+" not in snip, snip

    # Mail link reasons appear localized in EN & TR instead of being dropped
    mail_res = _sample_result(
        name="phish.eml",
        detected_type="eml",
        score=55,
        risk=RiskLevel.RED,
        indicators=[],
    )
    mail_res.mail_security = {"spf": "fail", "dkim": "none", "dmarc": "fail", "sender": "mismatch"}
    mail_res.mail_links = [
        LinkFacts(
            url="https://bit.ly/abc",
            host="bit.ly",
            scheme="https",
            is_shortener=True,
        )
    ]
    en_lines = dict(mail_lines(mail_res, lang="en"))
    tr_lines = dict(mail_lines(mail_res, lang="tr"))
    assert "URL shortener hides the final destination" in en_lines["Link 1"]
    assert "Kısaltılmış bağlantı gerçek hedef adresi gizliyor" in tr_lines["Link 1"]


def test_v12_audit_regression_fixes(tmp_path: Path) -> None:
    """Regressions caught by the v1.2 456-file + 220-file GUI/HTML/PDF audit."""
    from pathlib import Path as _Path

    from malaz.core.sevenzip import _sanitize_7z_output
    from malaz.gui.options_view import _localize_engine_status_line
    from malaz.gui.sanitize import clip_text, masked_widget_text
    from malaz.i18n import (
        localized_incomplete_reason,
        localized_indicator_detail,
        localized_indicator_title,
    )

    # BUG-1 + M2 + N2: real OptionsView pipeline (masked_widget_text -> localize -> clip_text)
    for de_line, avail in (
        ("RAR/7z/deb/rpm-Inhalte werden entpackt und gescannt.", True),
        ("On-Demand-Scans möglich. Defender aktiv", True),
        ("Signatur-DB: C:\\clam\\db\nDatenbank vor 2 Tag(en) aktualisiert", True),
        ("Signatur-DB: C:\\clam\\db Datenbank vor 2 Tag(en) aktualisiert", True),
        ("Regeln geladen und einsatzbereit.\nYARA: 2026-04-01", True),
        ("Detect It Easy verfügbar (Packererkennung).", True),
        ("Detect It Easy nicht installiert (optional).", False),
        ("Nicht installiert — optional (Defender übernimmt die AV-Spalte).", False),
        ("Installiert, aber ohne Signatur-DB — jeder Scan wird übersprungen.", False),
        ("Stufe abgeschaltet (SEVENZIP_ENABLED=False) — RAR/7z/deb/rpm-Inhalte bleiben ungeprüft.", False),
        ("Status unklar (Probe ohne Ergebnis) — Binary vorhanden, Scan-Fähigkeit unbewiesen.", False),
    ):
        for lang in ("en", "tr"):
            out = clip_text(
                _localize_engine_status_line(masked_widget_text(de_line), lang, avail=avail),
                90,
            )
            for forbidden in (
                "entpackt",
                "möglich",
                "aktualisiert",
                "einsatzbereit",
                "abgeschaltet",
                "unbewiesen",
                "datenbank",
            ):
                assert forbidden not in out.lower(), f"{lang} leaked {forbidden!r}: {out!r}"
    # N2: non-AV optional tool must NOT mention Defender
    assert "Defender" not in _localize_engine_status_line(
        "capa nicht installiert (optional).", "en", avail=False
    )

    # BUG-2: BINARY_IOC title & detail localize in EN/TR while keeping extracted URLs
    ind = Indicator(
        rule_id="BINARY_IOC",
        title="Adressen im Binärinhalt (1)",
        detail="Serveradressen im Rohinhalt der Datei: URLs: http://198.51.100.12",
        severity=Severity.INFO,
        category="netz",
        weight=0,
    )
    for lang in ("en", "tr"):
        title = localized_indicator_title(ind, lang=lang)
        detail = localized_indicator_detail(ind, lang=lang)
        assert "Binärinhalt" not in title and "(1)" in title, title
        assert "Serveradressen" not in detail and "hxxp://198.51.100.12" in detail, detail

    # BUG-3 & BUG-4: synthetic container display_name keeps opening paren & localizes child reasons
    for synthetic in ("(CAB/ISO-Inhalt)", "(RAR/7z-Inhalt)", "(TAR/komprimierter Inhalt)"):
        r = ScanResult(path=synthetic, depth=1)
        assert r.display_name == synthetic, r.display_name

    for lang in ("en", "tr"):
        r1 = localized_incomplete_reason(
            "(CAB/ISO-Inhalt): 7-Zip-Listing fehlgeschlagen — Archiv aus Sicherheitsgründen nicht entpackt",
            lang=lang,
        )
        r2 = localized_incomplete_reason(
            "(TAR/komprimierter Inhalt): Zip-Slip: 1 Eintragsname(n) würden beim Entpacken schreiben",
            lang=lang,
        )
        r3 = localized_incomplete_reason(
            "rechnung.pdf: PDF konnte nicht geöffnet werden — Tiefen-Scan nicht gelaufen",
            lang=lang,
        )
        r4 = localized_incomplete_reason(
            "(ZIP-Inhalt): ZIP-Container nicht lesbar: Bad magic number",
            lang=lang,
        )
        for out in (r1, r2, r3, r4):
            for de_tok in ("Inhalt)", "fehlgeschlagen", "geöffnet", "nicht lesbar", "würden"):
                assert de_tok not in out, f"{lang} leaked {de_tok!r} in {out!r}"
        assert r3.startswith("rechnung.pdf: "), r3

    # BUG-5: 7-Zip error sanitizer redacts local temp dir + strips copyright banner
    fake_work = tmp_path / "alice_home" / "malaz_7z_xyz"
    noisy = (
        "7-Zip 26.05 (x64) : Copyright (c) 1999-2026 Igor Pavlov\n\n"
        "Scanning the drive for archives:\n1 file, 512 bytes (1 KiB)\n\n"
        f"Listing archive: {fake_work}\\archive.iso\n\n"
        f"ERROR: {fake_work}\\archive.iso : Can not open the file as archive"
    )
    cleaned = _sanitize_7z_output(noisy, fake_work)
    assert "alice_home" not in cleaned and "Copyright" not in cleaned and "Scanning the drive" not in cleaned
    assert "Can not open the file as archive" in cleaned
    assert "<temp>" in cleaned

    # M1: deeply nested ': ' input must never raise RecursionError
    for lang in ("en", "tr"):
        deep = "a: " * 1200 + "ZIP-Container nicht lesbar: x"
        out_deep = localized_incomplete_reason(deep, lang=lang)
        assert isinstance(out_deep, str) and len(out_deep) > 0

    # N1: case-insensitive Windows path redaction & relative Path('.') must not mangle dots
    mixed_case = noisy.replace("alice_home", "ALICE_HOME")
    cleaned_ci = _sanitize_7z_output(mixed_case, fake_work)
    assert "alice_home" not in cleaned_ci.lower() and "<temp>" in cleaned_ci
    assert _sanitize_7z_output("ERROR: foo.bar", _Path(".")) == "ERROR: foo.bar"

    # N3: multi-segment parenthesized path & uppercase HTTPS:// defang
    assert ScanResult(path="(dir)/sub/(file)", depth=1).display_name == "(file)"
    ind_upper = Indicator(
        rule_id="BINARY_IOC",
        title="Adressen im Binärinhalt (1)",
        detail="URLs: HTTPS://198.51.100.12/drop",
        severity=Severity.INFO,
        category="netz",
        weight=0,
    )
    assert "hxxps://198.51.100.12/drop" in localized_indicator_detail(ind_upper, lang="en")

    # Sister HTML & PDF report checks: result.error must localize in EN/TR
    err_res = ScanResult(
        path="(CAB/ISO-Inhalt)",
        error="7-Zip-Listing fehlgeschlagen — Archiv aus Sicherheitsgründen nicht entpackt",
        depth=1,
    )
    for lang in ("en", "tr"):
        html_out = generate_report([err_res], lang=lang)
        assert "7-Zip-Listing fehlgeschlagen" not in html_out, lang
        pdf_path = tmp_path / f"err_{lang}.pdf"
        generate_pdf([err_res], pdf_path, lang=lang)
        assert pdf_path.is_file() and pdf_path.stat().st_size > 500

    # BiDi-masking order: raw RLO in result.error must stay visibly masked (\u202e), not silently stripped
    bidi_res = ScanResult(
        path="spoof.zip",
        error="Archiv-Eintrag '../rechnung\u202eexe.pdf' verlässt das Zielverzeichnis",
    )
    for lang in ("de", "en", "tr"):
        html_bidi = generate_report([bidi_res], lang=lang)
        assert "\u202e" not in html_bidi
        assert "\\u202e" in html_bidi, f"{lang} stripped RLO instead of visibly masking it"


def test_all_incomplete_rule_titles_localized_in_en_and_tr() -> None:
    """Every German title emitted for any _INCOMPLETE_RULES entry must localize in EN & TR."""
    import ast

    from malaz.i18n import localized_incomplete_reason
    from malaz.models import _INCOMPLETE_RULES

    # Direct check for live-test catch ("capa nicht installiert") + sister titles
    for raw_title in (
        "capa nicht installiert",
        "AV-Mitgliedsscan fehlerhaft",
        "PDF-Struktur-Scan unvollständig — Aktionsgraph zu tief/groß",
        "PDF-Struktur-Scan unvollständig — Seitenbaum/Root nicht lesbar",
        "PDF-Struktur-Scan fehlerhaft — Objekt-/Anhang-Scan unvollständig",
    ):
        for lang in ("en", "tr"):
            loc = localized_incomplete_reason(raw_title, lang=lang)
            assert loc != raw_title, f"{lang} failed to translate {raw_title!r}"
            assert "nicht installiert" not in loc and "fehlerhaft" not in loc, loc

    # AST sweep over src/malaz/ to prevent any future _INCOMPLETE_RULES title from leaking German
    src_dir = _ROOT / "src" / "malaz"
    unlocalized: list[str] = []
    for py_file in sorted(src_dir.rglob("*.py")):
        if "i18n" in py_file.name:
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(k, ast.Constant)
                        and isinstance(k.value, str)
                        and k.value in _INCOMPLETE_RULES
                        and isinstance(v, ast.Constant)
                        and isinstance(v.value, str)
                    ):
                        for lang in ("en", "tr"):
                            if localized_incomplete_reason(v.value, lang=lang) == v.value:
                                unlocalized.append(f"{lang}:{k.value}:{v.value!r}")
            elif isinstance(node, ast.Call):
                fn = node.func
                fname = (
                    fn.id
                    if isinstance(fn, ast.Name)
                    else (fn.attr if isinstance(fn, ast.Attribute) else "")
                )
                if fname != "Indicator":
                    continue
                rule_id = None
                title_val = None
                if (
                    node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value in _INCOMPLETE_RULES
                ):
                    rule_id = str(node.args[0].value)
                    if (
                        len(node.args) > 1
                        and isinstance(node.args[1], ast.Constant)
                        and isinstance(node.args[1].value, str)
                    ):
                        title_val = node.args[1].value
                for kw in node.keywords:
                    if (
                        kw.arg == "rule_id"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value in _INCOMPLETE_RULES
                    ):
                        rule_id = str(kw.value.value)
                    if (
                        kw.arg == "title"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        title_val = kw.value.value
                if rule_id and title_val and title_val != "Defender/ClamAV":
                    for lang in ("en", "tr"):
                        if localized_incomplete_reason(title_val, lang=lang) == title_val:
                            unlocalized.append(f"{lang}:{rule_id}:{title_val!r}")
    assert not unlocalized, f"Unlocalized _INCOMPLETE_RULES titles: {unlocalized}"
