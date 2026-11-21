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
    r'["\']((?:ARCH|AV|BINARY_IOC|CAPA|CLAMAV|CORE|DIE|ELF|GEN|HEIC|IMG|JPEG|LNK|'
    r'MACHO|MAIL|OFFICE|PDF|PE|PNG|SCRIPT|SWF|URL|YARA|HASH_BLOCKLIST|'
    r'DOMAIN_BLOCKLIST|IP_BLOCKLIST)_[A-Z0-9_]+)["\']'
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
    """JSON and CSV schemas/values remain 100 % invariant regardless of active UI language."""
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
            )
        ],
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
    """Encrypted/incomplete file must render Unchecked / Denetlenmedi — NEVER Clean / Temiz."""
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
    assert state_label("unk", lang="tr") == "Denetlenmedi"
    assert state_label("unk", lang="tr") != "Temiz"
    i18n.set_language("tr")
    card.retranslate()
    assert "Denetlenmedi" in card.headline.text()
    assert "Temiz" not in card.headline.text()
    assert "Ungeprüft" not in card.headline.text()

    html_tr = generate_report([enc_res], lang="tr")
    assert '<html lang="tr">' in html_tr
    assert "Denetlenmedi:" in html_tr
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
    assert ring._level_lbl.text() == "Denetlenmedi"
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
    assert "Betikler: Yok" in pdf_footer_tr and "Skripte" not in pdf_footer_tr

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
