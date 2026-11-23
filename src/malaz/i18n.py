"""Offline DE/EN/TR localization layer for Malaz.

Design contracts (docs/designs/011-i18n-en-de.md):
- Zero external/Qt/core/pipeline imports (Python stdlib ONLY).
- Module import default is deterministically ``"de"`` (zero OS locale
  side-effects at import time).
- Thread-safe via lock-protected process default + ``ContextVar`` override
  (``language_context``) so concurrent GUI, worker, and report threads never
  cross-contaminate.
- Plain-text invariant (B1): every helper returns un-escaped, Bidi-control-
  stripped plain text. NEVER call ``html.escape()`` here; callers escape once
  at the rendering sink (Qt PlainText / ``escape_html`` / ``mask_invisible``).
"""

from __future__ import annotations

import contextvars
import ctypes
import locale
import re
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from typing import Any

from .i18n_catalog import (
    CATEGORY_DE_LABELS,
    CATEGORY_EN_EXPLANATIONS,
    CATEGORY_EN_LABELS,
    ENGINE_EN_LABELS,
    ENGINE_EN_NAMES,
    INCOMPLETE_REASON_EN,
    OOXML_EN_LABELS,
    RULE_EN_DETAILS,
    RULE_EN_TITLES,
    SHORT_TYPE_EN_LABELS,
    STRINGS_DE,
    STRINGS_EN,
    TYPE_EN_LABELS,
)
from .i18n_catalog_tr import (
    CATEGORY_TR_EXPLANATIONS,
    CATEGORY_TR_LABELS,
    ENGINE_TR_LABELS,
    ENGINE_TR_NAMES,
    INCOMPLETE_REASON_TR,
    OOXML_TR_LABELS,
    RULE_TR_DETAILS,
    RULE_TR_TITLES,
    SHORT_TYPE_TR_LABELS,
    STRINGS_TR,
    TYPE_TR_LABELS,
)

SUPPORTED_LANGS: tuple[str, ...] = ("de", "en", "tr")
LANGUAGE_PREFS: tuple[str, ...] = ("system", "de", "en", "tr")

_STRINGS_BY_LANG: dict[str, dict[str, str]] = {
    "de": STRINGS_DE,
    "en": STRINGS_EN,
    "tr": STRINGS_TR,
}

_STATE_LOCK = threading.Lock()
_DEFAULT_LANG: str = "de"
_LANG_CTX: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "malaz_lang", default=None
)
_LISTENERS: list[Callable[[str], None]] = []

# Bidi control characters stripped at the i18n boundary (C-speed translate).
_BIDI_STRIP_TABLE = str.maketrans(
    "",
    "",
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f",
)

# Bounded extraction patterns for preserving forensic evidence without leaking
# source prose across languages.
_PAREN_COUNT_RE = re.compile(r"\((\d+(?:\s*(?:Bytes?|×\s*%%EOF))?)\)\s*$")
_DEFANGED_URL_RE = re.compile(r"\b(?:hxxps?|https?)://[^\s,;\"'<>]{3,240}", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{16,64}\b")
_YARA_COUNT_RE = re.compile(r"^(\d+)\s+Treffer$")
_STATIC_LABEL_RE = re.compile(
    r"^(Unauffällig|Verdächtig|Gefährlich)\s*·\s*(\d+/100)(\s*\(unvollständig\))?$"
)
_STUFEN_NOTE_RE = re.compile(
    r"^(\d+)\s+Stufe\(n\)\s+nicht\s+gelaufen:\s*([^—\n]{1,500}?)(?:—|--)\s*das Ergebnis.*$"
)
_THREAT_PAREN_RE = re.compile(r"\(([^()]{2,120})\)\s*$")
_COLON_PAYLOAD_RE = re.compile(r":\s*([^\n]{2,160})$")


def strip_bidi(text: str) -> str:
    """Remove Unicode bidirectional override/isolate marks from plain text."""
    if not text:
        return ""
    return str(text).translate(_BIDI_STRIP_TABLE)


def _detect_system_language() -> str:
    """Detect OS UI language: ``de`` (0x07), ``tr`` (0x1F), else ``en``."""
    with suppress(Exception):
        windll = getattr(ctypes, "windll", None)
        if windll is not None:
            lcid = int(windll.kernel32.GetUserDefaultUILanguage())
            if lcid > 0:
                primary = lcid & 0x3FF
                if primary == 0x07:
                    return "de"
                if primary == 0x1F:
                    return "tr"
                return "en"
    with suppress(Exception):
        loc = (locale.getlocale()[0] or "").lower()
        if loc.startswith(("de", "german")):
            return "de"
        if loc.startswith(("tr", "turkish", "türk")):
            return "tr"
    return "en"


def resolve_language(pref: str | None = None) -> str:
    """Resolve ``system | de | en | tr`` (or None) to concrete ``de | en | tr``."""
    raw = (pref or "system").strip().lower()
    if raw == "de" or raw.startswith(("de_", "de-", "german")):
        return "de"
    if raw == "tr" or raw.startswith(("tr_", "tr-", "turkish", "türk")):
        return "tr"
    if raw == "en" or raw.startswith(("en_", "en-", "english")):
        return "en"
    if raw == "system":
        return _detect_system_language()
    return "en"


def get_language() -> str:
    """Return active concrete language (``de``, ``en``, or ``tr``)."""
    ctx_val = _LANG_CTX.get()
    if ctx_val in SUPPORTED_LANGS:
        return ctx_val
    with _STATE_LOCK:
        return _DEFAULT_LANG


def set_language(lang: str) -> str:
    """Set process-wide default language and notify listeners on change."""
    resolved = resolve_language(lang)
    with _STATE_LOCK:
        global _DEFAULT_LANG
        if resolved == _DEFAULT_LANG:
            return resolved
        _DEFAULT_LANG = resolved
        callbacks = list(_LISTENERS)
    for cb in callbacks:
        with suppress(Exception):
            cb(resolved)
    return resolved


@contextmanager
def language_context(lang: str) -> Iterator[str]:
    """Thread-/async-safe temporary language override via ``ContextVar``."""
    resolved = resolve_language(lang)
    token = _LANG_CTX.set(resolved)
    try:
        yield resolved
    finally:
        _LANG_CTX.reset(token)


def register_language_listener(callback: Callable[[str], None]) -> None:
    """Register a deduplicated callback invoked when ``set_language`` changes."""
    with _STATE_LOCK:
        if callback not in _LISTENERS:
            _LISTENERS.append(callback)


def unregister_language_listener(callback: Callable[[str], None]) -> None:
    """Remove a previously registered language listener (safe no-op if absent)."""
    with _STATE_LOCK, suppress(ValueError):
        _LISTENERS.remove(callback)


def _effective_lang(lang: str | None) -> str:
    return resolve_language(lang) if lang is not None else get_language()


def pick(de: str, en: str, tr: str, *, lang: str | None = None) -> str:
    """Concise inline 3-language selector returning Bidi-stripped plain text."""
    eff = _effective_lang(lang)
    if eff == "en":
        return strip_bidi(en)
    if eff == "tr":
        return strip_bidi(tr)
    return strip_bidi(de)


def t(key: str, *, lang: str | None = None, **kwargs: Any) -> str:
    """Look up localized plain-text string for ``key`` with resilient formatting."""
    eff = _effective_lang(lang)
    table = _STRINGS_BY_LANG.get(eff, STRINGS_DE)
    template = table.get(key)
    if template is None:
        template = STRINGS_DE.get(key, key)
    if not kwargs:
        return strip_bidi(template)
    try:
        return strip_bidi(template.format(**kwargs))
    except (KeyError, ValueError, IndexError):
        return strip_bidi(template)


def tn(
    key_one: str,
    key_other: str,
    count: int,
    *,
    lang: str | None = None,
    **kwargs: Any,
) -> str:
    """Singular/plural lookup passing ``count`` into template formatting."""
    key = key_one if count == 1 else key_other
    return t(key, lang=lang, count=count, **kwargs)


# --------------------------------------------------------------------------- #
# Domain-level localization helpers (risk, severity, types, categories,
# engines, incomplete reasons, and indicators)
# --------------------------------------------------------------------------- #


def localized_risk_label(risk: Any, *, lang: str | None = None) -> str:
    name = (getattr(risk, "name", None) or str(risk)).strip().lower()
    return t(f"risk.{name}.label", lang=lang)


def localized_risk_short(risk: Any, *, lang: str | None = None) -> str:
    name = (getattr(risk, "name", None) or str(risk)).strip().lower()
    return t(f"risk.{name}.short", lang=lang)


def localized_risk_advice(risk: Any, *, lang: str | None = None) -> str:
    name = (getattr(risk, "name", None) or str(risk)).strip().lower()
    return t(f"risk.{name}.advice", lang=lang)


def localized_severity_label(severity: Any, *, lang: str | None = None) -> str:
    name = (getattr(severity, "name", None) or str(severity)).strip().lower()
    return t(f"sev.{name}", lang=lang)


def localized_type_label(
    detected_type: str,
    filename: str = "",
    *,
    lang: str | None = None,
    short: bool = False,
) -> str:
    """Return localized human-readable file type label."""
    eff = _effective_lang(lang)
    dt = (detected_type or "").lower()
    low = (filename or "").lower()
    if eff in ("en", "tr"):
        ooxml = OOXML_TR_LABELS if eff == "tr" else OOXML_EN_LABELS
        short_map = SHORT_TYPE_TR_LABELS if eff == "tr" else SHORT_TYPE_EN_LABELS
        full_map = TYPE_TR_LABELS if eff == "tr" else TYPE_EN_LABELS
        if short:
            if dt == "pe" and low.endswith(".dll"):
                return "DLL"
            if dt == "zip":
                for ext, label in ooxml.items():
                    if low.endswith(ext):
                        return label
            if dt == "ole" and low.endswith(".msg"):
                return "E-posta (.msg)" if eff == "tr" else "Email (.msg)"
            default_word = "Dosya" if eff == "tr" else "File"
            return strip_bidi(short_map.get(dt, dt.upper() if dt else default_word))
        return strip_bidi(full_map.get(dt, detected_type or "—"))
    return strip_bidi(detected_type or "—")


def localized_category_label(category: str, *, lang: str | None = None) -> str:
    eff = _effective_lang(lang)
    key = (category or "").strip().lower()
    table = (
        CATEGORY_TR_LABELS
        if eff == "tr"
        else (CATEGORY_EN_LABELS if eff == "en" else CATEGORY_DE_LABELS)
    )
    return strip_bidi(table.get(key, category.capitalize() if category else ""))


def localized_category_explanation(
    category: str,
    de_explanations: dict[str, str] | None = None,
    *,
    lang: str | None = None,
) -> str:
    eff = _effective_lang(lang)
    key = (category or "").strip().lower()
    if eff == "tr":
        return strip_bidi(CATEGORY_TR_EXPLANATIONS.get(key, ""))
    if eff == "en":
        return strip_bidi(CATEGORY_EN_EXPLANATIONS.get(key, ""))
    if de_explanations:
        return strip_bidi(de_explanations.get(key, ""))
    return ""


def localized_engine_name(engine: str, *, lang: str | None = None) -> str:
    eff = _effective_lang(lang)
    clean = strip_bidi(engine or "")
    if eff == "tr":
        return ENGINE_TR_NAMES.get(clean, clean)
    if eff == "en":
        return ENGINE_EN_NAMES.get(clean, clean)
    return clean


def localized_engine_label(
    state: str, label: str, *, lang: str | None = None
) -> str:
    """Localize an ``EngineVerdict.label`` while preserving dynamic counts."""
    eff = _effective_lang(lang)
    clean = strip_bidi(label or "")
    if eff == "de":
        return clean
    lbl_map = ENGINE_TR_LABELS if eff == "tr" else ENGINE_EN_LABELS
    if clean in lbl_map:
        return lbl_map[clean]
    m_yara = _YARA_COUNT_RE.match(clean)
    if m_yara:
        n = int(m_yara.group(1))
        if eff == "tr":
            return f"{n} eşleşme"
        return "1 match" if n == 1 else f"{n} matches"
    m_static = _STATIC_LABEL_RE.match(clean)
    if m_static:
        verdict_loc = lbl_map.get(m_static.group(1), m_static.group(1))
        score_part = m_static.group(2)
        inc_word = " (eksik)" if eff == "tr" else " (incomplete)"
        inc_part = inc_word if m_static.group(3) else ""
        return f"{verdict_loc} · {score_part}{inc_part}"
    if state in ("threat", "clean", "skipped", "error", "off") and not clean:
        return t(f"engine.state.{state}", lang=eff)
    return clean


_CONTAINER_PREFIX_EN: dict[str, str] = {
    "(ZIP-Inhalt)": "(ZIP contents)",
    "(CAB/ISO-Inhalt)": "(CAB/ISO contents)",
    "(RAR/7z-Inhalt)": "(RAR/7z contents)",
    "(TAR/komprimierter Inhalt)": "(TAR/compressed contents)",
    "(E-Mail)": "(Email)",
}

_CONTAINER_PREFIX_TR: dict[str, str] = {
    "(ZIP-Inhalt)": "(ZIP içeriği)",
    "(CAB/ISO-Inhalt)": "(CAB/ISO içeriği)",
    "(RAR/7z-Inhalt)": "(RAR/7z içeriği)",
    "(TAR/komprimierter Inhalt)": "(TAR/sıkıştırılmış içerik)",
    "(E-Mail)": "(E-posta)",
}


_MAX_INCOMPLETE_RECURSION = 8


def localized_incomplete_reason(
    reason: str, *, lang: str | None = None, _depth: int = 0
) -> str:
    """Localize an incomplete-stage reason string into DE, EN, or TR."""
    eff = _effective_lang(lang)
    clean = strip_bidi(reason or "").strip()
    if eff == "de" or not clean:
        return clean
    reason_map = INCOMPLETE_REASON_TR if eff == "tr" else INCOMPLETE_REASON_EN
    if clean in reason_map:
        return reason_map[clean]
    if _depth < _MAX_INCOMPLETE_RECURSION:
        m_note = _STUFEN_NOTE_RE.match(clean[:600])
        if m_note:
            count = int(m_note.group(1))
            raw_parts = [p.strip() for p in m_note.group(2).split("|") if p.strip()]
            loc_parts = [
                localized_incomplete_reason(p, lang=eff, _depth=_depth + 1)
                for p in raw_parts
            ]
            return t(
                "report.incomplete_note",
                lang=eff,
                count=count,
                names=" | ".join(loc_parts),
            )
    for de_prefix, loc_text in reason_map.items():
        if clean.startswith(de_prefix):
            return loc_text
    if _depth < _MAX_INCOMPLETE_RECURSION and ": " in clean:
        child_prefix, rest = clean.split(": ", 1)
        cmap = _CONTAINER_PREFIX_TR if eff == "tr" else _CONTAINER_PREFIX_EN
        loc_prefix = cmap.get(child_prefix, child_prefix)
        loc_rest = localized_incomplete_reason(rest, lang=eff, _depth=_depth + 1)
        if loc_prefix != child_prefix or loc_rest != rest:
            return f"{loc_prefix}: {loc_rest}"
    if "nicht geprüft" in clean:
        prefix = clean.split("nicht geprüft", 1)[0].strip(" :—-")
        if eff == "tr":
            return f"{prefix}: taranamadı" if prefix else "Aşama taranamadı"
        return f"{prefix}: not checked" if prefix else "Stage not checked"
    if "Stufe nicht gelaufen:" in clean:
        rest = clean.split("Stufe nicht gelaufen:", 1)[1].strip()
        if eff == "tr":
            return f"Aşama çalışmadı: {rest}" if rest else "Kontrol aşaması çalışmadı"
        return f"Stage did not run: {rest}" if rest else "Inspection stage did not run"
    return clean


def localized_engine_detail(
    state: str, detail: str, *, lang: str | None = None
) -> str:
    """Localize an ``EngineVerdict.detail`` while preserving raw threat IDs."""
    eff = _effective_lang(lang)
    clean = strip_bidi(detail or "").strip()
    if eff == "de" or not clean:
        return clean
    if state == "threat":
        return clean
    translated_inc = localized_incomplete_reason(clean, lang=eff)
    if translated_inc != clean:
        return translated_inc
    if "nicht installiert" in clean or "nicht verfügbar" in clean:
        return (
            "Tarama motoru bu sistemde kurulu değil veya kullanılamıyor."
            if eff == "tr"
            else "Engine not installed or unavailable on this system."
        )
    if "übersprungen" in clean.lower():
        return (
            "Bu dosya için motor taraması atlandı."
            if eff == "tr"
            else "Engine scan was skipped for this file."
        )
    if "Größenlimit" in clean or "zu groß" in clean.lower():
        return (
            "Dosya boyut sınırını aştığı için bu motorla taranmadı."
            if eff == "tr"
            else "File exceeded the engine size limit and was not scanned."
        )
    if "keine Bedrohung" in clean or "keine Treffer" in clean:
        return (
            "Bu tarama motoru tehdit tespit etmedi."
            if eff == "tr"
            else "No threat detected by this engine."
        )
    if "fehler" in clean.lower() or "timeout" in clean.lower():
        return (
            "Motor taraması tamamlanamadan hata verdi veya zaman aşımına uğradı."
            if eff == "tr"
            else "Engine scan failed or timed out before completing."
        )
    return clean


def _extract_threat_name(title: str) -> str:
    m_p = _THREAT_PAREN_RE.search(title)
    if m_p:
        return m_p.group(1).strip()
    m_c = _COLON_PAYLOAD_RE.search(title)
    if m_c:
        tail = m_c.group(1).strip()
        if tail.lower() not in ("keine bedrohung", "scan übersprungen"):
            return tail
    return ""


def _dynamic_rule_title(rule_id: str, raw_title: str, eff: str) -> str | None:
    if rule_id.startswith("YARA_") and rule_id not in (
        "YARA_LOAD_ERROR",
        "YARA_SCAN_ERROR",
    ):
        rule_name = rule_id[len("YARA_") :]
        return f"YARA eşleşmesi: {rule_name}" if eff == "tr" else f"YARA match: {rule_name}"
    if rule_id.startswith("EXT_"):
        labels = (
            (
                ("_THREAT", "tehdit algılandı"),
                ("_CLEAN", "tehdit bulunmadı"),
                ("_SKIPPED", "tarama atlandı"),
                ("_ERROR", "tarama hatası"),
            )
            if eff == "tr"
            else (
                ("_THREAT", "threat detected"),
                ("_CLEAN", "no threat detected"),
                ("_SKIPPED", "scan skipped"),
                ("_ERROR", "scan error"),
            )
        )
        for suffix, label in labels:
            if rule_id.endswith(suffix):
                tag = rule_id[len("EXT_") : -len(suffix)].replace("_", " ").title()
                if suffix == "_THREAT":
                    threat = _extract_threat_name(raw_title)
                    if threat:
                        return f"{tag}: {threat}"
                return f"{tag}: {label}"
    if rule_id.startswith("PDF_KW_"):
        kw = rule_id[len("PDF_KW_") :]
        return (
            f"PDF şüpheli anahtar içeriyor (/{kw})"
            if eff == "tr"
            else f"PDF contains suspicious keyword (/{kw})"
        )
    if rule_id.endswith("_ERROR"):
        stage = rule_id[: -len("_ERROR")].replace("_", " ").title()
        return f"{stage} analiz hatası" if eff == "tr" else f"{stage} analysis error"
    return None


def localized_indicator_title(ind: Any, *, lang: str | None = None) -> str:
    """Return localized plain-text title for an ``Indicator``."""
    eff = _effective_lang(lang)
    raw_title = strip_bidi(getattr(ind, "title", "") or "")
    if eff == "de":
        return raw_title
    rule_id = str(getattr(ind, "rule_id", "") or "")
    titles_map = RULE_TR_TITLES if eff == "tr" else RULE_EN_TITLES

    if rule_id in ("AV_THREAT", "AV_DETECTED"):
        threat = _extract_threat_name(raw_title)
        return f"Windows Defender: {threat}" if threat else titles_map["AV_THREAT"]
    if rule_id == "CLAMAV_THREAT":
        threat = _extract_threat_name(raw_title)
        return f"ClamAV: {threat}" if threat else titles_map["CLAMAV_THREAT"]

    base = titles_map.get(rule_id)
    if base is None:
        dyn = _dynamic_rule_title(rule_id, raw_title, eff)
        return strip_bidi(dyn) if dyn else raw_title

    m_cnt = _PAREN_COUNT_RE.search(raw_title)
    if m_cnt and f"({m_cnt.group(1)})" not in base:
        if eff == "tr":
            val = m_cnt.group(1).replace("Bytes", "bayt").replace("Byte", "bayt")
        else:
            val = m_cnt.group(1).replace("Bytes", "bytes").replace("Byte", "byte")
        return f"{base} ({val})"
    return strip_bidi(base)


def _extract_evidence_snippets(raw_detail: str, eff: str) -> str:
    if not raw_detail:
        return ""
    urls = _DEFANGED_URL_RE.findall(raw_detail)
    if urls:
        defanged = [
            re.sub(
                r"^https?://",
                lambda m: "hxxp" + m.group(0)[4:].lower(),
                u,
                flags=re.IGNORECASE,
            )
            for u in urls
        ]
        all_unique = list(dict.fromkeys(defanged))
        unique = all_unique[:5]
        extra = len(all_unique) - len(unique)
        suffix = (f" (+{extra} daha)" if eff == "tr" else f" (+{extra} more)") if extra > 0 else ""
        return " · ".join(unique) + suffix
    hashes = [h for h in _SHA256_RE.findall(raw_detail) if len(h) >= 32]
    if hashes:
        return f"SHA-256: {hashes[0][:16]}…"
    return ""


def localized_indicator_detail(ind: Any, *, lang: str | None = None) -> str:
    """Return localized plain-text explanation for an ``Indicator``."""
    eff = _effective_lang(lang)
    raw_detail = strip_bidi(getattr(ind, "detail", "") or "")
    if eff == "de":
        return raw_detail
    rule_id = str(getattr(ind, "rule_id", "") or "")
    details_map = RULE_TR_DETAILS if eff == "tr" else RULE_EN_DETAILS

    if rule_id.startswith("YARA_") and rule_id not in (
        "YARA_LOAD_ERROR",
        "YARA_SCAN_ERROR",
    ):
        rule_name = rule_id[len("YARA_") :]
        if eff == "tr":
            return f"Yerel YARA imza kuralı '{rule_name}' ile eşleşti."
        return f"Matched local YARA signature rule '{rule_name}'."
    if rule_id.startswith("EXT_"):
        if eff == "tr":
            if rule_id.endswith("_THREAT"):
                return f"Harici antivirüs tarayıcısı tehdit bildirdi. {raw_detail}".strip()
            if rule_id.endswith("_CLEAN"):
                return "Harici antivirüs tarayıcısı tehdit bulmadı."
            if rule_id.endswith("_SKIPPED"):
                return "Bu dosya için harici antivirüs taraması atlandı."
            if rule_id.endswith("_ERROR"):
                return "Harici antivirüs tarayıcısı hata döndürdü."
        else:
            if rule_id.endswith("_THREAT"):
                return f"External antivirus scanner reported a detection. {raw_detail}".strip()
            if rule_id.endswith("_CLEAN"):
                return "External antivirus scanner reported no threat."
            if rule_id.endswith("_SKIPPED"):
                return "External antivirus scanner was skipped for this file."
            if rule_id.endswith("_ERROR"):
                return "External antivirus scanner returned an error."

    base = details_map.get(rule_id)
    if base is None:
        if rule_id.startswith("PDF_KW_"):
            kw = rule_id[len("PDF_KW_") :]
            base = (
                f"PDF içinde /{kw} anahtar/eylem kaydı bulunuyor."
                if eff == "tr"
                else f"The PDF contains the /{kw} keyword/action entry."
            )
        elif rule_id.endswith("_ERROR"):
            base = (
                "Bu inceleme aşaması hata verdi ve tam olarak tamamlanamadı."
                if eff == "tr"
                else "This analysis stage encountered an error and did not complete cleanly."
            )
        else:
            return raw_detail

    evidence = _extract_evidence_snippets(raw_detail, eff)
    if evidence:
        return strip_bidi(f"{base} ({evidence})")
    return strip_bidi(base)
