"""Three uniform Engine Summary Cards for Malaz v11 ("Klare Fläche v2").

Displays 3 equal-width cards below the Verdict Hero:
- Leaf files: ``Windows Defender`` | ``ClamAV`` | ``Deep Inspection``
- Archives: ``Contents (N files)`` | ``Archive Structure`` | ``Top Finding``
- E-Mails: ``Sender`` | ``Attachments`` | ``Links in Body`` (surfacing any direct
  AV threat or failure on the .eml/.msg file itself so nothing is hidden!).

Preserves ``EngineChip``, ``EngineStrip`` alias, and ``compact_engine_text``
for full compatibility with existing tests and exports.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from ..design_tokens import ARCHIVE_TYPES, is_ooxml_filename, visual_state
from ..i18n import (
    get_language,
    localized_engine_detail,
    localized_engine_label,
    localized_engine_name,
    localized_indicator_title,
    pick,
)
from ..models import EngineVerdict, ScanResult
from .sanitize import (
    ENCRYPTED_RULES,
    clip_text,
    escape_tooltip,
    indicator_weight,
    is_encrypted,
    is_mail_result,
    masked_widget_text,
    result_is_incomplete,
)
from .score_ring import StatusDotWidget


def compact_engine_text(result: ScanResult) -> str:
    """Compact one-line summary of engine verdicts (e.g. ``D:✓ C:✓ Y:1``)."""
    verdicts = getattr(result, "engine_verdicts", None) or []
    if not verdicts:
        return "—"
    parts: list[str] = []
    for v in verdicts:
        short = (v.engine[:1] or "?").upper()
        st = (v.state or "").lower()
        if st == "threat":
            sym = "!"
        elif st == "clean":
            sym = "✓"
        elif st in ("error", "skipped"):
            sym = "?"
        else:
            sym = "–"
        parts.append(f"{short}:{sym}")
    return " ".join(parts)


_NON_SCANNER_ENGINES = frozenset({"statisch", "static"})


def _elide_card(value: str | None, limit: int = 34) -> str:
    """Single-pass clean ellipsis for compact Engine Cards (no double '(gekürzt)')."""
    clean = masked_widget_text(value).strip()
    if len(clean) <= limit:
        return clean
    return clean[: max(1, limit - 1)].rstrip() + "…"


class EngineChip(QFrame):
    """Single clickable engine card inside the 3-card EngineCardsRow."""

    clicked = Signal()

    def __init__(
        self,
        verdict_or_parent: EngineVerdict | QWidget | None = None,
        parent: QWidget | None = None,
    ) -> None:
        verdict = verdict_or_parent if isinstance(verdict_or_parent, EngineVerdict) else None
        real_parent = (
            parent
            if verdict is not None
            else (verdict_or_parent if isinstance(verdict_or_parent, QWidget) else None)
        )
        super().__init__(real_parent)
        self.setObjectName("engineCard")
        self.setMinimumHeight(74)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(8)

        self._name = QLabel(self)
        self._name.setObjectName("captionLabel")
        self._name.setTextFormat(Qt.TextFormat.PlainText)
        top.addWidget(self._name, 1)

        self._dot = StatusDotWidget("ok", parent=self)
        top.addWidget(self._dot, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addLayout(top)

        self._val = QLabel(self)
        self._val.setObjectName("engineVal")
        self._val.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._val.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self._val)

        self._sub = QLabel(self)
        self._sub.setObjectName("mutedLabel")
        self._sub.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._sub.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self._sub)
        if verdict is not None:
            lang = get_language()
            tone = {"threat": "bad", "clean": "ok", "error": "warn", "skipped": "warn"}.get(
                verdict.state, "muted"
            )
            ring = verdict.state in ("skipped", "error", "off")
            eng = localized_engine_name(verdict.engine, lang=lang)
            lbl = localized_engine_label(verdict.state, verdict.label or verdict.state, lang=lang)
            det = localized_engine_detail(verdict.state, verdict.detail or "", lang=lang) or lbl
            self.set_card(
                eng,
                lbl,
                det,
                tone=tone,
                ring=ring,
                tooltip=f"{eng}: {lbl} — {det}",
            )

    def set_card(
        self,
        name: str,
        value: str,
        subtitle: str,
        *,
        tone: str = "ok",
        ring: bool = False,
        tooltip: str = "",
    ) -> None:
        self._name.setText(_elide_card(name, 38))
        self._val.setText(_elide_card(value, 32))
        self._sub.setText(_elide_card(subtitle, 44))
        self._val.setProperty("tone", tone)
        self._val.style().unpolish(self._val)
        self._val.style().polish(self._val)
        self._dot.set_state(tone, ring=ring)
        self.setToolTip(escape_tooltip(tooltip or f"{name}: {value} — {subtitle}"))

    def text(self) -> str:
        """Return combined card text (compatibility helper for unit tests)."""
        return f"{self._name.text()} {self._val.text()} {self._sub.text()}".strip()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


def _verdict_by_name(result: ScanResult, key: str) -> EngineVerdict | None:
    low = key.lower()
    for v in result.engine_verdicts:
        if low in (v.engine or "").lower():
            return v
    return None


def _av_card_tuple(
    label: str,
    verdict: EngineVerdict | None,
    *,
    encrypted: bool,
) -> tuple[str, str, str, str, bool, str]:
    lang = get_language()
    if encrypted and (verdict is None or verdict.state in ("skipped", "unavailable")):
        return (
            label,
            pick("Übersprungen", "Skipped", "Atlandı", lang=lang),
            pick("Verschlüsselt", "Encrypted", "Şifreli", lang=lang),
            "warn",
            True,
            pick(
                f"{label}: Passwortgeschützt",
                f"{label}: Password-protected",
                f"{label}: Parola korumalı",
                lang=lang,
            ),
        )
    if verdict is None:
        return (
            label,
            pick("Nicht geprüft", "Unchecked", "Taranamadı", lang=lang),
            pick("Kein Status", "No status", "Durum yok", lang=lang),
            "warn",
            True,
            pick(f"{label}: Nicht gelaufen", f"{label}: Not run", f"{label}: Çalışmadı", lang=lang),
        )
    st = (verdict.state or "").lower()
    detail = masked_widget_text(localized_engine_detail(st, verdict.detail or "", lang=lang))
    if st == "threat":
        val = clip_text(detail or pick("Bedrohung", "Threat", "Tehdit", lang=lang), 30)
        return (
            label,
            val,
            pick("Bedrohung erkannt", "Threat detected", "Tehdit algılandı", lang=lang),
            "bad",
            False,
            pick(
                f"{label}: Bedrohung ({detail})",
                f"{label}: Threat ({detail})",
                f"{label}: Tehdit ({detail})",
                lang=lang,
            ),
        )
    if st == "clean":
        return (
            label,
            pick("Kein Treffer", "No threat", "Tehdit bulunmadı", lang=lang),
            pick("Sauber", "Clean", "Temiz", lang=lang),
            "ok",
            False,
            pick(f"{label}: sauber", f"{label}: clean", f"{label}: temiz", lang=lang),
        )
    if st == "error":
        return (
            label,
            pick("Fehler", "Error", "Hata", lang=lang),
            clip_text(
                detail or pick("Prüfung fehlgeschlagen", "Scan failed", "Tarama başarısız", lang=lang), 40
            ),
            "warn",
            True,
            pick(
                f"{label}: Fehler ({detail})",
                f"{label}: Error ({detail})",
                f"{label}: Hata ({detail})",
                lang=lang,
            ),
        )
    if st == "skipped":
        return (
            label,
            pick("Übersprungen", "Skipped", "Atlandı", lang=lang),
            clip_text(detail or pick("Nicht gelaufen", "Not run", "Çalışmadı", lang=lang), 40),
            "warn",
            True,
            pick(
                f"{label}: übersprungen ({detail})",
                f"{label}: skipped ({detail})",
                f"{label}: atlandı ({detail})",
                lang=lang,
            ),
        )
    return (
        label,
        pick("Inaktiv", "Inactive", "Devre dışı", lang=lang),
        clip_text(detail or pick("Nicht verfügbar", "Unavailable", "Kullanılamıyor", lang=lang), 40),
        "warn",
        True,
        pick(f"{label}: nicht verfügbar", f"{label}: unavailable", f"{label}: kullanılamıyor", lang=lang),
    )


def _cards_for_leaf(result: ScanResult) -> list[tuple[str, str, str, str, bool, str]]:
    lang = get_language()
    encrypted = is_encrypted(result)
    defender = _av_card_tuple("Windows Defender", _verdict_by_name(result, "defender"), encrypted=encrypted)
    clamav = _av_card_tuple("ClamAV", _verdict_by_name(result, "clamav"), encrypted=encrypted)

    yara = _verdict_by_name(result, "yara")
    yara_hits = [i for i in result.indicators if i.rule_id.startswith("YARA_") and indicator_weight(i) > 0]
    static_hits = [
        i
        for i in result.indicators
        if indicator_weight(i) > 0 and not i.rule_id.startswith(("AV_", "CLAMAV_"))
    ]
    deep_name = pick("Tiefenprüfung", "Deep Inspection", "Derin Analiz", lang=lang)

    if encrypted:
        deep = (
            deep_name,
            pick("Gesperrt", "Locked", "Kilitli", lang=lang),
            pick("Passwort nötig", "Password required", "Parola gerekli", lang=lang),
            "warn",
            True,
            pick(
                "Tiefenprüfung: Inhalt verschlüsselt",
                "Deep Inspection: encrypted content",
                "Derin analiz: içerik şifreli",
                lang=lang,
            ),
        )
    elif yara is not None and yara.state == "threat":
        cnt = max(1, len(yara_hits))
        top_title = masked_widget_text(
            localized_indicator_title(yara_hits[0], lang=lang) if yara_hits else yara.detail
        )
        sub = pick(
            f"YARA: {cnt} Treffer",
            f"YARA: {cnt} match" if cnt == 1 else f"YARA: {cnt} matches",
            f"YARA: {cnt} eşleşme",
            lang=lang,
        )
        deep = (
            deep_name,
            top_title or pick("YARA-Treffer", "YARA match", "YARA eşleşmesi", lang=lang),
            sub,
            "bad",
            False,
            sub,
        )
    elif static_hits:
        worst = max(static_hits, key=lambda x: (indicator_weight(x), int(x.severity)))
        tone = "bad" if indicator_weight(worst) >= 35 or result.risk_level.value >= 2 else "warn"
        wtitle = localized_indicator_title(worst, lang=lang)
        if yara_hits:
            sub = pick(
                f"YARA: {len(yara_hits)} Treffer",
                f"YARA: {len(yara_hits)} match(es)",
                f"YARA: {len(yara_hits)} eşleşme",
                lang=lang,
            )
        else:
            sub = pick(
                f"{len(static_hits)} Auffälligkeit(en)",
                f"{len(static_hits)} finding" if len(static_hits) == 1 else f"{len(static_hits)} findings",
                f"{len(static_hits)} bulgu",
                lang=lang,
            )
        deep = (deep_name, masked_widget_text(wtitle), sub, tone, False, wtitle)
    elif result_is_incomplete(result):
        deep = (
            deep_name,
            pick("Unvollständig", "Unchecked", "Taranamadı", lang=lang),
            pick("Stufe ausgelassen", "Stage skipped", "Aşama atlandı", lang=lang),
            "warn",
            True,
            pick(
                "Mindestens eine Prüfphase fehlte",
                "At least one inspection stage did not run",
                "En az bir kontrol aşaması çalışmadı",
                lang=lang,
            ),
        )
    else:
        sub = (
            pick("YARA + Statik sauber", "YARA + Static clean", "YARA + Statik temiz", lang=lang)
            if (yara and yara.state == "clean")
            else pick("Statik sauber", "Static clean", "Statik temiz", lang=lang)
        )
        deep = (
            deep_name,
            pick("Unauffällig", "Clean", "Temiz", lang=lang),
            sub,
            "ok",
            False,
            pick("Tiefenprüfung ohne Befund", "Deep inspection clean", "Derin analiz temiz", lang=lang),
        )

    return [defender, clamav, deep]


def _cards_for_archive(result: ScanResult) -> list[tuple[str, str, str, str, bool, str]]:
    lang = get_language()
    encrypted = is_encrypted(result)
    kids = result.children
    if encrypted and not kids:
        return _cards_for_leaf(result)

    bad_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"]
    warn_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) in ("warn", "unk")]
    bad_n = len(bad_kids)
    warn_n = len(warn_kids)
    ok_n = len(kids) - bad_n - warn_n
    c1_hdr = pick(
        f"Inhalt ({len(kids)} Dateien)",
        f"Contents ({len(kids)} files)",
        f"İçerik ({len(kids)} dosya)",
        lang=lang,
    )

    if not kids:
        inc_empty = result_is_incomplete(result)
        c1 = (
            c1_hdr,
            pick("Leeres Archiv", "Empty archive", "Boş arşiv", lang=lang),
            pick("Keine Einträge", "No entries", "Öğe yok", lang=lang),
            "ok" if not inc_empty else "warn",
            inc_empty,
            pick("Keine Dateien im Archiv", "No files in archive", "Arşivde dosya yok", lang=lang),
        )
    elif bad_n:
        val_txt = (
            pick(
                f"{bad_n} gefährlich · {warn_n} auffällig",
                f"{bad_n} dangerous · {warn_n} flagged",
                f"{bad_n} tehlikeli · {warn_n} şüpheli",
                lang=lang,
            )
            if warn_n
            else pick(
                f"{bad_n} gefährlich · {ok_n} sauber",
                f"{bad_n} dangerous · {ok_n} clean",
                f"{bad_n} tehlikeli · {ok_n} temiz",
                lang=lang,
            )
        )
        c1 = (
            c1_hdr,
            val_txt,
            masked_widget_text(bad_kids[0].display_name),
            "bad",
            False,
            pick(
                "Schädliche Datei im Archiv",
                "Malicious file inside archive",
                "Arşiv içinde zararlı dosya",
                lang=lang,
            ),
        )
    elif warn_n:
        c1 = (
            c1_hdr,
            pick(
                f"{warn_n} auffällig · {ok_n} sauber",
                f"{warn_n} flagged · {ok_n} clean",
                f"{warn_n} şüpheli · {ok_n} temiz",
                lang=lang,
            ),
            pick("Prüfung empfohlen", "Review recommended", "İnceleme önerilir", lang=lang),
            "warn",
            False,
            pick(
                "Auffällige Datei im Archiv",
                "Suspicious file inside archive",
                "Arşiv içinde şüpheli dosya",
                lang=lang,
            ),
        )
    else:
        c1 = (
            c1_hdr,
            pick(f"{ok_n} sauber", f"{ok_n} clean", f"{ok_n} temiz", lang=lang),
            pick("Alle Einträge geprüft", "All entries scanned", "Tüm öğeler tarandı", lang=lang),
            "ok",
            False,
            pick("Alle Dateien sauber", "All archive files clean", "Arşivdeki tüm dosyalar temiz", lang=lang),
        )

    arch_warns = [
        i
        for i in result.indicators
        if i.rule_id.startswith(("ARCH_", "ZIP_", "TAR_", "SEVENZIP_"))
        and (indicator_weight(i) > 0 or i.rule_id in ENCRYPTED_RULES)
    ]
    c2_hdr = pick("Archiv-Struktur", "Archive Structure", "Arşiv Yapısı", lang=lang)
    if arch_warns:
        atitle = localized_indicator_title(arch_warns[0], lang=lang)
        c2 = (
            c2_hdr,
            masked_widget_text(atitle),
            pick("Auffällig", "Flagged", "Şüpheli", lang=lang),
            "warn",
            False,
            atitle,
        )
    elif result_is_incomplete(result):
        c2 = (
            c2_hdr,
            pick("Teilweise geprüft", "Partially checked", "Kısmen tarandı", lang=lang),
            pick("Limit oder Schutz", "Limit or encryption", "Limit veya şifreleme", lang=lang),
            "warn",
            True,
            pick(
                "Archiv nicht vollständig entpackt",
                "Archive was not fully extracted",
                "Arşiv tam olarak çıkarılamadı",
                lang=lang,
            ),
        )
    else:
        c2 = (
            c2_hdr,
            pick("Sicher entpackt", "Safely unpacked", "Güvenle açıldı", lang=lang),
            pick("Kein Pfadausbruch", "No path traversal", "Dizin aşımı yok", lang=lang),
            "ok",
            False,
            pick(
                "Keine Archiv-Bombe oder Zip-Slip",
                "No archive bomb or Zip-Slip",
                "Arşiv bombası veya Zip-Slip yok",
                lang=lang,
            ),
        )

    c3_hdr = pick("Schwerster Fund", "Top Finding", "En Önemli Bulgu", lang=lang)
    all_ind = sorted(result.all_indicators(), key=lambda x: (-indicator_weight(x), -int(x.severity)))
    top = next((i for i in all_ind if indicator_weight(i) > 0), None)
    if top is not None:
        tone = "bad" if result.risk_level.value >= 2 or indicator_weight(top) >= 35 else "warn"
        ttitle = localized_indicator_title(top, lang=lang)
        c3 = (
            c3_hdr,
            masked_widget_text(ttitle),
            pick(f"Score {result.score}", f"Score {result.score}", f"Puan {result.score}", lang=lang),
            tone,
            False,
            ttitle,
        )
    else:
        inc_arch = result_is_incomplete(result)
        c3 = (
            c3_hdr,
            pick("Unvollständig", "Unchecked", "Taranamadı", lang=lang)
            if inc_arch
            else pick("Kein Befund", "No findings", "Bulgu yok", lang=lang),
            pick("Prüfung lückenhaft", "Incomplete scan", "Eksik tarama", lang=lang)
            if inc_arch
            else pick("Sauber", "Clean", "Temiz", lang=lang),
            "warn" if inc_arch else "ok",
            inc_arch,
            pick("Prüfung nicht vollständig", "Scan incomplete", "Tarama eksik", lang=lang)
            if inc_arch
            else pick("Keine Befunde", "No findings", "Bulgu yok", lang=lang),
        )
    return [c1, c2, c3]


def _cards_for_mail(result: ScanResult) -> list[tuple[str, str, str, str, bool, str]]:
    lang = get_language()
    av_verdicts = [
        v for v in result.engine_verdicts if (v.engine or "").strip().lower() not in _NON_SCANNER_ENGINES
    ]
    av_threat = next((v for v in av_verdicts if v.state == "threat"), None)
    av_gap = [v for v in av_verdicts if v.state in ("error", "skipped")]
    ms = result.mail_security or {}
    sender_st = ms.get("sender", "unknown")
    auth_fail = any(ms.get(k) == "fail" for k in ("spf", "dkim", "dmarc"))
    rids = {i.rule_id for i in result.indicators}
    sender_spoof = bool(rids & {"MAIL_DISPLAY_NAME_SPOOF", "MAIL_RETURN_PATH_MISMATCH", "MAIL_AUTH_FAIL"})
    reply_mismatch = "MAIL_REPLY_TO_MISMATCH" in rids
    auth_unbacked = "MAIL_AUTH_CLAIM_UNBACKED" in rids
    incomplete = result_is_incomplete(result)

    c1_sender = pick("Absender", "Sender", "Gönderen", lang=lang)
    if av_threat is not None:
        c1 = (
            pick(
                f"Virenschutz ({av_threat.engine})",
                f"Antivirus ({av_threat.engine})",
                f"Antivirüs ({av_threat.engine})",
                lang=lang,
            ),
            masked_widget_text(av_threat.detail or pick("Bedrohung", "Threat", "Tehdit", lang=lang)),
            pick(
                "Direkter Treffer auf E-Mail", "Direct hit on email", "E-postada doğrudan tehdit", lang=lang
            ),
            "bad",
            False,
            av_threat.detail or pick("AV-Treffer", "AV hit", "AV tespiti", lang=lang),
        )
    elif sender_st == "mismatch" or auth_fail or sender_spoof:
        if auth_fail or "MAIL_AUTH_FAIL" in rids:
            sub = pick("SPF/DMARC fehlgeschlagen", "SPF/DMARC failed", "SPF/DMARC başarısız", lang=lang)
        elif "MAIL_DISPLAY_NAME_SPOOF" in rids:
            sub = pick(
                "Anzeigename täuscht Absender vor",
                "Display name spoofs sender",
                "Sahte görünen ad (kimlik avı belirtisi)",
                lang=lang,
            )
        else:
            sub = pick("Absender weicht ab", "Sender mismatch", "Gönderen uyumsuz", lang=lang)
        c1 = (c1_sender, pick("Gefälscht", "Spoofed", "Sahte", lang=lang), sub, "bad", False, sub)
    elif reply_mismatch:
        c1 = (
            c1_sender,
            pick("Antwort weicht ab", "Reply differs", "Yanıt adresi farklı", lang=lang),
            pick("Reply-To != Absender", "Reply-To != From", "Yanıt adresi farklı", lang=lang),
            "warn",
            False,
            pick(
                "Antwortadresse (Reply-To) weicht vom Absender ab",
                "Reply-To address differs from sender",
                "Yanıt adresi (Reply-To) gönderenden farklı",
                lang=lang,
            ),
        )
    elif auth_unbacked:
        c1 = (
            c1_sender,
            pick("Nicht belegt", "Unverified", "Doğrulanmadı", lang=lang),
            pick(
                "Header ohne DNS-Nachweis", "Header without DNS proof", "DNS kanıtı olmayan başlık", lang=lang
            ),
            "warn",
            True,
            pick(
                "Authentication-Results im Header sind unbestätigt",
                "Authentication-Results header is unverified",
                "Başlıktaki Authentication-Results doğrulanmadı",
                lang=lang,
            ),
        )
    elif av_gap:
        gap_names = ", ".join(v.engine for v in av_gap[:2])
        c1 = (
            pick(
                f"Virenschutz ({gap_names})",
                f"Antivirus ({gap_names})",
                f"Antivirüs ({gap_names})",
                lang=lang,
            ),
            pick("Unvollständig", "Unchecked", "Taranamadı", lang=lang),
            pick(
                "Prüfstufe ausgelassen/Fehler",
                "Stage skipped or failed",
                "Aşama atlandı veya hata oluştu",
                lang=lang,
            ),
            "warn",
            True,
            pick(
                f"Virenschutz auf E-Mail nicht vollständig gelaufen ({gap_names})",
                f"Antivirus did not complete on email ({gap_names})",
                f"E-posta üzerinde antivirüs taraması tamamlanamadı ({gap_names})",
                lang=lang,
            ),
        )
    elif sender_st == "ok":
        c1 = (
            c1_sender,
            pick("Stimmig", "Consistent", "Tutarlı", lang=lang),
            pick("Keine Abweichung", "No mismatch", "Uyumsuzluk yok", lang=lang),
            "ok",
            False,
            pick("Absender konsistent", "Sender consistent", "Gönderen tutarlı", lang=lang),
        )
    else:
        c1 = (
            c1_sender,
            pick("Nicht prüfbar", "Unverifiable", "Doğrulanamadı", lang=lang),
            pick("Kein Nachweis im Header", "No proof in header", "Başlıkta kanıt yok", lang=lang),
            "warn",
            True,
            pick("SPF/DMARC nicht prüfbar", "SPF/DMARC unverifiable", "SPF/DMARC doğrulanamadı", lang=lang),
        )

    c2_hdr = pick("Anhänge", "Attachments", "Ekler", lang=lang)
    kids = result.children
    bad_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"]
    warn_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) in ("warn", "unk")]
    if bad_kids:
        c2 = (
            c2_hdr,
            pick(
                f"{len(bad_kids)} Schadprogramm",
                f"{len(bad_kids)} malicious",
                f"{len(bad_kids)} zararlı",
                lang=lang,
            ),
            masked_widget_text(bad_kids[0].display_name),
            "bad",
            False,
            pick("Schädlicher Anhang", "Malicious attachment", "Zararlı ek", lang=lang),
        )
    elif warn_kids:
        c2 = (
            c2_hdr,
            pick(
                f"{len(warn_kids)} auffällig",
                f"{len(warn_kids)} flagged",
                f"{len(warn_kids)} şüpheli",
                lang=lang,
            ),
            pick(
                f"von {len(kids)} Anhang/Anhängen",
                f"of {len(kids)} attachment(s)",
                f"toplam {len(kids)} ekten",
                lang=lang,
            ),
            "warn",
            False,
            pick("Auffälliger Anhang", "Suspicious attachment", "Şüpheli ek", lang=lang),
        )
    elif kids:
        c2 = (
            c2_hdr,
            pick(f"{len(kids)} sauber", f"{len(kids)} clean", f"{len(kids)} temiz", lang=lang),
            pick("Alle geprüft", "All scanned", "Tümü tarandı", lang=lang),
            "ok",
            False,
            pick("Anhänge unauffällig", "Attachments clean", "Ekler temiz", lang=lang),
        )
    elif incomplete:
        c2 = (
            c2_hdr,
            pick("Unvollständig", "Unchecked", "Taranamadı", lang=lang),
            pick("Prüfung lückenhaft", "Incomplete scan", "Eksik tarama", lang=lang),
            "warn",
            True,
            pick(
                "E-Mail-Prüfung war nicht vollständig — Anhänge nicht abschließend geprüft",
                "Email scan incomplete — attachments not fully verified",
                "E-posta taraması tamamlanamadı — ekler kesin doğrulanmadı",
                lang=lang,
            ),
        )
    else:
        c2 = (
            c2_hdr,
            pick("Keine Anhänge", "No attachments", "Ek yok", lang=lang),
            pick("Nur Nachricht", "Message only", "Yalnızca mesaj", lang=lang),
            "ok",
            False,
            pick("Keine Anhänge", "No attachments", "Ek yok", lang=lang),
        )

    c3_hdr = pick("Links im Text", "Links in Body", "Mesajdaki Bağlantılar", lang=lang)
    links = list(result.mail_links or [])
    susp_links = [
        lnk
        for lnk in links
        if getattr(lnk, "suspicious", False)
        or getattr(lnk, "mismatch", False)
        or getattr(lnk, "is_ip", False)
    ]
    if susp_links:
        first_url = masked_widget_text(getattr(susp_links[0], "href", "") or str(susp_links[0]))
        c3 = (
            c3_hdr,
            pick(
                f"{len(susp_links)} verdächtig",
                f"{len(susp_links)} suspicious",
                f"{len(susp_links)} şüpheli",
                lang=lang,
            ),
            first_url,
            "warn",
            False,
            first_url,
        )
    elif links:
        c3 = (
            c3_hdr,
            pick(f"{len(links)} Link(s)", f"{len(links)} link(s)", f"{len(links)} bağlantı", lang=lang),
            pick("Unauffällig", "Clean", "Temiz", lang=lang),
            "ok",
            False,
            pick(
                f"{len(links)} Links gefunden",
                f"{len(links)} links found",
                f"{len(links)} bağlantı bulundu",
                lang=lang,
            ),
        )
    elif incomplete:
        c3 = (
            c3_hdr,
            pick("Unvollständig", "Unchecked", "Taranamadı", lang=lang),
            pick("Prüfung lückenhaft", "Incomplete scan", "Eksik tarama", lang=lang),
            "warn",
            True,
            pick(
                "E-Mail-Prüfung war nicht vollständig — Links nicht abschließend geprüft",
                "Email scan incomplete — links not fully verified",
                "E-posta taraması tamamlanamadı — bağlantılar kesin doğrulanmadı",
                lang=lang,
            ),
        )
    else:
        c3 = (
            c3_hdr,
            pick("Keine Links", "No links", "Bağlantı yok", lang=lang),
            pick("Sauber", "Clean", "Temiz", lang=lang),
            "ok",
            False,
            pick("Keine Links im Text", "No links in message", "Mesajda bağlantı yok", lang=lang),
        )

    if incomplete and all(card[3] == "ok" for card in (c1, c2, c3)):
        c1 = (
            pick("Prüfung", "Inspection", "Tarama", lang=lang),
            pick("Unvollständig", "Unchecked", "Taranamadı", lang=lang),
            pick(
                "Mindestens eine Stufe fehlte",
                "At least one stage skipped",
                "En az bir aşama atlandı",
                lang=lang,
            ),
            "warn",
            True,
            pick(
                "E-Mail wurde nicht vollständig geprüft",
                "Email was not fully inspected",
                "E-posta tam olarak taranamadı",
                lang=lang,
            ),
        )

    return [c1, c2, c3]


class EngineStrip(QWidget):
    """3-card uniform Engine Summary row (alias: EngineCardsRow)."""

    chip_clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._last_result: ScanResult | None = None
        self.setObjectName("engineStrip")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        self._cards: list[EngineChip] = []
        for _ in range(3):
            card = EngineChip(self)
            card.clicked.connect(self.chip_clicked.emit)
            lay.addWidget(card, 1)
            self._cards.append(card)

        self.hide()

    @property
    def chips(self) -> list[EngineChip]:
        return list(self._cards)

    def retranslate(self) -> None:
        if self._last_result is not None:
            self.show_result(self._last_result)

    def show_result(self, result: ScanResult) -> None:
        self._last_result = result
        dt = (result.detected_type or "").lower()
        is_ooxml = dt == "zip" and is_ooxml_filename(result.display_name)
        if is_mail_result(result):
            specs = _cards_for_mail(result)
        elif not is_ooxml and (dt in ARCHIVE_TYPES or bool(result.children)):
            specs = _cards_for_archive(result)
        else:
            specs = _cards_for_leaf(result)

        for card, (name, val, sub, tone, ring, tip) in zip(self._cards, specs, strict=True):
            card.set_card(name, val, sub, tone=tone, ring=ring, tooltip=tip)
        self.show()

    def clear(self) -> None:
        self._last_result = None
        for card in self._cards:
            card.set_card("", "", "", tone="muted", ring=True)
        self.hide()


EngineCardsRow = EngineStrip
