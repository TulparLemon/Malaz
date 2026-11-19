"""Three uniform Engine Summary Cards for Malaz v11 ("Klare Fläche v2").

Displays 3 equal-width cards below the Verdict Hero:
- Leaf files: ``Windows Defender`` | ``ClamAV`` | ``Tiefenprüfung``
- Archives: ``Inhalt (N Dateien)`` | ``Archiv-Struktur`` | ``Schwerster Fund``
- E-Mails: ``Absender`` | ``Anhänge`` | ``Links im Text`` (surfacing any direct
  AV threat or failure on the .eml/.msg file itself so nothing is hidden!).

Preserves ``EngineChip``, ``EngineStrip`` alias, and ``compact_engine_text``
for full compatibility with existing tests and exports.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from ..design_tokens import ARCHIVE_TYPES, MAIL_TYPES, visual_state
from ..models import EngineVerdict, ScanResult
from .sanitize import (
    ENCRYPTED_RULES,
    clip_text,
    escape_tooltip,
    indicator_weight,
    is_encrypted,
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


_AV_ENGINE_NAMES = frozenset({"defender", "windows defender", "clamav"})


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
            tone = {"threat": "bad", "clean": "ok", "error": "warn", "skipped": "warn"}.get(
                verdict.state, "muted"
            )
            ring = verdict.state in ("skipped", "error", "off")
            self.set_card(
                verdict.engine,
                verdict.label or verdict.state,
                verdict.detail or verdict.label,
                tone=tone,
                ring=ring,
                tooltip=f"{verdict.engine}: {verdict.label} — {verdict.detail}",
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
    if encrypted and (verdict is None or verdict.state in ("skipped", "unavailable")):
        return (label, "Übersprungen", "Verschlüsselt", "warn", True, f"{label}: Passwortgeschützt")
    if verdict is None:
        return (label, "Nicht geprüft", "Kein Status", "warn", True, f"{label}: Nicht gelaufen")
    st = (verdict.state or "").lower()
    detail = masked_widget_text(verdict.detail or "")
    if st == "threat":
        val = clip_text(detail or "Bedrohung", 30)
        return (label, val, "Bedrohung erkannt", "bad", False, f"{label}: Bedrohung ({detail})")
    if st == "clean":
        return (label, "Kein Treffer", "Sauber", "ok", False, f"{label}: sauber")
    if st == "error":
        return (
            label,
            "Fehler",
            clip_text(detail or "Prüfung fehlgeschlagen", 40),
            "warn",
            True,
            f"{label}: Fehler ({detail})",
        )
    if st == "skipped":
        return (
            label,
            "Übersprungen",
            clip_text(detail or "Nicht gelaufen", 40),
            "warn",
            True,
            f"{label}: übersprungen ({detail})",
        )
    return (
        label,
        "Inaktiv",
        clip_text(detail or "Nicht verfügbar", 40),
        "warn",
        True,
        f"{label}: nicht verfügbar",
    )


def _cards_for_leaf(result: ScanResult) -> list[tuple[str, str, str, str, bool, str]]:
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

    if encrypted:
        deep = (
            "Tiefenprüfung",
            "Gesperrt",
            "Passwort nötig",
            "warn",
            True,
            "Tiefenprüfung: Inhalt verschlüsselt",
        )
    elif yara is not None and yara.state == "threat":
        cnt = max(1, len(yara_hits))
        top_title = masked_widget_text(yara_hits[0].title if yara_hits else yara.detail)
        deep = (
            "Tiefenprüfung",
            top_title or "YARA-Treffer",
            f"YARA: {cnt} Treffer",
            "bad",
            False,
            f"YARA: {cnt} Treffer",
        )
    elif static_hits:
        worst = max(static_hits, key=lambda x: (indicator_weight(x), int(x.severity)))
        tone = "bad" if indicator_weight(worst) >= 35 or result.risk_level.value >= 2 else "warn"
        sub = f"YARA: {len(yara_hits)} Treffer" if yara_hits else f"{len(static_hits)} Auffälligkeit(en)"
        deep = (
            "Tiefenprüfung",
            masked_widget_text(worst.title),
            sub,
            tone,
            False,
            worst.title,
        )
    elif result_is_incomplete(result):
        deep = (
            "Tiefenprüfung",
            "Unvollständig",
            "Stufe ausgelassen",
            "warn",
            True,
            "Mindestens eine Prüfphase fehlte",
        )
    else:
        sub = "YARA + Statik sauber" if (yara and yara.state == "clean") else "Statik sauber"
        deep = ("Tiefenprüfung", "Unauffällig", sub, "ok", False, "Tiefenprüfung ohne Befund")

    return [defender, clamav, deep]


def _cards_for_archive(result: ScanResult) -> list[tuple[str, str, str, str, bool, str]]:
    encrypted = is_encrypted(result)
    kids = result.children
    if encrypted and not kids:
        return _cards_for_leaf(result)

    bad_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"]
    warn_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) in ("warn", "unk")]
    bad_n = len(bad_kids)
    warn_n = len(warn_kids)
    ok_n = len(kids) - bad_n - warn_n

    if not kids:
        c1 = (
            "Inhalt (0 Dateien)",
            "Leeres Archiv",
            "Keine Einträge",
            "ok" if not result_is_incomplete(result) else "warn",
            result_is_incomplete(result),
            "Keine Dateien im Archiv",
        )
    elif bad_n:
        val_txt = (
            f"{bad_n} gefährlich · {warn_n} auffällig"
            if warn_n
            else f"{bad_n} gefährlich · {ok_n} sauber"
        )
        c1 = (
            f"Inhalt ({len(kids)} Dateien)",
            val_txt,
            masked_widget_text(bad_kids[0].display_name),
            "bad",
            False,
            "Schädliche Datei im Archiv",
        )
    elif warn_n:
        c1 = (
            f"Inhalt ({len(kids)} Dateien)",
            f"{warn_n} auffällig · {ok_n} sauber",
            "Prüfung empfohlen",
            "warn",
            False,
            "Auffällige Datei im Archiv",
        )
    else:
        c1 = (
            f"Inhalt ({len(kids)} Dateien)",
            f"{ok_n} sauber",
            "Alle Einträge geprüft",
            "ok",
            False,
            "Alle Dateien sauber",
        )

    arch_warns = [
        i
        for i in result.indicators
        if i.rule_id.startswith(("ARCH_", "ZIP_", "TAR_", "SEVENZIP_"))
        and (indicator_weight(i) > 0 or i.rule_id in ENCRYPTED_RULES)
    ]
    if arch_warns:
        c2 = (
            "Archiv-Struktur",
            masked_widget_text(arch_warns[0].title),
            "Auffällig",
            "warn",
            False,
            arch_warns[0].title,
        )
    elif result_is_incomplete(result):
        c2 = (
            "Archiv-Struktur",
            "Teilweise geprüft",
            "Limit oder Schutz",
            "warn",
            True,
            "Archiv nicht vollständig entpackt",
        )
    else:
        c2 = (
            "Archiv-Struktur",
            "Sicher entpackt",
            "Kein Pfadausbruch",
            "ok",
            False,
            "Keine Archiv-Bombe oder Zip-Slip",
        )

    # Worst finding across archive & children (includes direct AV hit on archive)
    all_ind = sorted(result.all_indicators(), key=lambda x: (-indicator_weight(x), -int(x.severity)))
    top = next((i for i in all_ind if indicator_weight(i) > 0), None)
    if top is not None:
        tone = "bad" if result.risk_level.value >= 2 or indicator_weight(top) >= 35 else "warn"
        c3 = (
            "Schwerster Fund",
            masked_widget_text(top.title),
            f"Score {result.score}",
            tone,
            False,
            top.title,
        )
    else:
        inc_arch = result_is_incomplete(result)
        c3 = (
            "Schwerster Fund",
            "Unvollständig" if inc_arch else "Kein Befund",
            "Prüfung lückenhaft" if inc_arch else "Sauber",
            "warn" if inc_arch else "ok",
            inc_arch,
            "Prüfung nicht vollständig" if inc_arch else "Keine Befunde",
        )
    return [c1, c2, c3]


def _cards_for_mail(result: ScanResult) -> list[tuple[str, str, str, str, bool, str]]:
    # Surface any direct AV threat or failure/skip on the .eml/.msg itself (real AV only, NOT Statisch)!
    av_verdicts = [
        v for v in result.engine_verdicts if (v.engine or "").strip().lower() in _AV_ENGINE_NAMES
    ]
    av_threat = next((v for v in av_verdicts if v.state == "threat"), None)
    av_gap = [v for v in av_verdicts if v.state in ("error", "skipped")]
    ms = result.mail_security or {}
    sender_st = ms.get("sender", "unknown")
    auth_fail = any(ms.get(k) == "fail" for k in ("spf", "dkim", "dmarc"))
    rids = {i.rule_id for i in result.indicators}
    sender_spoof = bool(
        rids & {"MAIL_DISPLAY_NAME_SPOOF", "MAIL_RETURN_PATH_MISMATCH", "MAIL_AUTH_FAIL"}
    )
    reply_mismatch = "MAIL_REPLY_TO_MISMATCH" in rids
    auth_unbacked = "MAIL_AUTH_CLAIM_UNBACKED" in rids
    incomplete = result_is_incomplete(result)

    if av_threat is not None:
        c1 = (
            f"Virenschutz ({av_threat.engine})",
            masked_widget_text(av_threat.detail or "Bedrohung"),
            "Direkter Treffer auf E-Mail",
            "bad",
            False,
            av_threat.detail or "AV-Treffer",
        )
    elif sender_st == "mismatch" or auth_fail or sender_spoof:
        if auth_fail or "MAIL_AUTH_FAIL" in rids:
            sub = "SPF/DMARC fehlgeschlagen"
        elif "MAIL_DISPLAY_NAME_SPOOF" in rids:
            sub = "Anzeigename täuscht Absender vor"
        else:
            sub = "Absender weicht ab"
        c1 = ("Absender", "Gefälscht", sub, "bad", False, sub)
    elif reply_mismatch:
        c1 = (
            "Absender",
            "Antwort weicht ab",
            "Reply-To != Absender",
            "warn",
            False,
            "Antwortadresse (Reply-To) weicht vom Absender ab",
        )
    elif auth_unbacked:
        c1 = (
            "Absender",
            "Nicht belegt",
            "Header ohne DNS-Nachweis",
            "warn",
            True,
            "Authentication-Results im Header sind unbestätigt",
        )
    elif av_gap:
        gap_names = ", ".join(v.engine for v in av_gap[:2])
        c1 = (
            f"Virenschutz ({gap_names})",
            "Unvollständig",
            "Prüfstufe ausgelassen/Fehler",
            "warn",
            True,
            f"Virenschutz auf E-Mail nicht vollständig gelaufen ({gap_names})",
        )
    elif sender_st == "ok":
        c1 = ("Absender", "Stimmig", "Keine Abweichung", "ok", False, "Absender konsistent")
    else:
        c1 = ("Absender", "Nicht prüfbar", "Kein Nachweis im Header", "warn", True, "SPF/DMARC nicht prüfbar")

    kids = result.children
    bad_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"]
    warn_kids = [c for c in kids if visual_state(c.risk_level, result_is_incomplete(c)) in ("warn", "unk")]
    if bad_kids:
        c2 = (
            "Anhänge",
            f"{len(bad_kids)} Schadprogramm",
            masked_widget_text(bad_kids[0].display_name),
            "bad",
            False,
            "Schädlicher Anhang",
        )
    elif warn_kids:
        c2 = (
            "Anhänge",
            f"{len(warn_kids)} auffällig",
            f"von {len(kids)} Anhang/Anhängen",
            "warn",
            False,
            "Auffälliger Anhang",
        )
    elif kids:
        c2 = ("Anhänge", f"{len(kids)} sauber", "Alle geprüft", "ok", False, "Anhänge unauffällig")
    elif incomplete:
        c2 = (
            "Anhänge",
            "Unvollständig",
            "Prüfung lückenhaft",
            "warn",
            True,
            "E-Mail-Prüfung war nicht vollständig — Anhänge nicht abschließend geprüft",
        )
    else:
        c2 = ("Anhänge", "Keine Anhänge", "Nur Nachricht", "ok", False, "Keine Anhänge")

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
            "Links im Text",
            f"{len(susp_links)} verdächtig",
            first_url,
            "warn",
            False,
            first_url,
        )
    elif links:
        c3 = (
            "Links im Text",
            f"{len(links)} Link(s)",
            "Unauffällig",
            "ok",
            False,
            f"{len(links)} Links gefunden",
        )
    elif incomplete:
        c3 = (
            "Links im Text",
            "Unvollständig",
            "Prüfung lückenhaft",
            "warn",
            True,
            "E-Mail-Prüfung war nicht vollständig — Links nicht abschließend geprüft",
        )
    else:
        c3 = ("Links im Text", "Keine Links", "Sauber", "ok", False, "Keine Links im Text")

    if incomplete and all(card[3] == "ok" for card in (c1, c2, c3)):
        c1 = (
            "Prüfung",
            "Unvollständig",
            "Mindestens eine Stufe fehlte",
            "warn",
            True,
            "E-Mail wurde nicht vollständig geprüft",
        )

    return [c1, c2, c3]


class EngineStrip(QWidget):
    """3-card uniform Engine Summary row (alias: EngineCardsRow)."""

    chip_clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
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

    def show_result(self, result: ScanResult) -> None:
        dt = (result.detected_type or "").lower()
        if dt in MAIL_TYPES or bool(result.mail_security):
            specs = _cards_for_mail(result)
        elif dt in ARCHIVE_TYPES or bool(result.children):
            specs = _cards_for_archive(result)
        else:
            specs = _cards_for_leaf(result)

        for card, (name, val, sub, tone, ring, tip) in zip(self._cards, specs, strict=True):
            card.set_card(name, val, sub, tone=tone, ring=ring, tooltip=tip)
        self.show()

    def clear(self) -> None:
        self.hide()


EngineCardsRow = EngineStrip
