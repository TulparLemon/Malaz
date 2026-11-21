"""Verdict Hero card for Malaz v11 ("Klare Fläche v2").

Displays one punchy headline + one direct action sentence on the left, paired
with the ``ScoreRingWidget`` on the right. Enforces the monotone completeness
invariant: a GREEN result with ``is_incomplete=True`` never renders green.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ..design_tokens import ARCHIVE_TYPES, is_ooxml_filename, visual_state
from ..i18n import (
    get_language,
    localized_incomplete_reason,
    localized_indicator_title,
    pick,
    t,
)
from ..models import RiskLevel, ScanResult
from .sanitize import (
    clip_text,
    collect_incomplete_reasons,
    escape_tooltip,
    indicator_weight,
    is_encrypted,
    is_mail_result,
    masked_widget_text,
    result_is_incomplete,
)
from .score_ring import ScoreRingWidget
from .theme import RISK_MARKS

# Preserved for backward-compatibility tests asserting mark consistency.
RISK_MARK = {level: RISK_MARKS[level.name.lower()] for level in RiskLevel}


def _build_verdict_copy(result: ScanResult, state: str) -> tuple[str, str]:
    """Return concise (headline, 1-line action summary) for the Verdict Hero."""
    lang = get_language()
    dt = (result.detected_type or "").lower()
    is_mail = is_mail_result(result)
    is_ooxml = dt == "zip" and is_ooxml_filename(result.display_name)
    is_archive = dt in ARCHIVE_TYPES and not is_ooxml
    encrypted = is_encrypted(result)

    if state == "unk":
        if encrypted and not result.children:
            return (
                pick(
                    "Ungeprüft — Passwortgeschützt",
                    "Unchecked — Password-protected",
                    "Denetlenmedi — Parola korumalı",
                    lang=lang,
                ),
                pick(
                    "Inhalt verschlüsselt · Nach dem Entpacken erneut prüfen.",
                    "Contents are encrypted · Re-scan after extracting.",
                    "İçerik şifreli · Çıkardıktan sonra yeniden tarayın.",
                    lang=lang,
                ),
            )
        missing_raw = collect_incomplete_reasons(result, limit=2)
        missing = [localized_incomplete_reason(m, lang=lang) for m in missing_raw]
        detail = (
            ", ".join(missing)
            if missing
            else pick(
                "Mindestens eine Prüfstufe lief nicht",
                "At least one inspection stage did not run",
                "En az bir kontrol aşaması çalışmadı",
                lang=lang,
            )
        )
        return (
            pick(
                "Ungeprüft — Prüfung unvollständig",
                "Unchecked — Incomplete scan",
                "Denetlenmedi — Eksik tarama",
                lang=lang,
            ),
            clip_text(
                pick(
                    f"Nicht vollständig geprüft ({detail}) · Nicht als sicher einstufen.",
                    f"Not fully inspected ({detail}) · Do not treat as verified clean.",
                    f"Tam incelenemedi ({detail}) · Temiz kabul etmeyin.",
                    lang=lang,
                ),
                140,
            ),
        )

    if state == "bad":
        if is_mail:
            return (
                pick(
                    "Gefährlich — Schädliche E-Mail",
                    "Dangerous — Malicious Email",
                    "Tehlikeli — Zararlı E-posta",
                    lang=lang,
                ),
                pick(
                    "Nicht öffnen, keine Links klicken · E-Mail löschen oder IT melden.",
                    "Do not open or click any links · Delete email or report to IT.",
                    "Açmayın, bağlantılara tıklamayın · E-postayı silin veya BT ekibine bildirin.",
                    lang=lang,
                ),
            )
        if is_ooxml:
            return (
                pick(
                    "Gefährlich — Schädliches Office-Dokument",
                    "Dangerous — Malicious Office Document",
                    "Tehlikeli — Zararlı Office Belgesi",
                    lang=lang,
                ),
                pick(
                    "Aktive Makros oder schädliche Inhalte erkannt · Nicht öffnen.",
                    "Active macros or malicious content detected · Do not open.",
                    "Aktif makro veya zararlı içerik tespit edildi · Açmayın.",
                    lang=lang,
                ),
            )
        if is_archive and result.children:
            bad_kids = sum(
                1 for c in result.children if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"
            )
            if bad_kids:
                return (
                    pick(
                        "Gefährlich — Schädliche Datei im Archiv",
                        "Dangerous — Malicious File Inside Archive",
                        "Tehlikeli — Arşiv İçinde Zararlı Dosya",
                        lang=lang,
                    ),
                    pick(
                        f"{bad_kids} von {len(result.children)} Dateien im Archiv "
                        "sind gefährlich · Nicht entpacken.",
                        f"{bad_kids} of {len(result.children)} files in this archive "
                        "are dangerous · Do not extract.",
                        f"Arşivdeki {len(result.children)} dosyadan {bad_kids} tanesi "
                        "tehlikeli · Dışarı çıkarmayın.",
                        lang=lang,
                    ),
                )
        top = next(
            (
                i
                for i in sorted(
                    result.all_indicators(),
                    key=lambda x: (-indicator_weight(x), -int(x.severity)),
                )
                if indicator_weight(i) > 0
            ),
            None,
        )
        if top is not None:
            reason = clip_text(masked_widget_text(localized_indicator_title(top, lang=lang)), 82)
            return (
                t("verdict.bad.headline", lang=lang),
                t("verdict.bad.reason_summary", lang=lang, reason=reason),
            )
        return (
            t("verdict.bad.headline", lang=lang),
            t("verdict.bad.default_summary", lang=lang),
        )

    if state == "warn":
        top = next(
            (
                i
                for i in sorted(
                    result.all_indicators(),
                    key=lambda x: (-indicator_weight(x), -int(x.severity)),
                )
                if indicator_weight(i) > 0
            ),
            None,
        )
        if top is not None:
            reason = clip_text(masked_widget_text(localized_indicator_title(top, lang=lang)), 88)
            return (
                t("verdict.warn.headline", lang=lang),
                t("verdict.warn.reason_summary", lang=lang, reason=reason),
            )
        return (
            t("verdict.warn.headline", lang=lang),
            t("verdict.warn.default_summary", lang=lang),
        )

    return (
        t("verdict.ok.headline", lang=lang),
        t("verdict.ok.default_summary", lang=lang),
    )


class VerdictCard(QFrame):
    """v11 Verdict Hero card with concise headline, action summary, and ScoreRing."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._last_result: ScanResult | None = None
        self.setObjectName("verdictCard")
        self.setFrameShape(QFrame.Shape.NoFrame)

        root = QHBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(20)

        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(4)

        self._headline = QLabel(self)
        self._headline.setObjectName("verdictHeadline")
        self._headline.setTextFormat(Qt.TextFormat.PlainText)
        self._headline.setWordWrap(True)
        left.addWidget(self._headline)

        self._advice = QLabel(self)
        self._advice.setObjectName("verdictAdvice")
        self._advice.setTextFormat(Qt.TextFormat.PlainText)
        self._advice.setWordWrap(True)
        left.addWidget(self._advice)

        root.addLayout(left, 1)

        self._ring = ScoreRingWidget(self)
        root.addWidget(self._ring, 0, Qt.AlignmentFlag.AlignVCenter)

        # Compatibility label aliases for tests inspecting card text.
        self._word = self._headline
        self.headline = self._headline
        self.advice = self._advice
        self._mark = QLabel(self)
        self._mark.hide()
        self.mark = self._mark
        self._score = QLabel(self)
        self._score.hide()
        self.score = self._score

        self.clear()

    def retranslate(self) -> None:
        if self._last_result is not None:
            self.show_result(self._last_result)
        else:
            self._ring.retranslate()

    def show_result(self, result: ScanResult) -> None:
        self._last_result = result
        state = visual_state(result.risk_level, result_is_incomplete(result))
        headline, summary = _build_verdict_copy(result, state)

        self.setProperty("state", state)
        self._headline.setProperty("state", state)
        self._headline.setText(headline)
        self._advice.setText(summary)

        # Compatibility fields
        self._mark.setText(RISK_MARK.get(result.risk_level, "!"))
        score_text = t("verdict.score_fmt", score=result.score)
        if result.av_discount:
            score_text += t("verdict.score_discount", discount=result.av_discount)
        self._score.setText(score_text)

        tip_parts = [t("verdict.tip_score", score=result.score)]
        if result.av_discount:
            tip_parts.append(t("verdict.tip_discount", discount=result.av_discount))
        if result.is_incomplete:
            stages = ", ".join(i.rule_id for i in result.incomplete_stages[:4])
            tip_parts.append(t("verdict.tip_incomplete", stages=stages))
        tooltip = escape_tooltip(" | ".join(tip_parts))
        self._score.setToolTip(tooltip)
        self._ring.set_score(result.score, state, tooltip=tooltip)

        self.style().unpolish(self)
        self.style().polish(self)
        self._headline.style().unpolish(self._headline)
        self._headline.style().polish(self._headline)
        self.show()

    def clear(self) -> None:
        self._last_result = None
        self.setProperty("state", "")
        self._headline.setProperty("state", "")
        self._headline.setText("")
        self._advice.setText("")
        self._mark.setText("")
        self._score.setText("")
        self._score.setToolTip("")
        self._ring.clear()
        self.style().unpolish(self)
        self.style().polish(self)
        self.hide()
