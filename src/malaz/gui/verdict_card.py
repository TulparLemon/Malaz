"""Verdict Hero card for Malaz v11 ("Klare Fläche v2").

Displays one punchy headline + one direct action sentence on the left, paired
with the ``ScoreRingWidget`` on the right. Enforces the monotone completeness
invariant: a GREEN result with ``is_incomplete=True`` never renders green.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ..design_tokens import ARCHIVE_TYPES, MAIL_TYPES, visual_state
from ..models import RiskLevel, ScanResult
from .sanitize import (
    clip_text,
    escape_tooltip,
    indicator_weight,
    masked_widget_text,
    result_is_incomplete,
)
from .score_ring import ScoreRingWidget
from .theme import RISK_MARKS

# Preserved for backward-compatibility tests asserting mark consistency.
RISK_MARK = {level: RISK_MARKS[level.name.lower()] for level in RiskLevel}

_ENCRYPTED_RULES = frozenset({"ARCH_ENCRYPTED", "SEVENZIP_ENCRYPTED", "ZIP_ENCRYPTED", "PDF_ENCRYPTED"})


def _is_encrypted(result: ScanResult) -> bool:
    return any(i.rule_id in _ENCRYPTED_RULES for i in result.all_indicators())


def _build_verdict_copy(result: ScanResult, state: str) -> tuple[str, str]:
    """Return concise (headline, 1-line action summary) for the Verdict Hero."""
    dt = (result.detected_type or "").lower()
    is_mail = dt in MAIL_TYPES or bool(result.mail_security)
    is_archive = dt in ARCHIVE_TYPES or (bool(result.children) and not is_mail)
    encrypted = _is_encrypted(result)

    if state == "unk":
        if encrypted:
            return (
                "Ungeprüft — Passwortgeschützt",
                "Inhalt verschlüsselt · Nach dem Entpacken erneut prüfen.",
            )
        missing = [i.title for i in result.incomplete_stages[:2]]
        detail = (
            ", ".join(masked_widget_text(m) for m in missing)
            if missing
            else "Mindestens eine Prüfstufe lief nicht"
        )
        return (
            "Ungeprüft — Unvollständige Prüfung",
            clip_text(f"{detail} · Nicht als sicher einstufen.", 140),
        )

    if state == "bad":
        if is_mail:
            return (
                "Gefährlich — Schädliche E-Mail",
                "Nicht öffnen, keine Links klicken · E-Mail löschen oder IT melden.",
            )
        if is_archive and result.children:
            bad_kids = sum(
                1 for c in result.children if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"
            )
            if bad_kids:
                return (
                    "Gefährlich — Schädliche Datei im Archiv",
                    (
                        f"{bad_kids} von {len(result.children)} Dateien "
                        "im Archiv sind gefährlich · Nicht entpacken."
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
            reason = clip_text(masked_widget_text(top.title), 82)
            return ("Gefährlich — Nicht öffnen", f"{reason} · Löschen oder IT melden.")
        return ("Gefährlich — Nicht öffnen", "Schadsoftware erkannt · Löschen oder IT melden.")

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
            reason = clip_text(masked_widget_text(top.title), 88)
            return ("Verdächtig — Vorsicht beim Öffnen", f"{reason} · Nur bei bekanntem Absender öffnen.")
        return (
            "Verdächtig — Vorsicht beim Öffnen",
            "Auffälligkeiten erkannt · Im Zweifel beim Absender rückfragen.",
        )

    return (
        "Unauffällig — Sicher zu öffnen",
        "Alle Prüfer sauber · Keine schädlichen Inhalte oder Skripte erkannt.",
    )


class VerdictCard(QFrame):
    """v11 Verdict Hero card with concise headline, action summary, and ScoreRing."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
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

    def show_result(self, result: ScanResult) -> None:
        state = visual_state(result.risk_level, result_is_incomplete(result))
        headline, summary = _build_verdict_copy(result, state)

        self.setProperty("state", state)
        self._headline.setProperty("state", state)
        self._headline.setText(headline)
        self._advice.setText(summary)

        # Compatibility fields
        self._mark.setText(RISK_MARK.get(result.risk_level, "!"))
        score_text = f"Score {result.score}/100"
        if result.av_discount:
            score_text += f" (−{result.av_discount} AV-Abzug)"
        self._score.setText(score_text)

        tip_parts = [f"Risiko-Score: {result.score}/100"]
        if result.av_discount:
            tip_parts.append(f"AV-Entlastung: -{result.av_discount} Punkte")
        if result.is_incomplete:
            stages = ", ".join(i.rule_id for i in result.incomplete_stages[:4])
            tip_parts.append(f"Unvollständige Prüfstufen: {stages}")
        tooltip = escape_tooltip(" | ".join(tip_parts))
        self._score.setToolTip(tooltip)
        self._ring.set_score(result.score, state, tooltip=tooltip)

        self.style().unpolish(self)
        self.style().polish(self)
        self._headline.style().unpolish(self._headline)
        self._headline.style().polish(self._headline)
        self.show()

    def clear(self) -> None:
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
