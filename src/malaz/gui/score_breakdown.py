"""Explain the score: which findings contributed how many points.

The verdict card shows a number, the finding list shows prose. Neither answers
"why 45 and not 20?" at a glance. This tab shows the weighted contributions
in descending order, plus the AV discount, the green floor, the critical
anchor and the cap — each step only when it changes the number, so the
displayed arithmetic ends at the score the card shows.
"""

from __future__ import annotations

from PySide6.QtWidgets import QTextEdit, QWidget

from .. import config
from ..core.scoring import BASE_WEIGHTS, compute_score
from ..models import Indicator, ScanResult
from ..security.escaping import mask_invisible


class ScoreBreakdown(QTextEdit):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("scoreBreakdown")
        self.setReadOnly(True)
        self.setPlaceholderText(
            "Wählen Sie eine Zeile aus, um die Score-Zerlegung zu sehen."
        )

    def show_result(self, result: ScanResult) -> None:
        # The score is computed from all_indicators() (result + children).
        # Reading only result.indicators showed "Keine scorewirksamen
        # Befunde" next to a red archive whose malicious member carried the
        # score. Use the same source as the scoring engine.
        breakdown = compute_score(result.all_indicators())

        # EIN MERKMAL, EINE WERTUNG — dieselbe Regel wie in compute_score:
        # je rule_id zaehlt der hoechste Einzelwert, nicht die Summe der
        # Vorkommen. Vorher addierte der Reiter jeden Indikator: drei
        # GEN_IOC-Befunde ergaben "15" neben einem Score von 5. Die Anzahl
        # der Vorkommen bleibt sichtbar ("3x gefunden"), sie geht nur nicht
        # mehr in die Rechnung ein.
        hoechste: dict[str, tuple[int, Indicator, int]] = {}
        for indicator in result.all_indicators():
            weight = indicator.effective_weight(BASE_WEIGHTS)
            if weight <= 0:
                continue
            vorher = hoechste.get(indicator.rule_id)
            if vorher is None:
                hoechste[indicator.rule_id] = (weight, indicator, 1)
            else:
                hoechste[indicator.rule_id] = (
                    max(weight, vorher[0]),
                    indicator if weight > vorher[0] else vorher[1],
                    vorher[2] + 1,
                )
        contributions = sorted(
            hoechste.values(), key=lambda item: item[0], reverse=True
        )

        lines = [
            f"Score: {result.score}/100  ·  {result.risk_level.short}",
            "",
        ]
        if not contributions:
            lines.append("Keine scorewirksamen Befunde.")
        else:
            lines.append(
                f"Rohpunkte: {breakdown.raw}"
                "  (je Regel zählt der höchste Wert)"
            )
            for weight, indicator, count in contributions:
                bar = "█" * min(20, max(1, round(weight / 2.5)))
                mehrfach = f"  ({count}× gefunden)" if count > 1 else ""
                lines.append(
                    f"{weight:3d}  {bar}  {indicator.rule_id} — "
                    f"{indicator.title}{mehrfach}"
                )

        # Die Rechenschritte: Rohpunkte, Rabatt, Gruen-Untergrenze, Anker,
        # Kappung. Jeder Schritt steht nur da, wenn er den Wert aendert —
        # eine Zeile "-0 Rabatt" waere Rauschen, und eine fehlende Zeile
        # liesse 25 - 8 = 20 wie einen Rechenfehler aussehen.
        lines.append("")
        lines.append(f"= Rohpunkte {breakdown.raw}/100")
        lauf = max(0, breakdown.raw - breakdown.discount)
        if breakdown.discount:
            lines.append(
                f"−{breakdown.discount}  AV-ohne-Fund-Rabatt "
                "(saubere Engine-Stimmen)"
            )
            lines.append(f"= {lauf}/100")
        if breakdown.raw > config.SCORE_GREEN_MAX and lauf <= config.SCORE_GREEN_MAX:
            lauf = config.SCORE_GREEN_MAX + 1
            lines.append(
                f"Grün-Untergrenze: mindestens {lauf}/100 — ein sauberer "
                "Engine-Befund darf ein Urteil nicht hochstufen"
            )
        if breakdown.anchored and lauf < config.ANCHOR_CRITICAL_SCORE:
            lauf = config.ANCHOR_CRITICAL_SCORE
            lines.append(
                f"Anker: ein kritischer Befund erzwingt mindestens {lauf}/100."
            )
        if lauf > config.SCORE_CAP:
            lauf = config.SCORE_CAP
            lines.append(f"Kappung: höchstens {config.SCORE_CAP}/100.")
        lines.append(f"= {breakdown.score}/100")
        if result.score != breakdown.score:
            # Handgebaute Ergebnisse (Tests, kuenftige Aufrufer) koennen einen
            # anderen Wert tragen. Beide Zahlen nennen statt eine Rechnung
            # zeigen, die nicht zum sichtbaren Score fuehrt.
            lines.append(
                f"Angezeigter Score: {result.score}/100 "
                "(berechneter Wert weicht ab)."
            )
        if result.is_incomplete:
            lines.append("")
            lines.append(f"⚠ {result.incompleteness_note()}")
        self.setPlainText(mask_invisible("\n".join(lines)))
