"""A compact batch summary above the result table.

After a folder scan the user needs one screen that answers: how many files,
how many are red/yellow, which rules dominate, and did the engines actually
run? The table alone answers none of these without counting rows.
"""

from __future__ import annotations

from collections import Counter

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from ..core.scoring import BASE_WEIGHTS
from ..models import RiskLevel, ScanResult
from .theme import SPACE_M, SPACE_S


class BatchSummary(QFrame):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("batchSummary")
        self.setVisible(False)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_M, SPACE_M, SPACE_M, SPACE_M)
        layout.setSpacing(SPACE_S)

        self.headline = QLabel()
        self.headline.setObjectName("batchHeadline")
        self.detail = QLabel()
        self.detail.setProperty("role", "secondary")
        self.detail.setWordWrap(True)
        layout.addWidget(self.headline)
        layout.addWidget(self.detail)

    def update_results(self, results: list[ScanResult]) -> None:
        if not results:
            self.setVisible(False)
            return
        counts = Counter(result.risk_level for result in results)
        # Ein Fehler ist ein NICHT geprueftes Ergebnis: nicht jede Fehlerquelle
        # setzt einen CORE_ERROR-Indikator (aeltere Worker-Pfade), der Zustand
        # "unvollstaendig" muss trotzdem stimmen.
        incomplete = sum(
            1 for result in results if result.is_incomplete or result.error
        )
        rules: Counter[str] = Counter()
        engines: Counter[str] = Counter()
        for result in results:
            # all_indicators() includes archive/mail children; count each
            # rule once per FILE so one file with 11 entropy findings does not
            # dominate the batch summary.
            counted: set[str] = set()
            for indicator in result.all_indicators():
                # Das GEWICHT kommt aus demselben Scoring wie die Einzelzeile:
                # `indicator.weight` ist bei den meisten Regeln None, und die
                # Punkte stammen dann aus der Severity (GEN_FORMAT_MISMATCH
                # z. B. 30). Die alte Pruefung warf genau diese Regeln weg
                # (BUG-060).
                if (
                    indicator.effective_weight(BASE_WEIGHTS) > 0
                    and indicator.rule_id not in counted
                ):
                    counted.add(indicator.rule_id)
                    rules[indicator.rule_id] += 1
            for verdict in result.engine_verdicts:
                if verdict.engine in ("Defender", "ClamAV", "YARA"):
                    engines[f"{verdict.engine}: {verdict.label}"] += 1
        worst = ", ".join(
            f"{rule} ({count})" for rule, count in rules.most_common(3)
        )
        engine_text = ", ".join(
            f"{label} ×{count}" for label, count in engines.most_common(3)
        )
        durations = sorted(result.duration_ms for result in results)
        p50 = durations[len(durations) // 2] if durations else 0
        self.headline.setText(
            f"{len(results)} Dateien · "
            f"{counts[RiskLevel.GREEN]} grün · "
            f"{counts[RiskLevel.YELLOW]} gelb · "
            f"{counts[RiskLevel.RED]} rot · "
            f"{incomplete} unvollständig"
        )
        parts = [f"p50 {p50} ms"]
        if worst:
            parts.append(f"Top-Regeln: {worst}")
        if engine_text:
            parts.append(f"Engines: {engine_text}")
        self.detail.setText(" · ".join(parts))
        self.setVisible(True)
