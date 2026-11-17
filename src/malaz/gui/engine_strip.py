"""The per-result engine strip: what Defender, ClamAV and YARA actually said.

The verdict card answers "how dangerous is this file?". It deliberately does
not answer "which engine said what" — that was buried in the indicator list.
This strip puts the engine verdicts next to the score, with a word AND a
symbol AND a colour (never colour alone), and keeps "not checked" distinct
from "clean".
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QGridLayout, QPushButton, QWidget

from ..models import EngineVerdict
from ..security.escaping import escape_html

_STATE = {
    "threat": ("#f87171", "\u2716", "Bedrohung"),
    "clean": ("#4ade80", "\u2714", "sauber"),
    "skipped": ("#fbbf24", "\u26a0", "nicht geprüft"),
    "error": ("#fb923c", "!", "Fehler"),
    "off": ("#71767f", "\u2013", "nicht gelaufen"),
}


class EngineChip(QPushButton):
    """One engine: symbol + name + verdict word; tooltip carries the detail."""

    def __init__(self, verdict: EngineVerdict, parent: QWidget | None = None):
        super().__init__(parent)
        colour, symbol, default_label = _STATE.get(
            verdict.state, _STATE["off"]
        )
        self.setText(f"{symbol}  {verdict.engine}: {verdict.label or default_label}")
        self.setCursor(Qt.PointingHandCursor)
        self.setFlat(True)
        # Flat status text, not another box: the detail area already has a
        # verdict card, a tab pane and inner text views. Four bordered pills
        # were the visual clutter the user reported. The color + symbol still
        # carry the state; the tooltip carries the detail.
        self.setStyleSheet(
            "QPushButton {"
            f" color: {colour}; background: transparent; border: none;"
            " padding: 1px 2px; font-size: 11px; text-align: left; }"
            "QPushButton:hover { color: #ffffff; }"
        )
        detail = verdict.detail.strip()
        # Tooltips are Qt AutoText and can render HTML. The detail contains
        # engine output and attacker-controlled filenames, so escape it.
        tooltip = detail or f"{verdict.engine}: {verdict.label}"
        self.setToolTip(escape_html(tooltip))
        self.setAccessibleName(f"{verdict.engine}: {verdict.label}")


class EngineStrip(QFrame):
    """Horizontal row of engine chips; rebuilt for every selected result."""

    engine_clicked = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("engineStrip")
        self._layout = QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setHorizontalSpacing(8)
        self._layout.setVerticalSpacing(4)
        self._layout.setColumnStretch(0, 0)
        self.setVisible(False)

    def show_verdicts(self, verdicts: list[EngineVerdict]) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not verdicts:
            self.setVisible(False)
            return
        for index, verdict in enumerate(verdicts):
            chip = EngineChip(verdict, self)
            chip.clicked.connect(
                lambda _checked=False, name=verdict.engine: self.engine_clicked.emit(name)
            )
            # EINE Reihe, aber inhaltsbreit: der Chip bekommt keine
            # Stretch-Spalte, sonst zieht ihn Qt auf die volle Breite und das
            # Fenster waechst mit (gemessen 1736 px vor dieser Aenderung).
            # Die Chips stehen in den Spalten 0..n-1, die letzte Spalte
            # schluckt den Rest - so fuellt die Leiste das Fenster, ohne es
            # zu vergroessern.
            self._layout.addWidget(chip, 0, index)
        # Stretch nur auf der letzten (leeren) Spalte.
        self._layout.setColumnStretch(len(verdicts), 1)
        self.setVisible(True)

    def clear(self) -> None:
        self.show_verdicts([])


_SHORT = {"Defender": "D", "ClamAV": "C", "YARA": "Y", "Statisch": "S"}


def compact_engine_text(result) -> str:
    """Compact table cell, e.g. ``D✔ C⚠ Y✔`` — word remains in the tooltip."""
    parts = []
    for verdict in getattr(result, "engine_verdicts", []):
        short = _SHORT.get(verdict.engine)
        if short is None:
            continue
        _colour, symbol, _label = _STATE.get(verdict.state, _STATE["off"])
        parts.append(f"{short}{symbol}")
    return " ".join(parts)


def engine_tooltip(result) -> str:
    lines = []
    for verdict in getattr(result, "engine_verdicts", []):
        lines.append(f"{verdict.engine}: {verdict.label}")
        if verdict.detail:
            lines.append(f"  {verdict.detail.strip()}")
    # Same HTML sink as the chip tooltip.
    return escape_html("\n".join(lines))
