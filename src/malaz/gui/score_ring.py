"""Custom QPainter widgets for Malaz v11 ("Klare Fläche v2").

Contains:
- ``StatusDotWidget``: crisp circular status dot (solid or hollow ring).
- ``ScoreRingWidget``: 54x54 smooth anti-aliased risk ring + Risiko label +
  3-zone threshold bar (0-19 | 20-49 | 50-100). Displays ``—`` ONLY when
  ``visual_state == "unk"`` (GREEN + incomplete or unknown).
- ``ToggleSwitch``: QCheckBox subclass painted as a sleek modern pill switch.

All colours are read live from ``theme.current_palette()`` so theme changes
repaint immediately with zero hardcoded hex values.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QCheckBox, QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from .theme import current_palette


class StatusDotWidget(QWidget):
    """Crisp circular status dot (solid circle or hollow ring)."""

    def __init__(
        self,
        tone: str = "ok",
        *,
        ring: bool = False,
        diameter: int = 8,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._tone = tone
        self._ring = ring
        self._diameter = diameter
        self.setFixedSize(diameter + 4, diameter + 4)

    def set_state(self, tone: str, *, ring: bool = False) -> None:
        self._tone = tone
        self._ring = ring
        self.update()

    def _color(self) -> QColor:
        p = current_palette()
        mapping = {
            "bad": p["st_bad"],
            "warn": p["st_warn"],
            "unk": p["st_warn"],
            "ok": p["st_ok"],
            "info": p["st_info"],
            "scanning": p["st_info"],
            "muted": p["ink_3"],
            "pending": p["ink_3"],
            "cancelled": p["st_warn"],
        }
        return QColor(mapping.get(self._tone, p["ink_3"]))

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        col = self._color()
        d = float(self._diameter)
        x = (self.width() - d) / 2.0
        y = (self.height() - d) / 2.0
        if self._ring:
            pen = QPen(col, 1.7)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QRectF(x + 0.5, y + 0.5, d - 1.0, d - 1.0))
        else:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(col))
            painter.drawEllipse(QRectF(x, y, d, d))


class _RingGauge(QWidget):
    """54x54 circular arc + centered score readout."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: int = 0
        self._state: str = "ok"
        self.setFixedSize(56, 56)

    def set_data(self, score: int, state: str) -> None:
        self._score = max(0, min(100, int(score)))
        self._state = state
        self.update()

    def paintEvent(self, _event) -> None:
        p = current_palette()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        state_col = {
            "bad": p["st_bad"],
            "warn": p["st_warn"],
            "unk": p["st_warn"],
            "ok": p["st_ok"],
        }.get(self._state, p["st_warn"])

        rect = QRectF(5.0, 5.0, 46.0, 46.0)
        track_pen = QPen(QColor(p["track_bg"]), 4.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, 0, 360 * 16)

        pct = 25 if self._state == "unk" else max(4, self._score)
        span_angle = -int((pct / 100.0) * 360 * 16)
        arc_pen = QPen(QColor(state_col), 4.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(arc_pen)
        painter.drawArc(rect, 90 * 16, span_angle)

        # Center score number ("—" ONLY when visual_state == "unk")
        num_text = "—" if self._state == "unk" else str(self._score)
        f_num = QFont(self.font())
        f_num.setPixelSize(15)
        f_num.setWeight(QFont.Weight.Bold)
        painter.setFont(f_num)
        painter.setPen(QColor(p["ink_1"]))
        painter.drawText(QRectF(0, 12, 56, 18), Qt.AlignmentFlag.AlignCenter, num_text)

        f_sub = QFont(self.font())
        f_sub.setPixelSize(9)
        f_sub.setWeight(QFont.Weight.Normal)
        painter.setFont(f_sub)
        painter.setPen(QColor(p["ink_3"]))
        painter.drawText(QRectF(0, 31, 56, 13), Qt.AlignmentFlag.AlignCenter, "/ 100")


class _ThresholdBar(QWidget):
    """Three-segment risk threshold bar (0-19 | 20-49 | 50-100)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: int = 0
        self._state: str = "ok"
        self.setFixedSize(116, 6)

    def set_data(self, score: int, state: str) -> None:
        self._score = max(0, min(100, int(score)))
        self._state = state
        self.update()

    def paintEvent(self, _event) -> None:
        p = current_palette()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)

        gap = 3.0
        total = float(self.width()) - 2.0 * gap
        w1 = total * 0.20
        w2 = total * 0.30
        w3 = total * 0.50

        c1 = p["st_ok"] if self._state == "ok" else p["track_bg"]
        c2 = p["st_warn"] if self._state in ("warn", "unk") else p["track_bg"]
        c3 = p["st_bad"] if self._state == "bad" else p["track_bg"]

        for x, w, col in ((0.0, w1, c1), (w1 + gap, w2, c2), (w1 + w2 + 2 * gap, w3, c3)):
            painter.setBrush(QColor(col))
            painter.drawRoundedRect(QRectF(x, 1.0, w, 4.0), 2.0, 2.0)


class ScoreRingWidget(QFrame):
    """Right-hand score instrument inside the Verdict Hero card."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("scoreInstrument")
        self._state = "ok"
        self._score = 0

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 0, 0)
        layout.setSpacing(14)

        self._gauge = _RingGauge(self)
        layout.addWidget(self._gauge)

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(2)

        lbl_cap = QLabel("Risiko", self)
        lbl_cap.setObjectName("mutedLabel")
        lbl_cap.setTextFormat(Qt.TextFormat.PlainText)
        right.addWidget(lbl_cap)

        self._level_lbl = QLabel("Niedrig", self)
        self._level_lbl.setObjectName("engineVal")
        self._level_lbl.setTextFormat(Qt.TextFormat.PlainText)
        right.addWidget(self._level_lbl)

        right.addSpacing(4)
        self._bar = _ThresholdBar(self)
        right.addWidget(self._bar)
        layout.addLayout(right)

    def set_score(self, score: int, state: str, *, tooltip: str = "") -> None:
        self._score = max(0, min(100, int(score)))
        self._state = state
        self._gauge.set_data(self._score, state)
        self._bar.set_data(self._score, state)

        word_map = {
            "bad": ("Hoch", "bad"),
            "warn": ("Mittel", "warn"),
            "unk": ("Ungeprüft", "warn"),
            "ok": ("Niedrig", "ok"),
        }
        word, tone = word_map.get(state, ("Ungeprüft", "warn"))
        self._level_lbl.setText(word)
        self._level_lbl.setProperty("tone", tone)
        self._level_lbl.style().unpolish(self._level_lbl)
        self._level_lbl.style().polish(self._level_lbl)
        self.setToolTip(tooltip)
        self.update()

    def clear(self) -> None:
        self.setToolTip("")
        self._gauge.set_data(0, "ok")
        self._bar.set_data(0, "ok")
        self._level_lbl.setText("—")


class ToggleSwitch(QCheckBox):
    """QCheckBox rendered as a sleek modern 38x21 pill toggle switch.

    Preserves 100% QCheckBox API (``isChecked``, ``setChecked``, ``toggled``,
    keyboard Space, accessibility) so existing settings & tests work seamlessly.
    """

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(38, 22)

    def sizeHint(self) -> QSize:
        return QSize(38, 22)

    def hitButton(self, pos) -> bool:
        return self.rect().contains(pos)

    def paintEvent(self, _event) -> None:
        p = current_palette()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        checked = self.isChecked()
        enabled = self.isEnabled()

        if not enabled:
            track_col = QColor(p["border_subtle"])
            border_col = QColor(p["border_subtle"])
            knob_col = QColor(p["ink_3"])
        elif checked:
            track_col = QColor(p["st_ok_badge"])
            border_col = QColor(p["st_ok_line"])
            knob_col = QColor(p["st_ok"])
        else:
            track_col = QColor(p["track_bg"])
            border_col = QColor(p["border_default"])
            knob_col = QColor(p["ink_2"])

        if self.hasFocus():
            border_col = QColor(p["st_info"])

        painter.setPen(QPen(border_col, 1.2))
        painter.setBrush(QBrush(track_col))
        painter.drawRoundedRect(QRectF(0.6, 0.6, 36.8, 20.8), 10.4, 10.4)

        knob_x = 19.0 if checked else 3.0
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(knob_col))
        painter.drawEllipse(QRectF(knob_x, 3.0, 16.0, 16.0))
