"""Tests for the GUI theme (constants + apply_theme on a real application)."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication

from malaz.gui import theme


@pytest.fixture(scope="module")
def app():
    existing = QApplication.instance()
    if existing is not None:
        return existing
    return QApplication([])


def test_palette_constants_are_hex_colors():
    for name in ("WINDOW_BG", "PANEL_BG", "BORDER", "TEXT", "TEXT_SECONDARY",
                 "TEXT_DISABLED", "ACCENT"):
        value = getattr(theme, name)
        assert value.startswith("#") and len(value) == 7, (name, value)
        QColor(value)  # wirft bei ungueltiger Farbe


def test_risk_colors_complete():
    assert set(theme.RISK_COLORS) == {"green", "yellow", "red"}
    for color in theme.RISK_COLORS.values():
        QColor(color)


def test_apply_theme_sets_palette_and_stylesheet(app):
    theme.apply_theme(app)
    palette = app.palette()
    # Stichprobe: Fensterfarbe entspricht der Palette-Konstante (QColor.name()
    # liefert '#rrggbb', klein).
    assert palette.window().color().name().lower() == theme.WINDOW_BG.lower()
    assert app.styleSheet() == theme._QSS
    assert "QPushButton#primaryButton" in app.styleSheet()


def test_stylesheet_covers_core_widgets(app):
    qss = theme._QSS
    for selector in ("QTableWidget", "QListWidget", "QProgressBar", "QStatusBar",
                     "QMenu", "QToolTip", "QScrollBar"):
        assert selector in qss, selector
