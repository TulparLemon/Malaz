"""Token-driven PySide6 theme & stylesheet builder for Malaz ("Klare Fläche v2").

All colours originate exclusively from ``malaz.design_tokens`` (zero literal
hex values in this module or anywhere under ``src/malaz/gui/``).
Supports ``"dark"`` (default), ``"light"``, and ``"system"`` modes, persisted
in ``QSettings("ui/theme")``, with live repaint broadcast for custom QPainter
widgets.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication, QStyle, QStyledItemDelegate

from ..design_tokens import PALETTE_DARK, palette_for
from .settings import app_settings

# -- Backward-compatible constants (resolved from PALETTE_DARK) ------------ #

WINDOW_BG = PALETTE_DARK["canvas"]
PANEL_BG = PALETTE_DARK["surface"]
BORDER = PALETTE_DARK["border_default"]
TEXT = PALETTE_DARK["ink_1"]
TEXT_SECONDARY = PALETTE_DARK["ink_2"]
TEXT_DISABLED = PALETTE_DARK["ink_3"]
ACCENT = PALETTE_DARK["st_info"]
ACCENT_HOVER = PALETTE_DARK["row_active_line"]
ACCENT_PRESSED = PALETTE_DARK["st_info_line"]

RISK_COLORS: dict[str, str] = {
    "green": PALETTE_DARK["st_ok"],
    "yellow": PALETTE_DARK["st_warn"],
    "red": PALETTE_DARK["st_bad"],
}

RISK_MARKS: dict[str, str] = {
    "green": "✓",
    "yellow": "!",
    "red": "✖",
}

FONT_TITLE = "20px"
FONT_SUBTITLE = "15px"
FONT_BODY = "13px"
FONT_MONO = "12px"
FONT_MARK = "16px"

SPACE_S = 8
SPACE_M = 12
SPACE_L = 16

_THEME_KEY = "ui/theme"
_ACTIVE_MODE: str = "dark"
_ACTIVE_PREF: str = "dark"
_LISTENERS: list[Callable[[str, dict[str, str]], None]] = []
_QSS: str = ""


def resolve_theme_mode(mode: str | None = None) -> str:
    """Resolve ``dark | light | system`` to concrete ``dark`` or ``light``."""
    pref = (mode or app_settings().value(_THEME_KEY, "dark", str) or "dark").strip().lower()
    if pref == "light":
        return "light"
    if pref == "system":
        with suppress(Exception):
            hints = QGuiApplication.styleHints()
            if hints is not None and hints.colorScheme() == Qt.ColorScheme.Light:
                return "light"
        return "dark"
    return "dark"


def saved_theme_preference() -> str:
    """Return persisted preference (``dark | light | system``)."""
    val = str(app_settings().value(_THEME_KEY, "dark", str) or "dark").strip().lower()
    return val if val in ("dark", "light", "system") else "dark"


def current_theme_mode() -> str:
    """Return currently active resolved mode (``dark`` or ``light``)."""
    return _ACTIVE_MODE


def current_palette() -> dict[str, str]:
    """Return the active colour token dictionary."""
    return palette_for(_ACTIVE_MODE)


def register_theme_listener(callback: Callable[[str, dict[str, str]], None]) -> None:
    """Register a callback invoked whenever ``apply_theme`` switches palettes."""
    if callback not in _LISTENERS:
        _LISTENERS.append(callback)


def unregister_theme_listener(callback: Callable[[str, dict[str, str]], None]) -> None:
    with suppress(ValueError):
        _LISTENERS.remove(callback)


def risk_tint(color_hex: str, *, mode: str | None = None) -> QColor:
    """Blend a semantic state colour softly onto the active surface."""
    p = palette_for(mode or _ACTIVE_MODE)
    base = QColor(p["surface"])
    accent = QColor(color_hex)
    alpha = 0.14 if (mode or _ACTIVE_MODE) == "dark" else 0.08
    r = int(base.red() * (1 - alpha) + accent.red() * alpha)
    g = int(base.green() * (1 - alpha) + accent.green() * alpha)
    b = int(base.blue() * (1 - alpha) + accent.blue() * alpha)
    return QColor(r, g, b)


class RiskTintDelegate(QStyledItemDelegate):
    """Compatibility delegate painting a soft background tint without losing focus."""

    def paint(self, painter, option, index) -> None:
        if option.state & QStyle.StateFlag.State_Selected:
            super().paint(painter, option, index)
            return
        tint = index.data(Qt.ItemDataRole.BackgroundRole)
        if isinstance(tint, QColor) and tint.isValid():
            painter.save()
            painter.fillRect(option.rect, tint)
            painter.restore()
        super().paint(painter, option, index)


def build_stylesheet(mode: str = "dark") -> str:
    """Build the complete application QSS from design tokens (zero duplicate selectors)."""
    p = palette_for(mode)
    return f"""
QWidget {{
    color: {p["ink_1"]};
    font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
    font-size: 13px;
}}

QMainWindow, QDialog, QWidget#appRoot {{
    background-color: {p["canvas"]};
}}

QMenuBar {{
    background-color: {p["sidebar"]};
    color: {p["ink_2"]};
    border-bottom: 1px solid {p["border_subtle"]};
    padding: 2px 8px;
    font-size: 12px;
}}
QMenuBar::item {{
    padding: 4px 10px;
    border-radius: 4px;
    background: transparent;
}}
QMenuBar::item:selected {{
    background-color: {p["row_hover"]};
    color: {p["ink_1"]};
}}

QMenu {{
    background-color: {p["surface"]};
    color: {p["ink_1"]};
    border: 1px solid {p["border_default"]};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 20px 6px 12px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background-color: {p["row_active"]};
    color: {p["ink_1"]};
}}
QMenu::separator {{
    height: 1px;
    background-color: {p["border_subtle"]};
    margin: 4px 8px;
}}

QFrame#topBar {{
    background-color: {p["sidebar"]};
    border-bottom: 1px solid {p["border_subtle"]};
}}

QFrame#sidebar {{
    background-color: {p["sidebar"]};
}}

QFrame#sidebarHeader {{
    background-color: {p["sidebar"]};
    border-bottom: 1px solid {p["border_subtle"]};
}}

QFrame#sidebarFooter, QFrame#rightFooter {{
    background-color: {p["sidebar"]};
    border-top: 1px solid {p["border_subtle"]};
}}

QSplitter::handle {{
    background-color: {p["border_subtle"]};
    width: 1px;
}}
QSplitter::handle:hover {{
    background-color: {p["border_strong"]};
}}

QPushButton {{
    background-color: {p["surface"]};
    color: {p["ink_1"]};
    border: 1px solid {p["border_default"]};
    border-radius: 6px;
    padding: 4px 11px;
    min-height: 22px;
    font-size: 12px;
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {p["elevated"]};
    border-color: {p["border_strong"]};
}}
QPushButton:pressed {{
    background-color: {p["row_active"]};
}}
QPushButton:disabled {{
    color: {p["ink_3"]};
    border-color: {p["border_subtle"]};
    background-color: {p["sidebar"]};
}}
QPushButton:focus {{
    border: 1.5px solid {p["st_info"]};
}}

QPushButton#primaryButton {{
    background-color: {p["cta_bg"]};
    color: {p["cta_ink"]};
    border: 1px solid {p["cta_bg"]};
    font-weight: 600;
    font-size: 12px;
    min-height: 24px;
}}
QPushButton#primaryButton:hover {{
    border-color: {p["st_info"]};
}}
QPushButton#primaryButton:disabled {{
    background-color: {p["elevated"]};
    color: {p["ink_3"]};
    border-color: {p["border_subtle"]};
}}

QPushButton#dangerButton {{
    background-color: {p["st_bad_soft"]};
    color: {p["st_bad"]};
    border: 1px solid {p["st_bad_line"]};
    font-weight: 600;
    min-height: 24px;
}}
QPushButton#dangerButton:hover {{
    background-color: {p["st_bad_badge"]};
}}

QFrame#statusCapsule {{
    background-color: {p["surface"]};
    color: {p["ink_2"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 6px;
    padding: 3px 11px;
    min-height: 22px;
    font-size: 12px;
}}
QFrame#statusCapsule:hover {{
    border-color: {p["border_default"]};
    color: {p["ink_1"]};
}}
QFrame#statusCapsule[active="true"] {{
    background-color: {p["row_active"]};
    border-color: {p["row_active_line"]};
    color: {p["ink_1"]};
}}

QFrame#filterChip {{
    background-color: {p["surface"]};
    color: {p["ink_2"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 5px;
    padding: 2px 4px;
    min-height: 20px;
    font-size: 11px;
    font-weight: 500;
}}
QFrame#filterChip:hover {{
    background-color: {p["row_hover"]};
    color: {p["ink_1"]};
}}
QFrame#filterChip[checked="true"] {{
    background-color: {p["elevated"]};
    border-color: {p["border_strong"]};
    color: {p["ink_1"]};
    font-weight: 600;
}}

QFrame#summaryBar {{
    background-color: {p["surface"]};
    color: {p["ink_2"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 6px;
    padding: 5px 10px;
    text-align: left;
    font-size: 12px;
}}
QFrame#summaryBar:hover {{
    border-color: {p["border_default"]};
    color: {p["ink_1"]};
}}
QFrame#summaryBar[selected="true"] {{
    background-color: {p["row_active"]};
    border-color: {p["row_active_line"]};
    color: {p["ink_1"]};
    font-weight: 600;
}}

QPushButton#hashPill {{
    background-color: {p["surface"]};
    color: {p["ink_2"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 6px;
    padding: 3px 10px;
    min-height: 22px;
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 11px;
}}
QPushButton#hashPill:hover {{
    border-color: {p["border_default"]};
    color: {p["ink_1"]};
}}

QPushButton#copyButton {{
    background-color: {p["canvas"]};
    color: {p["ink_2"]};
    border: 1px solid {p["border_default"]};
    border-radius: 5px;
    padding: 2px 8px;
    min-width: 84px;
    min-height: 22px;
    font-size: 11px;
    font-weight: 500;
}}
QPushButton#copyButton:hover {{
    color: {p["ink_1"]};
    border-color: {p["border_strong"]};
}}

QPushButton#tabButton {{
    background: transparent;
    color: {p["ink_2"]};
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0px;
    padding: 6px 2px 8px 2px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton#tabButton:hover {{
    color: {p["ink_1"]};
}}
QPushButton#tabButton:checked {{
    color: {p["ink_1"]};
    border-bottom: 2px solid {p["ink_1"]};
    font-weight: 600;
}}

QPushButton#breadcrumbLink {{
    background-color: {p["surface"]};
    color: {p["ink_2"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 4px;
    padding: 1px 6px;
    min-height: 18px;
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 11px;
}}
QPushButton#breadcrumbLink:hover {{
    color: {p["ink_1"]};
    border-color: {p["border_default"]};
}}

QLineEdit, QComboBox {{
    background-color: {p["canvas"]};
    color: {p["ink_1"]};
    border: 1px solid {p["border_default"]};
    border-radius: 6px;
    padding: 4px 8px;
    min-height: 22px;
    font-size: 12px;
}}
QLineEdit:focus, QComboBox:focus {{
    border-color: {p["st_info"]};
}}
QComboBox::drop-down {{
    border: none;
    width: 18px;
}}
QComboBox QAbstractItemView {{
    background-color: {p["surface"]};
    color: {p["ink_1"]};
    border: 1px solid {p["border_default"]};
    selection-background-color: {p["row_active"]};
}}

QTreeWidget, QTableWidget, QListWidget {{
    background-color: {p["sidebar"]};
    color: {p["ink_1"]};
    border: none;
    outline: 0;
}}
QTreeWidget::item:hover, QListWidget::item:hover {{
    background-color: {p["row_hover"]};
}}
QTreeWidget::item:selected, QListWidget::item:selected {{
    background-color: {p["row_active"]};
    color: {p["ink_1"]};
}}

QFrame#card, QFrame#engineCard, QFrame#scanBanner {{
    background-color: {p["surface"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 8px;
}}
QFrame#scanBanner {{
    border-color: {p["st_info_line"]};
}}
QFrame#dropZone {{
    background-color: {p["surface"]};
    border: 1.5px dashed {p["border_default"]};
    border-radius: 12px;
}}
QFrame#tabBarRow {{
    border-bottom: 1px solid {p["border_subtle"]};
}}

QFrame#verdictCard {{
    background-color: {p["surface"]};
    border: 1px solid {p["border_default"]};
    border-radius: 10px;
}}
QFrame#verdictCard[state="bad"] {{
    background-color: {p["st_bad_soft"]};
    border-color: {p["st_bad_line"]};
}}
QFrame#verdictCard[state="warn"], QFrame#verdictCard[state="unk"] {{
    background-color: {p["st_warn_soft"]};
    border-color: {p["st_warn_line"]};
}}
QFrame#verdictCard[state="ok"] {{
    background-color: {p["st_ok_soft"]};
    border-color: {p["st_ok_line"]};
}}

QFrame#kpiCard {{
    background-color: {p["surface"]};
    border: 1px solid {p["border_default"]};
    border-radius: 8px;
}}
QFrame#kpiCard[state="bad"] {{
    background-color: {p["st_bad_soft"]};
    border-color: {p["st_bad_line"]};
}}
QFrame#kpiCard[state="warn"] {{
    background-color: {p["st_warn_soft"]};
    border-color: {p["st_warn_line"]};
}}
QFrame#kpiCard[state="ok"] {{
    background-color: {p["st_ok_soft"]};
    border-color: {p["st_ok_line"]};
}}

QFrame#listRow {{
    background: transparent;
    border-bottom: 1px solid {p["border_subtle"]};
    border-left: 3px solid transparent;
}}
QFrame#listRow[last="true"] {{
    border-bottom: none;
}}
QFrame#listRow[accent="bad"] {{
    border-left: 3px solid {p["st_bad"]};
    background-color: {p["st_bad_soft"]};
}}
QFrame#listRow[accent="warn"] {{
    border-left: 3px solid {p["st_warn"]};
    background-color: {p["st_warn_soft"]};
}}
QFrame#listRow[accent="ok"] {{
    border-left: 3px solid {p["st_ok"]};
}}
QFrame#listRow[clickable="true"]:hover {{
    background-color: {p["row_hover"]};
}}

QLabel#fileTitle {{
    font-size: 20px;
    font-weight: 600;
    color: {p["ink_1"]};
}}
QLabel#sectionTitle {{
    font-size: 11px;
    font-weight: 600;
    color: {p["ink_3"]};
}}
QLabel#verdictHeadline {{
    font-size: 17px;
    font-weight: 700;
}}
QLabel#verdictHeadline[state="bad"] {{ color: {p["st_bad"]}; }}
QLabel#verdictHeadline[state="warn"], QLabel#verdictHeadline[state="unk"] {{ color: {p["st_warn"]}; }}
QLabel#verdictHeadline[state="ok"] {{ color: {p["st_ok"]}; }}

QLabel#verdictAdvice {{
    font-size: 13px;
    color: {p["ink_1"]};
}}
QLabel#panelHeading {{
    font-size: 13px;
    font-weight: 600;
    color: {p["ink_1"]};
}}
QLabel#panelKey {{
    font-size: 12px;
    color: {p["ink_2"]};
}}
QLabel#panelValue {{
    font-size: 13px;
    color: {p["ink_1"]};
}}
QLabel#mutedLabel {{
    font-size: 12px;
    color: {p["ink_2"]};
}}
QLabel#captionLabel {{
    font-size: 11px;
    color: {p["ink_3"]};
}}
QLabel#monoValue {{
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 12px;
    color: {p["ink_1"]};
}}
QLabel#hashValue {{
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 11px;
    font-weight: 400;
    color: {p["ink_2"]};
}}

QLabel#badgeRight {{
    min-width: 84px;
    min-height: 22px;
    padding: 2px 6px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: 600;
}}
QLabel#tagLeft {{
    min-width: 56px;
    min-height: 20px;
    padding: 1px 6px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: 600;
}}
QLabel#fmtTag {{
    min-width: 32px;
    min-height: 18px;
    padding: 1px 4px;
    border-radius: 4px;
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 10px;
    font-weight: 600;
    background-color: {p["tag_bg"]};
    border: 1px solid {p["border_subtle"]};
    color: {p["ink_2"]};
}}
QLabel#fmtTag[kind="spoof"] {{
    background-color: {p["st_bad_badge"]};
    border-color: {p["st_bad_line"]};
    color: {p["st_bad"]};
}}
QLabel#fmtTag[kind="container"] {{
    background-color: {p["st_info_badge"]};
    border-color: {p["st_info_line"]};
    color: {p["st_info"]};
}}

QLabel[tone="bad"] {{
    background-color: {p["st_bad_badge"]};
    color: {p["st_bad"]};
    border: 1px solid {p["st_bad_line"]};
}}
QLabel[tone="warn"] {{
    background-color: {p["st_warn_badge"]};
    color: {p["st_warn"]};
    border: 1px solid {p["st_warn_line"]};
}}
QLabel[tone="ok"] {{
    background-color: {p["st_ok_badge"]};
    color: {p["st_ok"]};
    border: 1px solid {p["st_ok_line"]};
}}
QLabel[tone="info"] {{
    background-color: {p["st_info_badge"]};
    color: {p["st_info"]};
    border: 1px solid {p["st_info_line"]};
}}

QLabel#engineVal[tone="bad"] {{
    color: {p["st_bad"]}; background: transparent; border: none;
    font-size: 13px; font-weight: 600;
}}
QLabel#engineVal[tone="warn"] {{
    color: {p["st_warn"]}; background: transparent; border: none;
    font-size: 13px; font-weight: 600;
}}
QLabel#engineVal[tone="ok"] {{
    color: {p["st_ok"]}; background: transparent; border: none;
    font-size: 13px; font-weight: 600;
}}
QLabel#engineVal[tone="info"] {{
    color: {p["st_info"]}; background: transparent; border: none;
    font-size: 13px; font-weight: 600;
}}

QProgressBar {{
    background-color: {p["track_bg"]};
    border: none;
    border-radius: 2px;
    max-height: 4px;
    min-height: 4px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {p["st_info"]};
    border-radius: 2px;
}}

QPlainTextEdit, QTextEdit {{
    background-color: {p["surface"]};
    color: {p["ink_1"]};
    border: 1px solid {p["border_subtle"]};
    border-radius: 8px;
    padding: 10px;
    font-family: "Cascadia Mono", Consolas, monospace;
    font-size: 12px;
}}

QScrollArea {{
    background: transparent;
    border: none;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 0px;
}}
QScrollBar::handle:vertical {{
    background-color: {p["border_default"]};
    border-radius: 4px;
    min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 0px;
}}
QScrollBar::handle:horizontal {{
    background-color: {p["border_default"]};
    border-radius: 4px;
    min-width: 24px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QStatusBar {{
    background-color: {p["sidebar"]};
    color: {p["ink_2"]};
    border-top: 1px solid {p["border_subtle"]};
    font-size: 11px;
}}

QToolTip {{
    background-color: {p["elevated"]};
    color: {p["ink_1"]};
    border: 1px solid {p["border_default"]};
    border-radius: 4px;
    padding: 5px 8px;
    font-size: 12px;
}}

QCheckBox {{
    spacing: 8px;
    color: {p["ink_1"]};
    font-size: 13px;
}}

QTabWidget::pane {{
    border: 1px solid {p["border_subtle"]};
    border-radius: 8px;
    background-color: {p["surface"]};
}}
QTabBar::tab {{
    background: transparent;
    color: {p["ink_2"]};
    padding: 6px 12px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {p["ink_1"]};
    border-bottom: 2px solid {p["ink_1"]};
    font-weight: 600;
}}
"""


def _build_qpalette(p: dict[str, str]) -> QPalette:
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(p["canvas"]))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(p["ink_1"]))
    pal.setColor(QPalette.ColorRole.Base, QColor(p["surface"]))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(p["sidebar"]))
    pal.setColor(QPalette.ColorRole.Text, QColor(p["ink_1"]))
    pal.setColor(QPalette.ColorRole.Button, QColor(p["surface"]))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(p["ink_1"]))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(p["row_active"]))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(p["ink_1"]))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(p["ink_3"]))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(p["elevated"]))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(p["ink_1"]))
    return pal


def apply_theme(app: QApplication, mode: str | None = None, *, persist: bool = False) -> str:
    """Apply dark, light, or system theme to ``app`` and repaint all widgets."""
    global _ACTIVE_MODE, _ACTIVE_PREF, _QSS

    if mode is not None:
        _ACTIVE_PREF = mode.strip().lower()
        if persist and _ACTIVE_PREF in ("dark", "light", "system"):
            app_settings().setValue(_THEME_KEY, _ACTIVE_PREF)
    else:
        _ACTIVE_PREF = saved_theme_preference()

    _ACTIVE_MODE = resolve_theme_mode(_ACTIVE_PREF)
    p = palette_for(_ACTIVE_MODE)

    # Keep module-level compatibility constants synced with active palette.
    RISK_COLORS["green"] = p["st_ok"]
    RISK_COLORS["yellow"] = p["st_warn"]
    RISK_COLORS["red"] = p["st_bad"]

    _QSS = build_stylesheet(_ACTIVE_MODE)
    app.setPalette(_build_qpalette(p))
    app.setStyleSheet(_QSS)

    for cb in list(_LISTENERS):
        with suppress(Exception):
            cb(_ACTIVE_MODE, p)
    for w in app.topLevelWidgets():
        w.update()
    return _ACTIVE_MODE


# Initialize default QSS string for direct inspection in unit tests.
_QSS = build_stylesheet("dark")
