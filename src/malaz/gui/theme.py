"""Application theme.

A compact, dependency-free dark theme in the style of modern security tools:
dark surfaces, a single accent colour, strong risk colours, rounded corners.
It is implemented purely as a Qt Style Sheet so it works identically in the
development layout and in the frozen Nuitka build (no extra package data).

Applied once at startup via :func:`apply_theme` (see ``__main__.run_gui``).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem

# Palette (kept here as constants so the GUI code can reuse the same colours
# for e.g. risk colouring instead of diverging with its own values).
WINDOW_BG = "#0b0e13"
PANEL_BG = "#141a22"
BORDER = "#222b38"
TEXT = "#e9eef6"
TEXT_SECONDARY = "#9aa7b8"
TEXT_DISABLED = "#687385"
# Der Hintergrund der Ergebnistabelle - Bezugswert fuer risk_tint().
TABLE_BG = "#0f141b"
ACCENT = "#5ed7f5"

# Zeichen je Risikostufe — neben den Farben, weil sie zusammengehoeren.
#
# EINE Quelle: die Abbildung stand wortgleich an vier Stellen (mail_panel
# zweimal, mail_viewer_dialog einmal, verdict_card mit RiskLevel-Schluesseln).
# scripts/check_duplicate_logic.py findet sie nicht — sie liegen IN Funktionen,
# und der Pruefer liest nur Modulebene.
#
# Die Form traegt die Aussage auch dann, wenn die Farbe nicht ankommt
# (Farbenblindheit, Graustufendruck eines Screenshots).
RISK_MARKS = {
    "green": "\u2714",  # schweres Haekchen
    "yellow": "\u26a0",  # Warndreieck
    "red": "\u2716",  # schweres Kreuz
}

RISK_COLORS = {
    "green": "#4ade80",
    "yellow": "#fbbf24",
    "red": "#f87171",
}

# -- Typen-Rampe ------------------------------------------------------------ #
#
# WARUM ES SIE GIBT
# =================
# GEMESSEN vorher: acht verschiedene Schriftgroessen im Baum, ohne System —
# 13/14/15/16/20/26 px und 9/12 pt. Und **pt neben px**: pt ist eine
# physische Einheit, px eine logische; bei Windows-Skalierung (125 %, 150 %)
# laufen sie auseinander, und dieselbe Oberflaeche sah auf zwei Rechnern
# unterschiedlich aus.
#
# Jetzt drei Stufen in px, nach der Windows-Typen-Rampe benannt
# (Subtitle/Body/Caption, siehe Microsoft "Content layout and spacing").
# Wer eine Groesse braucht, nimmt eine STUFE — nicht eine Zahl.
FONT_SUBTITLE = "15px"  # Abschnitt, hervorgehobener Wert
FONT_BODY = "13px"  # Fliesstext, Tabellenzelle, Knopf
FONT_CAPTION = "11px"  # Fussnote, Zaehler, Nebenbemerkung
# Das Risikozeichen in der Urteilskarte. Groesser als alles andere, weil
# es die Aussage auf einen Blick traegt — und die Form sagt dasselbe wie
# die Farbe (Farbenblindheit, Graustufendruck).
FONT_MARK = "26px"

# -- Abstands-Raster -------------------------------------------------------- #
#
# 8er-Raster (Microsoft: 8 px zwischen Bedienelementen, 12 px zwischen Label
# und Inhalt, 16 px zum Rand). GEMESSEN vorher: 10, 6, 18 und 2 — jeder
# Wert eine eigene Entscheidung, keiner davon aus einem System. Das ist der
# Unterschied zwischen "zusammengebaut" und "gestaltet", auch wenn ihn
# niemand benennen kann.
SPACE_S = 8
SPACE_M = 12
SPACE_L = 16
SPACE_XL = 24

_QSS = f"""
* {{ outline: none; }}
QWidget {{ color: {TEXT}; background: transparent; }}
QMainWindow, QDialog, QMessageBox {{ background: {WINDOW_BG}; }}

QLabel {{ background: transparent; }}
QLabel[role="secondary"] {{ color: {TEXT_SECONDARY}; }}
QLabel[role="hint"] {{ color: {TEXT_DISABLED}; font-size: {FONT_CAPTION}; }}

QPushButton {{
    background: #2a2c36; border: 1px solid #3a3d4a; border-radius: 6px;
    padding: {SPACE_S}px {SPACE_L}px;
}}
QPushButton:hover {{ background: #323542; border-color: #4a4e5e; }}
QPushButton:pressed {{ background: #23252e; }}
QPushButton:disabled {{ color: {TEXT_DISABLED}; background: #20222a; border-color: #2b2d36; }}
QPushButton#primaryButton {{
    background: {ACCENT}; color: #0b1220; border: none; font-weight: 600;
    padding: {SPACE_S}px {SPACE_XL}px;
}}
QPushButton#primaryButton:hover {{ background: #6cd0ff; }}
QPushButton#primaryButton:pressed {{ background: #2ea8e5; }}
QPushButton#primaryButton:disabled {{ background: #274150; color: #6d7d86; }}

QListWidget {{
    background: {PANEL_BG}; border: 1px solid {BORDER}; border-radius: 8px;
    padding: 4px;
}}
QListWidget::item {{ padding: 8px 8px; border-radius: 5px; color: #cdd2dc; }}
QListWidget::item:hover {{ background: #262935; }}
QListWidget::item:selected {{ background: #26435c; color: #eaf6ff; }}

/* Der Baum traegt die Ergebnisliste. GEMESSEN fehlte er hier vollstaendig:
   das Stylesheet gestaltete QTableWidget, die Liste ist seit dem Umbau auf
   Aufklappbarkeit aber ein QTreeWidget — sie lief mit Qt-Standardoptik, und
   genau das sah nach 2010 aus. QTreeWidget erbt von QTreeView, deshalb steht
   hier QTreeView. */
QTreeWidget, QTreeView {{
    background: {PANEL_BG};
    alternate-background-color: #1a1c22;
    border: 1px solid {BORDER}; border-radius: 8px;
    show-decoration-selected: 1;
}}
QTreeView::item {{
    padding: 5px 6px; border: none; color: #cdd2dc;
}}
QTreeView::item:hover {{ background: #262935; }}
QTreeView::item:selected {{ background: #26435c; color: #eaf6ff; }}
/* Die Aufklapp-Pfeile: NICHT anfassen.
 *
 * Hier stand zuerst ein Block mit "image: none" — in der Absicht, das
 * hellgraue Standard-Dreieck loszuwerden. GEMESSEN im gerenderten Baum: damit
 * war der Pfeil WEG. Die Kinder waren eingerueckt, aber nichts zeigte an,
 * dass sich etwas aufklappen laesst — bei einer Liste, deren Zweck genau das
 * ist, verschwand die einzige Bedienung dafuer.
 *
 * Qt zeichnet den Indikator selbst, sobald der Baum gestylt ist; die
 * Standardform ist auf dunklem Grund sichtbar. Wer sie ersetzen will, muss
 * ein eigenes Bild mitbringen — nicht "none".
 */
/* KEINE ::branch-Regel.
 *
 * Zwei Versuche, den Standardpfeil zu "verbessern", haben ihn entfernt:
 * erst "image: none" (offensichtlich), dann "background: transparent"
 * (nicht offensichtlich). Sobald ein Stylesheet ::branch ueberhaupt
 * beruehrt, zeichnet die Style-Engine den Indikator NICHT mehr selbst —
 * ohne eigenes Bild bleibt die Stelle leer. GEMESSEN im gerenderten Baum:
 * die Kinder waren eingerueckt, aber nichts zeigte an, dass sich etwas
 * aufklappen laesst. Wer den Pfeil ersetzen will, muss ein Bild mitbringen. */

/* Die Warteschlange und andere einfache Listen. */
QTableWidget {{
    background: {PANEL_BG}; alternate-background-color: #1a1c22;
    border: 1px solid {BORDER}; border-radius: 8px; gridline-color: #262833;
}}
QTableWidget::item {{ padding: 8px 8px; border: none; }}
QTableWidget::item:selected {{ background: #26435c; color: #eaf6ff; }}
QHeaderView::section {{
    background: #20222b; color: {TEXT_SECONDARY}; border: none;
    border-right: 1px solid #262833; border-bottom: 1px solid #262833;
    padding: 8px 8px; font-weight: 600;
}}
QTableCornerButton::section {{ background: #20222b; border: none; }}

QTextEdit, QPlainTextEdit {{
    background: {PANEL_BG}; border: 1px solid {BORDER}; border-radius: 8px;
    padding: 8px; selection-background-color: #26435c;
}}

QProgressBar {{
    background: {PANEL_BG}; border: 1px solid {BORDER}; border-radius: 6px;
    min-height: 16px; text-align: center; color: #cdd2dc; font-size: {FONT_CAPTION};
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

QSplitter::handle {{ background: {BORDER}; }}
QSplitter::handle:vertical {{ height: 3px; }}
QSplitter::handle:horizontal {{ width: 3px; }}

QMenuBar {{ background: {WINDOW_BG}; padding: 2px; }}
QMenuBar::item {{ padding: 5px 10px; border-radius: 5px; background: transparent; }}
QMenuBar::item:selected {{ background: #262935; }}
QMenu {{
    background: #1f2129; border: 1px solid #32343e; border-radius: 8px; padding: 6px;
}}
QMenu::item {{ padding: 6px 24px; border-radius: 5px; }}
QMenu::item:selected {{ background: #26435c; }}
QMenu::item:disabled {{ color: {TEXT_DISABLED}; }}
QMenu::separator {{ height: 1px; background: #2c2e38; margin: 4px 8px; }}

QStatusBar {{ background: #121318; color: {TEXT_SECONDARY}; border-top: 1px solid #23252e; }}
QStatusBar QLabel {{ color: {TEXT_SECONDARY}; }}

QScrollBar:vertical {{ background: transparent; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{ background: #3a3d4a; border-radius: 5px; min-height: 30px; margin: 2px; }}
QScrollBar::handle:vertical:hover {{ background: #4a4e5e; }}
QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: #3a3d4a; border-radius: 5px; min-width: 30px; margin: 2px; }}
QScrollBar::handle:horizontal:hover {{ background: #4a4e5e; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QToolTip {{
    background: #262935; color: {TEXT}; border: 1px solid #3a3d4a;
    padding: 4px 6px; border-radius: 4px;
}}
/* --- Ergebnis-Karte und Panels (gui/verdict_card.py, gui/mail_panel.py) ---

   Kontrast: der Fliesstext auf diesen Flaechen haelt mindestens 4,5:1 gegen
   den Hintergrund (WCAG 2.1 AA). Der Farbstreifen traegt NIE allein die
   Aussage — daneben stehen immer ein Zeichen und ein Wort, damit die
   Einstufung auch in Graustufen und bei Farbenblindheit lesbar bleibt. */
#verdictAdvice {{ color: {TEXT}; font-size: {FONT_BODY}; }}
#verdictScore {{ color: {TEXT_SECONDARY}; font-size: {FONT_BODY}; }}
#batchSummary {{
    background: {PANEL_BG}; border: 1px solid {BORDER};
    border-radius: 8px;
}}
#batchHeadline {{ color: {TEXT}; font-size: {FONT_SUBTITLE}; font-weight: 700; }}
#scoreBreakdown {{
    background: transparent; border: none;
    font-family: "Consolas", "Cascadia Mono", monospace;
    font-size: {FONT_BODY}; padding: 4px;
}}
#panelHeading {{
    color: {TEXT}; font-size: {FONT_SUBTITLE}; font-weight: 700;
    padding-top: {SPACE_S}px; border-top: 1px solid {BORDER};
}}
#panelKey {{ color: {TEXT_SECONDARY}; font-size: {FONT_BODY}; }}
#panelValue {{ color: {TEXT}; font-size: {FONT_BODY}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px; }}
QTabBar::tab {{
    background: #22242c; border: 1px solid {BORDER}; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
    padding: 8px 12px; margin-right: 4px; color: {TEXT_SECONDARY};
}}
QTabBar::tab:selected {{ background: {PANEL_BG}; color: {TEXT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

/* --- Arbeitsflaeche (Revamp) --------------------------------------------- */
#sidebar {{
    background: #090c11;
    border-right: 1px solid #1d2531;
}}
#workspace {{ background: {WINDOW_BG}; }}
#brandTitle {{
    color: {TEXT}; font-size: 21px; font-weight: 800; letter-spacing: 2px;
}}
#brandTagline {{ color: {TEXT_SECONDARY}; font-size: 11px; }}
#brandVersion {{ color: {TEXT_DISABLED}; font-size: 10px; padding-top: 2px; }}
#sectionLabel {{
    color: #7f8da3; font-size: 11px; font-weight: 500; letter-spacing: 0.5px;
}}
#queueCount {{ color: {TEXT_SECONDARY}; font-size: 11px; font-weight: 600; }}
#headerTitle {{ color: {TEXT}; font-size: 24px; font-weight: 700; }}
#headerMeta {{ color: {TEXT_SECONDARY}; font-size: 12px; }}
#emptyState {{
    color: #7f8da3; font-size: 14px; padding: 24px;
    background: #0f141b; border: 1px dashed #26303e; border-radius: 10px;
}}
#systemPanel {{
    background: #10151d; border: 1px solid #202a37; border-radius: 10px;
}}
#systemEngine {{ color: #aab6c8; font-size: 10px; }}
#systemState {{ color: {TEXT_SECONDARY}; font-size: 10px; }}
#fileQueue {{
    background: #0f141b; border: 1px dashed #2b3545; border-radius: 10px;
    padding: 8px;
}}
#fileQueue:focus {{ border: 1px solid {ACCENT}; }}
QPushButton#ghostButton {{
    background: #151b24; border: 1px solid #26303e; border-radius: 8px;
    color: {TEXT}; padding: 8px 12px;
}}
QPushButton#ghostButton:hover {{ background: #1c2430; border-color: #364459; }}
QPushButton#ghostButton:pressed {{ background: #111720; }}
QPushButton#ghostButton:disabled {{
    color: {TEXT_DISABLED}; background: #11161e; border-color: #1d2531;
}}
QPushButton#primaryButton {{
    background: {ACCENT}; color: #061016; border: none; border-radius: 8px;
    font-weight: 700; padding: 8px 16px;
}}
QPushButton#primaryButton:hover {{ background: #83e4fb; }}
QPushButton#primaryButton:pressed {{ background: #3cc4e5; }}
QLineEdit#searchField, QComboBox#filterCombo {{
    background: #111821; border: 1px solid #26303e; border-radius: 8px;
    color: {TEXT}; padding: 8px 12px;
}}
QLineEdit#searchField:focus, QComboBox#filterCombo:focus {{
    border-color: {ACCENT};
}}
QComboBox#filterCombo::drop-down {{ border: none; width: 22px; }}
QComboBox#filterCombo QAbstractItemView {{
    background: #141a22; border: 1px solid #26303e; selection-background-color: #203244;
}}
QTreeWidget#resultTable {{
    background: #0f141b; alternate-background-color: #121923;
    border: 1px solid #202a37; border-radius: 10px;
}}
QTreeWidget#resultTable::item {{ padding: 8px 8px; }}
QTreeWidget#resultTable::item:selected {{ background: #203244; }}
QTextEdit#detailView, QTextEdit#technicalView {{
    background: transparent; border: none; padding: 8px 4px;
}}
QSplitter#resultSplitter::handle {{ background: #1a2230; height: 8px; }}
#batchSummary {{
    background: #10151d; border: 1px solid #202a37; border-radius: 10px;
}}
#batchHeadline {{ color: {TEXT}; font-size: 15px; font-weight: 700; }}
QTabWidget#detailTabs::pane {{
    border: none; background: transparent;
    padding: 8px 0 0 0;
}}
QTabWidget#detailTabs QTabBar::tab {{
    background: transparent; border: none; border-bottom: 2px solid transparent;
    padding: 8px 12px; margin-right: 4px; color: {TEXT_SECONDARY};
}}
QTabWidget#detailTabs QTabBar::tab:selected {{
    color: {TEXT}; border-bottom: 2px solid {ACCENT};
}}
QTabWidget#detailTabs QTabBar::tab:hover {{ color: {TEXT}; }}
QFrame#systemPanel QLabel {{ background: transparent; }}
"""


class RiskTintDelegate(QStyledItemDelegate):
    """Paint an item's BackgroundRole ourselves.

    WHY THIS EXISTS
    ===============
    The stylesheet carries ``QTreeWidget#resultTable::item { padding: 8px; }``
    and Qt then draws the item background from the stylesheet, ignoring
    ``setBackground()`` entirely. Measured offscreen on the real widget: green,
    yellow and red all rendered as RGB(15,20,27) — pixel-identical to the
    table background, so the risk colouring was invisible. A vision check of
    the rendered image confirmed "rows 2-5: black".

    Filling the rect before the default paint restores the tint without
    touching the stylesheet (the padding rule is what keeps rows readable).
    """

    def paint(self, painter, option, index) -> None:
        brush = index.data(Qt.ItemDataRole.BackgroundRole)
        if brush is not None:
            painter.fillRect(option.rect, brush)
            # Hand the default paint an option without a background, or it
            # draws the stylesheet colour over the tint again.
            option = QStyleOptionViewItem(option)
            option.backgroundBrush = QBrush()
        super().paint(painter, option, index)


def risk_tint(color: str, alpha: int = 48) -> QColor:
    """A SOLID tint of ``color`` over the table background.

    Not a translucent colour: ``setBackground`` with alpha is composited
    against black by Qt, not against the theme surface, so 28/255 of green,
    yellow and red all came out as the same dark grey. Blending here makes the
    result independent of what Qt composites against.
    """
    fg = QColor(color)
    bg = QColor(TABLE_BG)
    a = alpha / 255.0
    return QColor(
        round(fg.red() * a + bg.red() * (1 - a)),
        round(fg.green() * a + bg.green() * (1 - a)),
        round(fg.blue() * a + bg.blue() * (1 - a)),
    )


def apply_theme(app) -> None:
    """Set the dark palette and stylesheet on the application.

    The palette covers the few native/styled-by-palette parts (message boxes,
    native-looking elements), the stylesheet does the actual design work.
    /* --- Ergebnis-Karte und Panels (gui/verdict_card.py, gui/mail_panel.py) ---

   Kontrast: der Fliesstext auf diesen Flaechen haelt mindestens 4,5:1 gegen
   den Hintergrund (WCAG 2.1 AA). Der Farbstreifen traegt NIE allein die
   Aussage — daneben stehen immer ein Zeichen und ein Wort, damit die
   Einstufung auch in Graustufen und bei Farbenblindheit lesbar bleibt. */
#verdictAdvice {{ color: {TEXT}; font-size: 13px; }}
#verdictScore {{ color: {TEXT_SECONDARY}; font-size: 13px; }}
#panelHeading {{
    color: {TEXT}; font-size: 14px; font-weight: 700;
    padding-top: 6px; border-top: 1px solid {BORDER};
}}
#panelKey {{ color: {TEXT_SECONDARY}; font-size: 13px; }}
#panelValue {{ color: {TEXT}; font-size: 13px; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px; }}
QTabBar::tab {{
    background: #22242c; border: 1px solid {BORDER}; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
    padding: 6px 14px; margin-right: 2px; color: {TEXT_SECONDARY};
}}
QTabBar::tab:selected {{ background: {PANEL_BG}; color: {TEXT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}
"""
    from PySide6.QtGui import QColor, QFont, QPalette

    # Segoe UI Variable is the Windows 11 UI face; Qt falls back cleanly on
    # older systems. One font for the whole app, so widgets do not drift.
    font = QFont("Segoe UI Variable Text", 10)
    app.setFont(font)

    palette = app.palette()
    window = QColor(WINDOW_BG)
    panel = QColor(PANEL_BG)
    text = QColor(TEXT)
    secondary = QColor(TEXT_SECONDARY)
    accent = QColor(ACCENT)
    palette.setColor(QPalette.Window, window)
    palette.setColor(QPalette.Base, panel)
    palette.setColor(QPalette.AlternateBase, panel)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Button, panel)
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.ToolTipBase, panel)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.Highlight, accent)
    palette.setColor(QPalette.HighlightedText, QColor("#0b1220"))
    palette.setColor(QPalette.PlaceholderText, secondary)
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(TEXT_DISABLED))
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(TEXT_DISABLED))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(TEXT_DISABLED))
    app.setPalette(palette)
    app.setStyleSheet(_QSS)
