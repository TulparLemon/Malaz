"""Die Ergebnis-Karte: ein Urteil, das ein Laie auf einen Blick liest.

WARUM DIESE DATEI EXISTIERT
===========================
Die Ergebnisse standen bisher als Fliesstext in einem QTextEdit. Fachlich
vollstaendig, aber der erste Satz war "ERGEBNIS: Rot (blockieren) — Score
100/100 (-8 Punkte durch AV-ohne-Fund)": eine Zahl, ein Klammerzusatz und ein
Rechenhinweis, bevor ueberhaupt steht, was zu tun ist.

Die Recherche zu dieser Aenderung (Wettbewerber + NN/g) ergab drei Regeln, die
hier umgesetzt sind:

1. **Wort vor Zahl.** Kein fuehrendes Produkt zeigt den nackten Score allein.
   ANY.RUN zeigt nur drei Woerter, Malwarebytes nennt ausdruecklich das
   Rating-Wort, damit der Nutzer nicht raten muss. Der Score bleibt — als
   kleine Beizahl, fuer die, die ihn suchen.
2. **Nie Farbe allein.** Rund 8 % der Maenner sind farbenblind. Die Stufe wird
   IMMER doppelt kodiert: Farbe + Zeichen + Wort. Pruefregel: in Graustufen
   muss die Einstufung noch erkennbar sein.
3. **Eine Handlungszeile.** Die Empfehlung steht unter dem Urteil, nicht in
   einem Abschnitt weiter unten.

Der Score ist bewusst NICHT das Hauptsignal: "37/100" ist ohne Deutung nicht
lesbar, und "1 von 70 Engines" wird von Laien leicht als Beweis gelesen.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout

from ..models import RiskLevel
from .theme import FONT_MARK, RISK_COLORS, RISK_MARKS

# Zeichen je Stufe. Die Form traegt die Aussage auch dann, wenn die Farbe
# nicht ankommt (Farbenblindheit, Graustufendruck eines Screenshots).
# Aus der gemeinsamen Quelle abgeleitet (gui/theme.RISK_MARKS): das Zeichen
# darf zwischen Liste, Panel und Bericht nicht auseinanderlaufen.
RISK_MARK = {level: RISK_MARKS[level.name.lower()] for level in RiskLevel}


class VerdictCard(QFrame):
    """Farbige Karte mit Zeichen, Urteil, Score und Handlungszeile."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("verdictCard")
        self.setFrameShape(QFrame.NoFrame)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(16)

        self.mark = QLabel()
        self.mark.setObjectName("verdictMark")
        self.mark.setAlignment(Qt.AlignCenter)
        self.mark.setFixedWidth(38)
        top.addWidget(self.mark)

        text = QVBoxLayout()
        text.setSpacing(4)
        self.headline = QLabel()
        self.headline.setObjectName("verdictHeadline")
        self.advice = QLabel()
        self.advice.setObjectName("verdictAdvice")
        self.advice.setWordWrap(True)
        text.addWidget(self.headline)
        text.addWidget(self.advice)
        top.addLayout(text, 1)

        self.score = QLabel()
        self.score.setObjectName("verdictScore")
        self.score.setAlignment(Qt.AlignRight | Qt.AlignTop)
        top.addWidget(self.score)

        layout.addLayout(top)
        # Die Engine-Statuszeile gehoert zum Urteil, nicht in eine eigene
        # Box darunter: sonst stehen zwischen Tabelle und Tabs drei Karten.
        self.footer = QVBoxLayout()
        self.footer.setContentsMargins(0, 0, 0, 0)
        self.footer.setSpacing(8)
        layout.addLayout(self.footer)

    def add_footer(self, widget) -> None:
        """Statuszeile unter dem Urteil einsetzen (eine Karte, ein Rahmen)."""
        self.footer.addWidget(widget)

    def show_result(self, result) -> None:
        """Karte fuer ein Ergebnis setzen."""
        level = result.risk_level
        color = RISK_COLORS[level.name.lower()]

        self.mark.setText(RISK_MARK[level])
        self.mark.setStyleSheet(f"color: {color}; font-size: {FONT_MARK};")

        # Wort zuerst, dann die Zahl — die Reihenfolge ist die Aussage.
        if result.is_incomplete:
            self.headline.setText(f"{level.short} (unvollständig)")
            self.advice.setText(
                "Nicht vollständig geprüft: "
                f"{result.incompleteness_note()}\n{level.advice}"
            )
        else:
            self.headline.setText(level.short)
            self.advice.setText(level.advice)

        # Der AV-Nachlass steht als Tooltip, nicht als Klammer im Urteil:
        # er erklaert eine Zahl, die niedriger ist als ihre Befunde, und
        # gehoert damit zum Score, nicht zum Urteil.
        self.score.setText(f"{result.score}/100")
        hint = "Punkte, je hoeher desto auffaelliger"
        if result.av_discount:
            # Dieselbe Wortwahl wie CLI, Bericht und Technik-Reiter
            # ("AV-ohne-Fund"): ein Begriff, der an vier Stellen anders
            # heisst, ist an vier Stellen zu erklaeren.
            hint += (
                f"\n-{result.av_discount} Punkte durch AV-ohne-Fund "
                f"(der Virenscanner hat nichts gefunden)"
            )
        if result.anchored:
            hint += "\nEin kritischer Befund erzwingt mindestens diese Stufe"
        self.score.setToolTip(hint)

        self.setStyleSheet(
            f"#verdictCard {{ background: {_tint(color)}; "
            f"border-left: 6px solid {color}; border-radius: 8px; }}"
        )

    def clear(self) -> None:
        self.mark.clear()
        self.headline.setText("Keine Datei ausgewaehlt")
        self.headline.setStyleSheet("")
        self.advice.setText("Waehlen Sie eine Zeile aus, um das Ergebnis zu sehen.")
        self.score.clear()
        # Ohne das erklaerte der Tooltip ueber dem LEEREN Score-Feld weiter
        # den AV-Rabatt/Anker der zuletzt gewaehlten Datei (BUG-059).
        self.score.setToolTip("")
        self.setStyleSheet("")


def _tint(color: str) -> str:
    """Sehr dunkle Einfaerbung derselben Farbe fuer den Kartenhintergrund.

    Der Streifen links traegt die Farbe kraeftig; die Flaeche dahinter nur
    angedeutet, damit der Text darauf lesbar bleibt (Kontrast 4,5:1).
    """
    rot = int(color[1:3], 16)
    gruen = int(color[3:5], 16)
    blau = int(color[5:7], 16)
    # 12 % der Farbe auf den Panel-Hintergrund gemischt.
    mix = 0.12
    base = (0x1C, 0x1E, 0x25)
    r = int(base[0] * (1 - mix) + rot * mix)
    g = int(base[1] * (1 - mix) + gruen * mix)
    b = int(base[2] * (1 - mix) + blau * mix)
    return f"#{r:02x}{g:02x}{b:02x}"
