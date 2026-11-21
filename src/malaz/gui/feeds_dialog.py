"""Der Datenbanken-Dialog: Feeds nachladen, bewusst und auf Klick.

WARUM DIESE DATEI EXISTIERT
===========================
Malaz ist offline. Die Regel- und Hashdatenbanken waren damit leer: 14
Hash-Eintraege in `rules/hashes/blocklist.sha256`, sonst nichts. Ein
Malware-Scanner ohne Datenbank findet nur, was seine Heuristiken finden.

Der Nutzer hat die Wahl: **einmal herunterladen, dann rein lokal**. Dieses
Fenster ist die einzige Stelle in Malaz, die von sich aus eine Netzverbindung
aufbauen KANN — und sie tut es nur, wenn hier eine Schaltflaeche gedrueckt
wird. Kein Hintergrundabruf, kein Zeitplan, keine Telemetrie.

WARUM DER LIZENZHINWEIS AN JEDER ZEILE STEHT
============================================
Malaz steht unter GPL-3.0-or-later. Ob ein Feed mitgeliefert werden DARF,
entscheidet trotzdem die Lizenz der QUELLE — sie bindet den Weitergebenden
unabhaengig von der eigenen Lizenz, und sie unterscheidet sich je Quelle:

* **Phishing.Database** steht unter MIT: Weitergabe waere erlaubt.
* **abuse.ch** (URLhaus, MalwareBazaar) erlaubt die Nutzung, aber nicht das
  Weitergeben der Daten.
* **Spamhaus DROP** verlangt Namensnennung.

Deshalb steht an jeder Zeile, was gilt. Ein Nutzer, der eine Firma berät, muss
das sehen, ohne die Lizenztexte zu lesen.

WARUM NACH `%LocalAppData%` UND NICHT INS REPO
==============================================
Dieselbe Ueberlegung: was der Nutzer herunterlaedt, gehoert ihm und nicht in
das ausgelieferte Programm. `core/feeds.download_feed` schreibt nur die
Rohdatei; der Import in die Blockliste ist ein eigener, sichtbarer Schritt.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from .. import config
from ..core.feed_import import refresh_feed
from ..core.feeds import FEEDS, Feed, FeedError
from ..i18n import get_language, pick, t
from .display import clamp_dialog_to_screen, show_message_box
from .theme import FONT_SUBTITLE


def _feed_dir() -> Path:
    """Ablage der Rohdateien — neben den importierten Blocklisten."""
    base = Path(config.USER_HASH_BLOCKLIST_FILE).parent
    return base / "feeds"


class FeedsDialog(QDialog):
    """Liste der nachladbaren Quellen mit je einer Schaltflaeche."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(t("feeds.title"))
        clamp_dialog_to_screen(self, preferred_w=760, preferred_h=560)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(8)

        kopf = QLabel(
            "Malaz arbeitet offline. Diese Quellen werden nur geladen, wenn "
            "Sie die Schaltflaeche druecken — es gibt keinen automatischen "
            "Abruf. Die Dateien bleiben auf diesem Rechner."
        )
        kopf.setWordWrap(True)
        kopf.setObjectName("panelValue")
        outer.addWidget(kopf)

        ziel = QLabel(f"Ablage: {_feed_dir()}")
        ziel.setObjectName("panelKey")
        ziel.setWordWrap(True)
        outer.addWidget(ziel)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        self._layout = QVBoxLayout(body)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        self._rows: list[tuple[Feed, QLabel, QPushButton]] = []
        for feed in FEEDS:
            self._layout.addWidget(self._row(feed))
        self._layout.addStretch(1)

        # EIN Knopf fuer alle Quellen: sechs einzelne Klicks sind fuer den
        # ersten Start unnoetig muehsam, und die Reihenfolge ist ohnehin
        # egal - jede Quelle landet in ihrem eigenen Verzeichnis.
        self.btn_alle = QPushButton("Alle installieren")
        self.btn_alle.setObjectName("primaryAction")
        self.btn_alle.clicked.connect(self._laden_alle)

        schliessen = QPushButton("Schliessen")
        schliessen.clicked.connect(self.accept)
        unten = QHBoxLayout()
        unten.addWidget(self.btn_alle)
        unten.addStretch(1)
        unten.addWidget(schliessen)
        outer.addLayout(unten)

    def _row(self, feed: Feed) -> QWidget:
        """Eine Zeile: Zweck, Groesse, Lizenz und die Schaltflaeche."""
        rahmen = QFrame()
        rahmen.setObjectName("card")
        layout = QVBoxLayout(rahmen)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        titel = QLabel(feed.title)
        titel.setStyleSheet(f"font-weight: 700; font-size: {FONT_SUBTITLE};")
        titel.setWordWrap(True)
        layout.addWidget(titel)

        zweck = QLabel(feed.purpose)
        zweck.setObjectName("panelValue")
        zweck.setWordWrap(True)
        layout.addWidget(zweck)

        # Groesse und Lizenz in einer Zeile: der Nutzer soll den Aufwand und
        # die Weitergabe-Regel sehen, bevor er klickt.
        meta = QLabel(f"{feed.size_hint}  ·  {feed.license_note}")
        meta.setObjectName("panelKey")
        meta.setWordWrap(True)
        layout.addWidget(meta)

        zeile = QHBoxLayout()
        status = QLabel("")
        status.setObjectName("panelKey")
        status.setWordWrap(True)
        knopf = QPushButton(pick("Herunterladen", "Download", "İndir"))
        knopf.clicked.connect(lambda _=False, f=feed, s=status, b=knopf: self._laden(f, s, b))
        zeile.addWidget(status, 1)
        zeile.addWidget(knopf)
        layout.addLayout(zeile)
        if not hasattr(self, "_rows"):
            self._rows = []
        self._rows.append((feed, status, knopf))
        return rahmen

    def _laden_alle(self) -> None:
        """Alle Quellen nacheinander holen.

        Nacheinander, nicht parallel: die Quellen sind gross, und sechs
        gleichzeitige Downloads ueber dieselbe Leitung bringen keinen
        Gewinn — sie machen nur den Fortschritt unlesbar. Der Knopf bleibt
        gesperrt, bis alle durch sind.
        """
        self.btn_alle.setEnabled(False)
        fehler = 0
        for feed, status, knopf in self._rows:
            if not knopf.isEnabled():
                continue  # laeuft schon oder ist fertig
            self._laden(feed, status, knopf, still=True)
            if "Fehlgeschlagen" in status.text():
                fehler += 1
            QApplication.processEvents()
        self.btn_alle.setEnabled(True)
        if fehler:
            self.btn_alle.setText(f"Alle installieren ({fehler} fehlgeschlagen)")
        else:
            self.btn_alle.setText("Alle installiert")

    def _laden(
        self, feed: Feed, status: QLabel, knopf: QPushButton, *, still: bool = False
    ) -> None:
        """Einzelnen Feed holen — synchron, mit sichtbarem Zustand.

        Bewusst NICHT in einem Thread: der Dialog ist modal, und ein
        Fortschritt ueber mehrere Fenster hinweg waere mehr Mechanik als
        Nutzen. Die Schaltflaeche wird waehrend des Ladens gesperrt, damit ein
        zweiter Klick nicht zwei Downloads startet.
        """
        knopf.setEnabled(False)
        status.setText(pick("Lädt …", "Downloading …", "İndiriliyor …"))
        self.repaint()
        # Ein Aufruf fuer beide Schritte — dieselbe Funktion nutzt die
        # automatische Auffrischung beim Start, damit die Reihenfolge
        # (erst holen, dann uebernehmen) nur an EINER Stelle steht.
        try:
            ziel, ergebnis = refresh_feed(feed, _feed_dir())
        except FeedError as exc:
            status.setText(f"Fehlgeschlagen: {exc}")
            knopf.setEnabled(True)
            return
        except Exception as exc:
            status.setText(f"Fehlgeschlagen: {type(exc).__name__}: {exc}")
            knopf.setEnabled(True)
            return

        groesse = ziel.stat().st_size
        status.setText(f"{ergebnis.summary} — {ziel.name} ({groesse / 1024:.0f} KB)")
        knopf.setEnabled(True)
        # Beim Sammellauf KEIN modaler Dialog: er blockiert auf einen Klick,
        # den im stillen Lauf niemand geben kann (gemessen: der erste Feed
        # haengte 600 s). Der Status steht in der Zeile, das genuegt.
        if still:
            return
        hinweis = f"\n\n{ergebnis.note}" if ergebnis.note else ""
        lang = get_language()
        show_message_box(
            self,
            pick("Übernommen", "Imported", "İçe aktarıldı", lang=lang),
            pick(
                f"{feed.title}\n\n{ergebnis.summary}\n"
                f"Ablage: {ergebnis.target}{hinweis}\n\n"
                "Die Einträge werden beim nächsten Scan mitgelesen.",
                f"{feed.title}\n\n{ergebnis.summary}\n"
                f"Saved to: {ergebnis.target}{hinweis}\n\n"
                "Entries will be used on the next scan.",
                f"{feed.title}\n\n{ergebnis.summary}\n"
                f"Kayıt yeri: {ergebnis.target}{hinweis}\n\n"
                "Yeni kayıtlar bir sonraki taramada otomatik olarak kullanılacaktır.",
                lang=lang,
            ),
            icon=QMessageBox.Icon.Information,
        )
