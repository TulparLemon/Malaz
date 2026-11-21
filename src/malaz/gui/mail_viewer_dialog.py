"""Eine gedroppte Mail ansehen, OHNE sie zu oeffnen.

WARUM DIESE DATEI EXISTIERT
===========================
Bis hierher gab es keinen Weg, eine .eml anzusehen, ohne sie zu scannen und
danach die Ergebniszeile anzuklicken. Wer eine verdaechtige Mail bekam, hatte
zwei Moeglichkeiten: das Mailprogramm (das Anhaenge ausfuehren kann und dem
Absender meldet, dass die Mail gelesen wurde) oder Malaz scannen lassen.

Verlangt war: **eine Anzeige, mit der man die Mail oeffnet** — nach dem
Drag-and-Drop, ohne Umweg. Genau das ist dieses Fenster.

WAS HIER NICHT PASSIERT
=======================
* **Kein Mailprogramm.** Die Datei wird nicht an Windows uebergeben, es startet
  kein Prozess. Ein Doppelklick auf eine .eml wuerde Outlook oeffnen — hier
  nicht.
* **Keine Ausfuehrung.** Kein Anhang wird entpackt, kein Makro beruehrt, kein
  Skript gestartet. Es wird gelesen und angezeigt.
* **Kein Netz.** Der HTML-Rumpf wird NICHT gerendert: er ist
  angreiferkontrolliert, und ein einzelnes Bild darin waere ein Beacon, der dem
  Absender meldet, dass die Mail gelesen wurde. Angezeigt wird Klartext.
* **Kein Scan.** Dieses Fenster bewertet die Datei nicht — es zeigt sie. Wer
  ein Urteil will, laesst sie scannen. Das steht auch im Fenster, damit die
  Anzeige nicht als Freispruch missverstanden wird.

WARUM DER ABSENDER-BLOCK TROTZDEM DA IST
========================================
Die Frage "ist der Absender echt" stellt sich beim Lesen, nicht beim Scannen.
Der Block zeigt dieselben Angaben wie das Ergebnis-Panel, mit derselben
Ehrlichkeit: bei einer ungedeckten Behauptung heisst es "behauptet: bestanden".
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from .. import config
from ..core.eml_analysis import analyze_structure, looks_like_mail, parse_mail
from ..core.mail_score import mechanism_label, sender_score
from ..core.mail_view import MAX_DISPLAY_CHARS, _clip, render_mail, sender_verdict
from ..i18n import pick, t
from ..security.escaping import mask_invisible
from .display import clamp_dialog_to_screen
from .theme import FONT_SUBTITLE, RISK_COLORS, RISK_MARKS

# Endungen, die dieses Fenster oeffnen kann. Inhaltsbasiert waere besser, aber
# hier geht es um eine VORSCHAU vor dem Scan: der Nutzer hat gerade eine Datei
# fallen gelassen und will wissen, was drinsteht.
MAIL_SUFFIXES = (".eml", ".msg")


def has_mail_suffix(path: str | Path) -> bool:
    """Hat diese Datei die Endung einer Mail?

    Nach ENDUNG, nicht nach Inhalt — hier geht es um die Frage, ob der Knopf
    angeboten wird, nicht um die Frage, ob wirklich eine Mail drinsteckt. Das
    ist eine andere Frage, und sie wird anders beantwortet:
    ``eml_analysis.looks_like_mail`` prueft die Kopfzeilen.
    """
    return str(path).lower().endswith(MAIL_SUFFIXES)


class MailViewerDialog(QDialog):
    """Zeigt den Inhalt einer Mail als Klartext — ohne sie zu oeffnen."""

    def __init__(self, path: str | Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._path = Path(path)
        # Der Dateiname ist angreiferkontrolliert: U+202E im Titel liess
        # "Rechnung\u202egpj.eml" wie "Rechnungeml.jpg" aussehen, und ein
        # 60 000-Zeichen-Name landete ungekuerzt in der Titelleiste.
        self.setWindowTitle(
            pick("Mail ansehen: ", "Email viewer: ", "E-posta görüntüleyici: ")
            + _clip(mask_invisible(self._path.name), MAX_DISPLAY_CHARS)
        )
        clamp_dialog_to_screen(self, preferred_w=820, preferred_h=680)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(8)

        outer.addWidget(self._notice())
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        self._body = QWidget()
        self._layout = QVBoxLayout(self._body)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        scroll.setWidget(self._body)
        outer.addWidget(scroll, 1)

        unten = QHBoxLayout()
        unten.addStretch(1)
        schliessen = QPushButton(t("btn.close"))
        schliessen.clicked.connect(self.accept)
        unten.addWidget(schliessen)
        outer.addLayout(unten)

        self._fill()

    def _notice(self) -> QWidget:
        """Der Hinweis, was dieses Fenster NICHT tut.

        Ohne ihn liest sich eine Vorschau wie ein Freispruch — und der Nutzer
        oeffnet die Mail danach doch im Mailprogramm.
        """
        rahmen = QFrame()
        rahmen.setObjectName("card")
        layout = QVBoxLayout(rahmen)
        layout.setContentsMargins(12, 10, 12, 10)
        text = QLabel(
            pick(
                "Diese Anzeige oeffnet die Mail NICHT in Ihrem Mailprogramm und "
                "fuehrt nichts aus. Anhaenge werden nicht entpackt, Bilder nicht "
                "geladen — der Absender erfaehrt also nicht, dass Sie die Mail "
                "angesehen haben. Sie bewertet die Datei auch nicht; dafuer "
                "scannen Sie sie.",
                "This viewer does NOT open the email in your mail client and executes "
                "nothing. Attachments are not extracted and remote images are never "
                "loaded — the sender is never notified. This view does not judge risk; "
                "scan the file for a verdict.",
                "Bu görüntüleyici e-postayı e-posta istemcinizde AÇMAZ ve hiçbir kod çalıştırmaz. "
                "Ekler çıkarılmaz ve harici görseller yüklenmez — göndericiye bildirim gitmez. "
                "Bu ekran risk değerlendirmesi yapmaz; karar için dosyayı tarayın.",
            )
        )
        text.setWordWrap(True)
        text.setObjectName("panelValue")
        layout.addWidget(text)
        return rahmen

    def _fill(self) -> None:
        try:
            # BEGRENZT lesen, nicht erst alles holen und dann schneiden:
            # ``read_bytes()`` hat die Datei vorher komplett im Speicher. Der
            # Knopf erscheint schon bei der Endung .eml/.msg (has_mail_suffix
            # sieht die Datei nicht an), also genuegte eine beliebig grosse
            # Datei mit dieser Endung. Der Dispatcher liest aus demselben
            # Grund begrenzt (core/dispatcher.py) — hier wird es nachgeholt.
            with self._path.open("rb") as handle:
                data = handle.read(config.MAX_READ_SIZE)
        except OSError as exc:
            self._add(f"Diese Datei kann nicht gelesen werden: {exc}")
            return

        if self._path.suffix.lower() == ".msg":
            # Ein Outlook-Container ist kein MIME. Der Parser dafuer liegt in
            # core/mail_view und wird hier NICHT nachgebaut.
            from ..core.mail_view import render_msg

            vorschau = render_msg(data)
            if not vorschau:
                self._add(
                    "Diese Datei ist kein lesbarer Outlook-Container. "
                    "Scannen Sie sie, um zu sehen, was sie ist."
                )
                return
            self._add(vorschau)
            return

        facts = parse_mail(data)
        if not looks_like_mail(facts):
            # KEINE Mail-Anzeige fuer etwas, das keine Mail ist. Sonst stuende
            # ueber rohen Bytes eine Ueberschrift "Textinhalt" und der Nutzer
            # haelt sie fuer den Rumpf einer Mail.
            self._add(
                "Diese Datei ist keine E-Mail: sie traegt keine Mail-Kopfzeilen "
                "(Absender, Betreff, Datum, Message-ID). Scannen Sie sie, um zu "
                "sehen, was sie wirklich ist."
            )
            return

        # Fuer das Absender-Urteil muss bekannt sein, ob eine Behauptung
        # GEDECKT ist. analyze_structure prueft das gegen die Empfangskette —
        # rein lokal und ohne Dateisystem. Ohne diese Pruefung druckte die
        # Anzeige "SPF: bestanden" fuer eine Kopfzeile, die sich der Absender
        # selbst geschrieben hat, waehrend der Score daneben "widerspruechlich"
        # sagte.
        regel_ids = {k for k, _ in analyze_structure(facts).findings}
        self._add_sender(facts, unbacked="MAIL_AUTH_CLAIM_UNBACKED" in regel_ids)
        vorschau = render_mail(facts)
        if not vorschau:
            self._add(
                "Die Datei enthaelt keine lesbaren Maildaten. Scannen Sie sie, "
                "um zu sehen, was sie ist."
            )
            return
        self._add(vorschau)

    def _add_sender(self, facts, *, unbacked: bool = False) -> None:
        """Derselbe Absender-Block wie im Ergebnis-Panel."""
        verdict = sender_verdict(facts)
        score = sender_score(
            facts.auth_verdicts,
            verdict,
            claim_unbacked=unbacked,
            has_from=bool(facts.from_addr),
        )
        farbe = RISK_COLORS[score.color]
        mark = RISK_MARKS[score.color]

        self._add(pick("Absender", "Sender", "Gönderici"), heading=True)
        zeile = QLabel(mask_invisible(f"{mark}  {score.label}"))
        zeile.setStyleSheet(
            f"color: {farbe}; font-size: {FONT_SUBTITLE}; font-weight: 700;"
        )
        self._layout.addWidget(zeile)

        for grund in score.reasons:
            self._add("• " + grund)
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
            self._add(
                f"    {name}: "
                + mechanism_label(facts.auth_verdicts.get(key, ""), claimed=unbacked)
            )

    def _add(self, text: str, *, heading: bool = False) -> None:
        label = QLabel(mask_invisible(text))
        label.setObjectName("panelHeading" if heading else "panelValue")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._layout.addWidget(label)
