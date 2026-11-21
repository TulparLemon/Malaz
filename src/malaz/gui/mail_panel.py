"""Das E-Mail-Panel: Absender, Links und Inhalt — nur fuer Mails.

WARUM DIESE DATEI EXISTIERT
===========================
Das Absender-Urteil stand bisher im Fliesstext des Detailfelds, zwischen
"Hinweis" und "Technische Details". Wer wissen wollte, ob der Absender echt
ist, musste es suchen.

Die Recherche zu dieser Aenderung ergab, was ein Laie tatsaechlich braucht
(Quellen: Gmail-Sicherheitsdetails, Microsoft-Anti-Phishing-Hinweise,
Hornetsecurity-Sperrgrund "impersonation attempt", CISA-Phishing-Leitfaden):

* **EIN Absender-Urteil, nicht drei Kuerzel.** Gmail zeigt ein "?" neben dem
  Absender und im Detail "Mailed by"/"Signed by"; Microsoft ein "(?)". SPF,
  DKIM und DMARC einzeln nebeneinander sind Fachwissen — sie stehen hier
  deshalb im zweiten Abschnitt, nicht in der Kopfzeile.
* **Anzeigename gegen echte Adresse**, mit Warnung bei Abweichung. Genau
  diesen Fall sperren Gateways als "impersonation attempt".
* **Handlungssatz in Alltagssprache.**
* **Links einzeln bewertet**, nicht als "irgendwo ist ein kurzer Link".

SICHTBARKEIT
============
Das Panel wird NUR gefuellt, wenn das Ergebnis eine Mail ist (oder eine
enthaelt). Ein Panel voller Platzhalter fuer eine PDF-Datei waere Rauschen —
der Reiter wird in dem Fall gar nicht erst angeboten (siehe main_window).

BEWUSST NICHT KLICKBAR
======================
Die Links sind Text, keine Schaltflaechen. Ein Klick waere ein Beacon an den
Absender — dieselbe Ueberlegung wie beim Mail-Viewer, der aus demselben Grund
kein HTML rendert.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.mail_score import link_scores, mechanism_label, sender_score
from ..core.mail_view import MAX_DISPLAY_CHARS, _clip
from ..i18n import pick
from ..models import ScanResult
from ..security.escaping import mask_invisible
from .theme import FONT_SUBTITLE, RISK_COLORS, RISK_MARKS

# Ab hier gilt ein Link als vorzeigenswert. Ein Link ohne jedes Merkmal wird
# nicht aufgelistet: eine Werbe-Mail hat hundert davon, und die Liste soll die
# gefaehrlichen zeigen, nicht die Menge.
_LINK_MIN_SCORE = 1
# So viele Links stehen hoechstens im Panel. Die Grenze gilt NACH dem Filter:
# vorher kuerzte ``link_scores`` die Liste, BEVOR die harmlosen Links
# aussortiert waren — 30 auffaellige Shortener ergaben "Links (25 auffaellig)"
# und keinen Hinweis auf die fehlenden fuenf (BUG-062).
_LINK_DISPLAY_LIMIT = 25

# Die Ueberschriften, die ``core.mail_view.render_mail`` auf Spalte 0 setzt.
# Der Rumpf steht eingerueckt darunter; nur eine Zeile OHNE Einrueckung kann
# daher eine Abschnittsueberschrift sein.
_BODY_HEADING = "Textinhalt"
_BODY_ENDINGS = ("Enthaltene Links", "Anhänge", "Hinweis:")


def is_mail(result: ScanResult) -> bool:
    """Ist dieses Ergebnis eine Mail — es selbst oder etwas darin?

    Eine .eml in einem ZIP ist genau der Fall, den ein Laie uebersieht: der
    Reiter muss auch dann erscheinen, wenn die Mail verschachtelt ist.
    """
    if result.detected_type in ("eml", "msg") or result.mail_security:
        return True
    return any(is_mail(child) for child in result.children)


def _masked(text: str) -> str:
    """Anzeigetext entschaerfen — die EINE Stelle, an der das Panel das tut.

    Linkziel, Anzeigename und Anhangsname sind angreiferkontrolliert. Qt wendet
    den Bidi-Algorithmus auf QLabel-Text an: aus "rechnung<U+202E>gpj.exe" wird
    beim Zeichnen "rechnungexe.jpg", und der Nutzer liest eine harmlose Adresse
    fuer eine bosartige. Gemessen: zwei Labels zeigten das Zeichen unmaskiert.

    Das Projekt maskiert aus genau diesem Grund an fuenf Stellen in
    main_window. Ein neues Panel muss dieselbe Senke benutzen — nicht eine
    eigene Kopie der Regel, sondern mask_invisible selbst.

    MASKIEREN, NICHT ENTFERNEN: das Zeichen wird als \u202e sichtbar gemacht.
    Entfernen wuerde genau den Trick verbergen, den die Analyse meldet.
    """
    return mask_invisible(text)


def _plain_label(text: str) -> QLabel:
    """QLabel mit ERZWUNGENEM Klartext — kein Rich-Text, keine Bild-URLs.

    QLabel raet den Textformat-Modus (AutoText). Ein Mailrumpf oder
    Anhangsname mit ``<img src=file:///...>`` wurde deshalb als HTML
    gerendert, und Qt lud die lokale Datei — gemessen 20 000 rote Pixel im
    Panel. Der Inhalt einer Mail ist immer Text; er wird hier auch so
    gesetzt. Das Format steht VOR dem Text, damit keine Auto-Erkennung
    dazwischenfunkt.
    """
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setText(_masked(text))
    return label


def _has_from(security: dict) -> bool:
    """Nennt die Mail tatsaechlich einen Absender?

    Der Marker kommt aus dem Parser (``mail_security["has_from"]``). Fehlt
    er — aeltere Ergebnisse oder ein nicht erreichbarer Produzent —, gilt
    weiter das bisherige Verhalten (Absender vorhanden). ``bool(security)``
    ist jedenfalls KEIN Nachweis: das Dict ist bei jeder Mail gefuellt, und
    der Zweig "Kein Absender" war damit unerreichbar (70/GELB statt 0/ROT).
    """
    marker = security.get("has_from")
    if marker is None:
        return True
    return str(marker).strip().lower() not in ("", "0", "false")


def _heading(text: str) -> QLabel:
    label = _plain_label(text)
    label.setObjectName("panelHeading")
    return label


def _kv(label: str, value: str, color: str | None = None) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    key = _plain_label(label)
    key.setObjectName("panelKey")
    key.setFixedWidth(132)
    key.setAlignment(Qt.AlignLeft | Qt.AlignTop)
    val = _plain_label(value)
    val.setObjectName("panelValue")
    val.setWordWrap(True)
    val.setTextInteractionFlags(Qt.TextSelectableByMouse)
    if color:
        val.setStyleSheet(f"color: {color}; font-weight: 600;")
    layout.addWidget(key)
    layout.addWidget(val, 1)
    return row


class MailPanel(QScrollArea):
    """Der Inhalt des E-Mail-Reiters."""

    def __init__(self) -> None:
        super().__init__()
        self._last_result: ScanResult | None = None
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self._body = QWidget()
        self._layout = QVBoxLayout(self._body)
        self._layout.setContentsMargins(16, 12, 16, 12)
        self._layout.setSpacing(8)
        self.setWidget(self._body)

    def clear(self) -> None:
        self._last_result = None
        _clear_layout(self._layout)

    def retranslate(self) -> None:
        if self._last_result is not None:
            self.show_result(self._last_result)

    def show_result(self, result: ScanResult) -> None:
        """Panel fuer ein Ergebnis aufbauen."""
        self.clear()
        self._last_result = result

        mail = _find_mail(result)
        if mail is None:
            self._layout.addWidget(
                _plain_label(
                    pick(
                        "Dieses Ergebnis enthält keine E-Mail.",
                        "This result does not contain an email.",
                        "Bu sonuç bir e-posta içermiyor.",
                    )
                )
            )
            self._layout.addStretch(1)
            return

        self._add_sender(mail)
        self._add_content(mail)
        self._add_links(mail)
        self._add_attachments(mail)
        self._layout.addStretch(1)

    # -- Abschnitt 1: der Absender ---------------------------------------- #

    def _add_sender(self, result: ScanResult) -> None:
        security = result.mail_security
        rules = {ind.rule_id for ind in result.all_indicators()}
        score = sender_score(
            security,
            security.get("sender", "unknown"),
            claim_unbacked="MAIL_AUTH_CLAIM_UNBACKED" in rules,
            has_from=_has_from(security),
        )

        self._layout.addWidget(_heading(pick("Absender", "Sender", "Gönderici")))
        color = RISK_COLORS[score.color]
        mark = RISK_MARKS[score.color]

        # EIN Urteil, gross und mit Zeichen — nicht drei Kuerzel.
        verdict = _plain_label(f"{mark}  {score.label}")
        verdict.setStyleSheet(f"color: {color}; font-size: {FONT_SUBTITLE}; font-weight: 700;")
        verdict.setWordWrap(True)
        self._layout.addWidget(verdict)

        for reason in score.reasons:
            self._layout.addWidget(_kv("", "• " + reason))

        # Erst danach die Einzelmechanismen: Fachwissen, aber vollstaendig.
        unbacked = "MAIL_AUTH_CLAIM_UNBACKED" in rules
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
            verdict_text = mechanism_label(security.get(key, ""), claimed=unbacked)
            farbe = RISK_COLORS["red"] if "FEHLGESCHLAGEN" in verdict_text else None
            self._layout.addWidget(_kv(name, verdict_text, farbe))

        self._layout.addWidget(
            _kv(
                pick("Quelle", "Source", "Kaynak"),
                pick(
                    "Kopfzeilen der Datei — NICHT nachgeprüft. In einer Datei "
                    "kann der Absender diese Angaben selbst geschrieben haben.",
                    "File headers — NOT verified against live DNS. A sender can "
                    "forge header fields inside a raw .eml file.",
                    "Dosya başlıkları — canlı DNS ile DOĞRULANMADI. Ham bir .eml dosyasında "
                    "gönderici bu alanları kendisi yazmış olabilir.",
                ),
            )
        )

    # -- Abschnitt 2: der Inhalt ------------------------------------------ #

    def _add_content(self, result: ScanResult) -> None:
        if not result.mail_preview:
            return
        # Der Vorschautext ist bereits fertig gerendert und maskiert
        # (core/mail_view). Hier wird nichts neu geparst.
        body = _body_only(result.mail_preview)
        # Eine Mail nur mit Anhaengen hat KEINEN Textteil. Ohne diesen Ausstieg
        # stand eine leere Ueberschrift "Inhalt" ueber der Anhangsliste
        # (BUG-061).
        if not body:
            return
        self._layout.addWidget(_heading(pick("Inhalt", "Body", "İçerik")))
        text = _plain_label(body)
        text.setObjectName("panelValue")
        text.setWordWrap(True)
        text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._layout.addWidget(text)

    # -- Abschnitt 3: die Links ------------------------------------------- #

    def _add_links(self, result: ScanResult) -> None:
        links = getattr(result, "mail_links", None)
        if links is None:
            return
        # ERST alle bewerten und filtern, DANN begrenzen. Die Begrenzung in
        # ``link_scores`` schnitt vorher zuerst ab; bei 30 auffaelligen Links
        # fehlten fuenf, ohne dass es dastand (BUG-062).
        scored = [entry for entry in link_scores(links, limit=len(links)) if entry.score >= _LINK_MIN_SCORE]
        if not scored:
            return

        sichtbar = scored[:_LINK_DISPLAY_LIMIT]
        self._layout.addWidget(
            _heading(
                pick(
                    f"Links ({len(scored)} auffaellig)",
                    f"Links ({len(scored)} suspicious)",
                    f"Bağlantılar ({len(scored)} şüpheli)",
                )
            )
        )
        for entry in sichtbar:
            color = RISK_COLORS[entry.color]
            mark = RISK_MARKS[entry.color]
            zeile = _plain_label(f"{mark}  {_clip(entry.host, MAX_DISPLAY_CHARS)}  —  {entry.label}")
            zeile.setStyleSheet(f"color: {color}; font-weight: 600;")
            zeile.setWordWrap(True)
            self._layout.addWidget(zeile)
            for reason in entry.reasons:
                self._layout.addWidget(_kv("", "• " + reason))
            self._layout.addWidget(_kv("", _clip(entry.link.url, MAX_DISPLAY_CHARS)))

        weitere = len(scored) - len(sichtbar)
        if weitere:
            self._layout.addWidget(
                _plain_label(
                    pick(
                        f"… und {weitere} weitere auffaellige Links",
                        f"… and {weitere} more suspicious links",
                        f"… ve {weitere} şüpheli bağlantı daha",
                    )
                )
            )

    # -- Abschnitt 4: die Anhaenge ---------------------------------------- #

    def _add_attachments(self, result: ScanResult) -> None:
        if not result.children:
            return
        self._layout.addWidget(
            _heading(
                pick(
                    f"Anhaenge ({len(result.children)}) — einzeln geprueft",
                    f"Attachments ({len(result.children)}) — scanned individually",
                    f"Ekler ({len(result.children)}) — ayrı ayrı tarandı",
                )
            )
        )
        for child in result.children:
            farbe = RISK_COLORS[child.risk_level.name.lower()]
            mark = RISK_MARKS[child.risk_level.name.lower()]
            zeile = _plain_label(
                f"{mark}  {_clip(child.display_name, MAX_DISPLAY_CHARS)}  —  "
                f"{child.risk_level.short} ({child.score}/100)"
            )
            zeile.setStyleSheet(f"color: {farbe};")
            zeile.setWordWrap(True)
            self._layout.addWidget(zeile)


def _find_mail(result: ScanResult) -> ScanResult | None:
    """Die erste Mail in diesem Ergebnis (es selbst oder ein Kind)."""
    if result.detected_type in ("eml", "msg") or result.mail_security:
        return result
    for child in result.children:
        found = _find_mail(child)
        if found is not None:
            return found
    return None


def _body_only(preview: str) -> str:
    """Aus der Vorschau nur den Textteil — Kopfzeilen stehen oben schon.

    Die Vorschau beginnt mit "Kopfzeilen", dann folgen Abschnitte. Ohne diese
    Trennung staenden Betreff und Authentifizierung zweimal auf dem Schirm.

    Geschnitten wird ZWISCHEN ``Textinhalt`` und der naechsten Ueberschrift,
    nicht bis zum Ende: sonst wiederholte "Inhalt" die Rohabschnitte
    "Enthaltene Links" und "Anhänge", die das Panel gleich darauf selbst
    zeigt. Die END-Ueberschriften erkennt nur eine Zeile OHNE Einrueckung —
    ``render_mail`` rueckt jede Rumpfzeile um zwei Leerzeichen ein, damit ein
    Body, der zufaellig mit "Anhänge" beginnt, den Schnitt nicht ausloest.
    """
    zeilen = preview.splitlines()
    start = None
    for index, zeile in enumerate(zeilen):
        if zeile.strip() == _BODY_HEADING:
            start = index + 1
            break
    if start is None:
        return ""
    rumpf: list[str] = []
    for zeile in zeilen[start:]:
        if zeile.startswith(_BODY_ENDINGS):
            break
        rumpf.append(zeile)
    return "\n".join(rumpf).strip()


def _clear_layout(layout) -> None:
    """Alle Kind-Widgets entfernen — Qt hat dafuer kein eingebautes Mittel."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
        elif item.layout() is not None:
            _clear_layout(item.layout())
