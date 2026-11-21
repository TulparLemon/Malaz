"""Der Optionen-Dialog: alles, was Malaz verlassen darf — an EINER Stelle.

WARUM DIESE DATEI EXISTIERT
===========================
In der Statusleiste standen drei Schalter nebeneinander ("ClamAV bei Start
aktualisieren", "Faehigkeits-Analyse (langsam)", "Datenbanken bei Start
nachladen"), und mit SPF/DMARC ueber DNS kaeme ein vierter. Vier Kaestchen in
einer Leiste sind keine Uebersicht mehr, sondern ein Band.

Der Nutzer hat es so verlangt: *"wir sollten ein separates Optionen menue
haben"*. Hier stehen sie gruppiert, mit dem, was jeweils hinausgeht.

WARUM DER DIALOG DIE KAESTCHEN NICHT SELBST BESITZT
===================================================
Die Schalter bleiben QCheckBox-Objekte des Hauptfensters und werden hier nur
EINGEHAENGT. Qt haengt ein Widget beim ``addWidget`` um, das Objekt bleibt
dasselbe. Damit gibt es den Zustand weiterhin genau einmal
(``window.chk_capa``), und der Dialog ist reine Darstellung — zwei Orte mit
eigenem Zustand waeren zwei Wahrheiten.

DIE GRUPPE "NETZWERK" IST DIE WICHTIGSTE
========================================
Malaz ist offline. Jeder Haken dort ist die Erlaubnis, das zu aendern, und
jeder traegt im Text, WAS hinausgeht:

* ClamAV-Signaturen — die Anfrage selbst.
* Datenbanken — die Anfrage selbst.
* SPF/DMARC — der Domainname der geprueften Mail an den DNS-Resolver.

Der letzte ist der einzige, der einen Bezug zur ANALYSIERTEN DATEI herstellt.
Deshalb steht er getrennt und mit eigener Begruendung.
"""

from __future__ import annotations

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
from ..i18n import pick, t
from .display import clamp_dialog_to_screen


def _gruppe(titel: str, hinweis: str) -> tuple[QFrame, QVBoxLayout]:
    """Ein gerahmter Abschnitt mit Ueberschrift und einem Satz Begruendung."""
    rahmen = QFrame()
    rahmen.setObjectName("card")
    layout = QVBoxLayout(rahmen)
    layout.setContentsMargins(16, 12, 16, 12)
    layout.setSpacing(8)

    kopf = QLabel(titel)
    kopf.setObjectName("panelKey")
    layout.addWidget(kopf)

    text = QLabel(hinweis)
    text.setWordWrap(True)
    text.setObjectName("panelValue")
    layout.addWidget(text)
    return rahmen, layout


class OptionsDialog(QDialog):
    """Die Opt-ins, gruppiert nach Netzwerk und Analyse.

    Die Schalter kommen von aussen herein (siehe Modul-Kopf): dieser Dialog
    liest und setzt keinen eigenen Zustand.
    """

    def __init__(self, parent: QWidget | None = None, *, switches: dict | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(t("options.dialog_title"))
        clamp_dialog_to_screen(self, preferred_w=680, preferred_h=620)
        self._switches = switches or {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(8)

        kopf = QLabel(
            pick(
                "Malaz arbeitet offline. Alles, was eine Verbindung nach außen "
                "aufbaut, steht unten unter „Netzwerk“ und ist standardmäßig aus.",
                "Malaz runs offline by default. Everything that opens a network connection "
                "is listed under Network below and disabled by default.",
                "Malaz varsayılan olarak tamamen çevrimdışı çalışır. Ağ bağlantısı gerektiren "
                "tüm seçenekler aşağıda listelenir ve varsayılan olarak kapalıdır.",
            )
        )
        kopf.setWordWrap(True)
        kopf.setObjectName("panelValue")
        outer.addWidget(kopf)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        self._layout = QVBoxLayout(body)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        self._build_network()
        self._build_analysis()
        self._build_output()

        schliessen = QPushButton(t("btn.close"))
        schliessen.clicked.connect(self.accept)
        unten = QHBoxLayout()
        unten.addStretch(1)
        unten.addWidget(schliessen)
        outer.addLayout(unten)

    # -- Netzwerk ---------------------------------------------------------- #

    def _build_network(self) -> None:
        rahmen, layout = _gruppe(
            pick("Netzwerk", "Network", "Ağ"),
            pick(
                "Jeder Haken hier erlaubt Malaz eine Verbindung nach aussen. Ohne "
                "Haken findet die jeweilige Prüfung nicht statt — und der Bericht "
                "sagt das dann auch, statt sie als sauber auszugeben.",
                "Each toggle here allows Malaz to open an outbound connection. When "
                "disabled, the check does not run — and reports state that honestly "
                "instead of showing it as clean.",
                "Buradaki her seçenek Malaz'ın dış ağ bağlantısı açmasına izin verir. "
                "Kapalıysa ilgili kontrol çalışmaz ve rapor bunu temiz göstermek "
                "yerine açıkça belirtir.",
            ),
        )
        for schluessel in ("clam_auto", "feeds_auto", "dns_auth"):
            kaestchen = self._switches.get(schluessel)
            if kaestchen is not None:
                layout.addWidget(kaestchen)
        layout.addWidget(self._dns_hinweis())
        self._layout.addWidget(rahmen)

    def _dns_hinweis(self) -> QWidget:
        """Die Begruendung, die der DNS-Haken selbst nicht tragen kann."""
        text = QLabel(
            pick(
                "SPF/DMARC über DNS ist der einzige Haken, der einen Bezug zur "
                "analysierten Datei herstellt: der Domainname aus der Mail geht an "
                "den DNS-Server. Ein gefälschter Eintrag macht aus einer ehrlichen "
                "Lücke eine gelogene Bestätigung — deshalb wird nur gemeldet, was "
                "wirklich geprüft wurde, und ein fehlgeschlagener Abruf heisst "
                "„unbekannt“, nie „sauber“. Die DKIM-Signatur und die DNSSEC-Kette "
                "werden NICHT geprüft.",
                "SPF/DMARC via DNS is the only toggle related to scanned files: the "
                "sender domain from the email is queried at your DNS resolver. Failed "
                "lookups always report 'unknown', never 'clean'. DKIM signatures and "
                "DNSSEC are NOT verified.",
                "DNS üzerinden SPF/DMARC, taranan dosyayla ilişkili tek seçenektir: "
                "e-postadaki gönderici alan adı DNS sunucunuza sorgulanır. Başarısız "
                "sorgular asla 'temiz' değil, her zaman 'bilinmiyor' olarak bildirilir. "
                "DKIM imzası ve DNSSEC denetlenmez.",
            )
        )
        text.setWordWrap(True)
        text.setObjectName("mutedLabel")
        return text

    # -- Ausgabe ----------------------------------------------------------- #

    def _build_output(self) -> None:
        rahmen, layout = _gruppe(
            pick("Ausgabe", "Output", "Çıktı"),
            pick(
                "Nur Darstellung und Ablage. Der Report bleibt lokal, solange Sie "
                "ihn nicht selbst weitergeben.",
                "Display and storage only. Reports stay local unless you share them yourself.",
                "Yalnızca görünüm ve kayıt ayarları. Siz paylaşmadıkça raporlar yerel kalır.",
            ),
        )
        kaestchen = self._switches.get("auto_open")
        if kaestchen is not None:
            layout.addWidget(kaestchen)
        self._layout.addWidget(rahmen)

    # -- Analyse ----------------------------------------------------------- #

    def _build_analysis(self) -> None:
        rahmen, layout = _gruppe(
            pick("Analyse", "Analysis", "Analiz"),
            pick(
                "Rein lokal. Diese Schalter ändern nur, wie gründlich geprüft wird "
                "— nicht, ob etwas das Gerät verlässt.",
                "Strictly local. These toggles only adjust inspection depth — "
                "nothing ever leaves this device.",
                "Tamamen yereldir. Bu seçenekler yalnızca analiz derinliğini değiştirir; "
                "hiçbir veri cihazınızdan çıkmaz.",
            ),
        )
        kaestchen = self._switches.get("capa")
        if kaestchen is not None:
            layout.addWidget(kaestchen)
        hinweis = QLabel(
            pick(
                "Die Fähigkeits-Analyse prüft, WAS ein Programm tun KÖNNTE "
                "(Verschlüsselung, Netzwerk, Prozessstart). Sie ist der langsamste "
                "Schritt; ohne sie sagt der Bericht, dass sie nicht gelaufen ist.",
                "Capability analysis inspects WHAT an executable could do "
                "(encryption, networking, process launch). It is the slowest stage; "
                "when disabled, reports note that it did not run.",
                "Davranış analizi bir programın NELER yapabileceğini inceler "
                "(şifreleme, ağ erişimi, işlem başlatma). En yavaş aşamadır; "
                "kapalıyken rapor bu adımın çalışmadığını belirtir.",
            )
        )
        hinweis.setWordWrap(True)
        hinweis.setObjectName("mutedLabel")
        layout.addWidget(hinweis)
        self._layout.addWidget(rahmen)

        # Der Stand der Datenbanken gehoert zum Verstaendnis dazu: ohne
        # Regeln findet auch die beste Analyse nichts.
        stand, layout2 = _gruppe(
            pick("Datenbanken", "Databases", "Veritabanları"),
            pick(
                "Was gerade an Regeln und Listen vorliegt. Nachladen holt nur, was "
                "fehlt; die Dateien bleiben auf diesem Rechner.",
                "Currently installed rules and blocklists. Updates only fetch missing "
                "data; all files remain local on this PC.",
                "Şu anda kurulu olan kurallar ve engelleme listeleri. Güncellemeler "
                "yalnızca eksikleri indirir; tüm dosyalar bu bilgisayarda kalır.",
            ),
        )
        self._db_label = QLabel("…")
        self._db_label.setWordWrap(True)
        self._db_label.setObjectName("panelValue")
        layout2.addWidget(self._db_label)
        self._layout.addWidget(stand)
        self._refresh_databases()

    def _refresh_databases(self) -> None:
        """Den Stand der vier Listen nennen — ohne sie zu laden."""
        from pathlib import Path

        missing_lbl = pick("nicht vorhanden", "not present", "mevcut değil")
        zeilen = []
        for name, pfad in (
            (pick("Datei-Hashes", "File hashes", "Dosya özetleri"), Path(config.USER_HASH_BLOCKLIST_FILE)),
            (pick("Schad-URLs", "Malicious URLs", "Zararlı URL'ler"), Path(config.URL_BLOCKLIST_FILE)),
            (
                pick("Absender-Domains", "Sender domains", "Gönderen alan adları"),
                Path(config.DOMAIN_BLOCKLIST_FILE),
            ),
            (
                pick("Absender-Netze", "Sender networks", "Gönderen IP ağları"),
                Path(config.IP_BLOCKLIST_FILE),
            ),
        ):
            if pfad.is_file():
                groesse = pfad.stat().st_size
                zeilen.append(f"{name}: {groesse / 1024:.0f} KB")
            else:
                zeilen.append(f"{name}: {missing_lbl}")
        self._db_label.setText(" | ".join(zeilen))

    def refresh(self) -> None:
        """Den angezeigten Datenbankstand neu einlesen.

        Der Dialog wird EINMAL gebaut und behalten (siehe main_window); ohne
        diese Auffrischung zeigte er bis zum Neustart den Stand vom Aufbau —
        genau dann falsch, wenn der Nutzer ihn nach einem Import oeffnet
        (BUG-057).
        """
        self._refresh_databases()

    def showEvent(self, event) -> None:
        # Auch beim Schliessen/Wieder-Oeffnen lesen: der Dialog kann offen
        # geblieben sein, waehrend im Hintergrund Listen nachgeladen wurden.
        super().showEvent(event)
        self._refresh_databases()
