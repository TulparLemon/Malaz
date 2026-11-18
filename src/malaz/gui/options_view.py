"""Integrated Options & Auto-Update view for Malaz v11 ("Klare Fläche v2").

Contains all real Malaz opt-in network switches (clam_auto, feeds_auto,
dns_auth), manual update triggers (ClamAV, YARA, FeedsDialog), local analysis
switches (capa, session-only static_only, auto_open), theme switcher
(Dunkel / Hell / System), and live local engine status rows.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .. import config
from .sanitize import clip_text, escape_tooltip, masked_widget_text
from .theme import apply_theme, saved_theme_preference


def _section_header(
    title: str, right_text: str = "", parent: QWidget | None = None
) -> tuple[QWidget, QLabel]:
    bar = QWidget(parent)
    lay = QHBoxLayout(bar)
    lay.setContentsMargins(0, 4, 0, 2)
    lbl = QLabel(title.upper(), bar)
    lbl.setObjectName("sectionTitle")
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lay.addWidget(lbl, 1)
    r_lbl = QLabel(right_text, bar)
    r_lbl.setObjectName("captionLabel")
    r_lbl.setTextFormat(Qt.TextFormat.PlainText)
    lay.addWidget(r_lbl)
    return bar, r_lbl


def _option_row(
    key: str,
    desc: str,
    control: QWidget,
    *,
    is_last: bool = False,
    parent: QWidget | None = None,
) -> tuple[QFrame, QLabel]:
    row = QFrame(parent)
    row.setObjectName("listRow")
    row.setProperty("last", "true" if is_last else "false")
    row.setMinimumHeight(44)
    lay = QHBoxLayout(row)
    lay.setContentsMargins(16, 8, 16, 8)
    lay.setSpacing(14)

    k_lbl = QLabel(key, row)
    k_lbl.setObjectName("panelHeading")
    k_lbl.setMinimumWidth(175)
    k_lbl.setMaximumWidth(210)
    k_lbl.setTextFormat(Qt.TextFormat.PlainText)
    lay.addWidget(k_lbl)

    d_lbl = QLabel(desc, row)
    d_lbl.setObjectName("mutedLabel")
    d_lbl.setWordWrap(True)
    d_lbl.setTextFormat(Qt.TextFormat.PlainText)
    lay.addWidget(d_lbl, 1)

    lay.addWidget(control, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return row, d_lbl


class OptionsView(QWidget):
    """Integrated Options, Auto-Update, and Local Engine Status panel."""

    close_requested = Signal()
    update_clamav_requested = Signal()
    update_yara_requested = Signal()
    feeds_requested = Signal()
    refresh_engines_requested = Signal()
    theme_changed = Signal(str)

    def __init__(
        self,
        switches: dict[str, QCheckBox],
        *,
        show_header: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._switches = switches
        self._engine_rows: list[tuple[str, str, bool]] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        if show_header:
            hdr = QHBoxLayout()
            hdr.setContentsMargins(0, 0, 0, 4)
            title = QLabel("Optionen & Auto-Update", self)
            title.setObjectName("fileTitle")
            title.setTextFormat(Qt.TextFormat.PlainText)
            hdr.addWidget(title, 1)
            btn_close = QPushButton("Schließen", self)
            btn_close.clicked.connect(self.close_requested.emit)
            hdr.addWidget(btn_close)
            root.addLayout(hdr)

        net_hdr, self._net_status_lbl = _section_header(
            "Auto-Update & Netzwerk (Opt-in)",
            "Standardmäßig komplett offline",
            parent=self,
        )
        root.addWidget(net_hdr)

        net_card = QFrame(self)
        net_card.setObjectName("card")
        net_lay = QVBoxLayout(net_card)
        net_lay.setContentsMargins(0, 0, 0, 0)
        net_lay.setSpacing(0)

        if "clam_auto" in switches:
            r, _ = _option_row(
                "ClamAV Auto-Update",
                "ClamAV-Virensignaturen beim Programmstart automatisch aktualisieren",
                switches["clam_auto"],
                parent=net_card,
            )
            net_lay.addWidget(r)
            switches["clam_auto"].toggled.connect(self._update_net_badge)

        if "feeds_auto" in switches:
            r, _ = _option_row(
                "Sperrlisten Auto-Update",
                "YARA-Regeln & lokale Sperrlisten beim Start automatisch nachladen",
                switches["feeds_auto"],
                parent=net_card,
            )
            net_lay.addWidget(r)
            switches["feeds_auto"].toggled.connect(self._update_net_badge)

        if "dns_auth" in switches:
            r, _ = _option_row(
                "SPF / DMARC über DNS",
                "Absender-Domain geprüfter E-Mails live beim DNS-Server abfragen (DKIM/DNSSEC nicht geprüft)",
                switches["dns_auth"],
                parent=net_card,
            )
            net_lay.addWidget(r)
            switches["dns_auth"].toggled.connect(self._update_net_badge)

        upd_btns = QWidget(net_card)
        ub_lay = QHBoxLayout(upd_btns)
        ub_lay.setContentsMargins(0, 0, 0, 0)
        ub_lay.setSpacing(6)
        self.btn_clam_now = QPushButton("ClamAV", upd_btns)
        self.btn_clam_now.clicked.connect(self.update_clamav_requested.emit)
        self.btn_yara_now = QPushButton("YARA", upd_btns)
        self.btn_yara_now.clicked.connect(self.update_yara_requested.emit)
        self.btn_feeds_now = QPushButton("Sperrlisten…", upd_btns)
        self.btn_feeds_now.clicked.connect(self.feeds_requested.emit)
        ub_lay.addWidget(self.btn_clam_now)
        ub_lay.addWidget(self.btn_yara_now)
        ub_lay.addWidget(self.btn_feeds_now)

        manual_row, self._db_label = _option_row(
            "Manuelles Update",
            "…",
            upd_btns,
            is_last=True,
            parent=net_card,
        )
        net_lay.addWidget(manual_row)
        root.addWidget(net_card)

        loc_hdr, _ = _section_header("Analyse & Darstellung (Lokal)", parent=self)
        root.addWidget(loc_hdr)

        loc_card = QFrame(self)
        loc_card.setObjectName("card")
        loc_lay = QVBoxLayout(loc_card)
        loc_lay.setContentsMargins(0, 0, 0, 0)
        loc_lay.setSpacing(0)

        if "capa" in switches:
            r, _ = _option_row(
                "Fähigkeits-Analyse",
                "Tiefe Verhaltensprüfung (capa) für Programme aktivieren (langsamer)",
                switches["capa"],
                parent=loc_card,
            )
            loc_lay.addWidget(r)

        if "static_only" in switches:
            r, _ = _option_row(
                "Nur-Statik-Modus",
                "Pausiert Defender & ClamAV für diese Sitzung (verhindert Quarantäne bei Forensik-Proben)",
                switches["static_only"],
                parent=loc_card,
            )
            loc_lay.addWidget(r)

        if "auto_open" in switches:
            r, _ = _option_row(
                "Bericht automatisch öffnen",
                "Exportierten HTML-/PDF-Bericht direkt nach dem Speichern anzeigen",
                switches["auto_open"],
                parent=loc_card,
            )
            loc_lay.addWidget(r)

        self._btn_theme = QPushButton(self._theme_button_label(), loc_card)
        self._btn_theme.setObjectName("copyButton")
        self._btn_theme.clicked.connect(self._cycle_theme)
        theme_row, _ = _option_row(
            "Oberflächen-Design",
            "Zwischen dunklem, hellem und System-Farbschema wechseln",
            self._btn_theme,
            is_last=True,
            parent=loc_card,
        )
        loc_lay.addWidget(theme_row)
        root.addWidget(loc_card)

        eng_hdr = QWidget(self)
        eh_lay = QHBoxLayout(eng_hdr)
        eh_lay.setContentsMargins(0, 4, 0, 2)
        el = QLabel("ERKANNTE LOKALE PRÜF-MODULE", eng_hdr)
        el.setObjectName("sectionTitle")
        eh_lay.addWidget(el, 1)
        btn_ref = QPushButton("Neu prüfen", eng_hdr)
        btn_ref.clicked.connect(self.refresh_engines_requested.emit)
        eh_lay.addWidget(btn_ref)
        root.addWidget(eng_hdr)

        self._eng_card = QFrame(self)
        self._eng_card.setObjectName("card")
        self._eng_lay = QVBoxLayout(self._eng_card)
        self._eng_lay.setContentsMargins(0, 0, 0, 0)
        self._eng_lay.setSpacing(0)
        root.addWidget(self._eng_card)
        root.addStretch(1)

        self._update_net_badge()
        self.refresh()

    def _theme_button_label(self) -> str:
        pref = saved_theme_preference()
        return {"dark": "Dunkel", "light": "Hell", "system": "System"}.get(pref, "Dunkel")

    def _cycle_theme(self) -> None:
        order = ("dark", "light", "system")
        cur = saved_theme_preference()
        nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "light"
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, nxt, persist=True)
        self._btn_theme.setText(self._theme_button_label())
        self.theme_changed.emit(nxt)

    def _update_net_badge(self) -> None:
        any_net = any(
            self._switches[k].isChecked()
            for k in ("clam_auto", "feeds_auto", "dns_auth")
            if k in self._switches
        )
        self._net_status_lbl.setText("Opt-in aktiv" if any_net else "Standardmäßig komplett offline")

    def set_engine_rows(self, rows: list[tuple[str, str, bool]], *, static_only: bool = False) -> None:
        self._engine_rows = list(rows)
        while self._eng_lay.count():
            ch = self._eng_lay.takeAt(0)
            if ch.widget() is not None:
                w = ch.widget()
                w.hide()
                w.setParent(None)
                w.deleteLater()

        for idx, (name, detail, avail) in enumerate(rows):
            paused = static_only and name.lower() in ("windows defender", "defender", "clamav")
            eff = avail and not paused
            row = QFrame(self._eng_card)
            row.setObjectName("listRow")
            row.setProperty("last", "true" if idx == len(rows) - 1 else "false")
            if eff:
                row.setProperty("accent", "ok")
            row.setMinimumHeight(44)

            rl = QHBoxLayout(row)
            rl.setContentsMargins(13, 8, 16, 8)
            rl.setSpacing(14)

            k_lbl = QLabel(name, row)
            k_lbl.setObjectName("panelHeading")
            k_lbl.setMinimumWidth(175)
            k_lbl.setMaximumWidth(210)
            k_lbl.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(k_lbl)

            sub = "Pausiert durch Nur-Statik-Modus" if paused else clip_text(masked_widget_text(detail), 90)
            v_lbl = QLabel(sub, row)
            v_lbl.setObjectName("mutedLabel")
            v_lbl.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(v_lbl, 1)

            badge = QLabel("Bereit" if eff else ("Pausiert" if paused else "Inaktiv"), row)
            badge.setObjectName("badgeRight")
            badge.setProperty("tone", "ok" if eff else "warn")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(badge)

            self._eng_lay.addWidget(row)

    def refresh(self, *, feed_badge_text: str = "", feed_tooltip: str = "") -> None:
        parts = []
        for name, pfad in (
            ("Datei-Hashes", Path(config.USER_HASH_BLOCKLIST_FILE)),
            ("Schad-URLs", Path(config.URL_BLOCKLIST_FILE)),
            ("Domains", Path(config.DOMAIN_BLOCKLIST_FILE)),
            ("Netze", Path(config.IP_BLOCKLIST_FILE)),
        ):
            if pfad.is_file():
                parts.append(f"{name}: {pfad.stat().st_size / 1024:.0f} KB")
            else:
                parts.append(f"{name}: fehlt")
        text = " · ".join(parts)
        if feed_badge_text:
            text = f"{feed_badge_text} · {text}"
        self._db_label.setText(text)
        if feed_tooltip:
            self._db_label.setToolTip(escape_tooltip(feed_tooltip, limit=1200))
        self._btn_theme.setText(self._theme_button_label())
        self._update_net_badge()

    def set_scanning(self, scanning: bool) -> None:
        for btn in (self.btn_clam_now, self.btn_yara_now, self.btn_feeds_now):
            btn.setEnabled(not scanning)
