"""Integrated Options & Auto-Update view for Malaz v11 ("Klare Fläche v2").

Contains all real Malaz opt-in network switches (clam_auto, feeds_auto,
dns_auth), manual update triggers (ClamAV, YARA, FeedsDialog), local analysis
switches (capa, session-only static_only, auto_open), theme switcher
(Dark / Light / System), language switcher (System / Deutsch / English),
and live local engine status rows.
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
from ..i18n import get_language, pick, t
from .sanitize import clip_text, escape_tooltip, masked_widget_text
from .settings import active_language_preference, apply_language
from .theme import apply_theme, saved_theme_preference


def _section_header(
    title: str, right_text: str = "", parent: QWidget | None = None
) -> tuple[QWidget, QLabel, QLabel]:
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
    return bar, lbl, r_lbl


def _option_row(
    key: str,
    desc: str,
    control: QWidget,
    *,
    is_last: bool = False,
    parent: QWidget | None = None,
) -> tuple[QFrame, QLabel, QLabel]:
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
    return row, k_lbl, d_lbl


class OptionsView(QWidget):
    """Integrated Options, Auto-Update, and Local Engine Status panel."""

    close_requested = Signal()
    update_clamav_requested = Signal()
    update_yara_requested = Signal()
    feeds_requested = Signal()
    refresh_engines_requested = Signal()
    theme_changed = Signal(str)
    language_changed = Signal(str)

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
        self._engine_static_only = False
        self._last_feed_badge = ""
        self._last_feed_tooltip = ""
        self._row_labels: dict[str, tuple[QLabel, QLabel]] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        self._hdr_title: QLabel | None = None
        self._btn_close: QPushButton | None = None
        if show_header:
            hdr = QHBoxLayout()
            hdr.setContentsMargins(0, 0, 0, 4)
            self._hdr_title = QLabel("", self)
            self._hdr_title.setObjectName("fileTitle")
            self._hdr_title.setTextFormat(Qt.TextFormat.PlainText)
            hdr.addWidget(self._hdr_title, 1)
            self._btn_close = QPushButton("", self)
            self._btn_close.clicked.connect(self.close_requested.emit)
            hdr.addWidget(self._btn_close)
            root.addLayout(hdr)

        net_hdr, self._net_sec_lbl, self._net_status_lbl = _section_header("", "", parent=self)
        root.addWidget(net_hdr)

        net_card = QFrame(self)
        net_card.setObjectName("card")
        net_lay = QVBoxLayout(net_card)
        net_lay.setContentsMargins(0, 0, 0, 0)
        net_lay.setSpacing(0)

        if "clam_auto" in switches:
            r, kl, dl = _option_row("", "", switches["clam_auto"], parent=net_card)
            self._row_labels["clam_auto"] = (kl, dl)
            net_lay.addWidget(r)
            switches["clam_auto"].toggled.connect(self._update_net_badge)

        if "feeds_auto" in switches:
            r, kl, dl = _option_row("", "", switches["feeds_auto"], parent=net_card)
            self._row_labels["feeds_auto"] = (kl, dl)
            net_lay.addWidget(r)
            switches["feeds_auto"].toggled.connect(self._update_net_badge)

        if "dns_auth" in switches:
            r, kl, dl = _option_row("", "", switches["dns_auth"], parent=net_card)
            self._row_labels["dns_auth"] = (kl, dl)
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
        self.btn_feeds_now = QPushButton("", upd_btns)
        self.btn_feeds_now.clicked.connect(self.feeds_requested.emit)
        ub_lay.addWidget(self.btn_clam_now)
        ub_lay.addWidget(self.btn_yara_now)
        ub_lay.addWidget(self.btn_feeds_now)

        manual_row, self._manual_key_lbl, self._db_label = _option_row(
            "", "…", upd_btns, is_last=True, parent=net_card
        )
        net_lay.addWidget(manual_row)
        root.addWidget(net_card)

        loc_hdr, self._loc_sec_lbl, _ = _section_header("", parent=self)
        root.addWidget(loc_hdr)

        loc_card = QFrame(self)
        loc_card.setObjectName("card")
        loc_lay = QVBoxLayout(loc_card)
        loc_lay.setContentsMargins(0, 0, 0, 0)
        loc_lay.setSpacing(0)

        if "capa" in switches:
            r, kl, dl = _option_row("", "", switches["capa"], parent=loc_card)
            self._row_labels["capa"] = (kl, dl)
            loc_lay.addWidget(r)

        if "static_only" in switches:
            r, kl, dl = _option_row("", "", switches["static_only"], parent=loc_card)
            self._row_labels["static_only"] = (kl, dl)
            loc_lay.addWidget(r)

        if "auto_open" in switches:
            r, kl, dl = _option_row("", "", switches["auto_open"], parent=loc_card)
            self._row_labels["auto_open"] = (kl, dl)
            loc_lay.addWidget(r)

        self._btn_theme = QPushButton("", loc_card)
        self._btn_theme.setObjectName("copyButton")
        self._btn_theme.clicked.connect(self._cycle_theme)
        theme_row, kl, dl = _option_row("", "", self._btn_theme, is_last=False, parent=loc_card)
        self._row_labels["theme"] = (kl, dl)
        loc_lay.addWidget(theme_row)

        self._btn_lang = QPushButton("", loc_card)
        self._btn_lang.setObjectName("copyButton")
        self._btn_lang.clicked.connect(self._cycle_language)
        lang_row, kl, dl = _option_row("", "", self._btn_lang, is_last=True, parent=loc_card)
        self._row_labels["language"] = (kl, dl)
        loc_lay.addWidget(lang_row)
        root.addWidget(loc_card)

        eng_hdr = QWidget(self)
        eh_lay = QHBoxLayout(eng_hdr)
        eh_lay.setContentsMargins(0, 4, 0, 2)
        self._eng_sec_lbl = QLabel("", eng_hdr)
        self._eng_sec_lbl.setObjectName("sectionTitle")
        self._eng_sec_lbl.setTextFormat(Qt.TextFormat.PlainText)
        eh_lay.addWidget(self._eng_sec_lbl, 1)
        self._btn_ref = QPushButton("", eng_hdr)
        self._btn_ref.clicked.connect(self.refresh_engines_requested.emit)
        eh_lay.addWidget(self._btn_ref)
        root.addWidget(eng_hdr)

        self._eng_card = QFrame(self)
        self._eng_card.setObjectName("card")
        self._eng_lay = QVBoxLayout(self._eng_card)
        self._eng_lay.setContentsMargins(0, 0, 0, 0)
        self._eng_lay.setSpacing(0)
        root.addWidget(self._eng_card)
        root.addStretch(1)

        self.retranslate()

    def _theme_button_label(self) -> str:
        pref = saved_theme_preference()
        return t(f"options.theme.{pref}")

    def _language_button_label(self) -> str:
        pref = active_language_preference()
        return t(f"options.language.{pref}")

    def _cycle_theme(self) -> None:
        order = ("dark", "light", "system")
        cur = saved_theme_preference()
        nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "light"
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, nxt, persist=True)
        self._btn_theme.setText(self._theme_button_label())
        self.theme_changed.emit(nxt)

    def _cycle_language(self) -> None:
        order = ("system", "de", "en", "tr")
        cur = active_language_preference()
        nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "en"
        apply_language(nxt, persist=True)
        self._btn_lang.setText(self._language_button_label())
        self.language_changed.emit(nxt)

    def _update_net_badge(self) -> None:
        any_net = any(
            self._switches[k].isChecked()
            for k in ("clam_auto", "feeds_auto", "dns_auth")
            if k in self._switches
        )
        self._net_status_lbl.setText(
            pick("Opt-in aktiv", "Opt-in active", "İsteğe bağlı ağ açık")
            if any_net
            else t("options.net_offline")
        )

    def retranslate(self) -> None:
        if self._hdr_title is not None:
            self._hdr_title.setText(t("options.title"))
        if self._btn_close is not None:
            self._btn_close.setText(t("btn.close"))
        self._net_sec_lbl.setText(
            pick(
                "AUTO-UPDATE & NETZWERK (OPT-IN)",
                "AUTO-UPDATE & NETWORK (OPT-IN)",
                "OTOMATİK GÜNCELLEME VE AĞ (İSTEĞE BAĞLI)",
            )
        )
        self._loc_sec_lbl.setText(
            pick(
                "ANALYSE & DARSTELLUNG (LOKAL)",
                "LOCAL ANALYSIS & APPEARANCE",
                "YEREL ANALİZ VE GÖRÜNÜM",
            )
        )
        self._eng_sec_lbl.setText(
            pick(
                "ERKANNTE LOKALE PRÜF-MODULE",
                "DETECTED LOCAL ANALYSIS ENGINES",
                "ALGILANAN YEREL TARAMA MOTORLARI",
            )
        )
        self._btn_ref.setText(pick("Neu prüfen", "Re-check", "Yeniden Kontrol Et"))
        self.btn_feeds_now.setText(pick("Sperrlisten…", "Blocklists…", "Listeler…"))
        self._manual_key_lbl.setText(t("options.manual_update.title"))

        row_map = {
            "clam_auto": (t("options.clam_auto.title"), t("options.clam_auto.desc")),
            "feeds_auto": (t("options.feeds_auto.title"), t("options.feeds_auto.desc")),
            "dns_auth": (
                pick("SPF / DMARC über DNS", "SPF / DMARC via DNS", "DNS ile SPF / DMARC"),
                pick(
                    "Absender-Domain geprüfter E-Mails live beim DNS-Server "
                    "abfragen (DKIM/DNSSEC nicht geprüft)",
                    "Query sender domain of scanned emails against live DNS (DKIM/DNSSEC not checked)",
                    "Taranan e-postaların gönderen alan adını canlı DNS üzerinden "
                    "sorgula (DKIM/DNSSEC denetlenmez)",
                ),
            ),
            "capa": (
                pick("Fähigkeits-Analyse", "Capability Analysis", "Yetenek Analizi (capa)"),
                pick(
                    "Tiefe Verhaltensprüfung (capa) für Programme aktivieren (langsamer)",
                    "Enable deep behavioral analysis (capa) for executables (slower)",
                    "Uygulamalar için derin davranış analizini (capa) aç (daha yavaş)",
                ),
            ),
            "static_only": (
                pick("Nur-Statik-Modus", "Static-Only Mode", "Yalnızca Statik Mod"),
                pick(
                    "Pausiert Defender & ClamAV für diese Sitzung "
                    "(verhindert Quarantäne bei Forensik-Proben)",
                    "Pauses Defender & ClamAV for this session (prevents quarantine on forensic samples)",
                    "Bu oturum için Defender ve ClamAV taramasını duraklatır "
                    "(örneklerin karantinaya alınmasını önler)",
                ),
            ),
            "auto_open": (
                pick("Bericht automatisch öffnen", "Auto-open Report", "Raporu Otomatik Aç"),
                pick(
                    "Exportierten HTML-/PDF-Bericht direkt nach dem Speichern anzeigen",
                    "Open exported HTML/PDF report automatically right after saving",
                    "Kaydedilen HTML/PDF raporunu kaydetme sonrasında hemen aç",
                ),
            ),
            "theme": (t("options.theme.title"), t("options.theme.desc")),
            "language": (t("options.language.title"), t("options.language.desc")),
        }
        for key, (kl, dl) in self._row_labels.items():
            if key in row_map:
                kl.setText(row_map[key][0])
                dl.setText(row_map[key][1])

        self._btn_theme.setText(self._theme_button_label())
        self._btn_lang.setText(self._language_button_label())
        self._update_net_badge()
        self.refresh(
            feed_badge_text=self._last_feed_badge,
            feed_tooltip=self._last_feed_tooltip,
        )
        if self._engine_rows:
            self.set_engine_rows(self._engine_rows, static_only=self._engine_static_only)

    def set_engine_rows(self, rows: list[tuple[str, str, bool]], *, static_only: bool = False) -> None:
        self._engine_rows = list(rows)
        self._engine_static_only = bool(static_only)
        while self._eng_lay.count():
            ch = self._eng_lay.takeAt(0)
            if ch.widget() is not None:
                w = ch.widget()
                w.hide()
                w.setParent(None)
                w.deleteLater()

        for idx, (name, detail, avail) in enumerate(rows):
            paused = static_only and name.lower() in (
                "windows defender",
                "defender",
                "clamav",
            )
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

            lang = get_language()
            if paused:
                sub = pick(
                    "Pausiert durch Nur-Statik-Modus",
                    "Paused by static-only mode",
                    "Yalnızca statik mod nedeniyle duraklatıldı",
                    lang=lang,
                )
            else:
                sub_raw = clip_text(masked_widget_text(detail), 90)
                sub = _localize_engine_status_line(sub_raw, lang) if lang != "de" else sub_raw
            v_lbl = QLabel(sub, row)
            v_lbl.setObjectName("mutedLabel")
            v_lbl.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(v_lbl, 1)

            badge_txt = (
                pick("Bereit", "Ready", "Hazır", lang=lang)
                if eff
                else (
                    pick("Pausiert", "Paused", "Duraklatıldı", lang=lang)
                    if paused
                    else pick("Inaktiv", "Inactive", "Devre dışı", lang=lang)
                )
            )
            badge = QLabel(badge_txt, row)
            badge.setObjectName("badgeRight")
            badge.setProperty("tone", "ok" if eff else "warn")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(badge)

            self._eng_lay.addWidget(row)

    def refresh(self, *, feed_badge_text: str = "", feed_tooltip: str = "") -> None:
        self._last_feed_badge = feed_badge_text
        self._last_feed_tooltip = feed_tooltip
        lang = get_language()
        items = (
            (
                pick("Datei-Hashes", "File hashes", "Dosya özetleri", lang=lang),
                Path(config.USER_HASH_BLOCKLIST_FILE),
            ),
            (pick("Schad-URLs", "Malicious URLs", "Zararlı URL", lang=lang), Path(config.URL_BLOCKLIST_FILE)),
            (pick("Domains", "Domains", "Alan adları", lang=lang), Path(config.DOMAIN_BLOCKLIST_FILE)),
            (pick("Netze", "IP ranges", "IP aralıkları", lang=lang), Path(config.IP_BLOCKLIST_FILE)),
        )
        missing_word = pick("fehlt", "missing", "yok", lang=lang)
        parts = []
        for name, pfad in items:
            if pfad.is_file():
                parts.append(f"{name}: {pfad.stat().st_size / 1024:.0f} KB")
            else:
                parts.append(f"{name}: {missing_word}")
        text = " · ".join(parts)
        if feed_badge_text:
            badge_disp = _localize_feed_badge(feed_badge_text, lang) if lang != "de" else feed_badge_text
            text = f"{badge_disp} · {text}"
        self._db_label.setText(text)
        if feed_tooltip:
            self._db_label.setToolTip(escape_tooltip(feed_tooltip, limit=1200))
        self._btn_theme.setText(self._theme_button_label())
        self._btn_lang.setText(self._language_button_label())
        self._update_net_badge()

    def set_scanning(self, scanning: bool) -> None:
        for btn in (self.btn_clam_now, self.btn_yara_now, self.btn_feeds_now):
            btn.setEnabled(not scanning)


def _localize_engine_status_line(text: str, lang: str = "en") -> str:
    low = text.lower()
    is_tr = lang == "tr"
    if "nicht verfügbar" in low or "nicht verfuegbar" in low:
        return "Kullanılamıyor" if is_tr else "Unavailable"
    if "nicht installiert" in low or "nicht gefunden" in low or "fehlt" in low:
        return "Bu sistemde kurulu değil" if is_tr else "Not installed on this system"
    if low == "verfügbar":
        return "Kullanılabilir" if is_tr else "Available"
    if "aktiv" in low and "defender" in low:
        return "Windows Defender aktif (MpCmdRun)" if is_tr else "Windows Defender active (MpCmdRun)"
    if "daemon" in low or "clamd" in low:
        return "ClamAV hazır (clamd servisi)" if is_tr else "ClamAV ready (clamd daemon)"
    if "verfügbar" in low:
        return "Yerelde hazır" if is_tr else "Available locally"
    if "regeln" in low:
        if is_tr:
            return text.replace("lokale Regeln", "yerel kural").replace("Regeln", "kural")
        return text.replace("lokale Regeln", "local rules").replace("Regeln", "rules")
    return text


def _localize_feed_badge(badge: str, lang: str = "en") -> str:
    low = badge.lower()
    is_tr = lang == "tr"
    if "aktuell" in low:
        return "Listeler güncel" if is_tr else "Blocklists up to date"
    if "veraltet" in low or "alt" in low:
        return "Listeler güncellenmeli" if is_tr else "Blocklists aging"
    if "fehlt" in low or "leer" in low or "keine" in low:
        return "Listeler boş" if is_tr else "Blocklists empty"
    return badge
