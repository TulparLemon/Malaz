"""Right-hand File & Container Detail View for Malaz v11 ("Klare Fläche v2").

Implements:
- Single-line origin breadcrumb strip (clickable container pills) + elided H1 title
- Verdict Hero card + 3 uniform Engine Cards
- Balanced tab bar: Einschätzung | Technische Details N | E-Mail-Text | Fähigkeiten
  + right-aligned clickable SHA-256 copy pill and Bericht speichern button
- Deterministic category-grouped overview signals (max 4) + clickable children list
  for archives (ZIP/7Z/RAR/TAR) and E-Mails (EML/MSG)
- Structured 3-section analyst datasheet (Datei with thin single-line SHA-256,
  defanged IOCs capped at 100, technical findings with 3px left accent & AV-discount)
- Plain-text MailPanel (+ full MailViewerDialog trigger) & CapabilityPanel
"""

from __future__ import annotations

import re
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..design_tokens import (
    ARCHIVE_TYPES,
    MAIL_TYPES,
    format_short_type,
    format_size_de,
    format_tag_code,
    visual_state,
)
from ..models import (
    _INCOMPLETE_RULES,
    CAT_ARCHIVE,
    CAT_AV,
    CAT_ENTROPY,
    CAT_FORMAT,
    CAT_HASHLIST,
    CAT_IOC,
    CAT_MACRO,
    CAT_MAIL,
    CAT_SCRIPT,
    CAT_SIGNATURE,
    Indicator,
    ScanResult,
    Severity,
)
from .capability_panel import CapabilityPanel
from .engine_strip import EngineStrip
from .file_tree import is_spoofed_result
from .mail_panel import MailPanel
from .sanitize import (
    ENCRYPTED_RULES,
    clip_text,
    defang_ioc,
    escape_tooltip,
    indicator_weight,
    is_encrypted,
    masked_widget_text,
    result_is_incomplete,
)
from .score_ring import StatusDotWidget
from .verdict_card import VerdictCard

_MAX_IOC_ROWS = 100
_URL_RE = re.compile(r"https?://[^\s<>'\"\)\]]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def _reset_copy_button(btn: QPushButton) -> None:
    timer = getattr(btn, "_copy_timer", None)
    if timer is not None:
        timer.stop()
    btn.setProperty("_orig_copy_text", None)


def _copy_with_feedback(btn: QPushButton, raw_text: str, feedback: str = "Kopiert") -> None:
    cb = QGuiApplication.clipboard()
    if cb is not None:
        cb.setText(raw_text)
    orig = btn.property("_orig_copy_text")
    if not isinstance(orig, str):
        orig = btn.text()
        btn.setProperty("_orig_copy_text", orig)
    btn.setText(feedback)
    timer = getattr(btn, "_copy_timer", None)
    if timer is None:
        timer = QTimer(btn)
        timer.setSingleShot(True)

        def _restore(b: QPushButton = btn) -> None:
            saved = b.property("_orig_copy_text")
            if isinstance(saved, str):
                b.setText(saved)
            b.setProperty("_orig_copy_text", None)

        timer.timeout.connect(_restore)
        btn._copy_timer = timer  # type: ignore[attr-defined]
    timer.start(1100)


def _clear_layout(lay: QVBoxLayout | QHBoxLayout) -> None:
    while lay.count():
        item = lay.takeAt(0)
        if item.widget() is not None:
            w = item.widget()
            w.hide()
            w.setParent(None)
            w.deleteLater()
        elif item.layout() is not None:
            _clear_layout(item.layout())


def _severity_badge(ind: Indicator) -> tuple[str, str]:
    if indicator_weight(ind) >= 40 or ind.severity >= Severity.CRITICAL:
        return ("bad", "Kritisch")
    if ind.rule_id in ENCRYPTED_RULES or ind.rule_id in _INCOMPLETE_RULES:
        return ("warn", "Ungeprüft")
    if indicator_weight(ind) >= 15 or ind.severity >= Severity.MEDIUM:
        return ("warn", "Warnung")
    return ("ok", "Hinweis")


def _signal_category_label(ind: Indicator) -> str:
    cat = (ind.category or "").lower()
    if cat in (CAT_AV, CAT_SIGNATURE, CAT_HASHLIST):
        return "Schadsoftware"
    if cat == CAT_FORMAT:
        return "Datei-Tarnung"
    if cat in (CAT_SCRIPT, CAT_MACRO):
        return "Aktive Inhalte"
    if cat in (CAT_MAIL, CAT_IOC):
        return "Absender & Links"
    if cat in (CAT_ARCHIVE, CAT_ENTROPY):
        return "Archiv & Tarnung"
    return "Struktur & Inhalt"


def _extract_iocs(result: ScanResult) -> tuple[list[tuple[str, str, str, str, str]], int]:
    """Extract deterministic IOCs: ``(tone, tag, label, display_val, raw_copy)``."""
    seen: set[tuple[str, str]] = set()
    rows: list[tuple[str, str, str, str, str]] = []

    def _add(tone: str, tag: str, label: str, raw: str) -> None:
        clean = raw.strip()
        if not clean:
            return
        key = (tag, clean.lower())
        if key in seen:
            return
        seen.add(key)
        disp = defang_ioc(clean) if tag == "URL" else masked_widget_text(clean)
        rows.append((tone, tag, label, clip_text(disp, 110), clean))

    for lnk in list(result.mail_links or []):
        href = getattr(lnk, "href", "") or ""
        if href:
            susp = (
                getattr(lnk, "suspicious", False)
                or getattr(lnk, "mismatch", False)
                or getattr(lnk, "is_ip", False)
            )
            _add("warn" if susp else "info", "URL", "Mail-Link", href)

    for ind in result.indicators:
        hay = f"{ind.title} {ind.detail or ''}"[:4096]
        if ind.rule_id == "MAIL_REPLY_TO_MISMATCH":
            for m in _EMAIL_RE.findall(hay):
                _add("bad", "E-Mail", "Reply-To", m)
        if ind.category in (CAT_IOC, CAT_MAIL, CAT_HASHLIST) or ind.rule_id.startswith(
            ("URL_", "PDF_URI", "MAIL_")
        ):
            for u in _URL_RE.findall(hay):
                _add("warn" if indicator_weight(ind) > 0 else "info", "URL", "Link", u)
            for ip in _IP_RE.findall(hay):
                _add("info", "IPv4", "IP-Adresse", ip)

    total = len(rows)
    return rows[:_MAX_IOC_ROWS], max(0, total - _MAX_IOC_ROWS)


def build_footer_summary(result: ScanResult) -> str:
    """Crisp footer grounding line per Design 004 v2.1 wording table."""
    state = visual_state(result.risk_level, result_is_incomplete(result))
    dt_short = format_short_type(result.detected_type, result.display_name)
    encrypted = is_encrypted(result)

    if state == "ok":
        check_word = "Vollständig"
    elif state in ("bad", "warn"):
        check_word = "Teilweise" if result_is_incomplete(result) else "Vollständig"
    else:
        check_word = "Gesperrt" if encrypted else "Unvollständig"

    parts = [f"Typ: {dt_short}"]
    dt = (result.detected_type or "").lower()
    if dt == "pe":
        signed = any("SIGNED" in i.rule_id and "UN" not in i.rule_id for i in result.indicators)
        parts.append("Signatur: Vorhanden" if signed else "Signatur: Keine")
    elif dt in MAIL_TYPES or bool(result.mail_security):
        if result.children:
            bad_k = sum(
                1 for c in result.children if visual_state(c.risk_level, result_is_incomplete(c)) == "bad"
            )
            suffix = f" ({bad_k} gefährlich)" if bad_k else ""
            parts.append(f"Anhänge: {len(result.children)}{suffix}")
    elif dt in ARCHIVE_TYPES and result.children:
        parts.append(f"Inhalt: {len(result.children)} Dateien")
    elif dt == "pdf":
        has_script = any(i.category == CAT_SCRIPT and indicator_weight(i) > 0 for i in result.indicators)
        parts.append("Skripte: Gefunden" if has_script else "Skripte: Keine")

    parts.append(f"Prüfung: {check_word}")
    return " · ".join(parts)


class _ClickableChildRow(QFrame):
    clicked = Signal(object)

    def __init__(self, child: ScanResult, *, is_last: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._child = child
        st = visual_state(child.risk_level, result_is_incomplete(child))
        self.setObjectName("listRow")
        self.setProperty("clickable", "true")
        self.setProperty("last", "true" if is_last else "false")
        if st in ("bad", "warn"):
            self.setProperty("accent", st)
        self.setMinimumHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(13, 8, 16, 8)
        lay.setSpacing(14)

        left_box = QWidget(self)
        left_box.setMinimumWidth(185)
        left_box.setMaximumWidth(240)
        ll = QHBoxLayout(left_box)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        code, kind = format_tag_code(
            child.detected_type, child.display_name, spoofed=is_spoofed_result(child)
        )
        tag = QLabel(code, left_box)
        tag.setObjectName("fmtTag")
        tag.setProperty("kind", kind)
        tag.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tag.setTextFormat(Qt.TextFormat.PlainText)
        ll.addWidget(tag)

        name_lbl = QLabel(clip_text(masked_widget_text(child.display_name), 36), left_box)
        name_lbl.setObjectName("panelHeading")
        name_lbl.setTextFormat(Qt.TextFormat.PlainText)
        name_lbl.setToolTip(escape_tooltip(child.display_name))
        ll.addWidget(name_lbl, 1)
        lay.addWidget(left_box)

        top_i = next(
            (
                i
                for i in sorted(child.all_indicators(), key=lambda x: (-indicator_weight(x), -x.severity))
                if indicator_weight(i) > 0
            ),
            None,
        )
        desc = (
            masked_widget_text(top_i.title)
            if top_i is not None
            else (
                f"{format_short_type(child.detected_type, child.display_name)}"
                f" · {format_size_de(child.size)}"
            )
        )
        d_lbl = QLabel(clip_text(desc, 85), self)
        d_lbl.setObjectName("mutedLabel")
        d_lbl.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(d_lbl, 1)

        b_txt = {"bad": "Gefährlich", "warn": "Verdächtig", "unk": "Ungeprüft", "ok": "Sauber"}.get(
            st, "Ungeprüft"
        )
        b_tone = "warn" if st == "unk" else st
        badge = QLabel(b_txt, self)
        badge.setObjectName("badgeRight")
        badge.setProperty("tone", b_tone)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(badge)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._child)
        super().mousePressEvent(event)


class FileDetailView(QWidget):
    """Complete detail workspace for one selected ScanResult."""

    child_selected = Signal(object)
    ancestor_selected = Signal(object)
    export_requested = Signal()
    mail_viewer_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._current: ScanResult | None = None
        self._compact = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        origin_bar = QWidget(self)
        origin_bar.setMinimumHeight(22)
        self._origin_lay = QHBoxLayout(origin_bar)
        self._origin_lay.setContentsMargins(0, 0, 0, 4)
        self._origin_lay.setSpacing(6)
        root.addWidget(origin_bar)

        self._title = QLabel("", self)
        self._title.setObjectName("fileTitle")
        self._title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._title.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self._title)
        root.addSpacing(12)

        self.verdict = VerdictCard(self)
        root.addWidget(self.verdict)
        root.addSpacing(12)

        self.engines = EngineStrip(self)
        self.engines.chip_clicked.connect(lambda: self.select_tab(1))
        root.addWidget(self.engines)
        root.addSpacing(16)

        tab_bar = QFrame(self)
        tab_bar.setObjectName("tabBarRow")
        tb_lay = QHBoxLayout(tab_bar)
        tb_lay.setContentsMargins(0, 0, 0, 0)
        tb_lay.setSpacing(12)

        self._tab_group = QButtonGroup(self)
        self._tab_group.setExclusive(True)

        self._btn_tab_overview = QPushButton("Einschätzung", tab_bar)
        self._btn_tab_details = QPushButton("Technische Details", tab_bar)
        self._btn_tab_mail = QPushButton("E-Mail-Text", tab_bar)
        self._btn_tab_capa = QPushButton("Fähigkeiten", tab_bar)

        for idx, btn in enumerate(
            (self._btn_tab_overview, self._btn_tab_details, self._btn_tab_mail, self._btn_tab_capa)
        ):
            btn.setObjectName("tabButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._tab_group.addButton(btn, idx)
            tb_lay.addWidget(btn)
        self._btn_tab_overview.setChecked(True)
        self._btn_tab_mail.hide()
        self._btn_tab_capa.hide()

        tb_lay.addStretch(1)

        self._hash_pill = QPushButton("", tab_bar)
        self._hash_pill.setObjectName("hashPill")
        self._hash_pill.setCursor(Qt.CursorShape.PointingHandCursor)
        self._hash_pill.clicked.connect(self._copy_current_sha)
        tb_lay.addWidget(self._hash_pill)

        self.btn_report = QPushButton("Bericht speichern", tab_bar)
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self.export_requested.emit)
        tb_lay.addWidget(self.btn_report)

        root.addWidget(tab_bar)
        root.addSpacing(12)

        self._stack = QStackedWidget(self)
        root.addWidget(self._stack, 1)

        self._page_overview = QWidget(self._stack)
        self._overview_lay = QVBoxLayout(self._page_overview)
        self._overview_lay.setContentsMargins(0, 0, 0, 0)
        self._overview_lay.setSpacing(16)
        self._stack.addWidget(self._page_overview)

        self._page_details = QWidget(self._stack)
        self._details_lay = QVBoxLayout(self._page_details)
        self._details_lay.setContentsMargins(0, 0, 0, 0)
        self._details_lay.setSpacing(14)
        self._stack.addWidget(self._page_details)

        self._page_mail = QWidget(self._stack)
        mail_lay = QVBoxLayout(self._page_mail)
        mail_lay.setContentsMargins(0, 0, 0, 0)
        mail_lay.setSpacing(10)
        mail_hdr = QHBoxLayout()
        mail_hdr.setContentsMargins(0, 0, 0, 0)
        mail_hdr.addStretch(1)
        self._btn_mail_viewer = QPushButton("Vollständige Mail-Ansicht…", self._page_mail)
        self._btn_mail_viewer.clicked.connect(self.mail_viewer_requested.emit)
        mail_hdr.addWidget(self._btn_mail_viewer)
        mail_lay.addLayout(mail_hdr)
        self.mail_panel = MailPanel()
        mail_lay.addWidget(self.mail_panel, 1)
        self._stack.addWidget(self._page_mail)

        self._page_capa = QWidget(self._stack)
        capa_lay = QVBoxLayout(self._page_capa)
        capa_lay.setContentsMargins(0, 0, 0, 0)
        self.capa_panel = CapabilityPanel()
        capa_lay.addWidget(self.capa_panel, 1)
        self._stack.addWidget(self._page_capa)

        self._tab_group.idClicked.connect(self.select_tab)

    def set_compact(self, compact: bool) -> None:
        self._compact = bool(compact)

    def select_tab(self, idx: int) -> None:
        btns = (self._btn_tab_overview, self._btn_tab_details, self._btn_tab_mail, self._btn_tab_capa)
        if 0 <= idx < len(btns) and not btns[idx].isHidden():
            btns[idx].setChecked(True)
            self._stack.setCurrentIndex(idx)

    def _copy_current_sha(self) -> None:
        if self._current and self._current.sha256:
            _copy_with_feedback(self._hash_pill, self._current.sha256, "SHA-256 kopiert")

    def show_result(
        self,
        result: ScanResult,
        *,
        root_path: str = "",
        ancestor_chain: list[tuple[str, object]] | None = None,
    ) -> None:
        self._current = result
        ancestors = list(ancestor_chain or [])

        _clear_layout(self._origin_lay)
        parent_dir = str(Path(root_path or result.path).parent) if (root_path or result.path) else ""
        if parent_dir and parent_dir != ".":
            short_dir = clip_text(masked_widget_text(parent_dir), 48)
            dir_lbl = QLabel(short_dir, self)
            dir_lbl.setObjectName("captionLabel")
            dir_lbl.setTextFormat(Qt.TextFormat.PlainText)
            dir_lbl.setToolTip(escape_tooltip(root_path or result.path))
            self._origin_lay.addWidget(dir_lbl)

        display_ancestors = ancestors
        if len(ancestors) > 3:
            display_ancestors = [ancestors[0], ("…", None), ancestors[-1]]

        for label, tree_item in display_ancestors:
            sep = QLabel("›", self)
            sep.setObjectName("captionLabel")
            self._origin_lay.addWidget(sep)
            if tree_item is not None:
                pill = QPushButton(clip_text(masked_widget_text(label), 30), self)
                pill.setObjectName("breadcrumbLink")
                pill.setCursor(Qt.CursorShape.PointingHandCursor)
                pill.clicked.connect(lambda _=False, it=tree_item: self.ancestor_selected.emit(it))
                self._origin_lay.addWidget(pill)
            else:
                dots = QLabel("…", self)
                dots.setObjectName("captionLabel")
                self._origin_lay.addWidget(dots)

        self._origin_lay.addStretch(1)
        meta_txt = (
            f"{format_short_type(result.detected_type, result.display_name)} · {format_size_de(result.size)}"
        )
        meta_lbl = QLabel(meta_txt, self)
        meta_lbl.setObjectName("captionLabel")
        meta_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._origin_lay.addWidget(meta_lbl)

        masked_name = masked_widget_text(result.display_name)
        self._title.setText(clip_text(masked_name, 88))
        self._title.setToolTip(escape_tooltip(masked_name))

        self.verdict.show_result(result)
        self.engines.show_result(result)

        tech_items = self._select_tech_findings(result)
        self._btn_tab_details.setText(f"Technische Details  {len(tech_items)}")

        has_mail = bool(result.mail_preview or result.mail_security)
        self._btn_tab_mail.setVisible(has_mail)
        if has_mail:
            self.mail_panel.show_result(result)
            self._btn_mail_viewer.setVisible(not bool(ancestor_chain))
        else:
            self.mail_panel.clear()

        has_capa = bool(result.capa_capabilities)
        self._btn_tab_capa.setVisible(has_capa)
        if has_capa:
            self._btn_tab_capa.setText(f"Fähigkeiten ({len(result.capa_capabilities)})")
            self.capa_panel.show_result(result)
        else:
            self.capa_panel.clear()

        if self._stack.currentIndex() == 2 and not has_mail:
            self.select_tab(0)
        if self._stack.currentIndex() == 3 and not has_capa:
            self.select_tab(0)

        _reset_copy_button(self._hash_pill)
        if result.sha256:
            short_sha = f"{result.sha256[:8]}…{result.sha256[-6:]}"
            self._hash_pill.setText(f"SHA-256  {short_sha}")
            self._hash_pill.setToolTip(escape_tooltip(f"Volle SHA-256 kopieren: {result.sha256}"))
            self._hash_pill.show()
        else:
            self._hash_pill.hide()

        self._populate_overview(result)
        self._populate_details(result, tech_items)

    def _select_tech_findings(self, result: ScanResult) -> list[Indicator]:
        relevant = [
            i
            for i in result.indicators
            if indicator_weight(i) > 0
            or i.severity >= Severity.MEDIUM
            or i.rule_id in ENCRYPTED_RULES
            or i.rule_id in _INCOMPLETE_RULES
        ]
        relevant.sort(key=lambda x: (-indicator_weight(x), -int(x.severity), x.rule_id))
        return relevant

    def _populate_overview(self, result: ScanResult) -> None:
        _clear_layout(self._overview_lay)
        encrypted = is_encrypted(result)

        grouped: dict[str, Indicator] = {}
        for ind in sorted(result.indicators, key=lambda x: (-indicator_weight(x), -int(x.severity))):
            if indicator_weight(ind) <= 0 and ind.rule_id not in ENCRYPTED_RULES:
                continue
            cat = _signal_category_label(ind)
            if cat not in grouped:
                grouped[cat] = ind
            if len(grouped) >= 4:
                break

        rows_spec: list[tuple[str, bool, str, str, str, str]] = []
        if result.error:
            rows_spec.append(
                (
                    "bad",
                    False,
                    "Prüffehler",
                    masked_widget_text(result.error),
                    "bad",
                    "Fehler",
                )
            )
        if grouped:
            for label, ind in grouped.items():
                tone, b_txt = _severity_badge(ind)
                is_ring = ind.rule_id in ENCRYPTED_RULES or ind.rule_id in _INCOMPLETE_RULES
                rows_spec.append((tone, is_ring, label, masked_widget_text(ind.title), tone, b_txt))

        if result_is_incomplete(result):
            if encrypted and not grouped and not result.error:
                rows_spec.extend(
                    [
                        (
                            "warn",
                            True,
                            "Verschlüsselt",
                            "Passwortschutz verhindert jede Inhaltsprüfung",
                            "warn",
                            "Ungeprüft",
                        ),
                        (
                            "warn",
                            False,
                            "Vorgehen",
                            "Nur bei bekanntem Absender entpacken und Ordner neu prüfen",
                            "warn",
                            "Hinweis",
                        ),
                    ]
                )
            else:
                missing = ", ".join(masked_widget_text(i.title) for i in result.incomplete_stages[:3])
                rows_spec.append(
                    (
                        "warn",
                        True,
                        "Unvollständige Prüfung",
                        missing or "Mindestens eine Prüfstufe lief nicht",
                        "warn",
                        "Ungeprüft",
                    )
                )
        elif not rows_spec and not result.children:
            rows_spec = [
                ("ok", False, "Virenprüfung", "Lokale Signaturen & Muster ohne Befund", "ok", "Sauber"),
                (
                    "ok",
                    False,
                    "Inhalt",
                    "Keine schädlichen Skripte, Makros oder versteckten Aktionen",
                    "ok",
                    "Sauber",
                ),
            ]

        if rows_spec:
            sig_card = QFrame(self._page_overview)
            sig_card.setObjectName("card")
            sl = QVBoxLayout(sig_card)
            sl.setContentsMargins(0, 0, 0, 0)
            sl.setSpacing(0)
            for idx, (dot_tone, ring, lbl, txt, b_tone, b_txt) in enumerate(rows_spec):
                row = QFrame(sig_card)
                row.setObjectName("listRow")
                row.setProperty("last", "true" if idx == len(rows_spec) - 1 else "false")
                row.setMinimumHeight(44)
                rl = QHBoxLayout(row)
                rl.setContentsMargins(13, 8, 16, 8)
                rl.setSpacing(14)

                key_box = QWidget(row)
                key_box.setMinimumWidth(165)
                key_box.setMaximumWidth(205)
                kl = QHBoxLayout(key_box)
                kl.setContentsMargins(0, 0, 0, 0)
                kl.setSpacing(8)
                kl.addWidget(StatusDotWidget(dot_tone, ring=ring, parent=key_box))
                k_lbl = QLabel(lbl, key_box)
                k_lbl.setObjectName("panelHeading")
                k_lbl.setTextFormat(Qt.TextFormat.PlainText)
                kl.addWidget(k_lbl, 1)
                rl.addWidget(key_box)

                v_lbl = QLabel(clip_text(txt, 140), row)
                v_lbl.setObjectName("mutedLabel")
                v_lbl.setWordWrap(True)
                v_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
                v_lbl.setTextFormat(Qt.TextFormat.PlainText)
                rl.addWidget(v_lbl, 1)

                badge = QLabel(b_txt, row)
                badge.setObjectName("badgeRight")
                badge.setProperty("tone", b_tone)
                badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
                badge.setTextFormat(Qt.TextFormat.PlainText)
                rl.addWidget(badge)
                sl.addWidget(row)
            self._overview_lay.addWidget(sig_card)

        if result.children:
            dt = (result.detected_type or "").lower()
            hdr_txt = (
                f"ANHÄNGE ({len(result.children)})"
                if dt in MAIL_TYPES or bool(result.mail_security)
                else f"DATEIEN IM ARCHIV ({len(result.children)})"
            )
            hdr = QLabel(hdr_txt, self._page_overview)
            hdr.setObjectName("sectionTitle")
            hdr.setTextFormat(Qt.TextFormat.PlainText)
            self._overview_lay.addWidget(hdr)

            ch_card = QFrame(self._page_overview)
            ch_card.setObjectName("card")
            cl = QVBoxLayout(ch_card)
            cl.setContentsMargins(0, 0, 0, 0)
            cl.setSpacing(0)
            shown = result.children[:100]
            for idx, child in enumerate(shown):
                c_row = _ClickableChildRow(child, is_last=(idx == len(shown) - 1), parent=ch_card)
                c_row.clicked.connect(self.child_selected.emit)
                cl.addWidget(c_row)
            if len(result.children) > 100:
                more = QLabel(f"+ {len(result.children) - 100} weitere Einträge im Baum links", ch_card)
                more.setObjectName("captionLabel")
                more.setContentsMargins(16, 8, 16, 10)
                cl.addWidget(more)
            self._overview_lay.addWidget(ch_card)

        self._overview_lay.addStretch(1)

    def _populate_details(self, result: ScanResult, tech_items: list[Indicator]) -> None:
        _clear_layout(self._details_lay)

        s1 = QLabel("DATEI", self._page_details)
        s1.setObjectName("sectionTitle")
        self._details_lay.addWidget(s1)

        id_card = QFrame(self._page_details)
        id_card.setObjectName("card")
        il = QVBoxLayout(id_card)
        il.setContentsMargins(0, 0, 0, 0)
        il.setSpacing(0)

        spoof = is_spoofed_result(result)
        id_rows: list[tuple[str, str, str, tuple[str, str] | None, str | None, bool]] = [
            (
                "Typ",
                (
                    f"{format_short_type(result.detected_type, result.display_name)}"
                    f" ({format_size_de(result.size)})"
                ),
                "bad" if spoof else "",
                ("bad", "Tarnung") if spoof else ("ok", "Verifiziert"),
                None,
                False,
            ),
            ("SHA-256", result.sha256 or "Nicht berechnet", "", None, result.sha256 or None, True),
            ("Dauer", f"{result.duration_ms} ms", "", None, None, False),
        ]
        if (result.detected_type or "").lower() == "pe":
            signed = any("SIGNED" in i.rule_id and "UN" not in i.rule_id for i in result.indicators)
            id_rows.append(
                (
                    "Signatur",
                    "Digitale Signatur vorhanden" if signed else "Keine digitale Signatur",
                    "" if signed else "warn",
                    ("ok", "Vorhanden") if signed else ("warn", "Keine"),
                    None,
                    False,
                )
            )
        if result.error:
            id_rows.append(
                ("Fehler", masked_widget_text(result.error), "bad", ("bad", "Fehler"), None, False)
            )
        if result_is_incomplete(result):
            stages = ", ".join(masked_widget_text(i.rule_id) for i in result.incomplete_stages[:6])
            id_rows.append(
                ("Nicht gelaufen", stages or "Unvollständig", "warn", ("warn", "Ungeprüft"), None, False)
            )

        for idx, (k, v, acc, badge_spec, copy_val, is_hash) in enumerate(id_rows):
            row = QFrame(id_card)
            row.setObjectName("listRow")
            row.setProperty("last", "true" if idx == len(id_rows) - 1 else "false")
            if acc:
                row.setProperty("accent", acc)
            row.setMinimumHeight(44)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(13, 8, 16, 8)
            rl.setSpacing(14)

            k_lbl = QLabel(k, row)
            k_lbl.setObjectName("panelKey")
            k_lbl.setMinimumWidth(155)
            k_lbl.setMaximumWidth(185)
            k_lbl.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(k_lbl)

            v_lbl = QLabel(clip_text(v, 72) if is_hash else clip_text(v, 140), row)
            v_lbl.setObjectName("hashValue" if is_hash else "panelValue")
            v_lbl.setTextFormat(Qt.TextFormat.PlainText)
            v_lbl.setToolTip(escape_tooltip(v))
            rl.addWidget(v_lbl, 1)

            if badge_spec is not None:
                b = QLabel(badge_spec[1], row)
                b.setObjectName("badgeRight")
                b.setProperty("tone", badge_spec[0])
                b.setAlignment(Qt.AlignmentFlag.AlignCenter)
                b.setTextFormat(Qt.TextFormat.PlainText)
                rl.addWidget(b)
            elif copy_val:
                btn = QPushButton("Kopieren", row)
                btn.setObjectName("copyButton")
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.clicked.connect(lambda _=False, b=btn, val=copy_val: _copy_with_feedback(b, val))
                rl.addWidget(btn)
            il.addWidget(row)
        self._details_lay.addWidget(id_card)

        iocs, overflow = _extract_iocs(result)
        if iocs:
            s2 = QLabel("INDIKATOREN (IOCS)", self._page_details)
            s2.setObjectName("sectionTitle")
            self._details_lay.addWidget(s2)

            ioc_card = QFrame(self._page_details)
            ioc_card.setObjectName("card")
            iol = QVBoxLayout(ioc_card)
            iol.setContentsMargins(0, 0, 0, 0)
            iol.setSpacing(0)
            for idx, (tone, tag, lbl, disp, raw) in enumerate(iocs):
                row = QFrame(ioc_card)
                row.setObjectName("listRow")
                row.setProperty("last", "true" if idx == len(iocs) - 1 and not overflow else "false")
                row.setMinimumHeight(44)
                rl = QHBoxLayout(row)
                rl.setContentsMargins(13, 8, 16, 8)
                rl.setSpacing(14)

                key_box = QWidget(row)
                key_box.setMinimumWidth(155)
                key_box.setMaximumWidth(185)
                kl = QHBoxLayout(key_box)
                kl.setContentsMargins(0, 0, 0, 0)
                kl.setSpacing(8)
                t_lbl = QLabel(tag, key_box)
                t_lbl.setObjectName("tagLeft")
                t_lbl.setProperty("tone", tone)
                t_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                t_lbl.setTextFormat(Qt.TextFormat.PlainText)
                kl.addWidget(t_lbl)
                n_lbl = QLabel(lbl, key_box)
                n_lbl.setObjectName("panelKey")
                n_lbl.setTextFormat(Qt.TextFormat.PlainText)
                kl.addWidget(n_lbl, 1)
                rl.addWidget(key_box)

                v_lbl = QLabel(disp, row)
                v_lbl.setObjectName("monoValue")
                v_lbl.setTextFormat(Qt.TextFormat.PlainText)
                v_lbl.setToolTip(escape_tooltip(disp))
                rl.addWidget(v_lbl, 1)

                c_btn = QPushButton("Kopieren", row)
                c_btn.setObjectName("copyButton")
                c_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                c_btn.clicked.connect(lambda _=False, b=c_btn, val=raw: _copy_with_feedback(b, val))
                rl.addWidget(c_btn)
                iol.addWidget(row)
            if overflow:
                ov = QLabel(f"+ {overflow} weitere Indikatoren im Bericht", ioc_card)
                ov.setObjectName("captionLabel")
                ov.setContentsMargins(16, 8, 16, 10)
                iol.addWidget(ov)
            self._details_lay.addWidget(ioc_card)

        s3 = QLabel("BEFUNDE", self._page_details)
        s3.setObjectName("sectionTitle")
        self._details_lay.addWidget(s3)

        tf_card = QFrame(self._page_details)
        tf_card.setObjectName("card")
        tfl = QVBoxLayout(tf_card)
        tfl.setContentsMargins(0, 0, 0, 0)
        tfl.setSpacing(0)

        rows_f: list[tuple[str, str, str, str]] = []
        for ind in tech_items[:120]:
            tone, chip = _severity_badge(ind)
            text = masked_widget_text(ind.title)
            if ind.detail and ind.detail.strip() and ind.detail.strip() != ind.title.strip():
                text = f"{text} — {masked_widget_text(ind.detail)}"
            rows_f.append((ind.rule_id, clip_text(text, 200), tone, chip))

        if result.av_discount > 0:
            rows_f.append(
                (
                    "AV-Entlastung",
                    f"−{result.av_discount} Punkte durch saubere Virenprüfung (Endwert {result.score}/100)",
                    "ok",
                    "Abzug",
                )
            )

        if not rows_f:
            rows_f.append(("Struktur", "Keine auffälligen Befunde erkannt", "ok", "Sauber"))

        for idx, (rk, rv, tone, chip) in enumerate(rows_f):
            row = QFrame(tf_card)
            row.setObjectName("listRow")
            row.setProperty("accent", tone)
            row.setProperty("last", "true" if idx == len(rows_f) - 1 else "false")
            row.setMinimumHeight(44)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(13, 8, 16, 8)
            rl.setSpacing(14)

            k_lbl = QLabel(clip_text(masked_widget_text(rk), 24), row)
            k_lbl.setObjectName("panelKey")
            k_lbl.setMinimumWidth(155)
            k_lbl.setMaximumWidth(185)
            k_lbl.setTextFormat(Qt.TextFormat.PlainText)
            k_lbl.setToolTip(escape_tooltip(rk))
            rl.addWidget(k_lbl)

            v_lbl = QLabel(rv, row)
            v_lbl.setObjectName("panelValue")
            v_lbl.setWordWrap(True)
            v_lbl.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(v_lbl, 1)

            b = QLabel(chip, row)
            b.setObjectName("badgeRight")
            b.setProperty("tone", tone)
            b.setAlignment(Qt.AlignmentFlag.AlignCenter)
            b.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(b)
            tfl.addWidget(row)

        self._details_lay.addWidget(tf_card)
        self._details_lay.addStretch(1)

    def clear(self) -> None:
        self._current = None
        _clear_layout(self._origin_lay)
        self._title.setText("")
        self.verdict.clear()
        self.engines.clear()
        self.mail_panel.clear()
        self.capa_panel.clear()
        self._btn_tab_mail.hide()
        self._btn_tab_capa.hide()
        _reset_copy_button(self._hash_pill)
        self._hash_pill.hide()
        _clear_layout(self._overview_lay)
        _clear_layout(self._details_lay)
