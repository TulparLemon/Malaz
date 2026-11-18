"""Malaz Desktop Main Window ("Klare Fläche v2" — v1.1.0).

Clean master-detail workspace built from design tokens (zero hardcoded hex
values), featuring:
- Top Bar (46 px): official Malaz icon, read-only Engine Status Capsule, Optionen
- Resizable QSplitter Sidebar: Search + Type filter, flush full-width 5-chip
  status filter, live scan progress banner, Ordner-Übersicht bar, unified nested
  container tree with circular dots, and 52 px action footer
- Right Workspace: stacked Empty / Detail / Folder Overview / Options / Pending
  views + synchronized 52 px bottom footer with concise grounding facts and safe
  ``Im Ordner zeigen`` reveal
- Automatic High-DPI screen clamping & ``screenChanged`` protection
- Session-only ``Nur-Statik-Modus`` (never persisted, always enforces incomplete)
"""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, config
from ..core.dispatcher import Dispatcher, expand_scan_paths
from ..design_tokens import visual_state
from ..models import ScanResult
from ..workers.scan_worker import ScanWorker
from .batch_summary import BatchSummary
from .detail_view import FileDetailView, build_footer_summary
from .display import (
    clamp_window_to_screen,
    reclamp_to_current_screen,
    save_window_rect,
)
from .file_tree import (
    PARENT_CHAIN_ROLE,
    PENDING_PATH_ROLE,
    RESULT_ROLE,
    ROOT_PATH_ROLE,
    STATE_ROLE,
    FileTreeWidget,
)
from .jobs import (
    _app_icon,
    _AutoUpdateJob,
    _BlocklistWarmup,
    _build_engine_line,
    _ClamdStartJob,
    _engine_badges,
    _engine_health,
    _EngineProbe,
    _EngineSignals,
    _ExportJob,
    _ExportSignals,
    _FeedRefreshJob,
    _freshclam_runner,
    _StreamJob,
    _StreamSignals,
    _StreamUpdateDialog,
    _yara_rules_runner,
)
from .legacy_format import (
    _format_detail as _format_detail,
)
from .legacy_format import (
    _format_technical as _format_technical,
)
from .legacy_format import (
    _mail_security_summary as _mail_security_summary,
)
from .legacy_format import (
    _mail_security_tooltip as _mail_security_tooltip,
)
from .legacy_format import (
    _verdict_cell as _verdict_cell,
)
from .options_view import OptionsView
from .sanitize import (
    clip_text,
    escape_tooltip,
    is_unc_or_device_path,
    masked_widget_text,
    result_is_incomplete,
    reveal_in_explorer,
)
from .score_ring import StatusDotWidget, ToggleSwitch
from .settings import app_settings
from .theme import (
    apply_theme,
    register_theme_listener,
    saved_theme_preference,
    unregister_theme_listener,
)

# Re-export background job classes for tests importing them from main_window.
__all__ = [
    "MainWindow",
    "_AutoUpdateJob",
    "_BlocklistWarmup",
    "_ClamdStartJob",
    "_EngineProbe",
    "_EngineSignals",
    "_ExportJob",
    "_ExportSignals",
    "_FeedRefreshJob",
    "_StreamJob",
    "_StreamSignals",
    "_StreamUpdateDialog",
    "_app_icon",
    "_build_engine_line",
    "_engine_badges",
    "_engine_health",
]

_PAGE_EMPTY = 0
_PAGE_DETAIL = 1
_PAGE_BATCH = 2
_PAGE_OPTIONS = 3
_PAGE_PENDING = 4


def _urls_to_paths(urls: list[QUrl]) -> tuple[list[str], bool]:
    """Expand dropped local file/folder QUrls into concrete file paths."""
    raw = [u.toLocalFile() for u in urls if u.isLocalFile() and u.toLocalFile()]
    if not raw:
        return ([], False)
    files, truncated = expand_scan_paths(raw)
    return ([str(f) for f in files], truncated)


class _ClickableFrame(QFrame):
    """QFrame with native layout sizing, click signal, and keyboard activation."""

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.clicked.emit()
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter) and self.isEnabled():
            self.clicked.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class _FilterChip(_ClickableFrame):
    """Flush sidebar status filter chip with circular dot + count/label."""

    def __init__(
        self,
        key: str,
        label: str,
        *,
        dot_tone: str | None = None,
        ring: bool = False,
        tooltip: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.key = key
        self._checked = False
        self.setObjectName("filterChip")
        self.setMinimumHeight(26)
        self.setToolTip(tooltip)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(5, 2, 5, 2)
        lay.setSpacing(4)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        if dot_tone is not None:
            self._dot = StatusDotWidget(dot_tone, ring=ring, diameter=7, parent=self)
            lay.addWidget(self._dot)
        else:
            self._dot = None

        self._lbl = QLabel(label, self)
        self._lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        lay.addWidget(self._lbl)

    def setChecked(self, checked: bool) -> None:
        self._checked = bool(checked)
        self.setProperty("checked", "true" if self._checked else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def isChecked(self) -> bool:
        return self._checked

    def set_count_text(self, text: str) -> None:
        self._lbl.setText(text)


class _EngineCapsule(_ClickableFrame):
    """Top-bar read-only engine status capsule (Defender · ClamAV · YARA · 7-Zip)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statusCapsule")
        self.setMinimumHeight(28)
        self.setToolTip("Systemstatus & Optionen öffnen")

        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(10, 3, 10, 3)
        self._lay.setSpacing(10)
        self._items: list[tuple[StatusDotWidget, QLabel]] = []
        self.set_engines([("Defender", True), ("ClamAV", False), ("YARA", True), ("7-Zip", True)])

    def set_engines(self, entries: list[tuple[str, bool]]) -> None:
        while self._lay.count():
            ch = self._lay.takeAt(0)
            if ch.widget() is not None:
                w = ch.widget()
                w.hide()
                w.setParent(None)
                w.deleteLater()
        self._items.clear()

        for name, active in entries:
            box = QWidget(self)
            box.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            bl = QHBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(5)
            dot = StatusDotWidget("ok" if active else "muted", ring=not active, diameter=6, parent=box)
            lbl = QLabel(name, box)
            lbl.setObjectName("mutedLabel" if active else "captionLabel")
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            bl.addWidget(dot)
            bl.addWidget(lbl)
            self._lay.addWidget(box)
            self._items.append((dot, lbl))


class MainWindow(QMainWindow):
    def __init__(
        self,
        initial_paths: list[str] | None = None,
        dispatcher: Dispatcher | None = None,
        *,
        fixed_size: tuple[int, int] | None = None,
    ):
        super().__init__()
        self.setWindowIcon(_app_icon())
        self.setWindowTitle(f"{config.APP_NAME} — Dateien sicher prüfen")
        self.setAcceptDrops(True)

        self._fixed_size = fixed_size
        self._screen_signal_connected = False
        self._compact_mode = False
        self._injected_dispatcher = dispatcher is not None

        self.dispatcher = dispatcher if dispatcher is not None else Dispatcher()
        self.thread_pool = QThreadPool.globalInstance()
        self._worker: ScanWorker | None = None
        self._scan_active = False
        self._scan_cancelled = False
        self._export_running = False
        self._results: list[ScanResult] = []
        self._batch_truncated = False
        self._startup_timers: list[QTimer] = []
        self._status_filter = "all"
        self._last_page_before_options = _PAGE_EMPTY
        self._engine_badges_data: list[tuple[str, str, str]] = []
        self._current_reveal_path: str | None = None
        self._options_dialog = None

        self._build_switches()
        self._build_ui()
        self._build_menu()
        self._apply_initial_geometry()

        register_theme_listener(self._on_theme_changed)

        self.statusBar().hide()
        self.statusBar().showMessage("Bereit. Dateien ablegen oder auswählen.")

        # Probe engine status off the GUI thread.
        self._engine_signals = _EngineSignals(self)
        self._engine_signals.ready.connect(self._on_engine_status)
        self.thread_pool.start(_EngineProbe(self.dispatcher, self._engine_signals))

        # Staggered opt-in startup jobs (stopped cleanly in closeEvent).
        if not self._injected_dispatcher:
            self._schedule_once(200, lambda: QThreadPool.globalInstance().start(_BlocklistWarmup()))
        self._schedule_once(400, self._maybe_auto_update_clamav)
        self._schedule_once(700, self._maybe_auto_refresh_feeds)
        self._schedule_once(1100, self._start_clamd_if_needed)
        self._refresh_feed_state()

        if initial_paths:
            files, truncated = expand_scan_paths(initial_paths)
            if files:
                self.add_paths([str(f) for f in files], truncated=truncated)
                self._schedule_once(150, self._safe_initial_scan)

    # -- Sizing & High-DPI ------------------------------------------------- #

    def _apply_initial_geometry(self) -> None:
        if self._fixed_size is not None:
            w, h = self._fixed_size
            self.resize(w, h)
        else:
            clamp_window_to_screen(self, preferred_w=1280, preferred_h=760, min_w=960, min_h=560)
        saved_split = app_settings().value("ui/split_left")
        if saved_split is not None:
            with suppress(TypeError, ValueError):
                left_w = max(256, min(440, int(saved_split)))
                self._splitter.setSizes([left_w, max(400, self.width() - left_w)])

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._screen_signal_connected and self._fixed_size is None:
            handle = self.windowHandle()
            if handle is not None:
                handle.screenChanged.connect(lambda _scr: reclamp_to_current_screen(self))
                self._screen_signal_connected = True

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        is_compact = self.width() < 1080
        if is_compact != self._compact_mode:
            self._compact_mode = is_compact
            self._apply_compact_mode(is_compact)

    def _apply_compact_mode(self, compact: bool) -> None:
        pad_x = 20 if compact else 28
        pad_y = 16 if compact else 20
        self._detail_inner_lay.setContentsMargins(pad_x, pad_y, pad_x, pad_y)
        self._right_footer_inner_lay.setContentsMargins(pad_x, 0, pad_x, 0)
        self.detail_view.set_compact(compact)
        root = self.centralWidget()
        if root is not None:
            root.setProperty("compact", "true" if compact else "false")
            root.style().unpolish(root)
            root.style().polish(root)

    # -- Switches (Shared between OptionsView & OptionsDialog) ------------- #

    def _build_switches(self) -> None:
        s = app_settings()

        self.chk_clam_auto = ToggleSwitch(parent=self)
        self.chk_clam_auto.setAccessibleName("ClamAV Auto-Update")
        self.chk_clam_auto.setChecked(
            s.value("clam_auto_update", config.CLAMAV_AUTO_UPDATE_ENABLED_DEFAULT, bool)
        )
        self.chk_clam_auto.toggled.connect(self._on_clam_auto_toggled)

        self.chk_feeds_auto = ToggleSwitch(parent=self)
        self.chk_feeds_auto.setAccessibleName("Sperrlisten Auto-Update")
        self.chk_feeds_auto.setChecked(
            s.value("feeds_auto_update", config.FEEDS_AUTO_UPDATE_ENABLED_DEFAULT, bool)
        )
        self.chk_feeds_auto.toggled.connect(self._on_feeds_auto_toggled)

        self.chk_dns_auth = ToggleSwitch(parent=self)
        self.chk_dns_auth.setAccessibleName("SPF/DMARC über DNS prüfen")
        self.chk_dns_auth.setChecked(s.value("dns_auth_enabled", config.DNS_AUTH_ENABLED, bool))
        self.chk_dns_auth.toggled.connect(self._on_dns_auth_toggled)

        self.chk_capa = ToggleSwitch(parent=self)
        self.chk_capa.setAccessibleName("Fähigkeits-Analyse (capa)")
        self.chk_capa.setChecked(s.value("capa_enabled", config.CAPA_ENABLED, bool))
        self.chk_capa.toggled.connect(self._on_capa_toggled)

        # Pure session state: ALWAYS starts False, NEVER persisted to QSettings!
        self.chk_static_only = ToggleSwitch(parent=self)
        self.chk_static_only.setAccessibleName("Nur-Statik-Modus")
        self.chk_static_only.setChecked(False)
        self.chk_static_only.toggled.connect(self._on_static_only_toggled)

        self.chk_auto_open = ToggleSwitch(parent=self)
        self.chk_auto_open.setAccessibleName("Bericht automatisch öffnen")
        self.chk_auto_open.setChecked(s.value("auto_open_report", False, bool))
        self.chk_auto_open.toggled.connect(self._save_auto_open_setting)

        # Apply saved opt-ins immediately
        config.CAPA_ENABLED = self.chk_capa.isChecked()
        config.DNS_AUTH_ENABLED = self.chk_dns_auth.isChecked()

    # -- UI Construction --------------------------------------------------- #

    def _build_ui(self) -> None:
        central = QWidget(self)
        central.setObjectName("appRoot")
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 1. Top Header Bar (46 px)
        top_bar = QFrame(central)
        top_bar.setObjectName("topBar")
        top_bar.setFixedHeight(46)
        tb_lay = QHBoxLayout(top_bar)
        tb_lay.setContentsMargins(16, 0, 16, 0)
        tb_lay.setSpacing(10)

        self.logo_label = QLabel(top_bar)
        self.logo_label.setObjectName("brandLogo")
        self.logo_label.setFixedSize(28, 28)
        self.logo_label.setToolTip(f"{config.APP_NAME} v{__version__}")
        self.logo_label.setCursor(Qt.CursorShape.PointingHandCursor)
        from ..branding import logo_path

        pix = QPixmap(str(logo_path()))
        if not pix.isNull():
            self.logo_label.setPixmap(
                pix.scaled(
                    28,
                    28,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        else:
            self.logo_label.setText("M")
            self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.mousePressEvent = lambda _e: self._leave_options()
        tb_lay.addWidget(self.logo_label)

        tb_lay.addStretch(1)

        self.status_capsule = _EngineCapsule(top_bar)
        self.status_capsule.clicked.connect(self._toggle_options_view)
        tb_lay.addWidget(self.status_capsule)

        self.btn_options = QPushButton("Optionen", top_bar)
        self.btn_options.setAccessibleName("Optionen öffnen")
        self.btn_options.clicked.connect(self._toggle_options_view)
        tb_lay.addWidget(self.btn_options)

        outer.addWidget(top_bar)

        # 2. Splitter Body (Left Sidebar + Right Workspace)
        self._splitter = QSplitter(Qt.Orientation.Horizontal, central)
        self._splitter.setHandleWidth(1)
        self._splitter.setChildrenCollapsible(False)

        # --- LEFT SIDEBAR ---
        sidebar = QFrame(self._splitter)
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(256)
        sidebar.setMaximumWidth(440)
        sb_lay = QVBoxLayout(sidebar)
        sb_lay.setContentsMargins(0, 0, 0, 0)
        sb_lay.setSpacing(0)

        # Search + Type + Flush 5-Chip Filter Header
        sb_hdr = QFrame(sidebar)
        sb_hdr.setObjectName("sidebarHeader")
        sh_lay = QVBoxLayout(sb_hdr)
        sh_lay.setContentsMargins(12, 12, 12, 10)
        sh_lay.setSpacing(8)

        search_row = QHBoxLayout()
        search_row.setContentsMargins(0, 0, 0, 0)
        search_row.setSpacing(6)
        self.search_box = QLineEdit(sb_hdr)
        self.search_box.setPlaceholderText("Name, Endung, Hash…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.setAccessibleName("Dateien durchsuchen")
        self.search_box.textChanged.connect(self._apply_filter)
        search_row.addWidget(self.search_box, 1)

        self.type_combo = QComboBox(sb_hdr)
        self.type_combo.setAccessibleName("Nach Dateityp filtern")
        for lbl, code in (
            ("Typ: Alle", "all"),
            ("E-Mail", "EML"),
            ("Archiv", "ZIP"),
            ("Programm", "EXE"),
            ("PDF", "PDF"),
            ("Dokument", "DOC"),
            ("Sonstige", "OTHER"),
        ):
            self.type_combo.addItem(lbl, code)
        self.type_combo.currentIndexChanged.connect(self._apply_filter)
        search_row.addWidget(self.type_combo)
        sh_lay.addLayout(search_row)

        # Flush Full-Width 5-Chip Filter Row (zero right empty space!)
        chip_row = QHBoxLayout()
        chip_row.setContentsMargins(0, 0, 0, 0)
        chip_row.setSpacing(4)
        self._chip_all = _FilterChip("all", "Alle", tooltip="Alle Dateien anzeigen", parent=sb_hdr)
        self._chip_bad = _FilterChip("bad", "0", dot_tone="bad", tooltip="Nur Gefährliche", parent=sb_hdr)
        self._chip_warn = _FilterChip("warn", "0", dot_tone="warn", tooltip="Nur Verdächtige", parent=sb_hdr)
        self._chip_unk = _FilterChip(
            "unk", "0", dot_tone="unk", ring=True, tooltip="Nur Ungeprüfte", parent=sb_hdr
        )
        self._chip_ok = _FilterChip("ok", "OK", dot_tone="ok", tooltip="Nur Unauffällige", parent=sb_hdr)
        self._chip_all.setChecked(True)
        for chip in (self._chip_all, self._chip_bad, self._chip_warn, self._chip_unk, self._chip_ok):
            chip.clicked.connect(lambda _=False, k=chip.key: self._set_status_filter(k))
            chip_row.addWidget(chip, 1)
        sh_lay.addLayout(chip_row)
        sb_lay.addWidget(sb_hdr)

        # Live Scan Progress Banner (hidden when idle)
        self.scan_banner = QFrame(sidebar)
        self.scan_banner.setObjectName("scanBanner")
        sc_lay = QVBoxLayout(self.scan_banner)
        sc_lay.setContentsMargins(10, 8, 10, 8)
        sc_lay.setSpacing(4)
        sc_top = QHBoxLayout()
        sc_top.setContentsMargins(0, 0, 0, 0)
        self._scan_count_lbl = QLabel("Prüfe…", self.scan_banner)
        self._scan_count_lbl.setObjectName("panelHeading")
        self._scan_count_lbl.setTextFormat(Qt.TextFormat.PlainText)
        sc_top.addWidget(self._scan_count_lbl, 1)
        self._scan_pct_lbl = QLabel("0 %", self.scan_banner)
        self._scan_pct_lbl.setObjectName("engineVal")
        self._scan_pct_lbl.setProperty("tone", "info")
        self._scan_pct_lbl.setTextFormat(Qt.TextFormat.PlainText)
        sc_top.addWidget(self._scan_pct_lbl)
        sc_lay.addLayout(sc_top)

        self._scan_file_lbl = QLabel("", self.scan_banner)
        self._scan_file_lbl.setObjectName("mutedLabel")
        self._scan_file_lbl.setTextFormat(Qt.TextFormat.PlainText)
        sc_lay.addWidget(self._scan_file_lbl)

        self.progress = QProgressBar(self.scan_banner)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        sc_lay.addWidget(self.progress)
        self.scan_banner.hide()

        scan_wrap = QWidget(sidebar)
        sw_lay = QVBoxLayout(scan_wrap)
        sw_lay.setContentsMargins(8, 8, 8, 0)
        sw_lay.addWidget(self.scan_banner)
        sb_lay.addWidget(scan_wrap)

        # Ordner-Übersicht Bar (hidden when no results yet)
        self.summary_bar = _ClickableFrame(sidebar)
        self.summary_bar.setObjectName("summaryBar")
        self.summary_bar.setCursor(Qt.CursorShape.PointingHandCursor)
        sum_lay = QHBoxLayout(self.summary_bar)
        sum_lay.setContentsMargins(10, 0, 10, 0)
        lbl_sum = QLabel("Ordner-Übersicht", self.summary_bar)
        lbl_sum.setTextFormat(Qt.TextFormat.PlainText)
        lbl_sum.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._summary_count_lbl = QLabel("0 Dateien →", self.summary_bar)
        self._summary_count_lbl.setObjectName("captionLabel")
        self._summary_count_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._summary_count_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        sum_lay.addWidget(lbl_sum, 1)
        sum_lay.addWidget(self._summary_count_lbl)
        self.summary_bar.setMinimumHeight(34)
        self.summary_bar.clicked.connect(self._show_batch_overview)
        self.summary_bar.hide()

        sum_wrap = QWidget(sidebar)
        sum_w_lay = QVBoxLayout(sum_wrap)
        sum_w_lay.setContentsMargins(8, 8, 8, 4)
        sum_w_lay.addWidget(self.summary_bar)
        sb_lay.addWidget(sum_wrap)

        # Unified File & Container Tree
        self.table = FileTreeWidget(sidebar)
        self.table.files_dropped.connect(self._on_files_dropped)
        self.table.queue_changed.connect(self._refresh_sidebar_actions)
        self.table.clear_requested.connect(self._on_clear)
        self.table.currentItemChanged.connect(self._on_selection_changed)
        sb_lay.addWidget(self.table, 1)

        # Left 52 px Footer Bar
        self.sidebar_footer = QFrame(sidebar)
        self.sidebar_footer.setObjectName("sidebarFooter")
        self.sidebar_footer.setFixedHeight(52)
        sf_lay = QHBoxLayout(self.sidebar_footer)
        sf_lay.setContentsMargins(12, 0, 12, 0)
        sf_lay.setSpacing(6)

        self.btn_scan = QPushButton("Prüfen", self.sidebar_footer)
        self.btn_scan.setObjectName("primaryButton")
        self.btn_scan.setAccessibleName("Ausgewählte Dateien prüfen")
        self.btn_scan.clicked.connect(self._on_scan)
        self.btn_scan.hide()

        self.btn_add = QPushButton("+ Dateien", self.sidebar_footer)
        self.btn_add.setObjectName("primaryButton")
        self.btn_add.setAccessibleName("Dateien zur Prüfung hinzufügen")
        self.btn_add.clicked.connect(self._on_add_files)

        self.btn_add_folder = QPushButton("+ Ordner", self.sidebar_footer)
        self.btn_add_folder.setAccessibleName("Ordner zur Prüfung hinzufügen")
        self.btn_add_folder.clicked.connect(self._on_add_folder)

        self.btn_clear = QPushButton("Leeren", self.sidebar_footer)
        self.btn_clear.setAccessibleName("Liste leeren")
        self.btn_clear.clicked.connect(self._on_clear)
        self.btn_clear.hide()

        self.btn_cancel = QPushButton("Prüfung abbrechen", self.sidebar_footer)
        self.btn_cancel.setObjectName("dangerButton")
        self.btn_cancel.setAccessibleName("Laufende Prüfung abbrechen")
        self.btn_cancel.clicked.connect(self._on_cancel)
        self.btn_cancel.hide()

        sf_lay.addWidget(self.btn_scan, 1)
        sf_lay.addWidget(self.btn_add, 1)
        sf_lay.addWidget(self.btn_add_folder, 1)
        sf_lay.addWidget(self.btn_clear)
        sf_lay.addWidget(self.btn_cancel, 1)
        sb_lay.addWidget(self.sidebar_footer)

        self._splitter.addWidget(sidebar)

        # --- RIGHT WORKSPACE ---
        right_col = QWidget(self._splitter)
        rc_lay = QVBoxLayout(right_col)
        rc_lay.setContentsMargins(0, 0, 0, 0)
        rc_lay.setSpacing(0)

        scroll = QScrollArea(right_col)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        inner_wrap = QWidget(scroll)
        self._detail_inner_lay = QVBoxLayout(inner_wrap)
        self._detail_inner_lay.setContentsMargins(28, 20, 28, 22)
        self._detail_inner_lay.setSpacing(0)

        self._pages = QStackedWidget(inner_wrap)
        self._detail_inner_lay.addWidget(self._pages, 1)
        scroll.setWidget(inner_wrap)
        rc_lay.addWidget(scroll, 1)

        # Page 0: Empty Dropzone
        empty_page = QFrame(self._pages)
        empty_page.setObjectName("dropZone")
        empty_page.setMinimumHeight(400)
        ep_lay = QVBoxLayout(empty_page)
        ep_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ep_lay.setSpacing(10)
        ep_title = QLabel("Dateien oder Ordner zur Prüfung ablegen", empty_page)
        ep_title.setObjectName("fileTitle")
        ep_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ep_lay.addWidget(ep_title)
        ep_sub = QLabel(
            "Prüft PDF, Office-Dokumente, E-Mails (.eml/.msg), "
            "Archive und Programme lokal auf diesem Rechner.",
            empty_page,
        )
        ep_sub.setObjectName("mutedLabel")
        ep_sub.setWordWrap(True)
        ep_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ep_sub.setMaximumWidth(460)
        ep_lay.addWidget(ep_sub)
        ep_lay.addSpacing(10)
        ep_btns = QHBoxLayout()
        ep_btns.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ep_btns.setSpacing(10)
        b_ef = QPushButton("Dateien auswählen…", empty_page)
        b_ef.setObjectName("primaryButton")
        b_ef.clicked.connect(self._on_add_files)
        b_ed = QPushButton("Ordner prüfen…", empty_page)
        b_ed.clicked.connect(self._on_add_folder)
        ep_btns.addWidget(b_ef)
        ep_btns.addWidget(b_ed)
        ep_lay.addLayout(ep_btns)
        self._pages.addWidget(empty_page)

        # Page 1: File Detail View
        self.detail_view = FileDetailView(self._pages)
        self.detail_view.child_selected.connect(self._select_result_in_tree)
        self.detail_view.ancestor_selected.connect(self._select_tree_item)
        self.detail_view.export_requested.connect(self._on_export_report)
        self.detail_view.mail_viewer_requested.connect(self._on_view_mail)
        self._pages.addWidget(self.detail_view)

        # Compatibility aliases for existing tests
        self.verdict = self.detail_view.verdict
        self.engines = self.detail_view.engines
        self.mail_panel = self.detail_view.mail_panel
        self.capa_panel = self.detail_view.capa_panel
        self.btn_report = self.detail_view.btn_report

        # Page 2: Batch Folder Overview
        self.summary = BatchSummary(self._pages)
        self.summary.filter_requested.connect(self._set_status_filter)
        self.summary.result_selected.connect(self._select_result_in_tree)
        self.summary.export_requested.connect(self._on_export_report)
        self._pages.addWidget(self.summary)

        # Page 3: Integrated Options & Auto-Update View
        switches = {
            "clam_auto": self.chk_clam_auto,
            "feeds_auto": self.chk_feeds_auto,
            "dns_auth": self.chk_dns_auth,
            "capa": self.chk_capa,
            "static_only": self.chk_static_only,
            "auto_open": self.chk_auto_open,
        }
        self.options_view = OptionsView(switches, show_header=True, parent=self._pages)
        self.options_view.close_requested.connect(self._leave_options)
        self.options_view.update_clamav_requested.connect(self._on_update_clamav)
        self.options_view.update_yara_requested.connect(self._on_update_yara)
        self.options_view.feeds_requested.connect(self._on_feeds)
        self.options_view.refresh_engines_requested.connect(self._refresh_engine_status)
        self._pages.addWidget(self.options_view)

        # Page 4: Pending Item View
        pending_page = QFrame(self._pages)
        pending_page.setObjectName("card")
        pp_lay = QVBoxLayout(pending_page)
        pp_lay.setContentsMargins(24, 24, 24, 24)
        pp_lay.setSpacing(8)
        self._pending_title = QLabel("Bereit zur Prüfung", pending_page)
        self._pending_title.setObjectName("fileTitle")
        self._pending_title.setTextFormat(Qt.TextFormat.PlainText)
        pp_lay.addWidget(self._pending_title)
        self._pending_path_lbl = QLabel("", pending_page)
        self._pending_path_lbl.setObjectName("mutedLabel")
        self._pending_path_lbl.setWordWrap(True)
        self._pending_path_lbl.setTextFormat(Qt.TextFormat.PlainText)
        pp_lay.addWidget(self._pending_path_lbl)
        pp_lay.addSpacing(8)
        b_go = QPushButton("Jetzt prüfen", pending_page)
        b_go.setObjectName("primaryButton")
        b_go.setMaximumWidth(160)
        b_go.clicked.connect(self._on_scan)
        pp_lay.addWidget(b_go)
        pp_lay.addStretch(1)
        self._pages.addWidget(pending_page)

        # Synchronized 52 px Right Footer Bar
        self.right_footer = QFrame(right_col)
        self.right_footer.setObjectName("rightFooter")
        self.right_footer.setFixedHeight(52)
        rf_inner = self.right_footer
        self._right_footer_inner_lay = QHBoxLayout(rf_inner)
        self._right_footer_inner_lay.setContentsMargins(28, 0, 28, 0)
        self._right_footer_inner_lay.setSpacing(14)

        self.right_footer_lbl = QLabel(
            "Bereit · Ziehen Sie Dateien per Drag & Drop in das Fenster",
            rf_inner,
        )
        self.right_footer_lbl.setObjectName("mutedLabel")
        self.right_footer_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._right_footer_inner_lay.addWidget(self.right_footer_lbl, 1)

        self.btn_reveal = QPushButton("Im Ordner zeigen", rf_inner)
        self.btn_reveal.clicked.connect(self._on_reveal_current)
        self.btn_reveal.hide()
        self._right_footer_inner_lay.addWidget(self.btn_reveal)

        self._btn_opts_done = QPushButton("Fertig", rf_inner)
        self._btn_opts_done.clicked.connect(self._leave_options)
        self._btn_opts_done.hide()
        self._right_footer_inner_lay.addWidget(self._btn_opts_done)

        rc_lay.addWidget(self.right_footer)

        self._splitter.addWidget(right_col)
        self._splitter.setSizes([308, 972])
        outer.addWidget(self._splitter, 1)

        self.setCentralWidget(central)
        self._set_page(_PAGE_EMPTY)

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("&Datei")
        act_add = QAction("Dateien hinzufügen…", self)
        act_add.setShortcut(QKeySequence("Ctrl+O"))
        act_add.triggered.connect(self._on_add_files)
        menu.addAction(act_add)

        act_dir = QAction("Ordner hinzufügen…", self)
        act_dir.setShortcut(QKeySequence("Ctrl+Shift+O"))
        act_dir.triggered.connect(self._on_add_folder)
        menu.addAction(act_dir)

        act_scan = QAction("Prüfung starten", self)
        act_scan.setShortcut(QKeySequence("Ctrl+R"))
        act_scan.triggered.connect(self._on_scan)
        menu.addAction(act_scan)

        act_report = QAction("Bericht speichern…", self)
        act_report.setShortcut(QKeySequence("Ctrl+E"))
        act_report.triggered.connect(self._on_export_report)
        menu.addAction(act_report)

        menu.addSeparator()
        act_quit = QAction("Beenden", self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        menu.addAction(act_quit)

        view_menu = self.menuBar().addMenu("&Ansicht")
        act_search = QAction("Suche fokussieren", self)
        act_search.setShortcut(QKeySequence("Ctrl+F"))
        act_search.triggered.connect(lambda: self.search_box.setFocus())
        view_menu.addAction(act_search)

        act_opt = QAction("Optionen & Auto-Update", self)
        act_opt.setShortcut(QKeySequence("Ctrl+,"))
        act_opt.triggered.connect(self._toggle_options_view)
        view_menu.addAction(act_opt)

        act_theme = QAction("Design umschalten (Dunkel/Hell)", self)
        act_theme.setShortcut(QKeySequence("Ctrl+Shift+T"))
        act_theme.triggered.connect(self._toggle_dark_light)
        view_menu.addAction(act_theme)

        for idx, title in enumerate(("Einschätzung", "Technische Details", "E-Mail-Text", "Fähigkeiten")):
            act_t = QAction(f"Tab: {title}", self)
            act_t.setShortcut(QKeySequence(f"Ctrl+{idx + 1}"))
            act_t.triggered.connect(lambda _=False, i=idx: self.detail_view.select_tab(i))
            view_menu.addAction(act_t)

        act_esc = QAction("Abbrechen / Schließen", self)
        act_esc.setShortcut(QKeySequence("Escape"))
        act_esc.triggered.connect(self._on_escape)
        view_menu.addAction(act_esc)

        help_menu = self.menuBar().addMenu("&Hilfe")
        act_about = QAction(f"Über {config.APP_NAME}", self)
        act_about.setShortcut(QKeySequence("F1"))
        act_about.triggered.connect(self._on_about)
        help_menu.addAction(act_about)

    def _schedule_once(self, delay_ms: int, slot) -> None:
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(slot)
        timer.start(delay_ms)
        self._startup_timers.append(timer)

    def _safe_initial_scan(self) -> None:
        if self._worker is None and self.table.pending_paths():
            self._on_scan()

    # -- Drag & Drop on Whole Window --------------------------------------- #

    def dragEnterEvent(self, event) -> None:
        if not self._scan_active and event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event) -> None:
        if self._scan_active or not event.mimeData().hasUrls():
            event.ignore()
            return
        paths, truncated = _urls_to_paths(event.mimeData().urls())
        if paths:
            self.add_paths(paths, truncated=truncated)
            event.acceptProposedAction()
        else:
            event.ignore()

    def _on_files_dropped(self, raw_paths: list[str]) -> None:
        files, truncated = expand_scan_paths(raw_paths)
        if files:
            self.add_paths([str(f) for f in files], truncated=truncated)

    # -- Queue & Sidebar Actions ------------------------------------------- #

    def add_paths(self, paths: list[str], *, truncated: bool = False) -> None:
        if self._scan_active:
            return
        existing = set(self.table.all_top_level_paths())
        limit = config.MAX_BATCH_FILES
        added = 0
        for raw in paths:
            if not raw or raw in existing:
                continue
            if self.table.topLevelItemCount() >= limit:
                truncated = True
                break
            self.table.add_pending_path(raw)
            existing.add(raw)
            added += 1

        if truncated:
            self._batch_truncated = True
            self.statusBar().showMessage(f"Batch-Limit erreicht (max. {limit} Dateien gleichzeitig).")
        elif added:
            self.statusBar().showMessage(f"{added} Datei(en) zur Prüfung bereit.")

        self._refresh_sidebar_actions()
        if added and self._pages.currentIndex() == _PAGE_EMPTY and self.table.topLevelItemCount() > 0:
            self.table.setCurrentItem(self.table.topLevelItem(0))

    def _on_add_files(self) -> None:
        if self._scan_active:
            return
        paths, _ = QFileDialog.getOpenFileNames(self, "Dateien zur Prüfung auswählen")
        if paths:
            self.add_paths(paths)

    def _on_add_folder(self) -> None:
        if self._scan_active:
            return
        folder = QFileDialog.getExistingDirectory(self, "Ordner zur Prüfung auswählen")
        if folder:
            files, truncated = expand_scan_paths([folder])
            if files:
                self.add_paths([str(f) for f in files], truncated=truncated)
            else:
                QMessageBox.information(
                    self, "Leerer Ordner", "Im gewählten Ordner wurden keine Dateien gefunden."
                )

    def _refresh_sidebar_actions(self) -> None:
        pending = self.table.pending_paths()
        has_any = self.table.topLevelItemCount() > 0
        if self._scan_active:
            self.btn_scan.hide()
            self.btn_add.hide()
            self.btn_add_folder.hide()
            self.btn_clear.hide()
            self.btn_cancel.show()
            return

        self.btn_cancel.hide()
        if pending:
            self.btn_scan.setText(f"{len(pending)} prüfen")
            self.btn_scan.show()
            self.btn_add.setText("+")
            self.btn_add.setObjectName("")
            self.btn_add.style().unpolish(self.btn_add)
            self.btn_add.style().polish(self.btn_add)
            self.btn_add.show()
            self.btn_add_folder.hide()
            self.btn_clear.show()
        else:
            self.btn_scan.hide()
            self.btn_add.setText("+ Dateien")
            self.btn_add.setObjectName("primaryButton")
            self.btn_add.style().unpolish(self.btn_add)
            self.btn_add.style().polish(self.btn_add)
            self.btn_add.show()
            self.btn_add_folder.show()
            self.btn_clear.setVisible(has_any)

        self._update_filter_counts()

    def _update_filter_counts(self) -> None:
        real = [r for r in self._results if isinstance(r, ScanResult)]
        bad = sum(1 for r in real if visual_state(r.risk_level, result_is_incomplete(r)) == "bad")
        warn = sum(1 for r in real if visual_state(r.risk_level, result_is_incomplete(r)) == "warn")
        unk = sum(1 for r in real if visual_state(r.risk_level, result_is_incomplete(r)) == "unk")
        self._chip_bad.set_count_text(str(bad))
        self._chip_warn.set_count_text(str(warn))
        self._chip_unk.set_count_text(str(unk))

        if self._results:
            self._summary_count_lbl.setText(f"{len(self._results)} Dateien →")
            self.summary_bar.show()
        else:
            self.summary_bar.hide()

    # -- Scan Lifecycle ---------------------------------------------------- #

    def _effective_dispatcher(self) -> Dispatcher:
        """Return session dispatcher (static-only disables Defender & ClamAV)."""
        if not self.chk_static_only.isChecked():
            return self.dispatcher
        from ..analysis.clamav import ClamAVScanner
        from ..analysis.windows_av import WindowsDefenderScanner

        return Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )

    def _on_scan(self) -> None:
        if self._worker is not None:
            QMessageBox.information(self, "Läuft", "Ein Scan läuft bereits.")
            return
        paths = self.table.pending_paths() or self.table.all_top_level_paths()
        if not paths:
            QMessageBox.information(
                self,
                "Keine Dateien",
                "Bitte zuerst Dateien oder einen Ordner hinzufügen.",
            )
            return

        # If re-scanning already scanned items, reset previous results cleanly.
        if not self.table.pending_paths():
            self._reset_result_view()
            for p in paths:
                self.table.add_pending_path(p)

        self._clear_result_panes()
        self._scan_cancelled = False
        self.table.mark_pending_as_scanning()
        self.progress.setRange(0, len(paths))
        self.progress.setValue(0)
        self._scan_count_lbl.setText(f"Prüfe 0 / {len(paths)}")
        self._scan_pct_lbl.setText("0 %")
        self._scan_file_lbl.setText("Starte lokale Prüfung…")
        self.scan_banner.show()

        self._worker = ScanWorker(paths, dispatcher=self._effective_dispatcher())
        self._scan_active = True
        self._worker.signals.progress.connect(self._on_progress)
        self._worker.signals.status.connect(self._on_status)
        self._worker.signals.result.connect(self._on_result)
        self._worker.signals.error.connect(self._on_error)
        self._worker.signals.finished.connect(self._on_finished)
        self._set_scanning(True)
        self.thread_pool.start(self._worker)

    def _on_progress(self, current: int, total: int) -> None:
        self.progress.setMaximum(max(1, total))
        self.progress.setValue(current)
        pct = int((current / max(1, total)) * 100)
        self._scan_count_lbl.setText(f"Prüfe {current} / {total}")
        self._scan_pct_lbl.setText(f"{pct} %")

    def _on_status(self, message: str) -> None:
        clean = _masked = masked_widget_text(message)
        self._scan_file_lbl.setText(clip_text(_masked, 48))
        self.statusBar().showMessage(clean)

    def _on_error(self, message: str) -> None:
        self.statusBar().showMessage(f"Fehler: {masked_widget_text(message)}")

    def _on_result(self, result: ScanResult) -> None:
        self._results.append(result)
        item = self.table.upsert_result(result)
        self.summary.update_results(self._results)
        self._update_filter_counts()
        self._apply_filter()
        self.btn_report.setEnabled(not self._scan_active and bool(self._results))
        if self.table.currentItem() is item:
            self._on_selection_changed(item)
        elif len(self._results) == 1 and self._pages.currentIndex() in (_PAGE_EMPTY, _PAGE_PENDING):
            self.table.setCurrentItem(item)

    def _on_finished(self, _results: list[ScanResult] | None = None) -> None:
        self._worker = None
        self._scan_active = False
        if self._scan_cancelled:
            self.table.mark_unscanned_as_cancelled()
        self.scan_banner.hide()
        self._set_scanning(False)
        self._refresh_sidebar_actions()
        self.summary.update_results(self._results)

        if self._scan_cancelled:
            self.statusBar().showMessage(f"Scan abgebrochen ({len(self._results)} Datei(en) geprüft).")
        else:
            self.statusBar().showMessage(f"Fertig: {len(self._results)} Datei(en) geprüft.")

        if self._results and self.table.currentItem() is None:
            self.table.setCurrentItem(self.table.topLevelItem(0))

    def _on_cancel(self) -> None:
        if self._worker is not None:
            self._scan_cancelled = True
            self._worker.cancel()
            self.btn_cancel.setEnabled(False)
            self.statusBar().showMessage("Abbruch angefordert…")

    def _set_scanning(self, scanning: bool) -> None:
        self._scan_active = bool(scanning)
        self.table.set_locked(scanning)
        self.btn_options.setEnabled(not scanning)
        self.status_capsule.setEnabled(not scanning)
        self.options_view.set_scanning(scanning)
        for sw in (
            self.chk_clam_auto,
            self.chk_feeds_auto,
            self.chk_dns_auth,
            self.chk_capa,
            self.chk_static_only,
        ):
            sw.setEnabled(not scanning)
        self.btn_report.setEnabled(not scanning and not self._export_running and bool(self._results))
        self.btn_cancel.setEnabled(scanning and self._worker is not None)
        self._refresh_sidebar_actions()
        if scanning:
            self.statusBar().showMessage("Scan läuft…")

    # -- Reset / Clear ----------------------------------------------------- #

    def _clear_result_panes(self) -> None:
        self.detail_view.clear()
        self._current_reveal_path = None
        self._set_page(_PAGE_EMPTY)

    def _reset_result_view(self) -> None:
        self._results = []
        self._batch_truncated = False
        self.table.clear()
        self.summary.update_results([])
        self._clear_result_panes()
        self.btn_report.setEnabled(False)
        self._refresh_sidebar_actions()

    def _on_clear(self) -> None:
        if self._scan_active:
            return
        self._reset_result_view()
        self.statusBar().showMessage("Liste geleert.")

    # -- Selection, Filtering & Navigation --------------------------------- #

    def _set_status_filter(self, key: str) -> None:
        self._status_filter = key
        for chip in (self._chip_all, self._chip_bad, self._chip_warn, self._chip_unk, self._chip_ok):
            chip.setChecked(chip.key == key)
        self._apply_filter()

    def _apply_filter(self) -> None:
        t_filter = str(self.type_combo.currentData() or "all")
        self.table.apply_filter(self._status_filter, t_filter, self.search_box.text())
        cur = self.table.currentItem()
        if cur is not None and cur.isHidden():
            self.table.clearSelection()
            self.table.setCurrentItem(None)
            self._clear_result_panes()

    def _result_of(self, item: QTreeWidgetItem | None) -> ScanResult | None:
        if item is None:
            return None
        res = item.data(0, RESULT_ROLE)
        return res if isinstance(res, ScanResult) else None

    def _result_at(self, row: int) -> ScanResult | None:
        return self._result_of(self.table.topLevelItem(row))

    def _select_result_in_tree(self, result: ScanResult) -> None:
        item = self.table.find_item_for_result(result)
        if item is not None:
            self.table.setCurrentItem(item)
            self.table.scrollToItem(item)

    def _select_tree_item(self, item: object) -> None:
        if isinstance(item, QTreeWidgetItem):
            self.table.setCurrentItem(item)
            self.table.scrollToItem(item)

    def _on_selection_changed(self, current: QTreeWidgetItem | None = None, _previous=None) -> None:
        if current is None and self.table.selectedItems():
            current = self.table.currentItem()
        if current is None:
            if self._pages.currentIndex() in (_PAGE_DETAIL, _PAGE_PENDING):
                self._clear_result_panes()
            return

        res = self._result_of(current)
        root_path = str(current.data(0, ROOT_PATH_ROLE) or "")
        chain = current.data(0, PARENT_CHAIN_ROLE) or []
        if res is not None:
            self.detail_view.show_result(res, root_path=root_path, ancestor_chain=chain)
            self._current_reveal_path = root_path or res.path
            self._set_page(_PAGE_DETAIL, footer_text=build_footer_summary(res))
        else:
            self.detail_view.clear()
            raw = str(current.data(0, PENDING_PATH_ROLE) or root_path)
            state = str(current.data(0, STATE_ROLE) or "pending")
            self._pending_title.setText(
                "Prüfung abgebrochen" if state == "cancelled" else "Bereit zur Prüfung"
            )
            self._pending_path_lbl.setText(clip_text(masked_widget_text(raw), 180))
            self._current_reveal_path = raw
            self._set_page(_PAGE_PENDING, footer_text="Noch nicht geprüft · Klicken Sie auf ‚Prüfen‘")

    def _set_page(self, page_idx: int, *, footer_text: str | None = None) -> None:
        self._pages.setCurrentIndex(page_idx)
        self.summary_bar.setProperty("selected", "true" if page_idx == _PAGE_BATCH else "false")
        self.summary_bar.style().unpolish(self.summary_bar)
        self.summary_bar.style().polish(self.summary_bar)

        self.status_capsule.setProperty("active", "true" if page_idx == _PAGE_OPTIONS else "false")
        self.status_capsule.style().unpolish(self.status_capsule)
        self.status_capsule.style().polish(self.status_capsule)

        if page_idx == _PAGE_EMPTY:
            self.right_footer_lbl.setText("Bereit · Ziehen Sie Dateien per Drag & Drop in das Fenster")
            self.btn_reveal.hide()
            self._btn_opts_done.hide()
        elif page_idx == _PAGE_OPTIONS:
            self.right_footer_lbl.setText("Einstellungen werden lokal auf diesem Gerät gespeichert")
            self.btn_reveal.hide()
            self._btn_opts_done.show()
        elif page_idx == _PAGE_BATCH:
            total_ms = sum(max(0, r.duration_ms) for r in self._results)
            dur = f"{total_ms / 1000:.1f} s".replace(".", ",")
            cdir = self.summary.common_directory
            folder_name = (Path(cdir).name or cdir) if cdir else "Aktuelle Prüfung"
            self.right_footer_lbl.setText(
                f"Ordner: {clip_text(masked_widget_text(folder_name), 40)} "
                f"· {len(self._results)} Dateien · {dur}"
            )
            self._current_reveal_path = cdir
            can_open = bool(cdir and not is_unc_or_device_path(cdir) and Path(cdir).is_dir())
            self.btn_reveal.setEnabled(can_open)
            self.btn_reveal.setToolTip(
                "" if can_open else "Dateien stammen aus mehreren Ordnern oder Ziel existiert nicht"
            )
            self.btn_reveal.show()
            self._btn_opts_done.hide()
        else:
            if footer_text is not None:
                self.right_footer_lbl.setText(footer_text)
            can_open = False
            if self._current_reveal_path and not is_unc_or_device_path(self._current_reveal_path):
                with suppress(OSError, ValueError):
                    can_open = Path(self._current_reveal_path).exists()
            self.btn_reveal.setEnabled(can_open)
            self.btn_reveal.setToolTip("" if can_open else "Lokale Datei nicht gefunden")
            self.btn_reveal.show()
            self._btn_opts_done.hide()

    def _show_batch_overview(self) -> None:
        if not self._results:
            return
        self.summary.update_results(self._results)
        self._set_page(_PAGE_BATCH)

    def _toggle_options_view(self) -> None:
        if self._pages.currentIndex() == _PAGE_OPTIONS:
            self._leave_options()
        else:
            self._last_page_before_options = self._pages.currentIndex()
            self.options_view.refresh()
            self._set_page(_PAGE_OPTIONS)

    def _leave_options(self) -> None:
        if self._pages.currentIndex() != _PAGE_OPTIONS:
            return
        if self._last_page_before_options == _PAGE_BATCH and self._results:
            self._show_batch_overview()
        elif self.table.currentItem() is not None:
            self._on_selection_changed(self.table.currentItem())
        elif self._results:
            self._show_batch_overview()
        else:
            self._set_page(_PAGE_EMPTY)

    def _on_escape(self) -> None:
        if self._scan_active:
            self._on_cancel()
        elif self._pages.currentIndex() == _PAGE_OPTIONS:
            self._leave_options()

    def _on_reveal_current(self) -> None:
        if self._current_reveal_path:
            reveal_in_explorer(self._current_reveal_path)

    # -- Theme, Options & Background Jobs ---------------------------------- #

    def _toggle_dark_light(self) -> None:
        cur = saved_theme_preference()
        nxt = "light" if cur != "light" else "dark"
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, nxt, persist=True)
        self.options_view.refresh()

    def _on_theme_changed(self, _mode: str, _palette: dict[str, str]) -> None:
        self.table.viewport().update()
        self.update()

    def _open_options(self) -> None:
        """Open Options view (keeps compatibility with tests calling _open_options)."""
        self._toggle_options_view()

    def _refresh_engine_status(self) -> None:
        self.thread_pool.start(_EngineProbe(self.dispatcher, self._engine_signals))

    def _on_engine_status(self, line: str, badges: list) -> None:
        self._engine_badges_data = list(badges)
        self._render_engine_indicators(line)

    def _render_engine_indicators(self, tooltip_line: str = "") -> None:
        static_only = self.chk_static_only.isChecked()
        cap_entries: list[tuple[str, bool]] = []
        opt_rows: list[tuple[str, str, bool]] = []

        if self._engine_badges_data:
            for name, state, tip in self._engine_badges_data:
                avail = state == "ok"
                paused = static_only and name.lower() in ("defender", "windows defender", "clamav")
                cap_entries.append((name, avail and not paused))
                opt_rows.append((name, tip.splitlines()[0] if tip else state, avail))
        else:
            cap_entries = [
                ("Defender", self.dispatcher.av_scanner.available and not static_only),
                ("ClamAV", self.dispatcher.clam_scanner.available and not static_only),
                ("YARA", self.dispatcher.yara.available),
                ("7-Zip", config.SEVENZIP_ENABLED),
            ]
            opt_rows = [(n, "Verfügbar" if ok else "Nicht verfügbar", ok) for n, ok in cap_entries]

        self.status_capsule.set_engines(cap_entries[:4])
        if tooltip_line:
            self.status_capsule.setToolTip(escape_tooltip(tooltip_line))
        self.options_view.set_engine_rows(opt_rows, static_only=static_only)

    def _on_static_only_toggled(self, checked: bool) -> None:
        self._render_engine_indicators()
        self.statusBar().showMessage(
            "Nur-Statik-Modus aktiv (Defender & ClamAV für diese Sitzung pausiert)."
            if checked
            else "Nur-Statik-Modus beendet (Defender & ClamAV wieder aktiv)."
        )

    def _on_clam_auto_toggled(self, checked: bool) -> None:
        app_settings().setValue("clam_auto_update", bool(checked))

    def _on_feeds_auto_toggled(self, checked: bool) -> None:
        app_settings().setValue("feeds_auto_update", bool(checked))

    def _on_dns_auth_toggled(self, checked: bool) -> None:
        config.DNS_AUTH_ENABLED = bool(checked)
        app_settings().setValue("dns_auth_enabled", bool(checked))

    def _on_capa_toggled(self, checked: bool) -> None:
        config.CAPA_ENABLED = bool(checked)
        app_settings().setValue("capa_enabled", bool(checked))
        self.statusBar().showMessage(
            "Fähigkeits-Analyse (capa) eingeschaltet — Scans dauern länger."
            if checked
            else "Fähigkeits-Analyse (capa) ausgeschaltet."
        )

    def _save_auto_open_setting(self, checked: bool) -> None:
        app_settings().setValue("auto_open_report", bool(checked))

    def _refresh_feed_state(self) -> None:
        from ..core.feed_manifest import manifest_path, yara_rules_age
        from ..core.feeds import state_badge

        name, _state, tooltip = state_badge(config.FEEDS_AUTO_UPDATE_MIN_AGE_DAYS)
        tooltip += "\n\n" + yara_rules_age().detail
        tooltip += (
            "\nFeed-Manifest: vorhanden (Prüfung: scripts/verify_feeds.py)"
            if manifest_path().is_file()
            else "\nFeed-Manifest: noch nicht geschrieben"
        )
        self.options_view.refresh(feed_badge_text=name, feed_tooltip=tooltip)

    def _on_feeds(self) -> None:
        from .feeds_dialog import FeedsDialog

        FeedsDialog(self).exec()
        self._refresh_feed_state()

    def _on_update_clamav(self) -> None:
        from ..analysis.clamav_update import find_freshclam

        if find_freshclam() is None:
            QMessageBox.information(
                self,
                "freshclam nicht gefunden",
                "Das ClamAV-Werkzeug freshclam wurde auf diesem Rechner nicht gefunden. "
                "Installieren Sie ClamAV oder pruefen Sie docs/INSTALLATION.md.",
            )
            return
        dlg = _StreamUpdateDialog(
            "ClamAV-Signaturen aktualisieren",
            "Lädt aktuelle Virensignaturen über freshclam (einmalige Online-Verbindung).",
            _freshclam_runner,
            self,
        )
        dlg.updated.connect(self._refresh_engine_status)
        dlg.show()

    def _on_update_yara(self) -> None:
        dlg = _StreamUpdateDialog(
            "YARA-Regeln aktualisieren",
            "Lädt lizenzgeprüfte YARA-Regeln nach (siehe docs/SECURITY_MODEL.md).",
            _yara_rules_runner,
            self,
        )
        dlg.updated.connect(self._reload_yara_rules)
        dlg.show()

    def _reload_yara_rules(self) -> None:
        with suppress(Exception):
            self.dispatcher.yara.reload()
        self._refresh_engine_status()

    def _start_clamd_if_needed(self) -> None:
        if self._injected_dispatcher or not getattr(self.dispatcher.clam_scanner, "enabled", True):
            return
        sig = _EngineSignals(self)
        sig.ready.connect(lambda line, _b: self._on_clamd_start_done(line))
        self.thread_pool.start(_ClamdStartJob(sig))

    def _on_clamd_start_done(self, line: str) -> None:
        if line:
            self.statusBar().showMessage(masked_widget_text(line))
        self._refresh_engine_status()

    def _maybe_auto_update_clamav(self) -> None:
        if not self.chk_clam_auto.isChecked():
            return
        from ..core.feed_manifest import directory_age

        db = getattr(self.dispatcher.clam_scanner, "database", None)
        age = directory_age(db) if db is not None else None
        if age is not None and age < config.CLAMAV_AUTO_UPDATE_MIN_AGE_DAYS:
            return
        sig = _EngineSignals(self)
        sig.ready.connect(lambda line, _b: self._on_auto_update_done(line))
        self.thread_pool.start(_AutoUpdateJob(sig))

    def _on_auto_update_done(self, line: str) -> None:
        self.statusBar().showMessage(masked_widget_text(line))
        self._refresh_engine_status()

    def _maybe_auto_refresh_feeds(self) -> None:
        from ..core.feeds import refresh_due

        faellig, grund = refresh_due(enabled=self.chk_feeds_auto.isChecked())
        if not faellig:
            return
        self.statusBar().showMessage(f"Datenbanken: {grund}")
        self._feed_signals = _EngineSignals(self)
        self._feed_signals.ready.connect(lambda line, _b: self._on_feed_refresh_done(line))
        self._feed_job = _FeedRefreshJob(self._feed_signals)
        self.thread_pool.start(self._feed_job)

    def _on_feed_refresh_done(self, line: str) -> None:
        self.statusBar().showMessage(masked_widget_text(line))
        self._refresh_feed_state()

    # -- Reports & Mail Viewer --------------------------------------------- #

    def _on_export_report(self) -> None:
        if not self._results or self._export_running:
            return
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Bericht speichern",
            "malaz_bericht.html",
            "HTML-Bericht (*.html);;PDF-Bericht (*.pdf);;CSV-Tabelle (*.csv);;JSON-Export (*.json)",
        )
        if not path:
            return
        as_pdf = path.lower().endswith(".pdf") or "PDF" in (selected or "")
        self._export_running = True
        self.btn_report.setEnabled(False)
        self.statusBar().showMessage("Bericht wird erstellt…")

        sig = _ExportSignals(self)
        sig.saved.connect(self._on_report_saved)
        sig.failed.connect(self._on_report_failed)
        self.thread_pool.start(_ExportJob(list(self._results), path, as_pdf, sig))

    def _on_report_saved(self, path: str) -> None:
        self._export_running = False
        self.btn_report.setEnabled(not self._scan_active and bool(self._results))
        self.statusBar().showMessage(f"Bericht gespeichert: {masked_widget_text(path)}")
        if self.chk_auto_open.isChecked() and os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _on_report_failed(self, error: str) -> None:
        self._export_running = False
        self.btn_report.setEnabled(not self._scan_active and bool(self._results))
        self.statusBar().showMessage(f"Bericht fehlgeschlagen: {masked_widget_text(error)}")
        QMessageBox.critical(self, "Bericht fehlgeschlagen", error)

    def _on_view_mail(self) -> None:
        from .mail_viewer_dialog import MailViewerDialog

        cur = self.table.currentItem()
        if cur is None:
            return
        raw = str(cur.data(0, ROOT_PATH_ROLE) or "")
        res = self._result_of(cur)
        if res is not None and res.path and Path(res.path).is_file():
            raw = res.path
        if raw and Path(raw).is_file():
            MailViewerDialog(raw, self).exec()

    def _on_about(self) -> None:
        caps = "\n".join(
            f"  {name}: {'verfügbar' if ok else 'nicht verfügbar'}"
            for name, ok in sorted(config.available_capabilities().items())
        )
        box = QMessageBox(self)
        box.setWindowTitle(f"Über {config.APP_NAME}")
        from ..branding import logo_path

        logo = QPixmap(str(logo_path()))
        if not logo.isNull():
            box.setIconPixmap(
                logo.scaled(
                    72,
                    72,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        box.setText(
            f"{config.APP_NAME} v{__version__}\n\n"
            "Prüft Dateien (PDF, Office, E-Mails, Archive, Programme) lokal auf diesem Rechner.\n"
            "Standardmäßig komplett offline — keine Cloud, keine Telemetrie.\n\n"
            f"Module:\n{caps}"
        )
        box.exec()

    # -- Shutdown ---------------------------------------------------------- #

    def closeEvent(self, event) -> None:
        unregister_theme_listener(self._on_theme_changed)
        if self._fixed_size is None:
            save_window_rect(self)
            sizes = self._splitter.sizes()
            if sizes and sizes[0] >= 200:
                app_settings().setValue("ui/split_left", int(sizes[0]))

        for timer in self._startup_timers:
            timer.stop()
        self._startup_timers.clear()

        if self._worker is not None:
            from ..procio import clear_hard_shutdown, request_hard_shutdown

            self._worker.cancel()
            request_hard_shutdown()
            try:
                self.thread_pool.waitForDone(5000)
            finally:
                clear_hard_shutdown()
            self._worker = None
        super().closeEvent(event)
