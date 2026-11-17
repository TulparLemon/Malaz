"""Main application window.

Layout (top to bottom):
* a drag-and-drop file queue with a friendly placeholder hint,
* control buttons (primary "Scan starten") + progress bar,
* an engine/AV status line,
* a results table (file / type / verdict / findings / score / duration),
* a read-only detail panel explaining the selected result in plain language,
* report export to self-contained HTML5.

All analysis runs on a QThreadPool via :class:`ScanWorker`; the GUI thread only
reacts to signals. Visual styling comes from :mod:`gui.theme` (dark theme).
"""

from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import (
    QObject,
    QRect,
    QRunnable,
    QSize,
    Qt,
    QThreadPool,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QDesktopServices,
    QFontMetrics,
    QIcon,
    QKeySequence,
    QPixmap,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, config
from ..core.dispatcher import Dispatcher, expand_scan_paths
from ..core.mail_view import AUTH_LABELS, MAX_DISPLAY_CHARS, _clip
from ..models import (
    CAT_ARCHIVE,
    CAT_AV,
    CAT_CONTENT,
    CAT_ENTROPY,
    CAT_FORMAT,
    CAT_HASHLIST,
    CAT_IOC,
    CAT_MACRO,
    CAT_MAIL,
    CAT_METADATA,
    CAT_RESOURCE,
    CAT_SCRIPT,
    CAT_SIGNATURE,
    CAT_STEGO,
    CAT_STRUCTURE,
    CATEGORY_EXPLANATIONS,
    RiskLevel,
    ScanResult,
    type_description,
    type_label,
)
from ..reporting.html_report import save_report
from ..security.escaping import escape_html, mask_invisible
from ..workers.scan_worker import ScanWorker
from .batch_summary import BatchSummary
from .capability_panel import CapabilityPanel
from .engine_strip import EngineStrip, compact_engine_text, engine_tooltip
from .mail_panel import MailPanel, is_mail
from .score_breakdown import ScoreBreakdown
from .settings import app_settings
from .theme import RISK_COLORS, RiskTintDelegate, risk_tint
from .verdict_card import VerdictCard

# Risk colours tuned for the dark theme (models.RiskLevel.color targets the
# light-background HTML report instead).
_RISK_COLOR = {
    RiskLevel.GREEN: QColor(RISK_COLORS["green"]),
    RiskLevel.YELLOW: QColor(RISK_COLORS["yellow"]),
    RiskLevel.RED: QColor(RISK_COLORS["red"]),
}

_TABLE_COLUMNS = [
    "Datei",
    "Typ",
    "Ergebnis",
    "Absender",
    "Befunde",
    "Score (0-100)",
    "Dauer (ms)",
    "Engines",
]

# Spaltenindex der Absender-Spalte (Spalte 2 ist farbig das Ergebnis).
# Hoehe der Warteschlange: leer klein, gefuellt gross. EINE Quelle, weil
# Konstruktion und Anpassung dieselben Werte brauchen.
_QUEUE_EMPTY_H = 56
# Je Eintrag etwa eine Zeile. GEMESSEN im gerenderten Fenster: mit zwei
# Eintraegen standen 110 px da, davon zwei Drittel leer. Die Hoehe folgt jetzt
# der Zahl der Eintraege und deckelt erst oben.
_QUEUE_ROW_H = 30
_QUEUE_FULL_MIN_H = 88
_QUEUE_MAX_H = 224

_MAIL_COLUMN = 3
_ENGINE_COLUMN = 7
# Column widths for the 1180 px window. Sized so eight columns + the 304 px
# sidebar + margins stay inside the window; Qt otherwise grows the whole
# window to the table's size hint (measured 1402 px before this table).
# 1440-px-Fenster: die Datei-Spalte war mit 200 px zu schmal, und
# die Absender-Spalte brach bei jeder Mail um. Der Rest bleibt knapp.
_COLUMN_WIDTHS = (320, 90, 110, 210, 70, 80, 70, 100)

# Wie die drei Mechanismen in der Spalte kurz erscheinen.
_AUTH_MARK = {"pass": "\u2713", "fail": "\u2717", "none": "\u2013", "unknown": "?"}



def _verdict_cell(result: ScanResult) -> str:
    """Die Ampelszelle — mit sichtbarer Unvollstaendigkeit.

    Der Grundsatz: *was wir nicht geprüft haben, darf nicht wie geprüft
    aussehen.* Ein Grün auf einer Datei, deren Makro-Stufe mangels Bibliothek
    nie lief, ist kein Freispruch. Ohne diesen Zusatz sieht die Zeile aus wie
    eine geprüfte saubere Datei — die Stufenmeldungen tragen Gewicht 0 und
    ändern den Score nicht.

    Ausgeschrieben statt als Symbol: ein Warnzeichen muss man kennen, den
    Satz versteht jeder. Die Spalte ist breit genug.
    """
    kurz = result.risk_level.short
    if result.is_incomplete:
        return f"{kurz} (unvollständig)"
    return kurz


def _mail_security_summary(result) -> str:
    """Kurzfassung fuer die Listenzeile: ``SPF \u2717 \u00b7 DKIM \u2717 \u00b7 DMARC \u2717``.

    Leer fuer alles, was keine Mail ist \u2014 eine Spalte voller Striche waere
    Rauschen. Die Zeichen: \u2713 bestanden, \u2717 nicht verwendet oder
    fehlgeschlagen, ? nicht beurteilbar.
    """
    sec = getattr(result, "mail_security", None)
    if not sec:
        return ""
    # KURZ halten: die Zelle wird umgebrochen, und ein Umbruch schneidet den
    # Rest ab (im Screenshot fehlte genau die Absender-Warnung). Deshalb steht
    # die wichtigste Aussage VORNE und die Trennzeichen sind knapp.
    rules = {ind.rule_id for ind in result.all_indicators()}
    unbacked = "MAIL_AUTH_CLAIM_UNBACKED" in rules
    # Ist die Behauptung nicht gedeckt, sind die Verfahren NICHT beurteilbar —
    # ein Haekchen waere hier eine Falschaussage. Vorher stand neben einer
    # gefaelschten Mail "SPF\u2713 DKIM\u2713 DMARC\u2713", weil die Anzeige die
    # Behauptung wie ein Urteil las.
    parts = [
        f"{name}{'?' if unbacked else _AUTH_MARK.get(sec.get(key, ''), '?')}"
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"))
    ]
    text = " ".join(parts)
    warnungen = []
    if unbacked:
        warnungen.append("\u26a0 Auth nicht gedeckt")
    if sec.get("sender") == "mismatch":
        warnungen.append("\u26a0 Name \u2260 Adresse")
    if warnungen:
        return " | ".join([*warnungen, text])
    return text


def _mail_security_tooltip(result) -> str:
    """Die Langfassung als Tooltip \u2014 die Spalte selbst bleibt schmal."""
    sec = getattr(result, "mail_security", None)
    if not sec:
        return ""
    rules = {ind.rule_id for ind in result.all_indicators()}
    lines = ["Absender-Sicherheit (aus den Kopfzeilen der Mail, NICHT verifiziert):"]
    if "MAIL_AUTH_CLAIM_UNBACKED" in rules:
        lines.append(
            "  ! Die Kopfzeile behauptet bestandene Authentifizierung durch einen "
            "Server, der in der Received-Kette nicht vorkommt — die Angaben unten "
            "sind damit NICHT beurteilbar."
        )
    for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
        lines.append(f"  {name}: {AUTH_LABELS.get(sec.get(key, ''), 'unbekannt')}")
    sender = sec.get("sender")
    if sender == "mismatch":
        lines.append(
            "  Anzeigename: weicht von der Absenderadresse ab \u2014 der Name kann "
            "frei gewaehlt sein, massgeblich ist die Adresse."
        )
    elif sender == "ok":
        lines.append("  Anzeigename: passt zur Absenderadresse.")
    else:
        lines.append("  Anzeigename: nicht beurteilbar.")
    return "\n".join(lines)

# Short display names for the indicator categories (layman wording).
_CATEGORY_NAMES = {
    CAT_STRUCTURE: "Dateiaufbau",
    CAT_SCRIPT: "Skripte",
    CAT_MACRO: "Makros",
    CAT_STEGO: "Verborgene Daten",
    CAT_ARCHIVE: "Archiv-Inhalt",
    CAT_ENTROPY: "Verschlüsselung/Kompression",
    CAT_SIGNATURE: "Signatur-Treffer",
    CAT_FORMAT: "Dateiformat",
    CAT_METADATA: "Metadaten",
    CAT_RESOURCE: "Eingebettete Objekte",
    CAT_AV: "Virenscanner",
    CAT_HASHLIST: "Bekannte Schad-Datei",
    CAT_IOC: "Verdächtige Adressen",
    CAT_CONTENT: "Inhalt",
    CAT_MAIL: "E-Mail-Auffälligkeiten",
}


def _masked_widget_text(value: object) -> str:
    """Display text for a Qt widget: invisible/bidi controls spelled out.

    Qt runs plain text through the Unicode bidi algorithm, so a file stored as
    ``Rechnung\\u202efdp.exe`` is DRAWN as ``Rechnungexe.pdf`` — an executable
    reading as a document. That is the same deception the PDF renderer and the
    detail panel already block, and it is why the masking belongs at the sink
    (rule from Audit Lauf 2) rather than at whichever field a call site
    remembered. Every widget that shows an attacker-controlled string routes
    its text through here — the queue, the result table — so a new cell cannot
    quietly reintroduce the raw character. Masking twice is a no-op.
    """
    return mask_invisible(value)


class DropListWidget(QListWidget):
    """List widget that accepts dragged files and folders.

    Shows a centred placeholder hint while the queue is empty so first-time
    users immediately see what to do. Entries can be removed three ways —
    Delete/Backspace, the context menu, or :meth:`remove_selected` — because
    the keyboard shortcut alone was undiscoverable: nothing in the UI said
    the queue was editable at all.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.hint = QLabel(
            "Dateien ablegen\n"
            "oder Hinzufügen",
            self,
        )
        self.hint.setAlignment(Qt.AlignCenter)
        self.hint.setProperty("role", "hint")
        self.hint.setAttribute(Qt.WA_TransparentForMouseEvents)
        # Explicit context menu: right-click is where users look for
        # "remove", and it also makes the capability visible (the menu
        # entry is the only affordance the queue had none of).
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        # Tooltip: the empty-state hint vanishes as soon as entries exist —
        # exactly when the user needs to know how to remove one.
        self.setToolTip(
            "Einträge entfernen: markieren und Entf drücken, "
            "oder Rechtsklick → „Aus Liste entfernen“."
        )
        self.refresh_hint()

    def refresh_hint(self) -> None:
        self.hint.setVisible(self.count() == 0)

    def remove_selected(self) -> int:
        """Remove every selected entry; return how many were removed.

        Iterates over the item objects rather than their rows: taking an
        item shifts the rows of everything below it, so a row-index loop
        skips entries when more than one is selected.
        """
        items = self.selectedItems()
        for item in items:
            self.takeItem(self.row(item))
        if items:
            self.refresh_hint()
            # Der Mail-Knopf haengt am INHALT der Warteschlange. Entfernen ist
            # der dritte Weg, sie zu aendern (nach add_paths und Leeren) —
            # ohne diesen Aufruf blieb "Mail sicher ansehen" nach dem Entfernen
            # der letzten Mail sichtbar (BUG-056).
            main = self.window()
            if isinstance(main, MainWindow):
                main._refresh_mail_button()
        return len(items)

    def _editing_locked(self) -> bool:
        """True while a scan is running — the queue must not change then.

        The window disables its own buttons in that window (:meth:`_set_scanning`);
        the context menu has to honour the same rule, otherwise it becomes a
        back door that empties the queue while the worker still walks it.
        """
        main = self.window()
        return isinstance(main, MainWindow) and main._worker is not None

    def _build_context_menu(self) -> QMenu:
        """Build the queue's context menu (without showing it).

        Split from :meth:`_show_context_menu` so the menu contents can be
        asserted in a test: ``menu.exec()`` blocks until the user picks
        something, which makes a combined method untestable.
        """
        locked = self._editing_locked()
        count = len(self.selectedItems())
        menu = QMenu(self)
        act_remove = menu.addAction(
            "Aus Liste entfernen" if count <= 1 else f"{count} Einträge entfernen"
        )
        # Same gate as the window's buttons: no queue edits mid-scan.
        act_remove.setEnabled(count > 0 and not locked)
        act_remove.triggered.connect(self.remove_selected)
        menu.addSeparator()
        act_clear = menu.addAction("Liste leeren")
        act_clear.setEnabled(self.count() > 0 and not locked)
        # The window owns the "clear" semantics (it also resets results and
        # the report button); reaching it via the parent keeps ONE
        # implementation instead of a second, drifting copy here.
        act_clear.triggered.connect(self._request_clear)
        return menu

    def _show_context_menu(self, pos) -> None:
        # Only act on a real entry: right-clicking the empty area should not
        # offer to remove something invisible.
        item = self.itemAt(pos)
        if item is not None and not item.isSelected():
            self.clearSelection()
            item.setSelected(True)
        self._build_context_menu().exec(self.viewport().mapToGlobal(pos))

    def _request_clear(self) -> None:
        main = self.window()
        if isinstance(main, MainWindow):
            main._on_clear()

    def keyPressEvent(self, event):
        # Allow removing selected queue entries with Delete/Backspace — but
        # not mid-scan, where the worker is still walking the very list.
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            if not self._editing_locked():
                self.remove_selected()
            event.accept()
        else:
            super().keyPressEvent(event)

    def resizeEvent(self, event):
        self.hint.setGeometry(self.rect().adjusted(10, 10, -10, -10))
        super().resizeEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if not event.mimeData().hasUrls():
            event.ignore()
            return
        paths, truncated = _urls_to_paths(event.mimeData().urls())
        main = self.parent()
        while main is not None and not isinstance(main, MainWindow):
            main = main.parent()
        if main is not None:
            main.add_paths(paths, truncated=truncated)
        event.acceptProposedAction()


def _urls_to_paths(urls: list[QUrl]) -> tuple[list[str], bool]:
    """Convert dropped URLs to local file paths, preserving the batch cap state."""
    local: list[str] = []
    for url in urls:
        if url.isLocalFile():
            local.append(url.toLocalFile())
    files, truncated = expand_scan_paths(local)
    return [str(f) for f in files], truncated


_HEALTH_COLORS = {
    "ok": "#43a047", "warn": "#f9a825", "error": "#c62828", "off": "#9e9e9e",
}


def _engine_health(dispatcher) -> tuple[str, str]:
    """Aggregate traffic-light verdict (``ok | warn | error``, short reason).

    Used for the badge row's hover summary — the worst per-engine state in
    one sentence (error only when NO usable AV engine remains or YARA is
    missing entirely; details live in the individual badges).
    """
    from ..core.sevenzip import find_7z_binary

    status = dispatcher.defender_status
    defender_usable = dispatcher.av_scanner.available and (
        not status.probed or status.can_scan
    )
    clam = dispatcher.clam_scanner
    clam_bin = getattr(clam, "binary", None)
    is_daemon = (
        clam.available and clam_bin is not None
        and clam_bin.name.lower().startswith("clamdscan")
    )
    clam_usable = clam.available and (
        is_daemon or getattr(clam, "database", None) is not None
    )

    if not defender_usable and not clam_usable:
        return "error", "Kein funktionsfähiger AV-Engine (Defender & ClamAV)"
    if not dispatcher.yara.available:
        return "error", "YARA-Signatur-Engine fehlt"

    problems: list[str] = []
    if not defender_usable:
        problems.append("Defender nicht scan-bereit")
    if clam.available and not clam_usable:
        problems.append("ClamAV ohne Signatur-DB")
    if not config.SEVENZIP_ENABLED:
        problems.append("7-Zip-Stufe abgeschaltet (RAR/7z/CAB/ISO/deb/rpm-Inhalt ungeprüft)")
    elif not find_7z_binary():
        problems.append("7-Zip fehlt (RAR/7z/CAB/ISO/deb/rpm-Inhalt ungeprüft)")
    if dispatcher.yara.load_error:
        problems.append("YARA-Regelfehler")
    if problems:
        return "warn", "Eingeschränkt: " + " · ".join(problems)
    return "ok", "Alle Schutz-Engines bereit"


def _engine_badges(dispatcher) -> list[tuple[str, str, str]]:
    """One ``(name, state, tooltip)`` badge per engine (pure, unit-testable).

    State in ``ok | warn | error | off`` — how established security tools
    (Windows Security, VirusTotal, EDR consoles) present it: a compact
    per-component status row instead of one long prose line. ``error``
    means THIS engine is broken (Defender service dead, ClamAV without
    DB); ``off`` means absent and covered by design. Two red AV badges
    read as "no AV verdicts at all".
    """
    status = dispatcher.defender_status

    if not dispatcher.av_scanner.available:
        defender = (
            "off",
            ("MpCmdRun.exe nicht gefunden — Defender-Stufe wird "
             "übersprungen."),
        )
    elif status.probed and not status.can_scan:
        defender = (
            "error",
            ("Dienst läuft nicht — On-Demand-Scans schlagen fehl "
             "(AV_SKIPPED je Datei)."),
        )
    elif status.probed:
        defender = ("ok", f"On-Demand-Scans möglich. {status.summary}")
    else:
        hint = status.error or "Probe ohne Ergebnis"
        defender = (
            "warn",
            (f"Status unklar ({hint}) — Binary vorhanden, "
             "Scan-Fähigkeit unbewiesen."),
        )

    clam = dispatcher.clam_scanner
    clam_bin = getattr(clam, "binary", None)
    is_daemon = (
        clam.available and clam_bin is not None
        and clam_bin.name.lower().startswith("clamdscan")
    )
    if not getattr(clam, "enabled", True):
        clamav = (
            "off",
            ("Deaktiviert (CLAMAV_ENABLED=False) — die Stufe läuft nicht; "
             "das ist Konfiguration, nicht 'nicht installiert'."),
        )
    elif not clam.available:
        clamav = (
            "off",
            "Nicht installiert — optional (Defender übernimmt die AV-Spalte).",
        )
    elif is_daemon:
        clamav = (
            "ok",
            "clamd-Daemon aktiv (Signaturen im Speicher, sehr schnelle Scans).",
        )
    elif getattr(clam, "database", None) is not None:
        from ..core.feed_manifest import directory_age

        tip = f"Signatur-DB: {clam.database}"
        age = directory_age(clam.database)
        if age is not None:
            tip += f"\nDatenbank vor {age} Tag(en) aktualisiert"
        clamav = ("ok", tip)
    else:
        clamav = (
            "error",
            ("Installiert, aber ohne Signatur-DB — jeder Scan wird "
             "übersprungen. freshclam ausführen."),
        )

    yara_engine = dispatcher.yara
    if not yara_engine.available:
        yara = (
            "error",
            "yara-python fehlt — die Signatur-Engine ist komplett blind.",
        )
    elif yara_engine.load_error:
        yara = (
            "warn",
            f"Regeldatei(en) fehlerhaft: {yara_engine.load_error[:200]}",
        )
    elif getattr(yara_engine, "rule_count", None) == 0:
        yara = (
            "warn",
            ("Keine Regeln geladen — YARA liefert keine Treffer. "
             "Regelverzeichnis prüfen oder Regeln nachladen."),
        )
    else:
        from ..core.feed_manifest import yara_rules_age

        entry = yara_rules_age()
        yara = (
            "ok",
            f"Regeln geladen und einsatzbereit.\n{entry.name}: {entry.detail}",
        )

    from ..core.sevenzip import find_7z_binary

    # A found binary is NOT coverage: config.SEVENZIP_ENABLED can switch the
    # stage off, and then RAR/7z/deb/rpm contents are never extracted. The
    # badge must not promise scanning in that state (and the dispatcher marks
    # each such file ARCH_7Z_DISABLED -> YELLOW, so "ok" here would contradict
    # the result the user is looking at).
    if not config.SEVENZIP_ENABLED:
        sevenzip = (
            "warn",
            ("Stufe abgeschaltet (SEVENZIP_ENABLED=False) — RAR/7z/deb/rpm-"
             "Inhalte bleiben ungeprüft (GELB-Hinweis je Datei)."),
        )
    elif find_7z_binary():
        sevenzip = ("ok", "RAR/7z/deb/rpm-Inhalte werden entpackt und gescannt.")
    else:
        sevenzip = (
            "warn",
            ("Nicht installiert — RAR/7z/deb/rpm-Inhalte bleiben ungeprüft "
             "(GELB-Hinweis je Datei)."),
        )

    from ..analysis.die import DieScanner

    if DieScanner().available:
        die = ("ok", "Detect It Easy verfügbar (Packererkennung).")
    else:
        die = ("off", "Detect It Easy nicht installiert (optional).")

    return [
        ("Defender", *defender),
        ("ClamAV", *clamav),
        ("YARA", *yara),
        ("7-Zip", *sevenzip),
        ("DIE", *die),
    ]


def _build_engine_line(dispatcher) -> str:
    """Assemble the one-line engine status for the GUI status label.

    Pure function (no Qt) so the labelling logic is unit-testable. The
    labels must tell the truth about READINESS, not binary existence:
    a Defender whose service is dead ("not running") can't scan even with
    MpCmdRun present, and a ClamAV without a signature DB (freshclam never
    run) never yields a verdict — both were reported as "bereit" before,
    contradicting the per-file AV_SKIPPED/CLAMAV_SKIPPED findings.
    """
    from ..analysis.privilege import privilege_label
    from ..core.sevenzip import find_7z_binary

    status = dispatcher.defender_status
    if not dispatcher.av_scanner.available:
        av = "nicht verfügbar"
    elif status.probed and not status.can_scan:
        av = "nicht bereit (Dienst aus, On-Demand unmöglich)"
    else:
        av = "bereit"

    clam_avail = dispatcher.clam_scanner.available
    clam_bin = getattr(dispatcher.clam_scanner, "binary", None)
    clam_db = getattr(dispatcher.clam_scanner, "database", None)
    is_daemon = (
        clam_avail and clam_bin is not None
        and clam_bin.name.lower().startswith("clamdscan")
    )
    if not clam_avail:
        clam = "nicht installiert"
    elif is_daemon:
        clam = "bereit (clamd-Daemon)"
    elif clam_db is not None:
        clam = "bereit"
    else:
        clam = "installiert, Signatur-DB fehlt (freshclam ausführen)"

    if not config.SEVENZIP_ENABLED:
        # Same rule as the badge: an installed binary does not mean the stage
        # runs — with the stage off the archives stay unextracted.
        sevenzip = "abgeschaltet (SEVENZIP_ENABLED=False) — RAR/7z/deb/rpm ungeprüft"
    elif find_7z_binary():
        sevenzip = "bereit"
    else:
        sevenzip = "nicht installiert"
    yara_engine = dispatcher.yara
    if not yara_engine.available:
        yara = "nicht installiert"
    elif yara_engine.load_error:
        # A rule file that failed to compile must be visible — the
        # signature engine silently matching nothing is worse.
        yara = f"Regelfehler! ({yara_engine.load_error[:120]})"
    else:
        yara = "bereit"

    clam_detail = ""
    if clam_avail:
        from ..analysis.clamav_status import collect_status, format_status

        clam_detail = " · " + format_status(collect_status())
    from ..analysis.die import DieScanner

    die = "bereit" if DieScanner().available else "nicht installiert"
    ext = [s.name for s in dispatcher.external_scanners if s.available]
    ext_txt = (", ".join(ext) + " bereit") if ext else "keine externen Scanner"
    priv = privilege_label()
    base = (
        f"Schutz-Engines: Windows Defender {av} · ClamAV {clam} · "
        f"7-Zip {sevenzip} · YARA {yara} · DIE {die} · Extern: {ext_txt} · {priv}"
        + clam_detail
    )
    if status.probed:
        return base + f" · {status.summary}"
    if status.error:
        return base + f" · Defender-Status: {status.error}"
    return base


class _EngineSignals(QObject):
    """Carries the asynchronously computed engine status to the GUI.

    Payload: the full detail line (tooltips) and the per-engine badge
    list ``(name, state, tooltip)`` for the status row.
    """

    ready = Signal(str, list)


class _BlocklistWarmup(QRunnable):
    """Laedt die Blocklisten im Hintergrund, damit der erste Scan nicht haengt.

    Gemessen: der erste Scan einer Mail dauerte 5463 ms, der zweite 6,7 ms —
    die Listen (845 000 URL-Hashes, 386 000 Domains, 1700 Netze) werden beim
    ersten Zugriff von der Platte gelesen und geparst. Fuer den Nutzer sieht
    das aus, als haenge das Programm bei der ersten Datei.

    Rein lokal: kein Netz, nur Dateien, die schon da sind. Ein Fehler wird
    verschluckt — das Aufwaermen ist eine Abkuerzung, kein Feature. Fehlt eine
    Liste, laedt sie der Scan eben selbst.
    """

    def run(self) -> None:  # pool thread
        from .. import config
        from ..core.domain_blocklist import load_domain_blocklist
        from ..core.hashlist import load_blocklist
        from ..core.ipblocklist import load_ip_blocklist

        for aufgabe in (
            lambda: load_blocklist(),
            lambda: load_blocklist(Path(config.URL_BLOCKLIST_FILE)),
            load_domain_blocklist,
            lambda: load_ip_blocklist(config.IP_BLOCKLIST_FILE),
        ):
            with suppress(Exception):
                aufgabe()


class _EngineProbe(QRunnable):
    """Probe Defender/ClamAV status off the GUI thread (PowerShell is slow)."""

    def __init__(self, dispatcher, signals: _EngineSignals):
        super().__init__()
        self.dispatcher = dispatcher
        self.signals = signals
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        try:
            # Vor JEDER Statusabfrage neu nachsehen, was auf der Platte liegt.
            # Ohne das bliebe eine ueber Malaz nachgeladene ClamAV-Datenbank
            # unsichtbar: der Scanner haelt seinen Zustand vom Bau fest, und
            # das Abzeichen bliebe rot bis zum Neustart (gemessen 22.09.2026).
            self.dispatcher.clam_scanner.refresh_state()
            line = _build_engine_line(self.dispatcher)
            badges = _engine_badges(self.dispatcher)
        except Exception as exc:  # never break the GUI
            line = f"Engine-Status nicht abrufbar: {type(exc).__name__}: {exc}"
            badges = [("Engines", "warn", line)]
        with suppress(RuntimeError):
            # The window (and thus the signal object) may already be gone if it
            # was closed while this probe was still running. Harmless: drop it.
            self.signals.ready.emit(line, badges)


class _ClamdStartJob(QRunnable):
    """Den clamd-Daemon starten, falls er nicht laeuft.

    GEMESSEN: ohne Daemon kostet JEDE Datei 18 758 ms (clamscan laedt die
    3,6 Millionen Signaturen neu), mit Daemon 189 ms — Faktor 99. Der
    Unterschied ist fuer den Nutzer unsichtbar, weil das ERGEBNIS dasselbe
    ist; er merkt nur, dass es lange dauert.

    Laeuft im Threadpool: der Daemon braucht beim ersten Start Sekunden, bis
    er die Signaturen geladen hat, und das Fenster darf so lange nicht
    stehen. Meldet ueber ``_EngineSignals``.
    """

    def __init__(self, signals):
        super().__init__()
        self.signals = signals
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        # PFLICHT, nicht Kosmetik: ein Runnable im Threadpool kennt keinen
        # Aufrufer. Ohne diesen Fang wanderte eine Ausnahme in die
        # Qt-Ereignisschleife und schlug beim NAECHSTEN Testaufbau durch
        # ("Exceptions caught in Qt event loop" bei einem voellig anderen
        # Test). Gemessen im vollen Suite-Lauf. _EngineProbe macht es genauso.
        #
        # Diese Huelle ist ABSICHTLICH hier und nicht ausgelagert: eine
        # Zwischenmethode waere eine Naht, an der die Tests vorbeilaufen
        # koennten — und genau die Fehlerisolation waere dann ungeprueft.
        try:
            self._starten()
        except Exception as exc:
            with suppress(RuntimeError):
                self.signals.ready.emit(
                    f"clamd-Start uebersprungen: {type(exc).__name__}: {exc}", []
                )

    def _starten(self) -> None:
        """Die Entscheidung. Getrennt, damit ``run`` sie pruefbar umhuellt."""
        from .. import config
        from ..analysis.clamav import ClamAVScanner
        from ..analysis.clamav_update import clamd_port_offen, start_clamd

        # ERST die Stufe pruefen, dann das Binary. Die erste Fassung baute den
        # Scanner mit enabled=False und sah damit IMMER _clamdscan = None —
        # der Job stieg also immer aus, und der Autostart lief in der App NIE.
        # Aufgefallen, weil `enabled=False` den Konstruktor die Binaries gar
        # nicht suchen laesst (clamav.py: `if self.enabled:`). Direkt gegen
        # start_clamd() getestet zu haben verdeckte das.
        #
        # Ist die ClamAV-Stufe aus (etwa weil ein Dritt-EDR das Haupt-AV ist),
        # haette ein Daemon mit ~170 MB im Speicher keinen Zweck.
        if not config.CLAMAV_ENABLED:
            self.signals.ready.emit(
                "clamd wird nicht gebraucht (ClamAV-Stufe ist aus).", []
            )
            return
        # Und ohne clamdscan nutzt Malaz den Daemon nicht.
        if ClamAVScanner()._clamdscan is None:
            self.signals.ready.emit("clamd wird nicht gebraucht (clamdscan fehlt).", [])
            return
        if clamd_port_offen():
            self.signals.ready.emit("clamd laeuft.", [])
            return
        ok, grund = start_clamd()
        self.signals.ready.emit(grund if ok else f"clamd: {grund}", [])


class _FeedRefreshJob(QRunnable):
    """Holt faellige Quellen nach — im Thread, damit der Start nicht haengt.

    Die groesste Liste ist rund 65 MB; im GUI-Thread waere das Programm
    sekundenlang zu. Gemeldet wird ueber ``_EngineSignals``: eine Zeile fuer
    die Statusleiste, keine Badge-Liste (die Quelle-Zeile der Leiste liest
    ihren Stand selbst aus dem Dateisystem — sie braucht keinen Rueckkanal).

    Fehler EINER Quelle brechen den Rest nicht ab: die fuenf Server sind
    unabhaengig, und eine gelungene Liste ist mehr wert als keine.
    """

    def __init__(self, signals, timeout: float | None = None):
        super().__init__()
        self.signals = signals
        self.timeout = timeout
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        from .. import config
        from ..core.feed_import import refresh_feed
        from ..core.feeds import FEEDS, feed_dir

        if self.timeout is None:
            self.timeout = config.FEEDS_DOWNLOAD_TIMEOUT_SECONDS

        # Alle Quellen holen, sobald ueberhaupt etwas veraltet ist. Einzelne
        # Quellen herauszupicken ginge nicht sauber: mehrere feeds schreiben in
        # DIESELBE Liste (urlhaus und phishing_links beide in die URL-Hashes),
        # eine Liste hat also gar kein einzelnes Alter.
        faellig = list(FEEDS)
        ziel = feed_dir()
        ok = 0
        fehler: list[str] = []
        eintraege = 0
        for feed in faellig:
            try:
                # Der konfigurierte Timeout muss bis zum Download durchkommen;
                # ohne das Argument griff der 60-s-Default von download_feed
                # und die dokumentierten 120 s waren wirkungslos (BUG-058).
                _pfad, ergebnis = refresh_feed(feed, ziel, timeout=self.timeout)
                ok += 1
                eintraege += ergebnis.imported
            except Exception as exc:
                fehler.append(f"{feed.key}: {type(exc).__name__}")

        if not fehler:
            line = (
                f"{ok} Quelle(n) nachgeladen, {eintraege} Eintraege "
                "uebernommen. Neue Eintraege gelten ab dem naechsten Scan."
            )
        elif ok:
            line = (
                f"{ok} Quelle(n) nachgeladen, {len(fehler)} fehlgeschlagen "
                f"({', '.join(fehler[:3])})."
            )
        else:
            line = f"Nachladen fehlgeschlagen ({', '.join(fehler[:3])})."
        self.signals.ready.emit(line, [])


class _AutoUpdateJob(QRunnable):
    """Run the startup freshclam update silently (opt-in, age-gated).

    Reports through ``_EngineSignals`` (a status line + empty badge list) so
    the window can refresh its badges without a modal dialog stealing focus
    at launch.
    """

    def __init__(self, signals, timeout: float | None = None):
        super().__init__()
        self.signals = signals
        self.timeout = timeout
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        from ..analysis.clamav_update import run_freshclam

        if self.timeout is None:
            self.timeout = config.CLAMAV_AUTO_UPDATE_TIMEOUT_SECONDS
        try:
            result = run_freshclam(timeout=self.timeout)
            if not result.ran:
                line = f"Update nicht gestartet: {result.error}"
            elif result.timed_out:
                line = (
                    f"Automatisches Update-Timeout nach {self.timeout:.0f} s — "
                    "manueller Knopf eingeblendet."
                )
            elif result.rc == 0:
                line = "Signaturen automatisch aktualisiert."
            else:
                line = (
                    f"Automatisches Update fehlgeschlagen (Code {result.rc}) — "
                    "manueller Knopf eingeblendet."
                )
        except Exception as exc:  # never break the GUI
            line = f"Update-Fehler: {type(exc).__name__}: {exc}"
        with suppress(RuntimeError):
            # Window may be gone (closed during the update). Harmless.
            self.signals.ready.emit(line, [])


class _ExportSignals(QObject):
    """Carries the async report-export outcome back to the GUI thread."""

    saved = Signal(str)   # absolute path of the written report
    failed = Signal(str)  # error message


class _ExportJob(QRunnable):
    """Render the report off the GUI thread.

    PDF rendering of a large batch is CPU-bound and can take seconds to
    minutes — doing it in the GUI thread froze the window ("Not Responding").
    """

    def __init__(self, results: list[ScanResult], path: str, as_pdf: bool, signals: _ExportSignals):
        super().__init__()
        self.results = results
        self.path = path
        self.as_pdf = as_pdf
        self.signals = signals
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        try:
            if self.as_pdf:
                from ..reporting.pdf_report import save_pdf_report

                save_pdf_report(self.results, self.path)
            else:
                save_report(self.results, self.path)
        except Exception as exc:
            with suppress(RuntimeError):
                self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        with suppress(RuntimeError):
            self.signals.saved.emit(self.path)


class _StreamSignals(QObject):
    """Streams update output lines and the final verdict to the GUI."""

    line = Signal(str)
    done = Signal(int, str)  # rc (-1 = not started), error message


class _StreamJob(QRunnable):
    """Runs one update callable off the GUI thread, streaming its output.

    ``runner(line_callback) -> (rc, error)`` — rc 0 means success.
    """

    def __init__(self, signals: _StreamSignals, runner):
        super().__init__()
        self.signals = signals
        self.runner = runner
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        rc, error = self.runner(lambda line: self.signals.line.emit(line))
        with suppress(RuntimeError):
            self.signals.done.emit(rc, error)


def _freshclam_runner(line_callback):
    from ..analysis.clamav_update import run_freshclam

    result = run_freshclam(line_callback=line_callback)
    return (result.rc if result.ran else -1, result.error)


def _yara_rules_runner(line_callback):
    from ..core.yara_update import update_external_rules

    result = update_external_rules(line_callback=line_callback)
    return (0 if result.ok else 1, result.error)


class _StreamUpdateDialog(QDialog):
    """Live view of an external update run (freshclam / YARA rules).

    Non-modal — scans keep working while the update downloads.
    """

    updated = Signal()  # emitted once after a successful update (rc 0)

    def __init__(self, title: str, hint: str, runner, parent=None):
        super().__init__(parent)
        self.runner = runner
        self.setWindowTitle(title)
        self.resize(660, 420)
        layout = QVBoxLayout(self)
        hint_label = QLabel(hint)
        hint_label.setWordWrap(True)
        layout.addWidget(hint_label)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        buttons = QHBoxLayout()
        self.btn_start = QPushButton("Jetzt aktualisieren")
        self.btn_start.clicked.connect(self._start)
        btn_close = QPushButton("Schließen")
        btn_close.clicked.connect(self.close)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_start)
        buttons.addWidget(btn_close)
        layout.addLayout(buttons)
        self._signals = _StreamSignals(self)
        self._signals.line.connect(self._append_line)
        self._signals.done.connect(self._finish)

    def _start(self) -> None:
        self.btn_start.setEnabled(False)
        self.output.clear()
        self._append_line("[Malaz] Update läuft …")
        QThreadPool.globalInstance().start(_StreamJob(self._signals, self.runner))

    def _append_line(self, line: str) -> None:
        self.output.appendPlainText(line)

    def _finish(self, rc: int, error: str) -> None:
        self.btn_start.setEnabled(True)
        if rc == 0:
            self._append_line(
                "[Malaz] Aktualisierung abgeschlossen — gilt ab dem nächsten Scan."
            )
            self.updated.emit()
        elif rc == -1:
            self._append_line(f"[Malaz] Update nicht gestartet: {error}")
        else:
            self._append_line(
                f"[Malaz] Update endete mit Code {rc} — Ausgabe oben prüfen."
            )


def _app_icon() -> QIcon:
    """Window/taskbar icon (thin wrapper so tests can patch one place).

    Delegates to :mod:`malaz.branding` — QIcon(exe) is null on Windows
    (Qt reads image files, not PE resources), so the .ico file shipped
    next to the exe is the only reliable frozen-build source.
    """
    from ..branding import app_icon

    return app_icon()


class MainWindow(QMainWindow):
    def __init__(
        self,
        initial_paths: list[str] | None = None,
        dispatcher: Dispatcher | None = None,
    ):
        super().__init__()
        self.setWindowIcon(_app_icon())
        self.setWindowTitle(f"{config.APP_NAME} — Dateien sicher prüfen")
        self.resize(1440, 820)

        # Injectable so tests can supply an engine-free instance. Building the
        # live default probes Defender and ClamAV (subprocess) — measured
        # 2.2 s per window, paid 26 times by tests/test_gui.py, and thrown away
        # again there.
        self.dispatcher = dispatcher if dispatcher is not None else Dispatcher()
        self.thread_pool = QThreadPool.globalInstance()
        self._worker: ScanWorker | None = None
        self._scan_active = False
        self._results: list[ScanResult] = []
        self._batch_truncated = False
        # Einmal-Timer, die MIT dem Fenster enden (siehe _schedule_once).
        self._startup_timers: list[QTimer] = []

        self._build_ui()
        self._build_menu()
        self.statusBar().showMessage(
            "Bereit. Dateien links ablegen oder hinzufügen."
        )

        # Probe engine/Defender status once, off the GUI thread. The signal
        # object is parented to the window so its lifetime is tied to it.
        self._engine_signals = _EngineSignals(self)
        self._engine_signals.ready.connect(self._on_engine_status)
        self.thread_pool.start(_EngineProbe(self.dispatcher, self._engine_signals))

        # Opt-in signature refresh at launch: runs only when the checkbox is
        # ticked AND the DB is stale/missing (config.CLAMAV_AUTO_UPDATE_*).
        # A singleShot keeps the window visible first — freshclam may take
        # minutes on a first run and must never delay the UI.
        self._schedule_once(400, self._maybe_auto_update_clamav)
        # Dasselbe fuer die Datenbanken, versetzt: zwei Netzlaeufe gleichzeitig
        # beim Start waeren unnoetig — erst die Signaturen, dann die Listen.
        self._schedule_once(700, self._maybe_auto_refresh_feeds)
        # Ganz zuletzt und im Hintergrund: der Daemon braucht beim ersten
        # Start Sekunden zum Laden der Signaturen. Ohne ihn faellt JEDE Datei
        # auf den langsamen Weg (18 758 ms statt 189 ms, gemessen), und der
        # Nutzer sieht nur, dass es lange dauert.
        self._schedule_once(1100, self._start_clamd_if_needed)
        # Stand sofort anzeigen (nur Dateisystem), damit die Zeile nie leer
        # stehen bleibt, waehrend ein Lauf noch laeuft.
        self._refresh_feed_state()

        if initial_paths:
            # Explorer context menu / command line: queue the files and start
            # scanning once the event loop is up (timer, not a direct call, so
            # tests can swap the dispatcher before the first file runs).
            files, truncated = expand_scan_paths(initial_paths)
            if files:
                self.add_paths([str(f) for f in files], truncated=truncated)
                self._schedule_once(150, self._safe_initial_scan)

    # -- UI construction --------------------------------------------------- #

    def _fit_queue_height(self, *_args) -> None:
        """Die Warteschlange auf ihren Inhalt einstellen.

        Leer: nur der Platzhalter, also klein. Gefuellt: die volle Hoehe.
        Ohne das stand ein 110 px hoher leerer Kasten im Fenster.
        """
        anzahl = self.file_list.count()
        if anzahl == 0:
            hoehe = _QUEUE_EMPTY_H
        else:
            hoehe = min(_QUEUE_MAX_H, max(_QUEUE_FULL_MIN_H, anzahl * _QUEUE_ROW_H + 32))
        self.file_list.setMinimumHeight(hoehe)
        self.file_list.setMaximumHeight(hoehe)
        if hasattr(self, "queue_count"):
            self.queue_count.setText(str(anzahl))

    def _safe_initial_scan(self) -> None:
        """Timer callback for initial_paths: start the scan unless the window
        was closed or a scan is already running."""
        if self._worker is None and self.file_list.count() > 0:
            self._on_scan()

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("appRoot")
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---------------------------------------------------------------- #
        # Linke Spalte: Marke, Warteschlange, Aktionen, Systemstatus.
        # Die frueher hier stehenden Opt-in-Kaestchen und Update-Knoepfe
        # liegen jetzt im Optionsdialog; im Hauptfenster bleibt nur, was
        # fuer den naechsten Scan gebraucht wird.
        # ---------------------------------------------------------------- #
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(304)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(24, 24, 24, 16)
        side.setSpacing(12)

        brand = QHBoxLayout()
        brand.setSpacing(8)
        from ..branding import logo_path

        self.logo_label = QLabel()
        pixmap = QPixmap(str(logo_path()))
        if not pixmap.isNull():
            self.logo_label.setPixmap(
                pixmap.scaledToHeight(32, Qt.TransformationMode.SmoothTransformation)
            )
        brand.addWidget(self.logo_label)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        title = QLabel("MALAZ")
        title.setObjectName("brandTitle")
        tagline = QLabel("Offline-Triage für Dateien")
        tagline.setObjectName("brandTagline")
        brand_text.addWidget(title)
        brand_text.addWidget(tagline)
        brand.addLayout(brand_text, 1)
        version = QLabel(f"v{__version__}")
        version.setObjectName("brandVersion")
        brand.addWidget(version, 0, Qt.AlignTop)
        side.addLayout(brand)
        side.addSpacing(16)

        queue_head = QHBoxLayout()
        queue_label = QLabel("Dateien")
        queue_label.setObjectName("sectionLabel")
        self.queue_count = QLabel("0")
        self.queue_count.setObjectName("queueCount")
        queue_head.addWidget(queue_label)
        queue_head.addStretch(1)
        queue_head.addWidget(self.queue_count)
        side.addLayout(queue_head)

        self.file_list = DropListWidget(self)
        self.file_list.setObjectName("fileQueue")
        self.file_list.setMinimumHeight(_QUEUE_EMPTY_H)
        self.file_list.setMaximumHeight(_QUEUE_EMPTY_H)
        self.file_list.model().rowsInserted.connect(self._fit_queue_height)
        self.file_list.model().rowsRemoved.connect(self._fit_queue_height)
        side.addWidget(self.file_list)

        self.btn_scan = QPushButton("Dateien prüfen")
        self.btn_scan.setObjectName("primaryButton")
        self.btn_scan.setMinimumHeight(40)
        self.btn_add = QPushButton("Hinzufügen")
        self.btn_add.setObjectName("ghostButton")
        self.btn_clear = QPushButton("Leeren")
        self.btn_clear.setObjectName("ghostButton")
        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setObjectName("ghostButton")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setVisible(False)
        self.btn_view_mail = QPushButton("Mail sicher ansehen")
        self.btn_view_mail.setObjectName("ghostButton")
        self.btn_view_mail.setToolTip(
            "Zeigt den Inhalt einer E-Mail-Datei als Klartext an. Öffnet sie "
            "NICHT im Mailprogramm, führt nichts aus und lädt nichts nach."
        )
        self.btn_view_mail.setVisible(False)
        self.btn_scan.clicked.connect(self._on_scan)
        self.btn_add.clicked.connect(self._on_add_files)
        self.btn_clear.clicked.connect(self._on_clear)
        self.btn_cancel.clicked.connect(self._on_cancel)
        self.btn_view_mail.clicked.connect(self._on_view_mail)
        side.addWidget(self.btn_scan)
        add_row = QHBoxLayout()
        add_row.setSpacing(8)
        add_row.addWidget(self.btn_add, 1)
        add_row.addWidget(self.btn_clear, 1)
        side.addLayout(add_row)
        side.addWidget(self.btn_cancel)
        side.addWidget(self.btn_view_mail)
        side.addStretch(1)

        # Report + Fortschritt bleiben unter den Aktionsknoepfen. Der
        # Geometrie-Test vergleicht genau diese Reihenfolge.
        self.btn_report = QPushButton("Report speichern…")
        self.btn_report.setObjectName("ghostButton")
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self._on_export_report)
        side.addWidget(self.btn_report)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        self.progress.hide()
        side.addWidget(self.progress)

        # Systemstatus: kompakt, nicht interaktiv, Details im Tooltip.
        system = QFrame()
        system.setObjectName("systemPanel")
        system_layout = QVBoxLayout(system)
        system_layout.setContentsMargins(12, 12, 12, 12)
        system_layout.setSpacing(8)
        system_label = QLabel("System")
        system_label.setObjectName("sectionLabel")
        system_layout.addWidget(system_label)

        self.badge_row = QWidget()
        badge_layout = QVBoxLayout(self.badge_row)
        badge_layout.setContentsMargins(0, 0, 0, 0)
        badge_layout.setSpacing(4)
        self._badge_labels: dict[str, QLabel] = {}
        for names in (("Defender", "ClamAV", "YARA"), ("7-Zip", "DIE")):
            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(8)
            for name in names:
                label = QLabel(
                    f'<span style="color:#6b7485; font-size:12px;">●</span>'
                    f"&nbsp;{name}"
                )
                label.setObjectName("systemEngine")
                self._badge_labels[name] = label
                row.addWidget(label)
            row.addStretch(1)
            badge_layout.addLayout(row)
        system_layout.addWidget(self.badge_row)

        self.lbl_feeds_state = QLabel()
        self.lbl_feeds_state.setObjectName("systemState")
        self.lbl_feeds_state.setWordWrap(True)
        system_layout.addWidget(self.lbl_feeds_state)

        self.btn_feeds = QPushButton("Datenbanken")
        self.btn_feeds.setObjectName("ghostButton")
        self.btn_feeds.setToolTip(
            "Hashlisten und Phishing-Adressen einmalig herunterladen. "
            "Malaz fragt nichts automatisch ab — nur dieser Klick loest eine "
            "Verbindung aus."
        )
        self.btn_feeds.clicked.connect(self._on_feeds)
        self.btn_options = QPushButton("Einstellungen")
        self.btn_options.setObjectName("ghostButton")
        self.btn_options.setToolTip(
            "Alle Schalter an einer Stelle — Netzwerk (was hinausgeht) und "
            "Analyse (wie gruendlich geprueft wird)."
        )
        self.btn_options.clicked.connect(self._open_options)
        system_actions = QHBoxLayout()
        system_actions.setSpacing(8)
        system_actions.addWidget(self.btn_feeds, 1)
        system_actions.addWidget(self.btn_options, 1)
        system_layout.addLayout(system_actions)

        # Updates nur, wenn sie wirklich noetig sind (die Methode schaltet
        # sie ein/aus); sie bleiben im Systemblock, damit der Status sichtbar
        # ist, ohne die Hauptflaeche zu fuellen.
        self.btn_clam_update = QPushButton("Signaturen jetzt laden")
        self.btn_clam_update.setObjectName("ghostButton")
        self.btn_clam_update.setToolTip(
            "freshclam ausführen: lädt die ClamAV-Signaturen von den "
            "offiziellen ClamAV-Servern (einmalige Verbindung von freshclam)."
        )
        self.btn_clam_update.clicked.connect(self._on_update_clamav)
        self.btn_clam_update.setVisible(False)
        system_layout.addWidget(self.btn_clam_update)

        self.btn_yara_update = QPushButton("YARA-Regeln nachladen")
        self.btn_yara_update.setObjectName("ghostButton")
        self.btn_yara_update.setToolTip(
            "Lädt das gepflegte ReversingLabs-Regel-Set (MIT) von GitHub — "
            "einmalige Verbindung für den Download, Malaz bleibt offline."
        )
        self.btn_yara_update.clicked.connect(self._on_update_yara)
        self.btn_yara_update.setVisible(False)
        system_layout.addWidget(self.btn_yara_update)
        side.addWidget(system)
        root.addWidget(sidebar)

        # ---------------------------------------------------------------- #
        # Rechte Spalte: Arbeitsflaeche. Kopf, Zusammenfassung, Tabelle,
        # Urteil/Details. Keine Einstellungen, keine Update-Knoepfe.
        # ---------------------------------------------------------------- #
        workspace = QWidget()
        workspace.setObjectName("workspace")
        work = QVBoxLayout(workspace)
        work.setContentsMargins(24, 24, 24, 16)
        work.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(16)
        header_text = QVBoxLayout()
        header_text.setSpacing(4)
        results_title = QLabel("Ergebnisse")
        results_title.setObjectName("headerTitle")
        self.header_meta = QLabel(
            "Lokale Triage. Dateien prüfen, verstehen, entscheiden."
        )
        self.header_meta.setObjectName("headerMeta")
        self.header_meta.setWordWrap(True)
        self.header_meta.setMaximumWidth(400)
        header_text.addWidget(results_title)
        header_text.addWidget(self.header_meta)
        header.addLayout(header_text, 1)

        self.search_box = QLineEdit()
        self.search_box.setObjectName("searchField")
        self.search_box.setPlaceholderText("Dateien, Typen, Befunde…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.setFixedWidth(200)
        self.search_box.textChanged.connect(self._apply_filter)
        header.addWidget(self.search_box, 0, Qt.AlignVCenter)

        self.filter_combo = QComboBox()
        self.filter_combo.setObjectName("filterCombo")
        self.filter_combo.addItem("Alle", "all")
        self.filter_combo.addItem("Auffällig", "yellow")
        self.filter_combo.addItem("Gefährlich", "red")
        self.filter_combo.setFixedWidth(144)
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        header.addWidget(self.filter_combo, 0, Qt.AlignVCenter)
        work.addLayout(header)

        self.empty_state = QLabel(
            "Noch keine Dateien geprüft.\n"
            "Dateien links ablegen oder hinzufügen — die Ergebnisse erscheinen hier."
        )
        self.empty_state.setObjectName("emptyState")
        self.empty_state.setAlignment(Qt.AlignCenter)
        self.empty_state.setWordWrap(True)
        work.addWidget(self.empty_state, 1)

        self.summary = BatchSummary()
        work.addWidget(self.summary)

        self.result_splitter = QSplitter(Qt.Vertical)
        self.result_splitter.setObjectName("resultSplitter")
        self.result_splitter.hide()

        self.table = QTreeWidget()
        self.table.setObjectName("resultTable")
        # Ohne diesen Delegate ueberschreibt die ::item-Regel im Stylesheet
        # jede Zeilenfarbe (gemessen: alle drei Risikostufen RGB(15,20,27)).
        self.table.setItemDelegate(RiskTintDelegate(self.table))
        self.table.setColumnCount(len(_TABLE_COLUMNS))
        self.table.setHeaderLabels(_TABLE_COLUMNS)
        for _column, _width in enumerate(_COLUMN_WIDTHS):
            self.table.setColumnWidth(_column, _width)
        self.table.header().setSectionResizeMode(QHeaderView.Interactive)
        self.table.header().setStretchLastSection(True)
        # Die Absender-Spalte ist nur fuer Mails sinnvoll. Bei einer .pdf oder
        # .txt stand dort immer ein Strich, was die Frage "was ist Absender?"
        # aufwirft. Sie erscheint, sobald eine Mail in der Liste steht.
        self.table.setColumnHidden(_MAIL_COLUMN, True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.header().setSortIndicatorShown(True)
        self.table.setWordWrap(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.result_splitter.addWidget(self.table)

        self.verdict = VerdictCard()
        self.verdict.clear()
        self.engines = EngineStrip()
        self.engines.engine_clicked.connect(self._on_engine_chip_clicked)

        self.detail = QTextEdit()
        self.detail.setObjectName("detailView")
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText(
            "Wählen Sie eine Zeile aus, um die Erklärung zu sehen."
        )

        self.tabs = QTabWidget()
        self.tabs.setObjectName("detailTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self.detail, "Was gefunden wurde")

        self.technical = QTextEdit()
        self.technical.setObjectName("technicalView")
        self.technical.setReadOnly(True)
        self.tabs.addTab(self.technical, "Technische Details")

        self.score_breakdown = ScoreBreakdown()
        self.tabs.addTab(self.score_breakdown, "Warum dieser Score?")

        # Barrierefreiheit/Tastatur: die drei Ebenen sind auch ohne Maus und
        # ohne Farbwahrnehmung erreichbar. Die Reitertexte bleiben stabil
        # (Tests und Golden-Doku hängen daran); die Tooltips erklären die
        # Karte→Beleg→Technik-Reihenfolge, die Shortcuts springen direkt.
        self.tabs.setAccessibleName("Ergebnisdetails")
        self.detail.setAccessibleName("Warum und Belege")
        self.technical.setAccessibleName("Technische Details")
        self.score_breakdown.setAccessibleName("Score-Zerlegung")
        self.tabs.setTabToolTip(0, "Warum und Belege: Befunde in Klartext, mit Handlungsbezug")
        self.tabs.setTabToolTip(1, "Technik: rohe Engine-Ausgabe, Hashes, Pfade")
        self.tabs.setTabToolTip(2, "Score-Zerlegung: jeder Punkt mit Regel und Gewicht")
        # Referenzen halten: ein QShortcut ohne Python-Referenz wird vom GC
        # eingesammelt, das C++-Objekt gelöscht — danach meldet Qt
        # "Signal source has been deleted" beim nächsten Tastendruck.
        self._tab_shortcuts = []
        for index, keys in enumerate(("Ctrl+1", "Ctrl+2", "Ctrl+3")):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.activated.connect(
                lambda i=index: self.tabs.setCurrentIndex(i)
            )
            self._tab_shortcuts.append(shortcut)

        self.mail_panel = MailPanel()
        self.capa_panel = CapabilityPanel()

        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(12)
        # Urteil und Engine-Status teilen sich eine Karte; darunter nur
        # noch die Tabs. Das reduziert die Bloecke im unteren Bereich.
        self.verdict.add_footer(self.engines)
        bottom_layout.addWidget(self.verdict)
        bottom_layout.addWidget(self.tabs, 1)
        self.result_splitter.addWidget(bottom)
        self.result_splitter.setStretchFactor(0, 3)
        self.result_splitter.setStretchFactor(1, 2)
        bottom.setMinimumHeight(300)
        work.addWidget(self.result_splitter, 1)
        root.addWidget(workspace, 1)
        self.setCentralWidget(central)

        # Opt-in-Kaestchen werden NICHT in die Hauptflaeche gehaengt. Sie
        # bleiben Objekte dieses Fensters (ein Zustand, ein Besitzer) und
        # erscheinen ausschliesslich im Optionsdialog.
        self.chk_clam_auto = QCheckBox("ClamAV bei Start aktualisieren")
        self.chk_clam_auto.setToolTip(
            "Wenn die Signaturen älter als "
            f"{config.CLAMAV_AUTO_UPDATE_MIN_AGE_DAYS} Tag(e) sind, lädt "
            "freshclam sie beim Programmstart automatisch nach (einmalige "
            "Verbindung zu den offiziellen ClamAV-Servern). Malaz bleibt "
            "sonst vollständig offline."
        )
        self.chk_clam_auto.setChecked(
            app_settings().value(
                "clamav_auto_update",
                config.CLAMAV_AUTO_UPDATE_ENABLED_DEFAULT,
                bool,
            )
        )
        self.chk_clam_auto.toggled.connect(self._on_clam_auto_toggled)

        self.chk_capa = QCheckBox("Fähigkeits-Analyse (langsam)")
        self.chk_capa.setToolTip(
            "capa beantwortet „was kann dieses Programm?“ — Persistenz, "
            "Netzwerkzugriff, Analyse-Abwehr. Gemessen dauert das 23 bis über "
            "600 Sekunden JE DATEI, weil capa disassembliert und einen "
            "Aufrufgraphen baut. Braucht eine eigene capa-Installation."
        )
        self.chk_capa.setChecked(
            app_settings().value("capa_enabled", config.CAPA_ENABLED, bool)
        )
        self.chk_capa.toggled.connect(self._on_capa_toggled)

        self.chk_feeds_auto = QCheckBox("Datenbanken bei Start nachladen")
        self.chk_feeds_auto.setToolTip(
            "Wenn eine der Quellen aelter als "
            f"{config.FEEDS_AUTO_UPDATE_MIN_AGE_DAYS} Tag(e) ist, holt Malaz "
            "sie beim Programmstart selbst nach (Verbindung zu den in der "
            "Quellenliste genannten Servern, danach wieder vollstaendig "
            "offline). Ohne diesen Haken passiert nur etwas auf Klick."
        )
        self.chk_feeds_auto.setChecked(
            app_settings().value(
                "feeds_auto_update",
                config.FEEDS_AUTO_UPDATE_ENABLED_DEFAULT,
                bool,
            )
        )
        self.chk_feeds_auto.toggled.connect(self._on_feeds_auto_toggled)

        self.chk_dns_auth = QCheckBox("SPF/DMARC über DNS prüfen")
        self.chk_dns_auth.setToolTip(
            "Fragt den DNS-Server dieser Maschine, ob die Absender-IP für die "
            "Absenderdomain freigegeben ist. Dabei geht der DOMAINNAME aus der "
            "Mail hinaus — nicht der Inhalt. Ohne diesen Haken bleibt die "
            "Absenderprüfung 'nicht beurteilbar'. DKIM-Signatur und "
            "DNSSEC-Kette werden NICHT geprüft."
        )
        self.chk_dns_auth.setChecked(
            app_settings().value("dns_auth_enabled", config.DNS_AUTH_ENABLED, bool)
        )
        self.chk_dns_auth.toggled.connect(self._on_dns_auth_toggled)

        self.chk_auto_open = QCheckBox("Report nach dem Speichern öffnen")
        self.chk_auto_open.setChecked(
            app_settings().value("auto_open_report", False, type=bool)
        )
        self.chk_auto_open.toggled.connect(self._save_auto_open_setting)

        self._fit_queue_height()
        self._refresh_mail_button()

        # Die gespeicherte Einstellung gilt ab jetzt, nicht erst nach einem
        # Klick: der Haken steht sonst auf "an", waehrend die Stufe aus ist.
        config.CAPA_ENABLED = self.chk_capa.isChecked()
        self._schedule_once(
            200, lambda: QThreadPool.globalInstance().start(_BlocklistWarmup())
        )

    def _schedule_once(self, delay_ms: int, slot) -> None:
        """Einmal-Timer, der MIT dem Fenster endet.

        ``QTimer.singleShot(msec, callable)`` bindet den Slot an keinen
        Empfaenger und storniert ihn beim Zerstoeren des Fensters NICHT. Ein
        Fenster, das vor Ablauf geschlossen wird (Tests, schneller Exit),
        startete danach trotzdem seinen Ladejob: gemessen begann der
        Feed-Refresh nach dem Testende und rief echte Server auf, der
        Blocklisten-Lauf ebenso. Der Timer haengt hier am Fenster und wird in
        ``closeEvent`` gestoppt.
        """
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(slot)
        timer.start(delay_ms)
        self._startup_timers.append(timer)

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("&Datei")
        act_add = QAction("Dateien hinzufügen…", self)
        act_add.triggered.connect(self._on_add_files)
        menu.addAction(act_add)
        act_report = QAction("Report speichern…", self)
        act_report.triggered.connect(self._on_export_report)
        menu.addAction(act_report)
        menu.addSeparator()
        act_quit = QAction("Beenden", self)
        act_quit.triggered.connect(self.close)
        menu.addAction(act_quit)

        help_menu = self.menuBar().addMenu("&Hilfe")
        act_about = QAction(f"Über {config.APP_NAME}", self)
        act_about.triggered.connect(self._on_about)
        help_menu.addAction(act_about)

    # -- slots ------------------------------------------------------------- #

    def add_paths(self, paths: list[str], *, truncated: bool = False) -> None:
        # Dedup and scan on the RAW path, draw the masked one: an attacker-
        # named file ("Rechnung\u202efdp.exe") must not be able to display as
        # something else — and must still be scanned under its real name.
        existing = {
            self.file_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.file_list.count())
        }
        # Das Batch-Limit gilt fuer die GESAMTE Warteschlange, nicht je Aufruf.
        # `expand_scan_paths` deckelt nur eine Auswahl; der Dialog und ein
        # zweiter Drop umgingen ihn und die Queue wuchs unbegrenzt (BUG-052).
        limit = config.MAX_BATCH_FILES
        for p in paths:
            if p in existing:
                continue
            if self.file_list.count() >= limit:
                truncated = True
                break
            item = QListWidgetItem(_masked_widget_text(p))
            item.setData(Qt.ItemDataRole.UserRole, p)
            self.file_list.addItem(item)
            existing.add(p)
        if truncated:
            self._batch_truncated = True
            self.statusBar().showMessage(
                f"Batch-Limit von {config.MAX_BATCH_FILES} Dateien erreicht — "
                "weitere Dateien wurden nicht in die Warteschlange aufgenommen.",
                15000,
            )
        # Nach jeder Aenderung der Warteschlange: den Mail-Knopf anpassen.
        self._refresh_mail_button()
        self.file_list.refresh_hint()

    def _on_add_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Dateien auswählen")
        if files:
            self.add_paths(files)

    def _clear_result_panes(self) -> None:
        """Die ANSICHT eines Ergebnisses leeren — ohne die Ergebnisse anzutasten.

        Das ist die Menge, die an der Auswahl haengt: Urteilskarte, Klartext,
        und die beiden Reiter, die nur zu einem bestimmten Ergebnis gehoeren.

        Sie steht hier an EINER Stelle, weil sie an DREI Stellen gebraucht
        wird: beim Leeren der Liste, beim Start eines neuen Scans — und beim
        blossen ABWAEHLEN. Genau der letzte Fall war die eigentliche Ursache
        der Meldung "nach Liste leeren steht weiter unauffaellig da": das
        Leeren entzieht der Tabelle die Auswahl, Qt meldet das, und
        ``_on_selection_changed`` stieg mit ``if not rows: return`` aus,
        BEVOR irgendetwas zurueckgesetzt wurde. Wer nur das Leeren repariert,
        laesst den Klick ins Leere falsch stehen.
        """
        self.detail.clear()
        self.verdict.clear()
        self.engines.clear()
        self.score_breakdown.clear()
        # Ueber die WIDGET-Identitaet entfernen, nicht ueber den Index: nach
        # dem ersten removeTab verschiebt sich der Index des zweiten.
        for panel in (self.mail_panel, self.capa_panel):
            index = self.tabs.indexOf(panel)
            if index >= 0:
                self.tabs.removeTab(index)
            panel.clear()

    def _reset_result_view(self) -> None:
        """Alles zuruecksetzen: Ergebnisse UND Ansicht.

        Fuer "Liste leeren" und den Start eines neuen Scans. Ein neuer Scan
        zeigte sonst den Befund der vorigen Runde, bis der erste neue eintraf.
        """
        self.table.clear()
        self._results.clear()
        self.btn_report.setEnabled(False)
        self._clear_result_panes()
        self.empty_state.show()
        self.result_splitter.hide()
        self.summary.update_results([])
        # Die Absender-Spalte wird in _on_result eingeblendet, sobald eine
        # Mail auftaucht. Ohne diese Zeile bliebe sie nach "Liste leeren"
        # oder einem neuen Lauf ohne Mail sichtbar - genau die Verwirrung,
        # die zur Frage "was ist Absender?" gefuehrt hat.
        self.table.setColumnHidden(_MAIL_COLUMN, True)

    def _on_clear(self) -> None:
        self.file_list.clear()
        self._batch_truncated = False
        # Der Mail-Knopf haengt an der Warteschlange — ohne Eintraege ohne
        # Funktion, also weg damit.
        self._refresh_mail_button()
        self.file_list.refresh_hint()
        self._reset_result_view()
        self.progress.setValue(0)
        self.progress.hide()
        self.summary.update_results([])
        self.statusBar().showMessage("Liste geleert.")

    def _on_cancel(self) -> None:
        """Request cancellation of the running scan (checked between files)."""
        if self._worker is not None:
            self._worker.cancel()
            self.btn_cancel.setEnabled(False)
            self.statusBar().showMessage("Abbruch angefordert — aktueller Scan wird noch beendet …")

    def _refresh_engine_status(self) -> None:
        """Re-probe engines off the GUI thread (e.g. after a DB update)."""
        self.thread_pool.start(_EngineProbe(self.dispatcher, self._engine_signals))

    def _on_update_clamav(self) -> None:
        """Open the freshclam dialog (or explain why it cannot run)."""
        from ..analysis.clamav_update import find_freshclam

        if find_freshclam() is None:
            QMessageBox.information(
                self,
                "ClamAV aktualisieren",
                "freshclam.exe wurde nicht gefunden.\n\n"
                "ClamAV installieren (z. B. nach C:\\Program Files\\ClamAV) "
                "oder den Pfad in der Konfiguration hinterlegen.",
            )
            return
        dialog = _StreamUpdateDialog(
            title="ClamAV-Signaturen aktualisieren",
            hint=(
                "freshclam lädt die Signaturen von den offiziellen ClamAV-Servern "
                "(nur freshclam geht online, Malaz selbst bleibt offline). "
                "Neue Signaturen gelten ab dem nächsten Scan."
            ),
            runner=_freshclam_runner,
            parent=self,
        )
        dialog.updated.connect(self._refresh_engine_status)
        dialog.show()  # non-modal: the scan keeps working during the update

    def _on_update_yara(self) -> None:
        """Open the external YARA rule update dialog."""
        dialog = _StreamUpdateDialog(
            title="YARA-Regeln aktualisieren",
            hint=(
                "Lädt das gepflegte Regel-Set von ReversingLabs (MIT-Lizenz) "
                "von GitHub — eine einmalige Verbindung für diesen Download, "
                "Malaz selbst bleibt beim Scannen offline. Neue Regeln gelten "
                "ab dem nächsten Scan."
            ),
            runner=_yara_rules_runner,
            parent=self,
        )
        dialog.updated.connect(self._reload_yara_rules)
        dialog.show()

    def _reload_yara_rules(self) -> None:
        """Re-read the rule files after an update, then refresh the badges."""
        engine = getattr(self.dispatcher, "yara", None)
        if engine is not None:
            engine.reload()
        self._refresh_engine_status()

    def _on_engine_status(self, line: str, badges: list) -> None:
        """Update the per-engine badge row from the async engine probe."""
        _level, short = _engine_health(self.dispatcher)
        for name, state, tooltip in badges:
            label = self._badge_labels.get(name)
            if label is None:
                continue
            color = _HEALTH_COLORS.get(state, "#9e9e9e")
            label.setText(
                f'<span style="color:{color}; font-size:18px;">●</span>'
                f"&nbsp;{name}"
            )
            label.setToolTip(tooltip)
        # Full prose line and aggregate verdict stay available on hover —
        # being visible at a glance stays the badges' job.
        summary = f"Gesamt: {short}\n\n{line}"
        self.badge_row.setToolTip(summary)
        self._refresh_update_buttons()

    def _refresh_update_buttons(self) -> None:
        """Show the manual update buttons only when action is actually needed.

        Rationale: an always-visible "update" button next to a healthy engine
        invites needless network runs. The checkbox handles the routine case;
        these buttons appear for the broken/stale cases only.
        """
        from ..analysis.clamav_status import read_db_dates
        from ..analysis.clamav_update import update_due

        # ClamAV: needs a manual push when the DB is missing/stale (update is
        # due) — regardless of the auto-update checkbox, which we must not
        # silently override.
        clam = self.dispatcher.clam_scanner
        need_clam = False
        if config.CLAMAV_ENABLED and clam.available:
            due, _reason = update_due(enabled=True)
            need_clam = due or not read_db_dates()
        self.btn_clam_update.setVisible(need_clam)

        # YARA: only when the bundled/compiled rules failed to load at all.
        need_yara = bool(getattr(self.dispatcher.yara, "load_error", None))
        self.btn_yara_update.setVisible(need_yara)

    def _on_clam_auto_toggled(self, checked: bool) -> None:
        """Persist the auto-update opt-in and run it immediately if enabled."""
        app_settings().setValue("clamav_auto_update", bool(checked))
        if checked:
            self._maybe_auto_update_clamav(force=True)

    def _refresh_feed_state(self) -> None:
        """Stand der nachgeladenen Quellen in die Leiste schreiben.

        Reines Lesen des Dateisystems, kein Netz — deshalb beim Aufbau des
        Fensters aufrufbar, anders als der Download.
        """
        from ..core.feed_manifest import manifest_path, yara_rules_age
        from ..core.feeds import state_badge

        name, state, tooltip = state_badge(config.FEEDS_AUTO_UPDATE_MIN_AGE_DAYS)
        # Update-Alter der beiden anderen Datenbanken: reines Dateisystem-Lesen
        # (kein clamscan-Aufruf beim Fensteraufbau). Das vollständige Manifest
        # prüft scripts/verify_feeds.py — hier nur, ob eins existiert.
        tooltip += "\n\n" + yara_rules_age().detail
        tooltip += (
            "\nFeed-Manifest: vorhanden (Prüfung: scripts/verify_feeds.py)"
            if manifest_path().is_file()
            else "\nFeed-Manifest: noch nicht geschrieben"
        )
        farbe = _HEALTH_COLORS.get(state, "#9e9e9e")
        self.lbl_feeds_state.setText(
            f'<span style="color:{farbe}; font-size:18px;">●</span>'
            f"&nbsp;{name}"
        )
        self.lbl_feeds_state.setToolTip(tooltip)

    def _on_feeds_auto_toggled(self, checked: bool) -> None:
        app_settings().setValue("feeds_auto_update", bool(checked))

    def _open_options(self) -> None:
        """Die Schalter an einer Stelle zeigen.

        Die Kaestchen bleiben Objekte dieses Fensters und werden nur
        eingegangen; der Dialog liest und setzt keinen eigenen Zustand. Zwei
        Orte mit eigenem Zustand waeren zwei Wahrheiten.
        """
        if self._worker is not None:
            return
        # EINMAL gebaut, dann behalten. Der Dialog haengt die Kaestchen dieses
        # Fensters ein (Qt macht sie dabei zu seinen Kindern), und ein
        # WEGWERF-Dialog nimmt sie beim Schliessen mit:
        #
        #   libshiboken: Internal C++ object (PySide6.QtWidgets.QCheckBox)
        #   already deleted
        #
        # GEMESSEN. Danach stuerzt der naechste Scan ab, weil er
        # ``chk_capa.isChecked()`` liest. Das Behalten ist keine Kosmetik,
        # sondern die Bedingung dafuer, dass die Schalter ihren Besitzer
        # ueberleben.
        if getattr(self, "_options_dialog", None) is None:
            from .options_dialog import OptionsDialog

            self._options_dialog = OptionsDialog(
                self,
                switches={
                    "clam_auto": self.chk_clam_auto,
                    "feeds_auto": self.chk_feeds_auto,
                    "dns_auth": self.chk_dns_auth,
                    "capa": self.chk_capa,
                    "auto_open": self.chk_auto_open,
                },
            )
        self._options_dialog.refresh()
        self._options_dialog.show()
        self._options_dialog.raise_()
        self._options_dialog.activateWindow()

    def _on_dns_auth_toggled(self, checked: bool) -> None:
        config.DNS_AUTH_ENABLED = bool(checked)
        app_settings().setValue("dns_auth_enabled", bool(checked))
        if checked:
            self.statusBar().showMessage(
                "SPF/DMARC über DNS eingeschaltet — beim nächsten Mail-Scan "
                "geht der Domainname an den DNS-Server.",
                10000,
            )
        else:
            self.statusBar().showMessage("SPF/DMARC über DNS ausgeschaltet.", 10000)

    def _start_clamd_if_needed(self) -> None:
        """Den clamd-Daemon starten, wenn ClamAV ihn hat und er nicht laeuft.

        Kein Haken dafuer: der Daemon ist rein lokal (127.0.0.1), veraendert
        nichts am Scan-Ergebnis und ist der Unterschied zwischen 19 Sekunden
        und 0,2 Sekunden je Datei. Ein Opt-in waere hier eine Huerde ohne
        Schutzwirkung.
        """
        self._clamd_signals = _EngineSignals(self)
        self._clamd_signals.ready.connect(self._on_clamd_start_done)
        self.thread_pool.start(_ClamdStartJob(self._clamd_signals))

    def _on_clamd_start_done(self, line: str, _badges: list) -> None:
        self.statusBar().showMessage(line, 10000)
        # Der Scanner hat den Daemon beim Bau nicht gesehen — jetzt nachsehen
        # lassen, sonst liefe der naechste Scan weiter ueber clamscan.
        self._refresh_engine_status()

    def _maybe_auto_refresh_feeds(self) -> None:
        """Beim Start nachladen, wenn der Haken steht UND etwas veraltet ist.

        Nie blockierend: der Lauf geht in den Threadpool und meldet ueber die
        Statusleiste. Dieselbe Bauform wie das ClamAV-Update daneben.
        """
        from ..core.feeds import refresh_due

        faellig, grund = refresh_due(enabled=self.chk_feeds_auto.isChecked())
        if not faellig:
            return
        self.statusBar().showMessage(f"Datenbanken: {grund}")
        self._feed_signals = _EngineSignals(self)
        self._feed_signals.ready.connect(self._on_feed_refresh_done)
        self._feed_job = _FeedRefreshJob(self._feed_signals)
        self.thread_pool.start(self._feed_job)

    def _on_feed_refresh_done(self, line: str, _badges: list) -> None:
        """Statuszeile setzen und die Standanzeige neu lesen."""
        self.statusBar().showMessage(f"Datenbanken: {line}", 15000)
        self._refresh_feed_state()

    def _maybe_auto_update_clamav(self, force: bool = False) -> None:
        """Run the startup signature update when due (opt-in, age-gated).

        Never blocks the GUI: the update runs in the thread pool and reports
        through the status bar. Failures surface the manual button instead of
        a modal box — a broken update must not stop the user from scanning.
        """
        from ..analysis.clamav_update import update_due

        enabled = self.chk_clam_auto.isChecked()
        due, reason = update_due(enabled=True if force else enabled)
        if not due:
            if force or enabled:
                self.statusBar().showMessage(reason, 8000)
            return
        self.statusBar().showMessage(f"ClamAV: {reason}")
        self._auto_update_signals = _EngineSignals(self)
        self._auto_update_signals.ready.connect(self._on_auto_update_done)
        self._auto_update_job = _AutoUpdateJob(self._auto_update_signals)
        self.thread_pool.start(self._auto_update_job)

    def _on_auto_update_done(self, line: str, _badges: list) -> None:
        """Refresh the badges after a startup update and flag failures."""
        self.statusBar().showMessage(f"ClamAV: {line}", 10000)
        self._refresh_engine_status()
        self._refresh_update_buttons()

    def _on_scan(self) -> None:
        # The queue draws masked text (see _masked_widget_text); the path to
        # scan is the raw one kept in the item's UserRole.
        paths = [
            self.file_list.item(i).data(Qt.ItemDataRole.UserRole)
            or self.file_list.item(i).text()
            for i in range(self.file_list.count())
        ]
        if not paths:
            QMessageBox.information(
                self,
                "Keine Dateien",
                "Bitte zuerst Dateien hinzufügen – zum Beispiel per Drag & Drop "
                "in die Dateiliste links.",
            )
            return
        if self._worker is not None:
            QMessageBox.information(self, "Läuft", "Ein Scan läuft bereits.")
            return

        # Reset previous results — ueber die gemeinsame Stelle, sonst bleibt
        # die Urteilskarte des vorigen Laufs stehen.
        self._reset_result_view()
        self.progress.setMaximum(len(paths))
        self.progress.setValue(0)
        # Erst jetzt einblenden: im Ruhezustand ist der Balken ganz weg, sonst
        # stuende ein leerer Fortschrittsbalken dauerhaft im Fenster.
        self.progress.show()

        self._worker = ScanWorker(paths, dispatcher=self.dispatcher)
        self._scan_active = True
        self._worker.signals.progress.connect(self._on_progress)
        self._worker.signals.status.connect(self._on_status)
        self._worker.signals.result.connect(self._on_result)
        self._worker.signals.error.connect(self._on_error)
        self._worker.signals.finished.connect(self._on_finished)
        # AFTER the worker exists: _set_scanning enables the cancel button
        # only when self._worker is not None (regression caught by test).
        self._set_scanning(True)
        self.thread_pool.start(self._worker)

    def _on_progress(self, current: int, total: int) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(current)

    def _on_status(self, message: str) -> None:
        # Sink hardening (Runde 4): the worker sends "Analysiere: <roher Name>"
        # and Qt runs plain-status text through the Unicode bidi algorithm — a
        # file stored as "Rechnung\u202efdp.exe" is DRAWN as "Rechnungexe.pdf".
        # Masking at the funnel (not at the emitting call site) keeps every
        # future status message covered; ``mask_invisible`` is idempotent, so an
        # already masked string passes through unchanged.
        self.statusBar().showMessage(_masked_widget_text(message))

    def _on_error(self, message: str) -> None:
        self.statusBar().showMessage(f"Fehler: {_masked_widget_text(message)}")

    def _row_values(self, result: ScanResult) -> list[str]:
        """Die Spalten einer Ergebniszeile — fuer JEDE Ebene dieselben.

        Ein eigenes Layout fuer Archivmitglieder waere eine zweite Wahrheit:
        andere Spalten, andere Sortierung, andere Filterregeln. Ein Mitglied
        ist ein Scan-Ergebnis wie jedes andere.
        """
        findings = len(result.all_indicators())
        return [
            # Spalte 0 ist der Name, an dem der Nutzer das Urteil abliest —
            # angreiferkontrolliert (Archivmitglied, Anhangsname), deshalb
            # durch dieselbe Senken-Maskierung wie Detailpanel und Warteschlange.
            # Gekuerzt wie ueberall sonst: ein Archivmitglied darf bis 65 535
            # Zeichen heissen. Gemessen trug die Zelle 60 004 Zeichen — mit
            # resizeRowToContents wurde die Zeile turmhoch, sonst still
            # abgeschnitten. Der volle Name steht im Tooltip.
            _clip(_masked_widget_text(result.display_name), MAX_DISPLAY_CHARS),
            type_label(result.detected_type),
            _verdict_cell(result),
            # Fuer Nicht-Mails leer; eine Spalte voller Striche waere Rauschen.
            _mail_security_summary(result),
            str(findings),
            f"{result.score}/100",
            str(result.duration_ms),
            compact_engine_text(result),
        ]

    def _numeric_columns(self, result: ScanResult) -> dict:
        """Spalten, die als ZAHL sortiert werden.

        Der Wert geht als Zahl in die DisplayRole, denn Qt vergleicht QVariant
        typbewusst: als Text stuende "90/100" hinter "0/100" und "1000 ms" vor
        "90 ms". Ein eigener Item-Typ mit ``__lt__`` funktioniert NICHT —
        PySide6 reicht die Python-Methode nicht an die C++-Sortierung durch.
        """
        return {
            4: len(result.all_indicators()),
            5: result.score,
            6: result.duration_ms,
        }

    def _on_result(self, result: ScanResult) -> None:
        self.empty_state.hide()
        self.result_splitter.show()
        # Die Absender-Spalte gehoert nur zu Mails; sie erscheint mit der
        # ersten Mail und bleibt fuer den Rest des Laufs sichtbar.
        if result.detected_type in ("eml", "msg"):
            self.table.setColumnHidden(_MAIL_COLUMN, False)
        self._results.append(result)
        werte = self._row_values(result)
        item = self._make_item(
            result, werte, self._numeric_columns(result), _RISK_COLOR.get(result.risk_level)
        )
        self.table.addTopLevelItem(item)
        self._add_children(item, result)
        # Die Zeilenhoehe SELBST messen. resizeRowToContents und
        # sizeHintForRow rechnen mit einer Zeile; bei umgebrochenem Text in der
        # Absender-Spalte wird die unterste Zeile dann abgeschnitten (im
        # Screenshot fehlte "DMARC?"). QFontMetrics kennt den Umbruch.
        item.setSizeHint(0, QSize(0, self._row_height_for(werte)))
        # Nur die neue Zeile filtern: ein voller Durchlauf nach jedem Ergebnis
        # machte grosse Scans O(n^2) im GUI-Thread.
        self._apply_filter_to_item(item, result)

    def _make_item(self, result: ScanResult, values: list, zahlen: dict, color) -> QTreeWidgetItem:
        """Eine Zeile bauen — farbcodiert nach Risiko.

        DIE FARBE IST HIER ANDERS GESETZT ALS VORHER
        ============================================
        Vorher war nur die ERGEBNIS-Spalte eingefaerbt. Bei 15 Zeilen muss
        man dann die dritte Spalte von links nach rechts lesen, um zu sehen,
        wo es brennt. Jetzt traegt die GANZE Zeile einen Hintergrundton nach
        Risikostufe: Rot ist sofort zu finden, und die Farbe steht nicht
        allein (das Wort steht in der Ergebnisspalte daneben — NN/g: nie
        Farbe allein als Bedeutungstraeger).

        Der Ton ist gedaempft (alpha ~28 von 255): die Schrift muss auf dem
        dunklen Thema lesbar bleiben, und eine gesaettigte Flaeche erschlaegt
        bei 100 Zeilen.
        """
        item = QTreeWidgetItem()
        for col, text in enumerate(values):
            if col in zahlen:
                item.setData(col, Qt.ItemDataRole.DisplayRole, zahlen[col])
            else:
                item.setText(col, text)

        # Ganze Zeile toenen. Kinder erben den Ton ihres eigenen Risikos.
        # SOLIDE Mischfarbe, nicht Alpha: Qt komponiert eine Alpha-Farbe
        # gegen Schwarz statt gegen die Themenflaeche, wodurch Gruen, Gelb
        # und Rot alle als dasselbe Dunkelgrau erschienen (gemessen).
        if color is not None:
            ton = risk_tint(color.name())
            for col in range(len(values)):
                item.setBackground(col, QBrush(ton))

        if color is not None:
            item.setForeground(2, color)
            font = item.font(2)
            font.setBold(True)
            item.setFont(2, font)

        # Der volle Name bleibt erreichbar, sonst sieht der Nutzer nicht, wie
        # die Datei wirklich heisst. ESCAPED, nicht roh: Qt rendert Tooltips
        # als AutoText, ein ZIP-Mitglied "<img src=file:///...>" liess den
        # Tooltip die lokale Datei laden (gemessen 20 000 rote Pixel).
        item.setToolTip(0, escape_html(result.display_name))
        # Das ERGEBNIS haengt am Item. Mit Sortierung entspricht die sichtbare
        # Reihenfolge nicht mehr der in self._results; ein Zugriff ueber den
        # Index zeigte beim Klick die falsche Datei — mit deren Befunden,
        # also unauffaellig falsch.
        item.setData(0, Qt.ItemDataRole.UserRole, result)

        tip = _mail_security_tooltip(result)
        if tip:
            item.setToolTip(_MAIL_COLUMN, tip)
        engine_tip = engine_tooltip(result)
        if engine_tip:
            item.setToolTip(_ENGINE_COLUMN, engine_tip)
        # Ein abweichender Anzeigename ist die Taeter-Handschrift
        # schlechthin — die Zeile faellt dann auch ohne Klick auf.
        if result.mail_security.get("sender") == "mismatch":
            item.setForeground(_MAIL_COLUMN, QColor(RISK_COLORS["red"]))
            font = item.font(_MAIL_COLUMN)
            font.setBold(True)
            item.setFont(_MAIL_COLUMN, font)

        if result.is_incomplete:
            # Der Zusatz steht in der Ergebnisspalte; hier nur der Hinweis,
            # WARUM die Zeile so aussieht.
            item.setToolTip(2, result.incompleteness_note())
        return item

    def _add_children(self, parent: QTreeWidgetItem, result: ScanResult) -> None:
        """Die Kinder eines Ergebnisses als Untereintraege anhaengen.

        Ein Archivmitglied ist eine eigene Zeile mit eigenen Befunden — vorher
        stand es in einer Liste, die nur den Namen nannte. Wer wissen wollte,
        WELCHES Mitglied der Ausloeser war, musste raten.

        Kinder bekommen dieselben Spalten wie das Elternteil: gleiche Farbe,
        gleiche Sortierbarkeit, gleiche Filterregeln. Ein eigenes Layout fuer
        die zweite Ebene waere eine zweite Wahrheit.
        """
        for kind in result.children:
            werte = self._row_values(kind)
            kind_item = self._make_item(
                kind,
                werte,
                self._numeric_columns(kind),
                _RISK_COLOR.get(kind.risk_level),
            )
            parent.addChild(kind_item)
            self._add_children(kind_item, kind)

    def _apply_filter_to_item(self, item, result: ScanResult) -> bool:
        """Ausblenden nach Risikostufe und Suchtext. Gibt zurueck: passt etwas?

        DIE RICHTUNG, DIE MAN LEICHT FALSCH MACHT
        ========================================
        Sichtbar bleibt ein Eintrag, wenn ER SELBST **oder EIN NACHFAHRE**
        passt. Beide Richtungen sind noetig, und die zweite ist die, die man
        vergisst:

        * Passt der Elternteil, ein Kind nicht -> der Elternteil bleibt, das
          Kind verschwindet.
        * Passt ein KIND, der Elternteil nicht -> der Elternteil muss
          BLEIBEN. Sonst waere der Treffer aus der Liste, und mit ihm der
          einzige Weg dorthin. GEMESSEN: die Suche nach einem Archivmitglied
          ("findmich") versteckte das Archiv und zeigte eine LEERE Liste —
          wer nach dem Mitglied sucht, meint das Mitglied.
        """
        passt = self._row_matches_filter(result)
        kind_passt = False
        for i in range(item.childCount()):
            kind = item.child(i)
            kind_result = self._result_of(kind)
            if kind_result is not None and self._apply_filter_to_item(kind, kind_result):
                kind_passt = True
        item.setHidden(not (passt or kind_passt))
        return passt or kind_passt

    def _row_height_for(self, values: list[str]) -> int:
        """Hoehe einer Ergebniszeile, mit Umbruch in der Absender-Spalte."""
        metrics = QFontMetrics(self.table.font())
        height = metrics.height() + 20
        text = values[_MAIL_COLUMN] if len(values) > _MAIL_COLUMN else ""
        if text:
            width = max(self.table.columnWidth(_MAIL_COLUMN) - 12, 40)
            wrapped = metrics.boundingRect(
                QRect(0, 0, width, 0), Qt.TextWordWrap, text
            )
            height = max(height, wrapped.height() + 20)
        return height

    def _sync_mail_tab(self, result: ScanResult) -> None:
        """Den E-Mail-Reiter anlegen, fuellen oder entfernen.

        Der Reiter existiert NUR, solange eine Mail ausgewaehlt ist. Ein leerer
        Reiter "E-Mail" bei einer PDF-Datei waere ein Versprechen, das die
        Datei nicht einloest — und der Nutzer klickt ihn an und findet nichts.
        """
        hat_mail = is_mail(result)
        # Der Reiter wird ueber das WIDGET gesucht, nie ueber einen gemerkten
        # Index: insertTab(1, ...) verschiebt jeden bereits vorhandenen Reiter,
        # und ein alter Index zeigte danach auf den falschen Reiter — gemessen
        # entfernte removeTab(_capa_tab) nach "Faehigkeiten -> Mail" das
        # E-Mail-Panel, waehrend das Capa-Panel als "E-Mail" weiterlief.
        index = self.tabs.indexOf(self.mail_panel)
        if hat_mail:
            if index < 0:
                # Vor "Technische Details" einfuegen: das Fachliche steht
                # hinten, das Lesbare vorn.
                index = self.tabs.insertTab(1, self.mail_panel, "E-Mail")
            self.mail_panel.show_result(result)
            self.tabs.setTabText(
                index,
                "E-Mail" if len(result.children) <= 1 else "E-Mail + Anhaenge",
            )
        elif index >= 0:
            self.tabs.removeTab(index)
            self.mail_panel.clear()

    def _sync_capa_tab(self, result: ScanResult) -> None:
        """Den Faehigkeiten-Reiter anlegen, fuellen oder entfernen.

        Nur wenn capa Faehigkeiten gefunden hat: die blosse Anwesenheit von
        capa ist kein Reiter wert, und ein leerer Reiter ist Rauschen.
        """
        hat = bool(getattr(result, "capa_capabilities", None))
        # Widget-Identitaet wie beim E-Mail-Reiter — siehe _sync_mail_tab.
        index = self.tabs.indexOf(self.capa_panel)
        if hat:
            if index < 0:
                # insertTab(1, ...) wie der E-Mail-Reiter: die Faehigkeiten
                # sind das LESBARE ("was kann dieses Programm"), das
                # Technische gehoert hinten. addTab haette ihn HINTER
                # "Technische Details" gehaengt und damit genau die eigene
                # Begruendung widerlegt.
                index = self.tabs.insertTab(1, self.capa_panel, "Fähigkeiten")
            # Den Titel IMMER setzen, nicht nur beim Anlegen: sonst bleibt
            # "Fähigkeiten (8)" ueber einem Panel mit 3 Eintraegen stehen,
            # sobald der Nutzer eine andere Datei auswaehlt.
            self.tabs.setTabText(
                index, f"Fähigkeiten ({len(result.capa_capabilities)})"
            )
            self.capa_panel.show_result(result)
        elif index >= 0:
            self.tabs.removeTab(index)
            self.capa_panel.clear()

    def _on_finished(self, cancelled: bool = False) -> None:
        # Erst jetzt sortieren: alle Zeilen stehen, Qt ordnet einmal um statt
        # bei jeder eingefuegten Zeile (siehe _build_ui).
        self.table.setSortingEnabled(True)
        self._set_scanning(False)
        self._worker = None
        self._scan_active = False
        self.btn_report.setEnabled(bool(self._results))
        self.progress.hide()
        self.summary.update_results(self._results)

        greens = sum(1 for r in self._results if r.risk_level == RiskLevel.GREEN)
        yellows = sum(1 for r in self._results if r.risk_level == RiskLevel.YELLOW)
        reds = sum(1 for r in self._results if r.risk_level == RiskLevel.RED)
        # Die unvollstaendigen getrennt zaehlen: sie sind weder sauber noch
        # auffaellig, und in der Ampel allein nicht zu erkennen.
        unvollstaendig = sum(1 for r in self._results if r.is_incomplete)
        zusatz = (
            f" — davon {unvollstaendig} NICHT vollständig geprüft"
            if unvollstaendig
            else ""
        )
        batch_zusatz = (
            " — Batch unvollständig: weitere Dateien wurden nicht analysiert"
            if self._batch_truncated
            else ""
        )
        if cancelled:
            self.statusBar().showMessage(
                f"Abgebrochen — {len(self._results)} Datei(en) geprüft: "
                f"{greens} unauffällig, {yellows} verdächtig, {reds} gefährlich"
                f"{zusatz}{batch_zusatz}."
            )
        else:
            self.statusBar().showMessage(
                f"Fertig: {len(self._results)} Dateien geprüft — {greens} unauffällig, "
                f"{yellows} verdächtig, {reds} gefährlich{zusatz}{batch_zusatz}."
            )
        # Guide the user's eye to the most risky VISIBLE result first; with an
        # active filter, selecting a hidden row would show nothing at all.
        # Das Ergebnis haengt am ITEM: mit Sortierung entspricht die
        # sichtbare Reihenfolge nicht mehr der in self._results, ein Zugriff
        # ueber den Index traefe die falsche Datei.
        sichtbar = [
            self.table.topLevelItem(row)
            for row in range(self.table.topLevelItemCount())
            if not self.table.topLevelItem(row).isHidden()
        ]
        sichtbar = [i for i in sichtbar if self._result_of(i) is not None]
        if sichtbar:
            schlimmste = max(
                sichtbar,
                key=lambda i: (
                    self._result_of(i).risk_level,
                    self._result_of(i).score,
                ),
            )
            self.table.setCurrentItem(schlimmste)

    def _result_of(self, item) -> ScanResult | None:
        """Das Ergebnis zu einem Baum-Eintrag — aus dem Item, nicht der Zeile."""
        if item is None:
            return None
        daten = item.data(0, Qt.ItemDataRole.UserRole)
        return daten if isinstance(daten, ScanResult) else None

    def _result_at(self, row: int) -> ScanResult | None:
        """Das Ergebnis einer SICHTBAREN Zeile — ueber das Item, nicht den Index.

        Mit aktivierter Sortierung entspricht die sichtbare Reihenfolge NICHT
        mehr der Reihenfolge in ``self._results``. Ein Zugriff ueber
        ``self._results[row]`` zeigt dann die falsche Datei — und zwar mit
        deren Befunden, also unauffaellig falsch.
        """
        return self._result_of(self.table.topLevelItem(row))

    def _row_matches_filter(self, result: ScanResult) -> bool:
        """Risikostufe UND Suchtext — beide muessen passen."""
        mode = self.filter_combo.currentData() if hasattr(self, "filter_combo") else "all"
        level = result.risk_level
        passt_risiko = (
            mode == "all"
            or (mode == "yellow" and level.value >= 1)
            or (mode == "red" and level.value >= 2)
        )
        if not passt_risiko:
            return False

        suche = self.search_box.text().strip().lower() if hasattr(self, "search_box") else ""
        if not suche:
            return True
        # Gesucht wird in dem, was der Nutzer sieht und eingibt: Dateiname,
        # Typ und die Titel der Befunde. NICHT in Hashes oder Details — die
        # kennt ein Laie nicht auswendig.
        heu = [
            result.display_name,
            result.detected_type,
            type_description(result.detected_type, result.mime_hint),
        ]
        heu.extend(ind.title for ind in result.all_indicators())
        return any(suche in feld.lower() for feld in heu)

    def _apply_filter(self) -> None:
        """Zeilen nach Risikofilter UND Suchtext ein-/ausblenden.

        Auch die KINDER: ein Archivmitglied ist eine eigene Zeile mit eigenen
        Befunden, und wer nach einem Namen sucht, meint womoeglich das
        Mitglied, nicht das Archiv. Der Elternteil bleibt sichtbar, wenn er
        selbst passt — sonst verschwaende eine rote Mail, weil ein harmloser
        Anhang nicht zum Suchtext passt.
        """
        # Die Auswahl VOR dem Filtern merken: Qt entfernt eine gerade
        # ausgewaehlte Zeile beim Verstecken aus selectedItems(), ruft dabei
        # aber kein Auswahl-Signal. Danach stand das Urteil der unsichtbaren
        # Datei ueber einer Liste, die eine andere zeigte (gemessen: gruene
        # Datei markiert, Filter "Gefährlich" -> selection leer, Karte weiter
        # "Unauffällig"). Deshalb den Reset hier explizit nachziehen.
        ausgewaehlt = self.table.selectedItems()
        vorher = ausgewaehlt[0] if ausgewaehlt else self.table.currentItem()
        for row in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(row)
            result = self._result_of(item)
            if result is None:
                continue
            self._apply_filter_to_item(item, result)
        if vorher is not None and vorher.isHidden():
            self.table.setCurrentItem(None)
            self._clear_result_panes()

    def _save_auto_open_setting(self, checked: bool) -> None:
        app_settings().setValue("auto_open_report", checked)

    def _on_selection_changed(self) -> None:
        gewaehlt = self.table.selectedItems()
        if not gewaehlt:
            # Keine Auswahl heisst: es gibt kein Ergebnis ZU ZEIGEN. Ohne das
            # hier blieben Urteilskarte und Text der zuletzt markierten Zeile
            # stehen — nach "Liste leeren" also weiter "unauffaellig" ueber
            # einer leeren Tabelle, und nach einem Klick ins Leere ebenso.
            self._clear_result_panes()
            return
        # Das Ergebnis haengt AM ITEM, nicht an der Zeilennummer: mit
        # aktivierter Sortierung entspricht die sichtbare Reihenfolge nicht
        # mehr der in self._results, und ein Zugriff ueber den Index zeigte
        # beim Klick die falsche Datei — mit deren Befunden, also
        # unauffaellig falsch. Im Baum gilt das auch fuer JEDES Kind.
        result = self._result_of(gewaehlt[0])
        if result is None:
            self._clear_result_panes()
            return
        # Ebene 1: das Urteil als Karte (Zeichen + Wort + Handlung).
        self.verdict.show_result(result)
        self.engines.show_verdicts(result.engine_verdicts)
        self.score_breakdown.show_result(result)
        # Ebene 2: die Befunde in Klartext, inklusive Mailvorschau fuer
        # verschachtelte Ergebnisse (eine .eml im ZIP) — siehe
        # _format_detail, das diese Entscheidung traegt.
        self.detail.setPlainText(_format_detail(result))
        # Ebene 3: das Technische, getrennt und zugeklappt.
        self.technical.setPlainText(_format_technical(result))
        self._sync_mail_tab(result)
        self._sync_capa_tab(result)

    def _on_engine_chip_clicked(self, _engine: str) -> None:
        """A chip click opens the technical tab (raw engine output/detail)."""
        index = self.tabs.indexOf(self.technical)
        if index >= 0:
            self.tabs.setCurrentIndex(index)

    def _on_export_report(self) -> None:
        if not self._results or self._worker is not None:
            return
        # Date-stamped default name so successive reports never overwrite
        # each other and the file is self-describing ("welcher Tag?").
        # PDF is the primary format (best for archiving/sharing); HTML stays
        # available as the pixel-identical browser variant.
        stempel = f"{datetime.now(UTC).astimezone():%Y-%m-%d}"
        default_name = f"malaz_report_{stempel}.pdf"
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Ergebnisse speichern",
            default_name,
            "PDF-Report (*.pdf);;HTML-Report (*.html);;"
            "Tabelle für Excel (*.csv);;Daten für Programme (*.json)",
        )
        if not path:
            return
        chosen = selected or "PDF-Report (*.pdf)"

        # CSV und JSON gehen NICHT durch den Berichts-Renderer: sie sind fuer
        # Programme und Tabellen gedacht, nicht fuer Menschen. Der einzige
        # CSV-Pfad lag bisher im Sondermodus --evaluate (Korpusmessung) und
        # war fuer einen normalen Scan nicht erreichbar.
        if "CSV" in chosen or "JSON" in chosen:
            from ..reporting.export import write_csv, write_json

            als_json = "JSON" in chosen
            wanted = ".json" if als_json else ".csv"
            if Path(path).suffix.lower() != wanted:
                path += wanted
            try:
                (write_json if als_json else write_csv)(self._results, path)
            except OSError as exc:
                QMessageBox.critical(
                    self, "Fehler", f"Datei konnte nicht geschrieben werden:\n{exc}"
                )
                return
            self.statusBar().showMessage(f"Gespeichert: {path}")
            return

        # The FILTER decides the format — not the typed suffix. A user can
        # type "report.pdf" while the HTML filter is active; appending the
        # right extension keeps file content and name consistent.
        as_pdf = "HTML" not in chosen
        wanted = ".pdf" if as_pdf else ".html"
        if Path(path).suffix.lower() != wanted:
            path += wanted
        # Rendering happens OFF the GUI thread (a large PDF can take a
        # while); the outcome arrives via the _ExportSignals below.
        self.btn_report.setEnabled(False)
        self.statusBar().showMessage("Report wird erstellt …")
        self._export_signals = _ExportSignals(self)
        self._export_signals.saved.connect(self._on_report_saved)
        self._export_signals.failed.connect(self._on_report_failed)
        self.thread_pool.start(
            _ExportJob(
                list(self._results),
                path,
                as_pdf,
                self._export_signals,
            )
        )

    def _on_report_saved(self, path: str) -> None:
        self.btn_report.setEnabled(bool(self._results))
        self.statusBar().showMessage(f"Report gespeichert: {path}")
        if self.chk_auto_open.isChecked():
            # Opens in the default viewer (browser for HTML, reader for
            # PDF) — a local file, nothing leaves the machine.
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).resolve())))

    def _on_report_failed(self, message: str) -> None:
        self.btn_report.setEnabled(bool(self._results))
        self.statusBar().showMessage("Report fehlgeschlagen.")
        QMessageBox.critical(
            self, "Fehler", f"Report konnte nicht gespeichert werden:\n{message}"
        )

    def _mail_paths_in_queue(self) -> list[str]:
        """Die Mail-Dateien in der Warteschlange (fuer die Anzeige)."""
        from .mail_viewer_dialog import has_mail_suffix

        pfade = [
            self.file_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.file_list.count())
        ]
        return [p for p in pfade if p and has_mail_suffix(p)]

    def _refresh_mail_button(self) -> None:
        """Den Knopf zeigen, solange Mails in der Warteschlange liegen.

        Kein Knopf ohne Mail: eine Schaltflaeche, die nichts anzuzeigen hat,
        ist ein Versprechen, das die Datei nicht einloest.
        """
        self.btn_view_mail.setVisible(bool(self._mail_paths_in_queue()))

    def _on_view_mail(self) -> None:
        """Eine Mail aus der Warteschlange sicher ansehen."""
        from .mail_viewer_dialog import MailViewerDialog

        pfade = self._mail_paths_in_queue()
        if not pfade:
            return
        # Bei mehreren: die markierte nehmen, sonst die erste.
        gewaehlt = pfade[0]
        zeile = self.file_list.currentRow()
        if 0 <= zeile < self.file_list.count():
            kandidat = self.file_list.item(zeile).data(Qt.ItemDataRole.UserRole)
            if kandidat in pfade:
                gewaehlt = kandidat
        MailViewerDialog(gewaehlt, self).exec()

    def _on_capa_toggled(self, checked: bool) -> None:
        """Die Faehigkeits-Analyse ein- oder ausschalten — und merken.

        Die Einstellung gilt ab dem NAECHSTEN Scan: der Dispatcher liest
        ``config.CAPA_ENABLED`` beim Aufbau der Stufe. Laufende Scans bleiben
        unberuehrt, damit ein Haken mitten im Lauf nichts umwirft.
        """
        config.CAPA_ENABLED = bool(checked)
        app_settings().setValue("capa_enabled", bool(checked))
        self.statusBar().showMessage(
            "Fähigkeits-Analyse eingeschaltet — jeder Scan dauert jetzt "
            "spürbar länger."
            if checked
            else "Fähigkeits-Analyse ausgeschaltet."
        )

    def _on_feeds(self) -> None:
        """Datenbanken-Dialog oeffnen und danach den Stand neu lesen."""
        from .feeds_dialog import FeedsDialog

        FeedsDialog(self).exec()
        # Der Dialog importiert synchron; ohne diese Zeile zeigte die Anzeige
        # danach weiter den Stand VOR dem Import — genau der Fall, fuer den
        # sie da ist ("eine Liste fehlt") bliebe bis zum Neustart stehen.
        self._refresh_feed_state()

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
                    72, 72,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        box.setText(
            f"{config.APP_NAME} v{__version__}\n\n"
            "Prüft Dateien (PDF, Office, Bilder, Archive) auf Gefahren – "
            "komplett offline auf Ihrem Rechner.\n"
            "Keine Cloud, keine Telemetrie, keine Daten verlassen den PC.\n\n"
            f"Module:\n{caps}"
        )
        box.exec()

    def _set_scanning(self, scanning: bool) -> None:
        # Waehrend eines Scans wird nicht sortiert: Qt ordnet sonst bei jeder
        # eingefuegten Zeile um und `setItem(row, ...)` trifft eine verschobene
        # Zeile (siehe _build_ui).
        if scanning:
            self.table.setSortingEnabled(False)
        self.btn_scan.setEnabled(not scanning)
        self.btn_add.setEnabled(not scanning)
        self.btn_clear.setEnabled(not scanning)
        self.btn_options.setEnabled(not scanning)
        self.btn_feeds.setEnabled(not scanning)
        self.btn_clam_update.setEnabled(not scanning)
        self.btn_yara_update.setEnabled(not scanning)
        self.btn_report.setEnabled(not scanning and bool(self._results))
        for checkbox in (
            self.chk_capa,
            self.chk_feeds_auto,
            self.chk_dns_auth,
            self.chk_clam_auto,
        ):
            checkbox.setEnabled(not scanning)
        self.btn_cancel.setEnabled(scanning and self._worker is not None)
        self.btn_cancel.setVisible(scanning)
        if scanning:
            self.statusBar().showMessage("Scan läuft …")

    def closeEvent(self, event) -> None:
        """Cancel a running scan and drain the pool before the window goes.

        Without this the application could hang at exit waiting for pool
        threads (up to one AV timeout per engine) or tear down Qt while
        threads are still running. Cancellation is cooperative (the Abbrechen
        button lets the current file finish); closing the window additionally
        requests a HARD shutdown — engine subprocesses still running are
        killed instead of keeping the process alive for up to ~2 minutes.
        """
        # Zuletzt geplante Start-Laeufe (ClamAV-Update, Feed-Refresh,
        # clamd, Blocklisten) zuerst stoppen: nach dem Schliessen darf kein
        # Netzzugriff mehr beginnen.
        for timer in self._startup_timers:
            timer.stop()
        self._startup_timers.clear()
        if self._worker is not None:
            from ..procio import clear_hard_shutdown, request_hard_shutdown

            self._worker.cancel()
            # A worker object that was never started (tests create one to
            # exercise closeEvent) owns no subprocess; requesting a global
            # hard shutdown there would leak the switch into later tests.
            if self._scan_active:
                request_hard_shutdown()
            self.thread_pool.clear()  # drop queued-but-unstarted work
            drained = self.thread_pool.waitForDone(2000)
            if drained:
                # Reset the global switch: the window may close while the app
                # keeps running (tests, future multi-window use) — later
                # subprocesses must not be killed for a shutdown that is over.
                clear_hard_shutdown()
            else:
                # Pool still busy (a 90-s AV subprocess does not drain in
                # 2 s). Keep the kill switch ON long enough to hit the next
                # 250-ms poll of the running tools, but clear it afterwards
                # so a still-living app is not permanently crippled.
                QTimer.singleShot(10_000, clear_hard_shutdown)
        super().closeEvent(event)


def _group_by_category(result: ScanResult) -> list[tuple[str, str, list]]:
    """Group indicators by category, worst category first.

    Returns (category_name, explanation, indicators) triples.
    """
    groups: dict[str, list] = {}
    for ind in result.indicators:
        groups.setdefault(ind.category, []).append(ind)

    def worst(group: list) -> int:
        return max(ind.severity for ind in group)

    ordered = sorted(groups.items(), key=lambda kv: worst(kv[1]), reverse=True)
    out = []
    for category, inds in ordered:
        name = _CATEGORY_NAMES.get(category, category)
        explanation = CATEGORY_EXPLANATIONS.get(category, "Weitere Auffälligkeiten.")
        out.append((name, explanation, sorted(inds, key=lambda i: i.severity, reverse=True)))
    return out


def _format_detail(result: ScanResult, indent: int = 0) -> str:
    """Render a result as plain text with a layman-friendly structure.

    Layout: verdict → recommendation → what was found (grouped, explained) →
    technical details → mail content → nested archive members.

    The invisible/bidi masking sits on the whole rendered text, at the one
    place every field leaves this module (mirrors ``escape_html`` on the HTML
    side). Masking per call site covered the fields someone remembered —
    indicator title/detail and the path — and missed ``result.error``, which
    carries the Zip-Slip note with the raw entry name; a U+202E in it reached
    the panel unmodified (Qt applies the bidi algorithm to plain text, so it
    displayed as a different name). Masking a second time is a no-op.
    """
    pad = "  " * indent
    lines: list[str] = []
    if result.error:
        lines.append(f"{pad}Hinweis: {result.error}")
        lines.append("")

    # GANZ OBEN, vor dem Urteil. Der Nutzer liest die erste Zeile und
    # entscheidet danach; eine Fussnote am Ende erreicht ihn nicht mehr. Eine
    # Datei, deren Makro-Stufe mangels Bibliothek nie lief, ist nicht
    # freigesprochen — sie ist UNGEPRUEFT.
    if result.is_incomplete:
        lines.append(f"{pad}⚠ {result.incompleteness_note()}")
        lines.append("")

    groups = _group_by_category(result)
    lines.append(f"{pad}Was wurde gefunden?")
    if not groups:
        lines.append(f"{pad}  Keine Auffälligkeiten.")
    for name, explanation, inds in groups:
        lines.append(f"{pad}  ■ {name}")
        lines.append(f"{pad}    {explanation}")
        for ind in inds:
            lines.append(f"{pad}    – [{ind.severity.label}] {ind.title}")
            if ind.detail:
                for dl in ind.detail.splitlines() or [ind.detail]:
                    lines.append(f"{pad}        {dl}")
    lines.append("")

    if result.mail_preview:
        # THE MAIL ITSELF, not just the rule names: headers, decoded TEXT body,
        # annotated links, attachment names — plain text on purpose, since the
        # HTML body is attacker-controlled and the project never renders
        # untrusted markup (see core.mail_view).
        #
        # Rendered HERE, at every depth, and not appended to the top-level row:
        # a mail inside a ZIP or attached to another mail is exactly the case an
        # analyst must be able to read, and those are nested results.
        lines.append("")
        for preview_line in result.mail_preview.rstrip("\n").splitlines():
            lines.append(f"{pad}{preview_line}" if preview_line else "")

    if result.children:
        # A mail carries attachments, an archive carries members — calling both
        # "archive contents" made a scanned .eml read like a ZIP.
        noun = "Anhänge" if result.detected_type == "eml" else "Einträge"
        lines.append("")
        lines.append(f"{pad}Enthaltene {noun} ({len(result.children)}):")
        for child in result.children:
            lines.append("")
            lines.append(_format_detail(child, indent + 1))
    return mask_invisible("\n".join(lines))


def _format_technical(result: ScanResult, indent: int = 0) -> str:
    """Ebene 3: die Rohdaten — Hashes, Typ, Dauer, Ankerregel.

    Getrennt vom Befundtext, weil es eine andere Leserschaft hat: der Laie
    braucht es nicht, wer die Datei an einen Dienstleister weitergibt schon.
    Beides in einem Feld zu mischen war der Grund, warum der erste Satz des
    Detailfelds eine Zahl war statt einer Handlung.

    Die Maskierung liegt wie bei _format_detail auf dem fertigen Text: der Pfad
    kann aus einem Archivmitglied stammen und ist damit angreiferkontrolliert.
    """
    pad = "  " * indent
    type_text = type_description(result.detected_type, result.mime_hint)
    # Gekuerzt wie in core/mail_view: der Pfad eines Archivmitglieds ist
    # angreiferkontrolliert und darf bis 65 535 Zeichen lang sein. Gemessen
    # erzeugte ein 60 000-Zeichen-Name eine Einzelzeile von 60 013 Zeichen.
    # _clip setzt einen sichtbaren Hinweis — ein stiller Schnitt wuerde genau
    # den Trick verbergen, den die Analyse meldet.
    lines = [
        f"{pad}Datei: {_clip(result.path, MAX_DISPLAY_CHARS)}",
        f"{pad}Typ: {type_text}",
        f"{pad}Groesse: {result.size} Bytes",
        f"{pad}SHA-256: {result.sha256 or '—'}",
        f"{pad}MD5: {result.md5 or '—'}",
        f"{pad}Dauer: {result.duration_ms} ms",
        f"{pad}Score: {result.score}/100 ({result.risk_level.short})",
    ]
    if result.av_discount:
        lines.append(
            f"{pad}AV-Nachlass: -{result.av_discount} Punkte durch "
            f"AV-ohne-Fund (der Virenscanner hat nichts gefunden)"
        )
    if result.anchored:
        lines.append(
            f"{pad}Anker-Regel: aktiv — ein kritischer Befund erzwingt "
            f"mindestens diese Stufe"
        )
    for child in result.children:
        lines.append("")
        lines.append(
            f"{pad}--- {_clip(child.display_name, MAX_DISPLAY_CHARS)} ---"
        )
        lines.append(_format_technical(child, indent + 1))
    return mask_invisible("\n".join(lines))
