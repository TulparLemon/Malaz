"""Background QRunnable jobs, engine status helpers, and stream update dialog.

Extracted verbatim from ``main_window.py`` during the v1.1.0 UI rework so the
window shell stays modular while every tested job contract stays identical.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout

from .. import config
from ..i18n import get_language, pick, t
from ..models import ScanResult
from ..reporting.html_report import save_report
from .display import clamp_dialog_to_screen


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

    def __init__(
        self,
        results: list[ScanResult],
        path: str,
        as_pdf: bool,
        signals: _ExportSignals,
        *,
        lang: str | None = None,
    ):
        super().__init__()
        self.results = results
        self.path = path
        self.as_pdf = as_pdf
        self.signals = signals
        self.lang = lang or get_language()
        self.setAutoDelete(True)

    def run(self) -> None:  # pool thread
        try:
            low = self.path.lower()
            if self.as_pdf or low.endswith(".pdf"):
                from ..reporting.pdf_report import save_pdf_report

                save_pdf_report(self.results, self.path, lang=self.lang)
            elif low.endswith(".csv"):
                from ..reporting.export import write_csv

                write_csv(self.results, self.path)
            elif low.endswith(".json"):
                from ..reporting.export import write_json

                write_json(self.results, self.path)
            else:
                save_report(self.results, self.path, lang=self.lang)
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
        clamp_dialog_to_screen(self, preferred_w=660, preferred_h=420)
        layout = QVBoxLayout(self)
        hint_label = QLabel(hint)
        hint_label.setWordWrap(True)
        layout.addWidget(hint_label)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        buttons = QHBoxLayout()
        self.btn_start = QPushButton(pick("Jetzt aktualisieren", "Update now", "Şimdi güncelle"))
        self.btn_start.clicked.connect(self._start)
        btn_close = QPushButton(t("btn.close"))
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


