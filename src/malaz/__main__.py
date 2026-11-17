"""Application entry point.

Usage:
    python -m malaz                 # launch the GUI
    python -m malaz --cli FILE...   # headless scan, print summary
        [--report out.html]                  # also write an HTML5 report
    python -m malaz --evaluate BAD GOOD     # corpus hit-rate/FP measurement
        [--csv out.csv] [--report out.html] # (VM live test; no Python needed
                                            #  in the standalone build)
"""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import suppress
from pathlib import Path

from . import __version__, config
from .core.dispatcher import Dispatcher, _walk_results, expand_scan_paths
from .models import RiskLevel, ScanResult
from .security.escaping import mask_invisible


def _safe_text(value: object) -> str:
    """Name/Fehler fuer die Konsole: unsichtbare und C0-Zeichen maskieren.

    Dateinamen und Fehlertexte stammen aus der geprueften, also
    angreiferkontrollierten Datei. Ein U+202E stellt den Namen im Terminal
    anders dar, ein ESC beginnt eine ANSI-Sequenz, und ein Zeilenumbruch
    faelscht eine weitere Ergebniszeile. ``mask_invisible`` deckt Bidi/NUL ab;
    die uebrigen C0-Zeichen (inkl. ESC) und DEL werden hier sichtbar als
    ``\\xNN`` geschrieben — nicht entfernt, damit die Tarnung erkennbar bleibt.
    """
    text = mask_invisible(value)
    return "".join(
        f"\\x{ord(ch):02x}" if ord(ch) < 32 or ord(ch) == 0x7F else ch
        for ch in text
    )



def _enable_utf8_console() -> None:
    """Make Windows consoles render the German UTF-8 output correctly.

    Without this, ``cmd.exe`` defaults to a legacy code page (e.g. cp850) and
    prints garbled umlauts. We switch the console code page to UTF-8 (65001)
    and reconfigure the streams; both steps are best-effort and never raise.
    """
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        with suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]


def _print_summary(result: ScanResult, indent: int = 0) -> None:
    pad = "  " * indent
    error = getattr(result, "error", None)
    if error:
        # A file that could not be analysed at all (AV-locked, unreadable,
        # removed mid-scan) must never read as "[GRÜN] score=0" — the
        # evaluation CSV already shows FEHLER, the CLI summary must too.
        print(f"{pad}[FEHLER] {_safe_text(result.display_name)}  type={result.detected_type}"
              f"  fehler={_safe_text(error)[:80]}")
        return
    marker = {RiskLevel.GREEN: "[GRÜN]", RiskLevel.YELLOW: "[GELB]", RiskLevel.RED: "[ROT]"}[
        result.risk_level
    ]
    print(f"{pad}{marker} {_safe_text(result.display_name)}  score={result.score}/100  "
          f"type={result.detected_type}  findings={len(result.all_indicators())}"
          + (f"  (−{result.av_discount} durch AV-ohne-Fund)" if result.av_discount else ""))
    if result.engine_verdicts:
        print(f"{pad}    Engines: " + " · ".join(
            f"{v.engine}={v.label}" for v in result.engine_verdicts
        ))
    for ind in sorted(result.indicators, key=lambda i: i.severity, reverse=True):
        print(f"{pad}    - [{ind.severity.label}] {ind.rule_id}: {ind.title}")
    _print_mail_header(result, indent)
    for child in result.children:
        _print_summary(child, indent + 1)


def _print_mail_header(result: ScanResult, indent: int) -> None:
    """The mail's HEADER BLOCK — where the sender checks live.

    The plain-text view (core.mail_view) carries the sender authentication
    verdict, the display-name-vs-address check and the Reply-To/Return-Path
    comparison. Until now it reached the GUI detail panel only: whoever used
    --cli, or read the table, saw the findings but not the verdict they
    explain. Printed is everything from the "Kopfzeilen" heading up to the BODY
    (Textinhalt, Enthaltene Links, Anhaenge, Hinweis) — the body itself would
    flood a summary.
    """
    if not result.mail_preview:
        return
    pad = "  " * (indent + 1)
    lines = result.mail_preview.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("Kopfzeilen"))
    except StopIteration:
        return
    # Everything from the "Kopfzeilen" heading up to the BODY: Betreff, Von,
    # An, Antwort an, Rückläufer, Received-Zahl, Authentifizierung,
    # Absenderpruefung, Auth-Rohtext, Empfangsweg, Behauptungen fremder Filter.
    #
    # Frueher endete das am ersten Leerzeilen-Ende (dem Kopfblock). Der
    # Empfangsweg und die Behauptungen fremder Filter stehen aber DAHINTER und
    # sind beide begrenzt (max. 8 Stationen, 6 Behauptungen) — in einer
    # Zusammenfassung sind sie die Angabe, gegen die sich die Behauptungen
    # oben ueberhaupt halten lassen. Der Rumpf bleibt aussen vor.
    kopf_ende = ("Textinhalt", "Enthaltene Links", "Anhänge", "Hinweis:")
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped.startswith(kopf_ende):
            break
        if stripped:
            # Auch die Kopfzeilen stammen aus der Datei. mask_invisible lief
            # bereits in mail_view; C0/ESC fehlten dort und wuerden im
            # Terminal eine eigene Zeile/Farbe erzeugen.
            print(f"{pad}{_safe_text(stripped)}")


def _print_engines(dispatcher: Dispatcher) -> None:
    """Print a one-line engine/Defender status banner (CLI only)."""
    from .analysis.privilege import privilege_label

    av = "an" if dispatcher.av_scanner.available else "aus/fehlt"
    clam_bin = getattr(dispatcher.clam_scanner, "binary", None)
    if not dispatcher.clam_scanner.available:
        clam = "aus/fehlt"
    elif clam_bin is not None and clam_bin.name.lower().startswith("clamdscan"):
        clam = "an (clamd-Daemon)"
    else:
        clam = "an"
    from .analysis.die import DieScanner

    die = "an" if DieScanner().available else "aus/fehlt"
    yara_engine = dispatcher.yara
    if not yara_engine.available:
        yara = "aus/fehlt"
    elif yara_engine.load_error:
        yara = f"Regelfehler! ({yara_engine.load_error[:100]})"
    else:
        yara = "an"
    ext = [s.name for s in dispatcher.external_scanners if s.available]
    ext_txt = ", ".join(ext) if ext else "keine konfiguriert"
    print(f"[Engines] Defender={av}  ClamAV={clam}  YARA={yara}  DIE={die}  Extern={ext_txt}")
    print(f"[Rechte] {privilege_label()}")
    status = dispatcher.defender_status
    if status.probed:
        print(f"[Defender] {status.summary}")
    elif status.error:
        print(f"[Defender] Status nicht abrufbar: {status.error}")


def run_cli(paths: list[str], report: str | None, *, static_only: bool = False) -> int:
    if static_only:
        from .evaluation import build_dispatcher

        dispatcher = build_dispatcher(with_av=False)
    else:
        dispatcher = Dispatcher()
    _print_engines(dispatcher)

    # Resolve inputs: report missing ones, expand directories recursively.
    existing: list[str] = []
    for path in paths:
        if Path(path).exists():
            existing.append(path)
        else:
            print(f"!! Nicht gefunden: {_safe_text(path)}", file=sys.stderr)

    files, truncated = expand_scan_paths(existing)
    if truncated:
        print(
            f"!! Batch-Limit von {config.MAX_BATCH_FILES} Dateien erreicht — "
            "weitere Dateien übersprungen.",
            file=sys.stderr,
        )

    results: list[ScanResult] = []
    total = len(files)
    for index, file in enumerate(files, start=1):
        if total > 1:
            print(f"[{index}/{total}] {_safe_text(file)}")
        result = dispatcher.scan_path(file)
        results.append(result)
        _print_summary(result)

    if report and results:
        from .reporting.html_report import save_report

        try:
            out = save_report(results, report)
        except OSError as exc:
            # Ein gesperrter/ungueltiger Zielpfad ist ein Bedienfehler, kein
            # Programmabsturz: klare Meldung und ein eigener Exitcode, damit
            # Automatisierung den fehlenden Bericht erkennt (BUG-044).
            print(
                f"!! Report konnte nicht geschrieben werden: "
                f"{_safe_text(report)} — {_safe_text(exc)}",
                file=sys.stderr,
            )
            return 4
        print(f"\nReport gespeichert: {_safe_text(out)}")

    if not results:
        return 1
    # RED remains the highest-priority automation signal. A non-red result
    # with a failed/incomplete stage gets its own non-zero code so CI cannot
    # mistake it for a fully checked clean file.
    if any(r.risk_level == RiskLevel.RED for r in results):
        return 2
    # Die KINDER zaehlen mit: ein Archiv ist nur so vollstaendig geprueft wie
    # seine Mitglieder, und ``_log_stages`` protokolliert dieselbe Menge ueber
    # ``_walk_results``. Vorher sah dieser Test nur die Top-Level-Indikatoren —
    # dasselbe CLAMAV_SIZE_LIMIT ergab oben Exit 3 und als Mitglied Exit 0,
    # obwohl das eigene Protokoll die Datei "UNVOLLSTÄNDIG" nannte.
    if any(
        r.error or r.is_incomplete
        for result in results
        for r in _walk_results(result)
    ):
        return 3
    return 0


def _gui_app_icon():
    """Application icon for QApplication (GUI mode only, deferred import)."""
    from PySide6.QtGui import QIcon

    from .branding import app_icon

    icon = app_icon()
    return icon if isinstance(icon, QIcon) else QIcon()


def run_gui(initial_paths: list[str] | None = None) -> int:
    # Imported here so CLI mode never requires a Qt platform / display.
    from PySide6.QtCore import QThreadPool
    from PySide6.QtWidgets import QApplication

    from .gui.main_window import MainWindow
    from .gui.theme import apply_theme

    app = QApplication(sys.argv)
    app.setApplicationName(config.APP_NAME)
    app.setApplicationVersion(__version__)
    app.setWindowIcon(_gui_app_icon())
    if sys.platform == "win32":
        # Explicit AppUserModelID: without it the taskbar may group/label the
        # window under the Python/Qt default identity instead of Malaz.
        import ctypes

        with suppress(Exception):
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "Malaz.Scanner"
            )
    apply_theme(app)
    window = MainWindow(initial_paths=initial_paths)
    window.show()
    code = app.exec()
    # A scan cancelled at window close stops after the file it is on; engine
    # subprocesses still running get killed outright (see procio.run_tool) so
    # the process never lingers as a zombie for up to ~2 minutes.
    with suppress(Exception):
        from .procio import request_hard_shutdown

        request_hard_shutdown()
        drained = QThreadPool.globalInstance().waitForDone(60_000)
        if not drained:
            # A long PDF export (>60 s for a 5000-file batch) must not tear
            # down Qt mid-render (process abort): rendering always
            # terminates, so an unbounded second wait is the safe choice.
            QThreadPool.globalInstance().waitForDone(-1)
    return code


def _frozen_app_dir() -> Path | None:
    """Directory of the executable in frozen builds, else ``None``.

    Nuitka standalone normally sets ``sys.frozen``; some build/version
    combinations only set the module-level ``__compiled__`` marker. Both
    must count as "exe layout", otherwise the log silently lands in the
    WORKING directory — with a cwd of C:\\Windows\\System32 (Explorer
    "run as administrator") it would be lost or litter the system dir.
    """
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        return Path(sys.executable).resolve().parent
    return None


def _default_log_path() -> Path:
    """Resolve safe diagnostic log path outside untrusted working directories."""
    app_dir = _frozen_app_dir()
    if app_dir is not None:
        return app_dir / "malaz.log"
    env_dir = os.environ.get("MALAZ_LOG_DIR", "").strip()
    if env_dir:
        return Path(env_dir) / "malaz.log"
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data:
        return Path(local_app_data) / "Malaz" / "logs" / "malaz.log"
    return Path.home() / ".malaz" / "logs" / "malaz.log"


def _setup_logging() -> None:
    """Write bounded, privacy-filtered diagnostics to ``malaz.log``."""
    try:
        import logging
        from logging.handlers import RotatingFileHandler

        from .core.log_privacy import AnonymizeFilter, AnonymizeFormatter

        root = logging.getLogger()
        for old in list(root.handlers):
            if getattr(old, "_malaz_privacy_handler", False):
                root.removeHandler(old)
                old.close()

        log_path = _default_log_path()
        if _frozen_app_dir() is None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler._malaz_privacy_handler = True  # type: ignore[attr-defined]
        # The formatter is the final sink: it also covers traceback text,
        # which is appended after record-level filters have run.
        handler.setFormatter(
            AnonymizeFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        handler.addFilter(AnonymizeFilter())
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    except Exception:
        # Logging must never prevent a scan from starting.
        pass


def _warn_ignored_options(args: argparse.Namespace, modus: str) -> None:
    """Sagt laut, welche Optionen in DIESEM Modus nicht gelesen werden.

    Vorher verschwanden ``--report`` ohne Dateien, ``--csv``/``--json``
    ausserhalb von ``--evaluate`` und die Engine-Schalter still: der Nutzer
    glaubte, die Option sei aktiv. Eine Warnung auf stderr aendert das
    Ergebnis nicht, macht die Wirkungslosigkeit aber sichtbar (BUG-045).
    """
    if modus not in ("cli", "evaluate") and args.report:
        print(
            "Hinweis: --report gilt nur im --cli/--evaluate-Modus und wird "
            "sonst ignoriert (im GUI-Start über 'Report speichern…' "
            "exportieren).",
            file=sys.stderr,
        )
    if modus != "evaluate":
        if args.csv:
            print(
                "Hinweis: --csv gilt nur im --evaluate-Modus und wird ignoriert.",
                file=sys.stderr,
            )
        if args.json:
            print(
                "Hinweis: --json gilt nur im --evaluate-Modus und wird ignoriert.",
                file=sys.stderr,
            )
    if modus not in ("cli", "evaluate") and (args.static_only or args.with_av):
        print(
            "Hinweis: --static-only/--with-av gelten nur im "
            "--cli/--evaluate-Modus und werden ignoriert.",
            file=sys.stderr,
        )
    if modus in ("cli", "evaluate") and args.files:
        ziel = (
            "hinter --cli"
            if modus == "cli"
            else "im --evaluate-Modus gar nicht"
        )
        print(
            f"Hinweis: DATEI-Positionalargumente werden ignoriert — Dateien "
            f"gehören {ziel}.",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    _enable_utf8_console()
    _setup_logging()
    # Die gespeicherten Opt-ins gelten fuer BEIDE Wege. Ohne das wirken sie
    # nur im Fenster (dort setzt das Kaestchen die Config ueber sein Signal);
    # im --cli-Modus gibt es kein Fenster, und die Pruefung lief still nicht.
    with suppress(Exception):
        from .gui.settings import apply_saved_opt_ins

        apply_saved_opt_ins()
    parser = argparse.ArgumentParser(prog="malaz", description=config.APP_NAME)
    parser.add_argument("--cli", nargs="+", metavar="FILE", help="headless scan of files")
    parser.add_argument(
        "--evaluate",
        nargs=2,
        metavar=("BÖSE", "HARMLOS"),
        help=(
            "Korpus-Messung (Trefferquote/False-Positive-Rate): scannt zwei "
            "Ordner und schreibt die Auswertung auf die Konsole — der "
            "Live-Malware-Test der VM nutzt genau das."
        ),
    )
    parser.add_argument(
        "--csv",
        metavar="OUT.csv",
        help="Ergebnis-CSV schreiben (nur --evaluate)",
    )
    parser.add_argument(
        "--json",
        metavar="OUT.json",
        help="Ergebnis-JSON schreiben (nur --evaluate, inkl. unchecked-Zähler)",
    )
    engines = parser.add_mutually_exclusive_group()
    engines.add_argument(
        "--static-only",
        action="store_true",
        help=(
            "Scan ohne Defender/ClamAV (--cli und --evaluate): schnell, "
            "deterministisch und ohne AV-Remediation durch MpCmdRun"
        ),
    )
    engines.add_argument(
        "--with-av",
        action="store_true",
        help="Korpus-Messung mit Defender/ClamAV (Standard für --evaluate)",
    )
    parser.add_argument("--report", metavar="OUT.html", help="write an HTML5 report (CLI mode)")
    parser.add_argument(
        "--status",
        action="store_true",
        help="show Defender/ClamAV engine status and exit (useful with an EDR present)",
    )
    parser.add_argument(
        "--clamav-status",
        action="store_true",
        help="show ClamAV binary/signature-database status and exit (offline)",
    )
    parser.add_argument(
        "--clamav-update-check",
        action="store_true",
        help=(
            "like --clamav-status, plus a network comparison against "
            "database.clamav.net (explicit opt-in to a single small request)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{config.APP_NAME} {__version__}")
    parser.add_argument(
        "files",
        nargs="*",
        metavar="DATEI",
        help=(
            "Dateien/Ordner: ohne --cli öffnet die GUI, lädt sie in die "
            "Warteschlange und startet den Scan automatisch (Explorer-"
            "Kontextmenü: \"Malaz.exe DATEI\")."
        ),
    )
    args = parser.parse_args(argv)

    config.ensure_dirs()

    if args.status:
        modus = "status"
    elif args.clamav_status or args.clamav_update_check:
        modus = "clamav"
    elif args.evaluate:
        modus = "evaluate"
    elif args.cli:
        modus = "cli"
    else:
        modus = "gui"
    _warn_ignored_options(args, modus)

    if modus == "status":
        dispatcher = Dispatcher()
        _print_engines(dispatcher)
        return 0

    if modus == "clamav":
        from .analysis.clamav_status import collect_status, format_status

        status = collect_status(include_remote=args.clamav_update_check)
        print(f"[ClamAV] {format_status(status)}")
        if status.db_dir:
            print(f"[ClamAV] Datenbank-Pfad: {status.db_dir}")
        if args.clamav_update_check and not status.remote_dates:
            print(
                "[ClamAV] Online-Vergleich fehlgeschlagen — kein Netz oder "
                "Server nicht erreichbar (offline bleibt die App voll nutzbar).",
                file=sys.stderr,
            )
        return 0

    if modus == "evaluate":
        if args.cli:
            parser.error("--cli und --evaluate schließen sich gegenseitig aus.")
        from .evaluation import build_dispatcher, evaluate

        with_av = not args.static_only
        dispatcher = build_dispatcher(with_av=with_av)
        _print_engines(dispatcher)
        return evaluate(
            Path(args.evaluate[0]),
            Path(args.evaluate[1]),
            csv_path=Path(args.csv) if args.csv else None,
            report_path=Path(args.report) if args.report else None,
            dispatcher=dispatcher,
            with_av=with_av,
            json_path=Path(args.json) if args.json else None,
        )

    if modus == "cli":
        if args.static_only:
            return run_cli(args.cli, args.report, static_only=True)
        return run_cli(args.cli, args.report)
    return run_gui(args.files or None)


if __name__ == "__main__":
    raise SystemExit(main())
