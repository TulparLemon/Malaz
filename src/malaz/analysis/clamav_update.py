"""ClamAV signature update via freshclam (explicit user action only).

Malaz itself never goes online (docs/SECURITY_MODEL.md). This module exists
solely for the explicit "update signatures" affordances — the GUI button and
``scripts/update_clamav.bat`` — and runs ``freshclam.exe``, which downloads
from the official ClamAV mirrors.

Admin-less layout (variant B): when ``%LocalAppData%\\ClamAV\\freshclam.conf``
exists it is passed via ``--config-file`` so freshclam uses the user-writable
database directory instead of the read-only ``Program Files`` install. Without
that file freshclam still runs plainly (admin installs work without a config);
failures surface verbatim in the output for the user to act on.
"""

from __future__ import annotations

import os
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import monotonic

from .. import config
from ..core.toolpath import which_absolute
from ..procio import decode_tool_output, no_window_flags


@dataclass
class FreshclamResult:
    rc: int = -1
    output: str = ""
    ran: bool = False  # binary found and process started at all
    error: str = ""    # e.g. "freshclam.exe nicht gefunden"
    # True when the deadline killed the process. The exit code alone cannot
    # tell a timeout from a normal failure (a killed process exits rc=1).
    timed_out: bool = False


def find_freshclam() -> Path | None:
    """Locate freshclam.exe: configured install paths first, then PATH."""
    for candidate in config.CLAMAV_FRESHCLAM_CANDIDATES:
        expanded = Path(os.path.expandvars(candidate))
        if expanded.is_file():
            return expanded
    found = which_absolute("freshclam.exe") or which_absolute("freshclam")
    return Path(found) if found else None


def user_conf_path() -> Path:
    return Path(os.path.expandvars(config.CLAMAV_FRESHCLAM_USER_CONF))


def clamd_conf_path() -> Path:
    return Path(os.path.expandvars(config.CLAMAV_CLAMD_USER_CONF))


# clamd config for the admin-less layout. Without it, clamdscan finds no
# configuration, cannot learn where the daemon listens, and exits rc=2 — even
# while the daemon runs. Measured: ping rc=2 without this file, rc=0 with it;
# the engine then silently used the ~16 s-per-file clamscan path.
#
# SECURITY: TCPAddr MUST be 127.0.0.1. Windows supports only unencrypted TCP
# for clamd (no LocalSocket), and the clamd protocol has no authentication —
# binding to anything else would expose an unauthenticated scanner to the
# network. SHUTDOWN/RELOAD are disabled for the same reason: reaching the port
# must not let anyone stop the engine.
_CLAMD_CONF_TEMPLATE = (
    "# Erzeugt von Malaz: adminlose clamd-Konfiguration.",
    "# Siehe docs/SECURITY_MODEL.md - bewusster Trade-off:",
    "# nur localhost, keine Authentifizierung im clamd-Protokoll.",
    "DatabaseDirectory {db_dir}",
    "TCPSocket 3310",
    "TCPAddr 127.0.0.1",
    # Without this, a clamdscan call against a NON-LISTENING port blocks in a
    # ~2 s connect timeout before failing — measured 2075 ms, and every Malaz
    # start pays it as soon as ClamAV is installed but no clamd runs (the
    # two-stage ping reaches the config stage on every launch). With
    # ConnectTimeout 1 the same call returns in 33 ms. Same value the official
    # clamd.conf.sample recommends.
    "ConnectTimeout 1",
    # clamd's default is "Foreground no" (it forks into the background), which
    # would make start_clamd.bat's "closing the window stops the daemon" false
    # and leave an orphan process. Foreground keeps the console the handle for
    # the daemon's lifetime.
    "Foreground yes",
    "LogFile {log_file}",
    "MaxThreads 4",
    # ClamAV's compiled-in default is 100 MB and a skipped oversized file is
    # reported as "OK". Malaz accepts up to 2 GB; the daemon must be allowed
    # to look at it. MaxScanSize covers the decompressed total.
    "MaxFileSize {max_file_size}",
    "StreamMaxLength {max_file_size}",
    "MaxScanSize {max_scan_size}",
    # Global per-scan time limit (milliseconds); the default 120 s is too
    # short for multi-GB files.
    "MaxScanTime 600000",
    "EnableShutdownCommand no",
    "EnableReloadCommand no",
)


def _upgrade_malaz_clamd_conf(conf: Path) -> None:
    """Add size limits to an old Malaz-generated clamd config.

    Only files carrying the Malaz header are touched. A user-edited config is
    left alone: its author may have chosen a different limit deliberately.
    The daemon has to be restarted to pick the new value; the scanner detects
    the old limit and reports "not checked" until then.
    """
    try:
        text = conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    first_line = text.splitlines()[0] if text else ""
    if "Erzeugt von Malaz" not in first_line:
        return
    lowered = text.lower()
    if "maxfilesize" in lowered and "streammaxlength" in lowered:
        return
    additions = []
    if "maxfilesize" not in lowered:
        additions.append(
            f"MaxFileSize {config.CLAMAV_DAEMON_MAX_FILE_SIZE // config.MB}M"
        )
    if "streammaxlength" not in lowered:
        additions.append(
            f"StreamMaxLength {config.CLAMAV_DAEMON_MAX_FILE_SIZE // config.MB}M"
        )
    if "maxscansize" not in lowered:
        additions.append(
            f"MaxScanSize {config.CLAMAV_SCAN_MAX_SIZE // config.MB}M"
        )
    if "maxscantime" not in lowered:
        additions.append("MaxScanTime 600000")
    if not additions:
        return
    try:
        with conf.open("a", encoding="utf-8", newline="\r\n") as handle:
            handle.write("\n# Malaz: Datei-/Scanlimits fuer grosse Dateien\n")
            for line in additions:
                handle.write(line + "\n")
    except OSError:
        return


def ensure_clamd_conf() -> Path | None:
    """Make sure the admin-less clamd config exists; ``None`` on failure.

    Idempotent: an existing file (user-edited, or written by
    ``scripts/start_clamd.bat``) is never rewritten. An old Malaz-generated
    file is upgraded in place with the size limits; a user-edited file is
    untouched. Creates the log directory so clamd can write its log.
    """
    conf = clamd_conf_path()
    try:
        if conf.is_file():
            _upgrade_malaz_clamd_conf(conf)
            return conf
        db_dir = conf.parent / "db"
        db_dir.mkdir(parents=True, exist_ok=True)
        content = "\n".join(_CLAMD_CONF_TEMPLATE).format(
            db_dir=db_dir,
            log_file=conf.parent / "clamd.log",
            max_file_size=f"{config.CLAMAV_DAEMON_MAX_FILE_SIZE // config.MB}M",
            max_scan_size=f"{config.CLAMAV_SCAN_MAX_SIZE // config.MB}M",
        )
        # newline= translates: pre-baked \r\n would become \r\r\n and clamd
        # rejects the file ("Incorrect argument format"), same as freshclam.
        conf.write_text(content + "\n", encoding="utf-8", newline="\r\n")
        return conf
    except OSError:
        return None


# Variant B layout (docs/anleitung): everything inside the user profile so
# no admin rights are ever needed. A freshclam WITHOUT this config falls
# back to its compiled-in Program Files database directory, which a normal
# user cannot write to — the update then dies with rc 10 ("Can't create
# temporary directory", field report from an admin-less machine).
_USER_CONF_TEMPLATE = (
    "# Erzeugt von Malaz: adminlose freshclam-Konfiguration (Variante B).",
    "DatabaseDirectory {db_dir}",
    "DatabaseMirror database.clamav.net",
    "ConnectTimeout 30",
    "ReceiveTimeout 60",
)


def ensure_user_conf() -> Path | None:
    """Make sure the admin-less freshclam config exists; ``None`` on failure.

    Idempotent: an existing file (user-edited or from the manual setup) is
    never touched. Also creates the (empty) database directory so freshclam
    has somewhere to write to on its first run.
    """
    conf = user_conf_path()
    try:
        if not conf.is_file():
            db_dir = conf.parent / "db"
            db_dir.mkdir(parents=True, exist_ok=True)
            # join with \n and let newline= translate: pre-baked \r\n would
            # be translated again and corrupt the file to \r\r\n, which
            # freshclam rejects ("Incorrect argument format", rc 2).
            content = "\n".join(_USER_CONF_TEMPLATE).format(db_dir=db_dir) + "\n"
            conf.write_text(content, encoding="utf-8", newline="\r\n")
        return conf
    except OSError:
        # Read-only profile, quota, exotic setups: fall back to plain
        # freshclam behaviour and let its own output explain the failure.
        return None


def build_command(binary: Path | None = None) -> list[str] | None:
    """freshclam command line, or ``None`` when no binary exists.

    Always runs with the admin-less user config: the compiled-in default
    would target Program Files, which fails without admin rights.
    """
    if binary is None:
        binary = find_freshclam()
    if binary is None:
        return None
    command = [str(binary)]
    conf = ensure_user_conf()
    if conf is not None:
        command += ["--config-file", str(conf)]
    return command


def run_freshclam(
    line_callback=None,
    timeout: float | None = None,
    command: list[str] | None = None,
) -> FreshclamResult:
    """Run one freshclam update, streaming output lines as they arrive.

    ``line_callback`` (if given) is called from the worker thread with each
    decoded output line — the GUI dialog uses it to show progress. The
    timeout kills the process (a wedged download must not hang the dialog);
    partial output collected so far is preserved.
    """
    if command is None:
        command = build_command()
    if command is None:
        return FreshclamResult(error="freshclam.exe nicht gefunden")
    if timeout is None:
        timeout = config.CLAMAV_UPDATE_TIMEOUT_SECONDS

    chunks: list[str] = []
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            shell=False,
            creationflags=no_window_flags(),
        )
    except OSError as exc:
        return FreshclamResult(ran=False, error=f"{type(exc).__name__}: {exc}")

    deadline = monotonic() + timeout
    killed_by_timer = threading.Event()

    def _kill_on_timeout() -> None:
        # poll() first: a process that finished exactly at the deadline is a
        # normal run, not a timeout. When it IS still running, remember that
        # WE killed it — otherwise the EOF from the dying pipe ends the
        # readline loop and wait() returns rc=1, which the GUI reports as a
        # plain failure without the timeout hint (BUG-036).
        if proc.poll() is None:
            killed_by_timer.set()
            with suppress(OSError):
                proc.kill()

    timer = threading.Timer(timeout, _kill_on_timeout)
    timer.daemon = True
    timer.start()
    timed_out = False
    try:
        assert proc.stdout is not None
        for raw_line in iter(proc.stdout.readline, b""):
            # freshclam repaints its progress bars with carriage returns —
            # one readline chunk can contain many intermediate ticks. Strip
            # the line ending first, then keep only the final repaint state.
            line = decode_tool_output(raw_line).rstrip().split("\r")[-1].rstrip()
            if not line:
                continue
            chunks.append(line)
            if line_callback is not None:
                # A broken callback (e.g. dialog already closed) must not
                # kill the update run.
                with suppress(Exception):
                    line_callback(line)
        rc = proc.wait(timeout=max(1.0, deadline - monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        with suppress(OSError):
            proc.kill()
        rc = proc.wait()
    finally:
        timer.cancel()

    timed_out = timed_out or killed_by_timer.is_set()
    output = "\n".join(chunks)
    if timed_out:
        output += (
            f"\n[Malaz] Update nach {timeout:g} s abgebrochen (Timeout) — "
            "Netzwerk prüfen und erneut versuchen."
        )
    return FreshclamResult(rc=rc, output=output, ran=True, timed_out=timed_out)


def update_due(
    *,
    min_age_days: int | None = None,
    enabled: bool | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Decide whether the startup auto-update should run. ``(due, reason)``.

    Pure decision logic (no side effects, no network) so the GUI trigger stays
    thin and this stays unit-testable:

    * auto-update disabled -> not due,
    * no freshclam binary  -> not due (nothing we could run),
    * no local database    -> DUE (a missing DB means every ClamAV scan is
      skipped; fetching it is the single most valuable update),
    * database younger than ``min_age_days`` -> not due (avoid hammering the
      mirrors on every launch),
    * otherwise -> DUE with the age in the reason.

    The reason string is user-facing (status line / log), German to match the
    rest of the UI.
    """
    if enabled is None:
        enabled = config.CLAMAV_AUTO_UPDATE_ENABLED_DEFAULT
    if not enabled:
        return False, "Automatische Aktualisierung ist aus."
    if find_freshclam() is None:
        return False, "freshclam nicht gefunden — automatische Aktualisierung übersprungen."
    if min_age_days is None:
        min_age_days = config.CLAMAV_AUTO_UPDATE_MIN_AGE_DAYS

    from .clamav_status import db_age_days, read_db_dates

    dates = read_db_dates()
    age = db_age_days(dates, now=now)
    if age is None:
        return True, "Keine Signatur-Datenbank gefunden — wird jetzt geladen."
    if age < min_age_days:
        return False, f"Signaturen sind aktuell ({age} Tag(e) alt)."
    return True, f"Signaturen sind {age} Tag(e) alt — wird aktualisiert."


# -- clamd-Daemon: der Unterschied zwischen 19 Sekunden und 0,2 ------------ #
#
# GEMESSEN auf diesem Rechner, dieselben Dateien:
#   clamscan.exe (ohne Daemon):  18 758 ms je Datei
#   clamdscan.exe (mit Daemon):      41 ms je Datei   -> Faktor 455
#
# DIREKT NACH DEM START ist er noch nicht so schnell: gemessen 1 031 ms, weil
# er die Signaturen erst einliest. Nach kurzer Zeit steht es bei 41 ms. Wer
# unmittelbar nach dem Autostart scannt, sieht also noch nicht den vollen
# Gewinn — das ist kein Fehler, sondern die Ladezeit.
#
# Der Grund ist der Prozessstart: jeder clamscan laedt die rund 3,6 Millionen
# Signaturen (170 MB) neu von der Platte. Der Daemon haelt sie einmal im
# Speicher. Genau deshalb ist "mehrere Scans gleichzeitig" der FALSCHE Hebel:
# N parallele clamscan-Prozesse laden die Basis N-mal.
#
# Bis hierher musste der Nutzer scripts\start_clamd.bat von Hand starten. Wer
# das vergisst, bekommt den langsamen Weg - und merkt es nicht, weil das
# Ergebnis dasselbe ist. Gemessen im Log einer Testmaschine:
#   "clamd-Port laut Konfiguration nicht erreichbar - Ping uebersprungen"
#   "clamd-Ping fehlgeschlagen ... -> Fallback clamscan"

_CLAMD_CANDIDATES = (
    r"C:\Program Files\ClamAV\clamd.exe",
    r"C:\Program Files (x86)\ClamAV\clamd.exe",
)


def find_clamd() -> Path | None:
    """Das clamd-Binary, oder ``None``."""
    for kandidat in _CLAMD_CANDIDATES:
        pfad = Path(os.path.expandvars(kandidat))
        if pfad.is_file():
            return pfad
    gefunden = which_absolute("clamd")
    return Path(gefunden) if gefunden else None


def clamd_port_offen(timeout: float = 1.0) -> bool:
    """Lauscht der Daemon auf 127.0.0.1:3310?

    Eine reine TCP-Verbindung, kein clamd-Protokoll: gefragt ist "ist jemand
    da", nicht "antwortet er richtig". Den Beweis fuehrt der Ping von
    ``ClamAVScanner._clamd_reachable`` — hier geht es nur darum, wie lange
    gewartet werden muss.
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", 3310))
            return True
        except OSError:
            return False


def start_clamd(timeout: float = 90.0) -> tuple[bool, str]:
    """Den Daemon starten, falls er nicht laeuft. ``(laeuft, Begruendung)``.

    Blockiert bis der Port offen ist (oder die Frist ablaeuft) — der Aufrufer
    entscheidet, ob er das im Hintergrund tut. Der Prozess wird GELOEST
    gestartet: er soll Malaz ueberleben, sonst faellt der Nutzer beim
    naechsten Start wieder auf den langsamen Weg.

    Kein Dienst, keine Adminrechte: clamd laeuft als normaler Prozess und
    lauscht nur auf 127.0.0.1 (siehe die erzeugte Konfiguration).
    """
    if clamd_port_offen():
        return True, "clamd laeuft bereits."

    binary = find_clamd()
    if binary is None:
        return False, "clamd.exe nicht gefunden — ClamAV installieren oder den Pfad hinterlegen."

    conf = None
    with suppress(Exception):
        conf = ensure_clamd_conf()
    if conf is None:
        conf = clamd_conf_path()
    if conf is None:
        return False, "clamd.conf konnte nicht ermittelt werden."

    # DETACHED_PROCESS: der Daemon haengt nicht am Fenster und stirbt nicht
    # mit ihm. CREATE_NO_WINDOW unterdrueckt das Konsolenfenster.
    #
    # WARUM ER NICHT BEIM BEENDEN AUFGERAEUMT WIRD: der ganze Gewinn liegt
    # darin, dass die 170 MB Signaturen ZWISCHEN Programmstarts im Speicher
    # bleiben. Wuerde Malaz ihn beim Schliessen beenden, zahlte jeder Start
    # die Ladezeit erneut, und die ersten Scans waeren wieder langsam.
    # Der Preis ist ein unsichtbarer Prozess - deshalb gibt es
    # scripts\stop_clamd.bat als Gegenstueck, und die Sicherheitsdoku nennt
    # ihn ausdruecklich.
    #
    # FREMDE DAEMONS BLEIBEN UNANGETASTET: oben wird zuerst der Port geprueft.
    # Hat der Nutzer start_clamd.bat von Hand gestartet oder benutzt ein
    # anderes Werkzeug 3310, tut Malaz nichts — und beendet schon gar nichts.
    # (In dieser Datei steht bewusst KEIN terminate/kill fuer clamd.)
    DETACHED_PROCESS = 0x00000008
    flags = DETACHED_PROCESS | no_window_flags()
    try:
        subprocess.Popen(
            [str(binary), f"--config-file={conf}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=flags,
            close_fds=True,
        )
    except OSError as exc:
        return False, f"clamd konnte nicht gestartet werden: {type(exc).__name__}: {exc}"

    frist = monotonic() + timeout
    while monotonic() < frist:
        if clamd_port_offen(timeout=0.5):
            return True, "clamd gestartet."
        threading.Event().wait(0.5)
    return False, f"clamd startete, meldet sich aber nicht binnen {int(timeout)} s."
