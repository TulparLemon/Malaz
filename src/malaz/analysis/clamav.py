"""ClamAV integration as a second, offline AV engine.

ClamAV is independent of Windows Defender, so it provides a verdict even when
Defender is disabled (e.g. because a third-party EDR is the primary AV). The
engine itself is *not* a pip package: it is the external ``clamscan`` /
``clamdscan`` binary (or a running ``clamd`` daemon). This module locates an
installed binary and drives it via a fixed argument list; if nothing is found
the stage is skipped gracefully.

``clamscan`` is detection-only by default (it does not delete the file unless
``--remove`` is passed, which we never do), so it is safe for triage.

Security notes (see docs/SECURITY_MODEL.md):
* subprocess with an argument list and ``shell=False``; the file path is a
  single literal argv element (no injection).
* the binary is resolved from fixed install locations / PATH only.
* a hard timeout bounds the scan.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..core.toolpath import which_absolute
from ..procio import (
    decode_tool_output,
    run_tool,
    safe_temp_suffix,
    strip_scan_target,
    tool_output_truncated,
)

log = logging.getLogger(__name__)

_FOUND_RE = re.compile(r"^(?P<path>.+?):\s+(?P<name>.+?)\s+FOUND\s*$", re.MULTILINE)

# LibClamAV phrases that mean "the signature base could not be loaded". The
# scan then never happens at all — the engine is BLIND, not "the file is
# clean". Measured against ClamAV 1.5.3, each phrase in the situation that
# actually produces it:
#   "problem parsing database"          → unparsable signature file (rc 2)
#   "empty database file"               → 0-byte signature file (rc 2)
#   "no supported database files found" → no usable signature at all (rc 2)
#   "cl_load:"                          → database directory missing (rc 2)
#   "can't verify cvd" /
#   "failed to verify cvd" /
#   "error loading database" /
#   "can't verify database integrity"   → tampered/degraded .cvd or .cld,
#                                          signature check fails (rc 2)
#
# The CVD group was added after measuring it: a copy of main.cvd with ONE byte
# flipped produces "Failed to verify CVD with MD5-based RSA digital signature",
# "cli_cvdload: Can't verify CVD file", "cli_loaddbdir: error loading database"
# and "ERROR: Can't verify database integrity" — none of which the earlier four
# markers match ("cli_cvdload:" does NOT contain "cl_load:"). Without these, the
# very case that motivated this check — a damaged signature base blinding the
# engine — still fell back to the generic "Returncode 2" text.
#
# Deliberately NOT listed: "can't open file …". Measured: that message means
# the SCAN TARGET was unreadable (missing, or locked by an AV), not that the
# signature base failed — the database is fine in that case. Including it
# would have told the user "signature base could not be loaded" for what is
# really a locked file, which is a misleading diagnosis.
#
# One damaged file is enough to kill the whole directory: clamscan reads every
# signature file under --database. Relevant for third-party ClamAV databases
# (.ndb/.hdb/.ldb), which are exactly the "many files from elsewhere" case.
_DB_LOAD_FAILURE_MARKERS = (
    "problem parsing database",
    "empty database file",
    "no supported database files found",
    "cl_load:",
    "can't verify cvd",
    "failed to verify cvd",
    "error loading database",
    "can't verify database integrity",
)


def _is_loopback_host(host: str) -> bool:
    """True only for a loopback address or ``localhost``.

    clamd has no authentication: a TCP endpoint outside the machine would
    receive file content via INSTREAM and could answer the verdict itself
    (SEC-022). ``TCPAddr``/``TCPSocket`` live in a user-writable config, so
    they are validated before the first connection.
    """
    value = (host or "").strip().strip('"').strip("'")
    if not value:
        return False
    if value.lower() == "localhost":
        return True
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    # A scoped IPv6 address ("fe80::1%eth0") is never loopback; strip the
    # zone so ipaddress can parse the address part for the check.
    value = value.split("%", 1)[0]
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _tcp_reachable(conf_path: str | None, timeout: float = 0.25) -> bool:
    """True when the clamd TCP endpoint named in ``conf_path`` accepts a connection.

    ``clamdscan --config-file=<conf>`` blocks in a ~2 s connect timeout when
    nothing listens on the configured port (measured 2075 ms; the ClamAV
    default ``ConnectTimeout``). Every Malaz start pays that as soon as ClamAV
    is installed but no clamd runs, because the two-stage ping reaches the
    config stage on every launch. A plain socket connect answers the same
    question in ~250 ms, and it works for configs written before
    ``ConnectTimeout 1`` existed.

    Returns True when no endpoint can be determined — then the ping decides,
    so an unparsable or absent config never disables a working daemon. A
    configured endpoint that is NOT loopback returns False (SEC-022): clamd
    has no authentication, so a remote endpoint must never receive content.
    """
    import socket

    host, port = "127.0.0.1", 3310
    explicit_endpoint = False
    if conf_path:
        try:
            for raw in Path(conf_path).read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                key, value = parts[0].lower(), parts[1].strip().strip('"').strip("'")
                if key == "tcpaddr":
                    host = value or host
                    explicit_endpoint = True
                elif key == "tcpsocket":
                    explicit_endpoint = True
                    if not value.isdigit() or not (1 <= int(value) <= 65535):
                        log.warning(
                            "clamd-Konfiguration nennt einen ungültigen "
                            "TCPSocket-Wert (%r) — Endpunkt wird nicht benutzt",
                            value,
                        )
                        return False
                    port = int(value)
        except OSError:
            return True
    if explicit_endpoint and not _is_loopback_host(host):
        # SEC-022: a user-writable config must not redirect scans to a remote
        # endpoint; clamd has no authentication and would receive file content.
        log.warning(
            "clamd-Endpunkt %s:%s ist nicht Loopback — Konfiguration wird "
            "nicht benutzt (Fallback)",
            host,
            port,
        )
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _db_load_failure(output: str) -> str:
    """Return the original LibClamAV line if the DB could not be loaded.

    Empty string when the output shows no signature-base failure, so callers
    can treat it as "no evidence of a DB problem" (not as "DB is fine" —
    determining that would cost a full clamscan start-up, measured ~13 s).

    The ORIGINAL line is returned, not the lower-cased marker it matched on:
    the user has to recognise the message next to ClamAV's own output, and
    "problem parsing database" reads like a typo of the real phrase.
    """
    lowered = output.lower()
    for marker in _DB_LOAD_FAILURE_MARKERS:
        if marker not in lowered:
            continue
        pos = lowered.index(marker)
        # Return the whole line the marker sits in (trimmed).
        start = output.rfind("\n", 0, pos) + 1
        end = output.find("\n", pos)
        line = output[start : end if end != -1 else len(output)].strip()
        return line[:200] or marker
    return ""


@dataclass
class ClamAVResult:
    scanned: bool = False
    threat_found: bool = False
    threat_name: str = ""
    returncode: int | None = None
    detail: str = ""
    skipped_reason: str | None = None
    # True when the engine refused to inspect the file because its own size
    # limit is lower than the file. The engine reports "OK" in that case, so
    # this flag is the only way to avoid a false CLEAN.
    limit_exceeded: bool = False

    @property
    def clean(self) -> bool:
        return self.scanned and not self.threat_found


class ClamAVScanner:
    """Thin wrapper around the clamscan / clamdscan command-line scanner.

    Prefers ``clamdscan`` when a running clamd daemon answers the
    reachability probe: the daemon holds the signature database in memory,
    so per-file scans take milliseconds instead of the ~15+ s a fresh
    ``clamscan`` process spends reloading it. Without a daemon it falls
    back to plain ``clamscan`` with identical verdict parsing.
    """

    # Set once ``_retry_with_clamscan`` has run. A class attribute (not only
    # set in __init__) so instances built via ``__new__`` inherit the safe
    # default. The daemon-loss fallback must never be reachable twice from the
    # same instance — see _retry_with_clamscan.
    _fallback_done = False

    def __init__(self, enabled: bool | None = None, timeout: int | None = None):
        self.enabled = config.CLAMAV_ENABLED if enabled is None else enabled
        self.timeout = config.CLAMAV_TIMEOUT_SECONDS if timeout is None else timeout
        self._clamscan: Path | None = None
        self._fallback_lock = threading.Lock()
        self._fallback_done = False
        self._clamdscan: Path | None = None
        # Config that reached the daemon during the ping (None = clamdscan's
        # own default lookup worked, or no daemon answered at all).
        self._clamd_conf_used: str | None = None
        self.database: Path | None = None
        # Effective clamd file-size limit from the config that reached the
        # daemon. 0 means unlimited; the default is clamd's 100 MB when the
        # config does not name it.
        self.clamd_max_file_size: int = config.CLAMAV_DEFAULT_MAX_FILE_SIZE
        # Location happens regardless of the switch: the STATUS (binary
        # version, signature DB, update_due) must not read "not installed"
        # just because the user turned the stage off (BUG-037).
        self._clamscan, self._clamdscan = self._locate_binaries()
        self.database = self._locate_db()
        if self.enabled:
            self.binary = self._choose_binary()
        else:
            # BUG-037: "deactivated" is NOT "not installed". The status/GUI
            # and update_due ask what is on disk, so the binary and the
            # signature DB are located even when the stage is switched off.
            # No daemon ping here: the engine is off.
            self.binary = self._clamscan or self._clamdscan
        self.clamd_max_file_size = self._read_clamd_max_file_size()

    @property
    def available(self) -> bool:
        return self.enabled and self.binary is not None

    def refresh_state(self, force_rechoose: bool = False) -> None:
        """Nachsehen, was inzwischen auf der Platte liegt.

        Der Bau des Scanners bestimmt Binary und Signatur-DB EINMALIG. Ein
        Statusabgleich, der dieselbe Instanz weiterbenutzt, sieht eine frisch
        installierte Datenbank deshalb NIE: der Nutzer laedt sie ueber Malaz
        nach, und das ClamAV-Abzeichen bleibt rot, bis er das Programm neu
        startet. Am 22.09.2026 genau so aufgetreten.

        Zusaetzlich wird der **Binary-Wechsel** nachgeholt: die GUI startet
        clamd erst ~1,1 s nach dem Dispatcher, also war der erste Ping beim
        Bau negativ und die Instanz blieb auf ``clamscan`` (gemessen ~19 s
        statt ~0,04 s pro Datei). ``force_rechoose`` fragt den Daemon erneut,
        auch wenn schon ein Binary gewaehlt ist; ohne Flag wird nur von
        ``clamscan`` nach ``clamdscan`` aufgewertet, nie umgekehrt.
        """
        if not self.enabled:
            return
        self.database = self._locate_db()
        if getattr(self, "_clamscan", None) is None or getattr(self, "_clamdscan", None) is None:
            self._clamscan, self._clamdscan = self._locate_binaries()
        self.clamd_max_file_size = self._read_clamd_max_file_size()
        if self._clamdscan is not None and (
            force_rechoose
            or self.binary is None
            or self.binary == getattr(self, "_clamscan", None)
        ):
            reachable, conf = self._clamd_reachable()
            if reachable:
                self._clamd_conf_used = conf
                self.binary = self._clamdscan
                # BUG-034: the "fallback already tried" flag belongs to the
                # clamdscan binary. A fresh upgrade must be allowed to fall
                # back once more; otherwise the next daemon loss re-enters
                # _run with clamdscan forever (RecursionError).
                self._fallback_done = False
                self.clamd_max_file_size = self._read_clamd_max_file_size()
                return
        if self.binary is None:
            # Vielleicht wurde ClamAV inzwischen installiert.
            self.binary = self._choose_binary()
            self.clamd_max_file_size = self._read_clamd_max_file_size()

    def _locate_binaries(self) -> tuple[Path | None, Path | None]:
        """Find the clamscan and clamdscan binaries separately.

        The candidates list mixes both names; each kind keeps its own
        first hit (plus a PATH fallback), so a daemon client is never
        shadowed by the plain scanner or vice versa.
        """
        clamscan: Path | None = None
        clamdscan: Path | None = None
        for candidate in config.CLAMAV_SCAN_CANDIDATES:
            path = Path(candidate)
            if not path.is_file():
                continue
            name = path.name.lower()
            if name.startswith("clamdscan") and clamdscan is None:
                clamdscan = path
            elif name.startswith("clamscan") and clamscan is None:
                clamscan = path
        if clamscan is None:
            found = which_absolute("clamscan")
            clamscan = Path(found) if found else None
        if clamdscan is None:
            found = which_absolute("clamdscan")
            clamdscan = Path(found) if found else None
        return clamscan, clamdscan

    def _clamd_reachable(self) -> tuple[bool, str | None]:
        """Ping the daemon; return ``(reachable, config_to_use)``.

        Two attempts, cheapest and least invasive first:

        1. **Default lookup.** ``clamdscan`` finds ``clamd.conf`` in the ClamAV
           install directory on its own. A normal service installation works
           this way, and overriding it with a user config pointing at a
           different socket/port would BREAK a setup that already worked.
        2. **Explicit user config.** Only if the default attempt fails is
           ``--config-file`` passed. Measured on the admin-less setup this was
           written for: `clamdscan --ping=1` → rc=2, with `--config-file` →
           rc=0, even though the daemon was running. Without this second
           attempt the engine silently falls back to the ~16 s-per-file
           ``clamscan`` path.

        The config that worked is returned so ``scan_path`` uses the SAME path
        — a ping over one config and a scan over another could reach different
        daemons.
        """
        if self._clamdscan is None:
            return False, None
        conf = self._clamd_conf()
        attempts: list[str | None] = [None]
        if conf is not None:
            attempts.append(conf)
        for attempt in attempts:
            # Cheap pre-check: `clamdscan --config-file=...` against a port
            # that is NOT listening blocks in a ~2 s connect timeout before
            # failing (measured 2075 ms; with ConnectTimeout 1 in the config
            # only 33 ms). An existing user config may predate that line, so
            # the timeout must not depend on the config's content. A closed
            # port means no daemon: skip straight to the next attempt.
            if attempt is not None and not _tcp_reachable(attempt):
                log.info(
                    "clamd-Port laut Konfiguration nicht erreichbar — Ping übersprungen (%s)",
                    attempt,
                )
                continue
            args = [str(self._clamdscan)]
            if attempt is not None:
                args.append(f"--config-file={attempt}")
            args.append("--ping=1")
            try:
                rc, _out, _err = run_tool(
                    args, timeout=config.CLAMAV_PING_TIMEOUT_SECONDS
                )
            except Exception as exc:
                log.info(
                    "clamd-Ping fehlgeschlagen: %s: %s", type(exc).__name__, exc
                )
                continue
            if rc == 0:
                log.info(
                    "clamd-Ping rc=0 binary=%s conf=%s -> Daemon aktiv",
                    self._clamdscan.name, attempt or "(Default-Suche)",
                )
                return True, attempt
        log.info(
            "clamd-Ping fehlgeschlagen binary=%s -> Fallback clamscan",
            self._clamdscan.name,
        )
        return False, None

    @staticmethod
    def _clamd_conf() -> str | None:
        """Path to an existing clamd config, or ``None`` when there is none.

        Deliberately free of side effects: creating the file here would force
        ``--config-file`` onto the user path even for an admin install whose
        ``clamd.conf`` sits in the ClamAV directory and is found by clamdscan's
        own default lookup. A forced path pointing at the wrong port would
        break a setup that used to work. Creation is an explicit action instead
        (``clamav_update.ensure_clamd_conf``, called by
        ``scripts/start_clamd.bat``).

        Only a real file is returned: passing a non-existent ``--config-file``
        makes clamdscan fail exactly like passing none.
        """
        raw = getattr(config, "CLAMAV_CLAMD_USER_CONF", "")
        if not raw:
            return None
        path = Path(os.path.expandvars(raw))
        return str(path) if path.is_file() else None

    @staticmethod
    def _parse_size(value: str) -> int | None:
        """Parse a ClamAV size value (``100M``, ``2G``, ``1048576``, ``0``).

        Returns bytes, ``0`` for "unlimited", or ``None`` when unparsable.
        ClamAV accepts a bare byte count and the K/M/G suffixes; a malformed
        value must not silently become "unlimited".
        """
        text = (value or "").strip().strip('"').strip("'")
        if not text:
            return None
        match = re.fullmatch(r"(\d+)\s*([KMG]?)", text, re.IGNORECASE)
        if match is None:
            return None
        number = int(match.group(1))
        factor = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[
            match.group(2).upper()
        ]
        return number * factor

    def _read_clamd_max_file_size(self) -> int:
        """Effective ``MaxFileSize`` of the clamd config that reached the daemon.

        When the config does not name the key, clamd's compiled-in default is
        100 MB. ``0`` means unlimited. ONLY the config that actually reached
        the daemon is trusted (BUG-035): with the default lookup no local file
        is known to be the daemon's config, and reading a *different*
        user-writable config could claim a larger limit than the daemon
        enforces — the daemon would skip the file and report "OK". The
        conservative default (100 MB) is the only safe assumption there.
        """
        conf = getattr(self, "_clamd_conf_used", None)
        if not conf:
            return config.CLAMAV_DEFAULT_MAX_FILE_SIZE
        try:
            with open(conf, encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    key, _, value = line.partition(" ")
                    if key.strip().lower() != "maxfilesize":
                        continue
                    parsed = self._parse_size(value)
                    return config.CLAMAV_DEFAULT_MAX_FILE_SIZE if parsed is None else parsed
        except OSError:
            return config.CLAMAV_DEFAULT_MAX_FILE_SIZE
        return config.CLAMAV_DEFAULT_MAX_FILE_SIZE

    def _daemon_size_limit(self) -> int:
        """The limit currently in force for the selected binary (0 = none)."""
        return getattr(self, "clamd_max_file_size", config.CLAMAV_DEFAULT_MAX_FILE_SIZE)

    def _choose_binary(self) -> Path | None:
        if not self.enabled:
            return None
        if self._clamdscan is not None:
            reachable, conf = self._clamd_reachable()
            if reachable:
                # Remember WHICH config reached the daemon so scan_path uses
                # the same one (a ping over the default lookup and a scan over
                # the user config could address different daemons).
                self._clamd_conf_used = conf
                return self._clamdscan
        return self._clamscan

    @staticmethod
    def _db_signature_time(db_dir: Path) -> float:
        """Newest modification time among signature files (0.0 when none).

        mtime is the right signal here: the GUI update button maintains a
        per-user database copy whose files' mtimes move forward with every
        freshclam run, while a stale admin copy keeps its download date.
        """
        newest = 0.0
        try:
            if not db_dir.is_dir():
                return 0.0
            for entry in db_dir.iterdir():
                if entry.suffix.lower() not in (".cvd", ".cld"):
                    continue
                try:
                    newest = max(newest, entry.stat().st_mtime)
                except OSError:
                    continue
        except OSError:
            return 0.0
        return newest

    def _locate_db(self) -> Path | None:
        """Find the directory with the FRESHEST usable ClamAV signatures.

        clamscan's compiled-in default (``<install>\\database``) covers standard
        installs; admin-less setups keep signatures in the user profile
        (``%LocalAppData%\\ClamAV\\db``, written by the update button /
        ``freshclam --config-file``). Among all candidates that contain
        signature files the NEWEST one wins — otherwise the scanner would
        keep reading a stale admin copy after the per-user database was
        updated. Ties go to the first configured candidate; only fixed,
        internal candidate paths are probed (never payload data).
        """
        best: Path | None = None
        best_time = 0.0
        for candidate in config.CLAMAV_DB_CANDIDATES:
            path = Path(os.path.expandvars(candidate))
            signature_time = self._db_signature_time(path)
            if signature_time > best_time:
                best, best_time = path, signature_time
        return best

    @staticmethod
    def _detail_excerpt(output: str) -> str:
        """Output trimmed of LibClamAV banner noise for user-facing details."""
        lines = [
            line for line in output.splitlines()
            if not line.strip().startswith("LibClamAV Warning")
            and "****" not in line
        ]
        return "\n".join(lines).strip()[: config.MAX_STRING_CAPTURE]

    def scan_path(self, path: Path | str) -> ClamAVResult:
        if not self.available:
            if self.enabled:
                log.warning(
                    "clamscan skip: Binary in Kandidatenpfaden nicht gefunden "
                    "(Kandidaten: %s)", list(config.CLAMAV_SCAN_CANDIDATES),
                )
            return ClamAVResult(
                skipped_reason="ClamAV nicht installiert oder deaktiviert"
            )
        # Same contract as WindowsDefenderScanner: external engines must get an
        # absolute path, otherwise they can fail or scan the wrong cwd-relative
        # target.
        target = Path(path).resolve()
        if not target.is_file():
            return ClamAVResult(skipped_reason="Datei existiert nicht auf dem Datenträger")
        return self._run(str(target))

    def scan_bytes(self, data: bytes, suffix: str = ".bin") -> ClamAVResult:
        """Scan in-memory bytes by staging them to a secure temp file.

        Used for archive members: the payload never existed on disk, so it
        would otherwise never reach the engine. Detection-only as always
        (no --remove); the temp file is deleted right after the run.
        """
        if not self.available:
            return ClamAVResult(
                skipped_reason="ClamAV nicht installiert oder deaktiviert"
            )
        # The suffix can originate from an archive member name; sanitize it
        # centrally (ASCII-only, separators stripped, length capped).
        fd, tmp_path = tempfile.mkstemp(
            suffix=safe_temp_suffix(suffix), prefix="malaz_clam_"
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            return self._run(tmp_path)
        finally:
            with suppress(OSError):
                os.unlink(tmp_path)

    def _run(self, target: str) -> ClamAVResult:
        if not self.enabled or self.binary is None:  # callers check .available
            log.info("clamscan skip: Engine deaktiviert/nicht gefunden (target=%s)", target)
            return ClamAVResult(
                skipped_reason="ClamAV nicht installiert oder deaktiviert"
            )
        # clamscan: --no-summary keeps output small; we never pass --remove
        # (detect only). clamdscan (daemon client) understands NEITHER
        # --no-summary NOR --database reliably across versions — the daemon
        # already uses its configured DB. Passing them anyway could make
        # EVERY scan fail, silently blinding the whole engine. (Measured on
        # this machine clamdscan does accept --no-summary, but it buys nothing
        # here: _FOUND_RE matches the "…: <name> FOUND" line regardless of the
        # trailing summary, so the version-robustness argument wins.)
        args = [str(self.binary)]
        is_clamscan = self.binary.name.lower().startswith("clamscan")
        target_size = 0
        with suppress(OSError):
            target_size = Path(target).stat().st_size
        if is_clamscan:
            args.append("--no-summary")
            # ClamAV's compiled-in default skips files > 100 MB and calls them
            # clean. These flags are part of the fix for the 500 MB request:
            # the size limit must cover everything Malaz accepts.
            max_mb = max(1, config.CLAMAV_DAEMON_MAX_FILE_SIZE // config.MB)
            scan_mb = max(max_mb, config.CLAMAV_SCAN_MAX_SIZE // config.MB)
            args += [
                f"--max-filesize={max_mb}M",
                f"--max-scansize={scan_mb}M",
                f"--pcre-max-filesize={max_mb}M",
            ]
            if getattr(self, "database", None) is not None:
                args += ["--database", str(self.database)]
        else:
            limit = self._daemon_size_limit()
            if limit and target_size > limit:
                # clamd reports "OK" for a skipped oversized file. Without
                # this branch the result is a false CLEAN for every file
                # above the daemon's limit (measured: 150 MB -> OK in 0.03 s).
                return ClamAVResult(
                    scanned=False,
                    limit_exceeded=True,
                    skipped_reason=(
                        f"ClamAV-Dateilimit überschritten: {target_size} Bytes > "
                        f"{limit} Bytes (clamd MaxFileSize). Die Datei wurde "
                        "NICHT geprüft — das Ergebnis ist nicht als 'sauber' "
                        "zu werten. Limit in der clamd-Konfiguration anheben."
                    ),
                )
            # clamdscan: pass the config that actually reached the daemon
            # during the ping. Without it, clamdscan looks in the install
            # directory, finds nothing and exits rc=2 — the same trap as in
            # _clamd_reachable. None means the default lookup worked, and then
            # overriding it would be wrong.
            conf = getattr(self, "_clamd_conf_used", None)
            if conf is not None:
                args.append(f"--config-file={conf}")
        args.append(target)
        timeout = max(self.timeout, config.clamav_timeout_for_size(target_size))
        try:
            proc = run_tool(args, timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning(
                "clamscan Timeout > %ss (target=%s, db=%s) — DB-Laden zu langsam?",
                timeout, target, self.database,
            )
            return ClamAVResult(
                skipped_reason=f"ClamAV-Scan abgebrochen (Timeout > {timeout}s)"
            )
        except FileNotFoundError:
            log.warning("clamscan nicht startbar: FileNotFoundError (target=%s)", target)
            return ClamAVResult(skipped_reason="ClamAV-Binary nicht gefunden")
        except Exception as exc:
            log.warning(
                "clamscan fehlgeschlagen: %s: %s (target=%s)",
                type(exc).__name__, exc, target,
            )
            return ClamAVResult(
                skipped_reason=f"ClamAV-Scan fehlgeschlagen: {type(exc).__name__}: {exc}"
            )

        rc, raw_out, raw_err = proc
        output = self._decode(raw_out) + self._decode(raw_err)
        excerpt = output.strip()[: config.MAX_STRING_CAPTURE]
        # SEC-023: a capped output is a prefix. The FOUND line (or the rc=2
        # cause) can sit beyond it while the visible text looks like a clean
        # scan. No verdict is derived from it: CLAMAV_SKIPPED, never clean.
        if tool_output_truncated(proc):
            log.warning(
                "clamscan-Ausgabe an der Obergrenze abgeschnitten (rc=%s, "
                "target=%s) — Scan nicht ausgewertet, output=%r",
                rc, target, excerpt,
            )
            return ClamAVResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "ClamAV-Ausgabe wurde an der Ausgabe-Obergrenze "
                    "abgeschnitten — der Scan ist NICHT ausgewertet und nicht "
                    "als 'sauber' zu werten"
                ),
                detail=excerpt,
            )
        # Every decision is logged verbatim (mirroring windows_av): a silent
        # CLAMAV_SKIPPED in the results must be diagnosable from malaz.log
        # without re-running the scan — missing signature DBs (rc 2) and
        # timeouts otherwise stay invisible in the CSV.
        log.info(
            "clamscan rc=%s binary=%s db=%s target=%s output=%r",
            rc, self.binary.name, self.database, target, excerpt,
        )
        # User-facing detail: drop the LibClamAV banner block ("database is
        # older than 7 days" ...). It is engine status — shown with the DB
        # age in the engine line — and embedded in every clean verdict it
        # read like a contradiction right after the user had updated
        # (field report). The log above keeps the raw output.
        detail_excerpt = self._detail_excerpt(output)
        # Decision basis for the rc=2 diagnosis. The scanner echoes the scan
        # TARGET in its output, and that path (file name) is attacker
        # controlled: a probe called "connection refused.pdf" or "error
        # loading database.ndb" would otherwise fake a dead daemon or a broken
        # signature base. Stripping the path first is the same de-fanging
        # windows_av already applies to its verdict phrases. The user-facing
        # detail keeps the raw text (the path there is useful, not a verdict).
        analysis_text = strip_scan_target(output, target)

        match = _FOUND_RE.search(output)
        if match:
            name = match.group("name")
            return ClamAVResult(
                scanned=True,
                threat_found=True,
                threat_name=name,
                returncode=rc,
                detail=f"ClamAV hat eine Bedrohung erkannt: {name}. {detail_excerpt}",
            )
        if rc == 1:
            # rc==1 means "virus found", but the output carries no parsable
            # FOUND line (e.g. OEM-mojibake destroyed it). Report an
            # UNCONFIRMED hint instead of a CRITICAL anchor with a made-up
            # signature name — the dispatcher maps scanned-but-not-threat to
            # CLAMAV_CLEAN, so flag this explicitly via detail/threat_name.
            return ClamAVResult(
                scanned=True,
                threat_found=True,
                threat_name="unbestätigt (keine FOUND-Zeile in der Ausgabe)",
                returncode=rc,
                detail=(
                    "ClamAV meldete einen Fund-Returncode, aber die Ausgabe "
                    "enthält keine lesbare FOUND-Zeile (möglicherweise "
                    "Encoding-Problem). Als Bedrohung mit Vorbehalt gewertet. "
                    + detail_excerpt
                ),
            )
        if rc == 0 or ": OK" in output:
            return ClamAVResult(
                scanned=True,
                threat_found=False,
                returncode=rc,
                detail="ClamAV: keine Bedrohung gefunden. " + detail_excerpt,
            )
        # rc == 2 (or other) -> engine / DB error, inconclusive.
        #
        # A signature-base failure is named explicitly. It is the one engine
        # error the user can actually fix, and without the distinction it
        # vanished into a generic "Returncode 2" — while the engine badge kept
        # showing "bereit" (it only checks that a database DIRECTORY exists).
        # One damaged .ndb from a third-party feed is enough to blind the whole
        # engine, so this case must be recognisable in the report.
        db_failure = _db_load_failure(analysis_text)
        if db_failure:
            return ClamAVResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "ClamAV konnte die Signaturbasis NICHT laden — es wurde "
                    f"nichts geprüft (nicht: 'sauber'). Meldung: '{db_failure}'. "
                    f"DB-Verzeichnis: {self.database}. Eine einzige unlesbare "
                    "Signaturdatei legt die gesamte Engine still."
                ),
                detail=detail_excerpt,
            )
        # Only a daemon CLIENT can lose its daemon. When the binary is already
        # clamscan, "falling back to clamscan" is a no-op that would re-enter
        # _run on the same target (measured: RecursionError after 494 calls
        # when the file name carried the phrase).
        if not is_clamscan and self._daemon_lost(analysis_text):
            # The daemon died AFTER _choose_binary picked clamdscan (it only
            # pings once, in __init__). Without this the ClamAV stage would
            # return "not conclusive" for every remaining file in this process
            # — measured: scanned=False for all of them. Fall back to the
            # full-process scanner and retry ONCE.
            log.warning(
                "clamd nicht mehr erreichbar (rc=%s) — Fallback auf clamscan", rc
            )
            return self._retry_with_clamscan(target)
        return ClamAVResult(
            scanned=False,
            returncode=rc,
            skipped_reason=f"ClamAV-Scan nicht aussagekräftig (Returncode {rc})",
            detail=detail_excerpt,
        )

    @staticmethod
    def _daemon_lost(output: str) -> bool:
        """True when the output says the clamd connection is gone.

        Matched on the client's own wording; a generic rc=2 (broken database)
        must NOT trigger the fallback, or a damaged DB would silently switch
        scanners instead of being reported.

        Callers MUST pass text with the scan target removed
        (``procio.strip_scan_target``): the target path is attacker
        controlled, and its echo — a file named ``connection refused.pdf`` —
        would otherwise look exactly like a dead daemon.
        """
        lowered = (output or "").lower()
        return "connection refused" in lowered or "could not connect to clamd" in lowered

    def _retry_with_clamscan(self, target: str) -> ClamAVResult:
        """Switch once, then let every concurrent file scan use clamscan."""
        lock = getattr(self, "_fallback_lock", None)
        if lock is None:
            lock = self._fallback_lock = threading.Lock()
        with lock:
            if self._clamscan is None:
                return ClamAVResult(
                    scanned=False,
                    skipped_reason=(
                        "clamd nicht erreichbar und clamscan nicht installiert — "
                        "es wurde nichts geprüft."
                    ),
                )
            # Always re-point at clamscan, even if the flag says a fallback
            # already happened. refresh_state may have upgraded the binary
            # back to clamdscan; leaving it there while returning to _run()
            # would recurse until RecursionError (BUG-034). The operation is
            # idempotent, so concurrent callers each switch for their own file.
            self._fallback_done = True
            self.binary = self._clamscan
            self._clamd_conf_used = None
        # Every caller owns a different target. The first one switches the
        # shared binary; later callers must still scan their own file rather
        # than inheriting a "fallback already tried" no-op.
        return self._run(target)

    @staticmethod
    def _decode(raw: bytes | None) -> str:
        return decode_tool_output(raw)
