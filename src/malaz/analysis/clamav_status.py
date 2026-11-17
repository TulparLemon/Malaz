"""ClamAV version/update status (offline-first).

Answers "which ClamAV is installed, how fresh is the signature database, and
is an update needed?" in three tiers:

1. **Offline (always):** the clamscan binary version and the build dates of
   the local signature databases (``daily.cvd``/``main.cvd``/``bytecode.cvd``
   — their headers are human-readable: ``ClamAV-VDB:11 Aug 2026 06-25 +00``).
   From the dates the database age is derived.
2. **Online comparison (explicit opt-in):** a 32-byte Range request against
   ``database.clamav.net`` fetches the *remote* CVD header (same format) and
   compares it with the local one — "update available" or "up to date".
3. Never blocks: hard timeouts everywhere; any failure degrades to a status
   note, not an error.

Per the 100%-offline design (docs/SECURITY_MODEL.md) the network request only
runs when explicitly requested (``--clamav-update-check`` or
``config.CLAMAV_UPDATE_CHECK_ENABLED``) — the scanner itself never goes
online.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..procio import decode_tool_output, run_tool, tool_output_truncated

# The local CVD header format, e.g. b"ClamAV-VDB:11 Aug 2026 06-25 +00".
_CVD_HEADER_RE = re.compile(
    rb"ClamAV-VDB:\s*(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2})-(\d{2})"
)

_MONTHS = {
    b"Jan": 1, b"Feb": 2, b"Mar": 3, b"Apr": 4, b"May": 5, b"Jun": 6,
    b"Jul": 7, b"Aug": 8, b"Sep": 9, b"Oct": 10, b"Nov": 11, b"Dec": 12,
}

# Which CVD files are relevant for the freshness verdict.
_DB_KINDS = ("daily", "main", "bytecode")

# Fixed internal update targets — fully literal URLs, no string assembly.
# Each is validated against the allowlisted host (https only) before the
# request, and the final response URL is re-checked afterwards so a redirect
# cannot silently move the connection elsewhere. Only ever reached in the
# explicit opt-in mode (--clamav-update-check).
_UPDATE_HOST = "database.clamav.net"
_UPDATE_URLS = {
    "daily": "https://database.clamav.net/daily.cvd",
    "main": "https://database.clamav.net/main.cvd",
    "bytecode": "https://database.clamav.net/bytecode.cvd",
}


def _validated_update_url(kind: str) -> str:
    """Return the update URL for ``kind`` after full SSRF guarding.

    * scheme locked to https and host locked to the fixed allowlist entry,
    * the host is DNS-resolved and every resolved address must be public
      (blocks loopback/private/link-local targets before any connection),
    * the final response URL is re-checked after redirects by the caller.
    """
    url = _UPDATE_URLS[kind]
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != _UPDATE_HOST:
        raise ValueError(f"unerlaubtes Update-Ziel: {url}")
    for *_ignored, sockaddr in socket.getaddrinfo(parsed.hostname, 443):
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ValueError(
                f"Update-Ziel {parsed.hostname} löst zu nicht-öffentlicher "
                f"Adresse {address} auf"
            )
    return url


@dataclass
class ClamAvStatus:
    binary_version: str = ""
    db_dates: dict[str, datetime] = field(default_factory=dict)
    db_dir: str = ""
    remote_dates: dict[str, datetime] = field(default_factory=dict)
    error: str = ""


def _locate_db_dir() -> Path | None:
    """Reuse the DB discovery of the scanner (config candidates)."""
    try:
        from .clamav import ClamAVScanner

        return ClamAVScanner().database
    except Exception:
        return None


def parse_cvd_date(header: bytes) -> datetime | None:
    """Parse a ``ClamAV-VDB:...`` header line into an aware datetime."""
    match = _CVD_HEADER_RE.search(header)
    if not match:
        return None
    day, month, year, hour, minute = match.groups()
    month_num = _MONTHS.get(month)
    if month_num is None:
        return None
    try:
        return datetime(
            int(year), month_num, int(day), int(hour), int(minute),
            tzinfo=UTC,
        )
    except ValueError:
        return None


def read_db_dates(db_dir: Path | None = None) -> dict[str, datetime]:
    """Read the build dates of every local signature database (offline).

    Both ``.cvd`` (downloaded) and ``.cld`` (locally rebuilt) layouts are
    accepted — the scanner in :mod:`analysis.clamav` treats them equally, and
    an install whose signatures live in ``daily.cld`` must not be reported as
    "keine Signatur-Datenbank gefunden".
    """
    if db_dir is None:
        db_dir = _locate_db_dir()
    out: dict[str, datetime] = {}
    if db_dir is None or not db_dir.is_dir():
        return out
    for kind in _DB_KINDS:
        head = _read_db_header(db_dir / f"{kind}.cvd")
        if head is None:
            head = _read_db_header(db_dir / f"{kind}.cld")
        if head is None:
            continue
        parsed = parse_cvd_date(head)
        if parsed is not None:
            out[kind] = parsed
    return out


def _read_db_header(path: Path) -> bytes | None:
    """Read the first bytes of a signature database, or None if absent."""
    try:
        if not path.is_file():
            return None
        with open(path, "rb") as fh:
            return fh.read(64)
    except OSError:
        return None


def read_binary_version(binary: Path | None = None) -> str:
    """Return the clamscan version string (offline), or '' on failure."""

    if binary is None:
        from .clamav import ClamAVScanner

        binary = ClamAVScanner().binary
    if binary is None:
        return ""
    try:
        proc = run_tool([str(binary), "--version"], timeout=10)
        if tool_output_truncated(proc):
            return ""  # cut-off version string is not a version (SEC-023)
        _rc, raw_out, _raw_err = proc
        first_line = raw_out.splitlines()[0] if raw_out else b""
        return decode_tool_output(first_line).strip()
    except Exception:
        return ""


def db_age_days(db_dates: dict[str, datetime], now: datetime | None = None) -> int | None:
    """Age of the newest CVD build in whole days; None when no dates."""
    if not db_dates:
        return None
    newest = max(db_dates.values())
    if now is None:
        now = datetime.now(UTC)
    return max(0, (now - newest).days)


def fetch_remote_dates(
    kinds: tuple[str, ...] = _DB_KINDS, timeout: float = 8.0
) -> dict[str, datetime]:
    """Fetch the remote CVD build dates (32-byte Range requests).

    Raises on network/parse failure — callers degrade to a status note.
    Only ever reaches the fixed internal HTTPS URL below, and only when the
    caller explicitly opted into the online check.
    """
    out: dict[str, datetime] = {}
    for kind in kinds:
        url = _validated_update_url(kind)
        # Inline-SSRF-Guard: ausschließlich die allowlisteten Literal-URLs
        # (https, fester Host, öffentliche IPs) sind als Ziel zulässig.
        if url not in _UPDATE_URLS.values():
            raise ValueError(f"unerlaubtes Update-Ziel: {url}")
        request = Request(
            url,
            headers={
                "Range": "bytes=0-63",
                "User-Agent": "ClamAV/1.5.3 (malaz status check)",
            },
        )
        # Fest: interne HTTPS-URL (nie Nutzerinput als Ziel), nur im expliziten
        # Opt-in-Modus, 64-Byte-Range-Request.
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            # Redirect-Nachpruefung: das Ziel darf auch nach Weiterleitungen
            # noch immer der allowlistete Update-Host sein.
            final = urlparse(response.geturl() or url)
            if final.hostname != _UPDATE_HOST or final.scheme != "https":
                raise ValueError(f"Update-Ziel wurde umgeleitet: {response.geturl()}")
            head = response.read(64)
        parsed = parse_cvd_date(head)
        if parsed is not None:
            out[kind] = parsed
    return out


def collect_status(include_remote: bool = False) -> ClamAvStatus:
    """Gather the offline (and optionally remote) ClamAV status."""
    status = ClamAvStatus()
    status.binary_version = read_binary_version()
    db_dir = _locate_db_dir()
    status.db_dir = str(db_dir) if db_dir else ""
    status.db_dates = read_db_dates(db_dir)
    if include_remote:
        try:
            status.remote_dates = fetch_remote_dates()
        except Exception as exc:
            status.error = f"{type(exc).__name__}: {exc}"
    return status


def format_status(status: ClamAvStatus) -> str:
    """One human-readable line for CLI/GUI display."""
    parts: list[str] = []
    if status.binary_version:
        parts.append(status.binary_version)
    else:
        parts.append("clamscan nicht gefunden")
    if status.db_dates:
        daily = status.db_dates.get("daily")
        if daily:
            age = db_age_days(status.db_dates)
            age_txt = f" ({age} Tag{'e' if age != 1 else ''} alt)" if age is not None else ""
            if age is not None and age >= 30:
                # Visible nudge: a silently ageing second engine is worse
                # than none — its "clean" verdicts lose meaning.
                age_txt += " — Update empfohlen (scripts\\update_clamav.bat)"
            parts.append(f"Signaturen vom {daily:%d.%m.%Y}{age_txt}")
    else:
        parts.append("keine Signatur-Datenbank gefunden")
    if status.remote_dates:
        verdict = _remote_verdict(status)
        parts.append(verdict)
    elif status.error:
        parts.append(f"Update-Check nicht möglich ({status.error})")
    return " · ".join(parts)


def _remote_verdict(status: ClamAvStatus) -> str:
    """Compare local vs. remote daily dates; 'aktuell' or 'Update verfügbar'."""
    local = status.db_dates.get("daily")
    remote = status.remote_dates.get("daily")
    if local is None or remote is None:
        return "Update-Status unklar (daily fehlt lokal oder remote)"
    if remote > local:
        return f"Update verfügbar (remote: {remote:%d.%m.%Y})"
    return "Datenbank aktuell"
