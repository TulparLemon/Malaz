"""URL reputation: an offline local check plus an opt-in online provider.

Why this module exists
----------------------
Static link analysis (``core/eml_analysis.py``) catches typosquatting, IP
literals, shorteners and the like without any network access. It cannot tell
whether a *specific* URL is already a known phishing/malware endpoint.

Two independent answers, and the difference matters:

**Local URL blocklist (offline, no opt-in).** A file of SHA-256 hashes of
known-bad URLs (``config.URL_BLOCKLIST_FILE``), filled by
``scripts/import_blocklist.py --urls``. Checked whenever it exists; no
network path is involved, so it needs no switch and is not covered by the
privacy rules below.

**Online provider (opt-in).** Asking a third party whether a specific URL is
known-bad means a network request, and therefore a privacy decision. Those
requests follow rules 1-5 below — all enforced in code, all tested, and they
apply ONLY to the provider payload:

1. **Off by default.** No provider request happens unless the user explicitly
   enabled it AND a provider is configured. (This does not gate the local
   check — that one has nothing to transmit.)
2. **Hash, never the URL.** Only the SHA-256 of the URL leaves the machine.
   The URL itself (path, query, credentials, tokens) is never transmitted.
   This is the same approach Google Safe Browsing uses for its update API and
   what keeps a scan from leaking the user's mail content to a third party.
3. **Not egress-free, but narrow.** Local, private and non-routable hosts are
   never sent (no internal hostnames leak to an external service). The local
   check is deliberately NOT filtered this way — it has no third party to
   protect, and skipping private hosts there would just miss detections.
4. **Bounded and failure-tolerant.** Hard timeout, capped number of provider
   lookups per mail, and any error degrades to "unknown" — never to a false
   "clean". Local hits survive a provider outage.
5. **No provider is hard-coded.** Without an explicitly configured endpoint the
   provider request is a no-op; the module ships no default URL, no embedded
   key, and no telemetry.

A compatible provider answers a POST with ``{"urls": {"<sha256>": "status"}}``
(Google Safe Browsing ``urls:lookup`` shape). Statuses map to findings in
:func:`status_to_finding`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .. import config
from . import hashlist

# Provider status strings -> human-readable verdict (and whether it is a hit).
# ``local_*`` marks hits from the local blocklist: the same finding, but with
# no provider involved — the text must not claim a "Dienst" was asked.
_HIT_STATUSES = {
    "malware": "Malware-Verteilung",
    "phishing": "Phishing",
    "unwanted": "unerwünschte Software",
    "social_engineering": "Social Engineering",
    "local_malware": "Malware-Verteilung (lokale URL-Blocklist)",
}

_LOCAL_STATUS = "local_malware"


@dataclass
class ReputationResult:
    """Outcome of one lookup batch."""

    ran: bool = False
    hits: dict[str, str] = None  # type: ignore[assignment]
    skipped_reason: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if self.hits is None:
            self.hits = {}


def url_hash(url: str) -> str:
    """SHA-256 of the URL, hex encoded.

    Only this value ever leaves the machine. The trailing ``#`` fragment is
    dropped first: it is interpreted by the browser, not the server, and
    including it would split identical requests.
    """
    try:
        split = urlsplit(url)
        cleaned = split._replace(fragment="").geturl()
    except Exception:
        cleaned = url
    return hashlib.sha256(cleaned.encode("utf-8", "replace")).hexdigest()


def _is_lookupable(url: str) -> bool:
    """False for hosts that must never be sent to a third party.

    Private ranges, loopback, link-local, reserved and single-label hostnames
    stay local: submitting them would leak the user's internal naming to an
    external service for zero detection value. A normal public domain IS
    lookupable — ``ipaddress`` failing to parse the host is the *expected*
    outcome for a domain name, not a reason to skip it (that inversion was a
    real bug caught by the privacy tests).
    """
    try:
        host = (urlsplit(url).hostname or "").strip().lower()
    except Exception:
        return False
    if not host:
        return False
    if "." not in host and ":" not in host:
        return False  # single-label (intranet) host
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return True  # a normal domain name — the usual, lookupable case
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def enabled() -> bool:
    """True only when the user opted in AND a provider is configured."""
    return bool(
        getattr(config, "URL_REPUTATION_ENABLED", False)
        and getattr(config, "URL_REPUTATION_ENDPOINT", "")
    )


def local_blocklist_enabled() -> bool:
    """True when a local URL blocklist exists and may be consulted.

    This is the offline half of the reputation feature: no provider, no
    network, no opt-in switch — a purely local file the user imported. It is
    independent of :func:`enabled` (the online provider); both can be active
    and their hits are merged.
    """
    path = local_blocklist_path()
    if path is None:
        return False
    try:
        return path.is_file()
    except OSError:
        # An unreadable path (Windows reports PermissionError for files the
        # process may not even stat, e.g. System32/config/SYSTEM) used to
        # escape ``lookup()`` and turned the whole EML pipeline into
        # CORE_ERROR — every mail finding was lost and the error text carried
        # the path (audit BUG-075). "Not usable" is the honest answer here.
        return False


def local_blocklist_path() -> Path | None:
    """The configured local URL blocklist as a path (may not exist)."""
    raw = getattr(config, "URL_BLOCKLIST_FILE", "")
    if not raw:
        return None
    return Path(os.path.expandvars(str(raw)))


class _BlocklistUnreadable(RuntimeError):
    """Die lokale URL-Blocklist ist vorhanden, aber nicht lesbar."""


def _lookup_local(urls: list[str]) -> dict[str, str]:
    """Hash-check ``urls`` against the local blocklist; hash -> status.

    Reuses the URL hashing of the online path, so a feed entry and a mail link
    only match when they hash identically (fragment stripped, same as the
    provider lookup). Entries in the file are plain SHA-256 hex tokens, which
    is exactly what ``core.hashlist`` already parses — the same importer
    (``scripts/import_blocklist.py``) can therefore fill it.
    """
    path = local_blocklist_path()
    if path is None:
        return {}
    try:
        exists = path.is_file()
    except OSError:
        exists = False
    if not exists:
        return {}
    listed, fehler = hashlist.load_blocklist_or_error(path)
    if fehler:
        # NICHT als "keine Treffer" behandeln: die Liste ist VORHANDEN, liess
        # sich aber nicht lesen. Ohne diese Zeile meldet der Aufrufer
        # "geprueft, kein Treffer" — eine Behauptung ueber eine Pruefung, die
        # nicht stattfand (Audit-Befund 7).
        raise _BlocklistUnreadable(fehler)
    if not listed:
        return {}
    hits: dict[str, str] = {}
    for url in urls:
        digest = url_hash(url)
        if digest in listed:
            hits[digest] = _LOCAL_STATUS
    return hits


def lookup(links, timeout: float | None = None) -> ReputationResult:
    """Look up the hashes of ``links`` (``LinkFacts`` or URL strings).

    Two independent sources, merged into one result:

    * the **local** URL blocklist (no network, no opt-in) — a file the user
      imported, checked first;
    * the **online** provider, only when explicitly enabled and configured.

    A local hit is conclusive on its own; the network is never contacted for
    it. Returns a result whose ``hits`` maps *hash* -> status. Never raises:
    any network or parse problem degrades to ``error`` and an empty hit set,
    so a failing provider can not turn into a silent "everything is fine".
    """
    online = enabled()
    local = local_blocklist_enabled()
    if not online and not local:
        return ReputationResult(skipped_reason="Reputations-Abfrage ist aus.")

    # All links as given — the local check is offline and unbounded.
    all_urls: list[str] = []
    for entry in links:
        url = getattr(entry, "url", None) or str(entry)
        all_urls.append(url)

    # The local blocklist is checked against EVERY link: ``_is_lookupable``
    # and the lookup cap exist to bound what may be sent to a third party
    # (privacy), not to bound a purely local comparison. Applying them here
    # would make the offline list silently miss private-host links and
    # anything past the cap.
    try:
        local_hits = _lookup_local(all_urls)
    except _BlocklistUnreadable as exc:
        # Der Abgleich hat NICHT stattgefunden. Weder "kein Treffer" noch
        # "sauber" darf daraus werden — der Fehler geht nach oben, und der
        # Aufrufer meldet ihn (eml_pipeline hat dafuer MAIL_REPUTATION_WARN).
        return ReputationResult(
            ran=False,
            error=f"Lokale URL-Blocklist nicht lesbar: {exc}",
        )

    if not online:
        # Offline-only mode: the local list is the whole answer.
        if not local_hits:
            return ReputationResult(
                ran=True,
                hits={},
                skipped_reason="Kein Link steht auf der lokalen Blocklist.",
            )
        return ReputationResult(ran=True, hits=local_hits)

    # Provider payload: only public hosts, capped.
    urls: list[str] = [u for u in all_urls if _is_lookupable(u)]
    if not urls:
        # Nothing for the provider. ``ran`` reports whether anything was
        # actually checked — with no public links and no local list, nothing
        # was, and the pipeline must not believe an engine ran.
        return ReputationResult(
            ran=local,
            hits=local_hits,
            skipped_reason="Keine öffentlichen Links zum Abgleich.",
        )

    limit = int(getattr(config, "URL_REPUTATION_MAX_LOOKUPS", 10))
    urls = urls[:limit]

    if timeout is None:
        timeout = float(getattr(config, "URL_REPUTATION_TIMEOUT_SECONDS", 8))

    endpoint = str(getattr(config, "URL_REPUTATION_ENDPOINT", ""))
    if not endpoint.lower().startswith("https://"):
        # A plain-HTTP reputation call would leak even the hash in transit.
        # The local hits were established BEFORE this point and must survive
        # the refusal: returning a fresh empty result made a known-bad link
        # disappear and the caller report MAIL_REPUTATION_CLEAN (audit
        # BUG-076). ``ran`` says what actually ran — the local check.
        return ReputationResult(
            ran=local,
            hits=local_hits,
            skipped_reason="Provider-URL ist nicht HTTPS.",
        )

    import urllib.request

    payload = json.dumps(
        {
            "client": {"clientId": "malaz", "clientVersion": "1.0"},
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            # Only hashes leave the machine — see the module docstring.
            "urlHashes": [url_hash(u) for u in urls],
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            body = response.read(256 * 1024)
        data = json.loads(body.decode("utf-8", "replace"))
    except Exception as exc:
        # Never report a failed lookup as "clean". Local hits survive the
        # provider outage — they were established without the network.
        return ReputationResult(
            ran=True, hits=local_hits, error=f"{type(exc).__name__}: {exc}"
        )

    hits: dict[str, str] = dict(local_hits)
    urls_map = data.get("urls") if isinstance(data, dict) else None
    if isinstance(urls_map, dict):
        for digest, entry in urls_map.items():
            if not isinstance(entry, dict):
                continue
            status = str(entry.get("threatType") or entry.get("status") or "").lower()
            if status:
                hits[str(digest).lower()] = status
    elif isinstance(data, dict) and isinstance(data.get("matches"), list):
        # Alternative provider shape: a list of {urlHash, threatType}.
        for entry in data["matches"]:
            if isinstance(entry, dict) and entry.get("urlHash"):
                hits[str(entry["urlHash"]).lower()] = str(
                    entry.get("threatType", "unknown")
                ).lower()
    return ReputationResult(ran=True, hits=hits)


def status_to_finding(status: str) -> tuple[str, str]:
    """Map a hit status to ``(human_verdict, severity_reason)``.

    The reason names the actual source: a local blocklist hit must not read as
    if a provider had been asked.
    """
    key = (status or "").strip().lower()
    verdict = _HIT_STATUSES.get(key)
    if key == _LOCAL_STATUS and verdict:
        return verdict, "Der Link steht in der lokalen URL-Blocklist."
    if verdict:
        return verdict, f"Vom Reputationsdienst gemeldet: {verdict}"
    return f"unbekannter Status '{status}'", "Reputationsdienst meldet einen Treffer"
