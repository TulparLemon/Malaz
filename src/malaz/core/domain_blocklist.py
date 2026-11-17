"""Domain-Blockliste: bekannte Phishing-Absenderdomains, rein lokal.

WARUM DIESE DATEI EXISTIERT
===========================
Die URL-Blockliste (``core/url_reputation``) erkennt eine bekannte Schad-URL.
Sie erkennt NICHT die Domain, die dahintersteht: eine Phishing-Mail mit
``http://serioese-bank.tld/login?token=abc`` wird nur bei genau dieser URL
gefunden — dieselbe Domain mit einem anderen Pfad nicht.

Fuer den Absender ist das die falsche Frage. Wer wissen will, ob eine MAIL von
einer bekannten Phishing-Domain kommt, hat keine URL, sondern einen Host aus
dem ``From:``-Kopf. Deshalb hier ein eigener Abgleich ueber Domainnamen.

WARUM DIE SUFFIX-SUCHE
======================
Blocklisten fuehren gemischte Tiefe: mal ``evil.tld``, mal
``login.evil.tld``. Eine exakte Suche wuerde ``mail.evil.tld`` nicht finden,
obwohl die Domain darunter aufgefuehrt ist. Deshalb wird der Name von rechts
gekuerzt und jeder Schritt nachgeschlagen — bei ``mail.login.evil.tld`` also
vier Schluesselabfragen in einem ``frozenset``. Das ist O(Labels), nicht O(n):
die Liste hat schnell eine halbe Million Eintraege, und eine lineare Suche je
Mail waere bei jedem Scan spuerbar.

WARUM DIE OEFFENTLICHE SUFFIX-GRENZE NICHT GEBRAUCHT WIRD
=========================================================
Naheliegend waere, nur bis zur registrierbaren Domain zu kuerzen
(``evil.tld``). Dann wuerde aber ein Eintrag ``co.uk`` jede britische Domain
treffen. Die Liste wird von den Feeds gepflegt und enthaelt ganze Domains;
jeder Kuerzungsschritt ist ein gueltiger Kandidat. Ein Eintrag ``tld`` waere
in einer echten Liste ein Fehler, nicht ein Sonderfall.
"""

from __future__ import annotations

import errno
import logging
import re
from contextlib import suppress
from pathlib import Path
from urllib.parse import unquote

from .. import config

log = logging.getLogger(__name__)

# Gross/klein wird vereinheitlicht: DNS ist case-insensitiv, die Feeds sind es
# nicht immer. Beim Laden einmal normalisieren, nicht bei jeder Abfrage.
_DOMAIN_CACHE: dict[tuple[float, int, str], frozenset[str]] = {}


def _stat_key(target: Path) -> tuple[float, int] | None:
    """Cache key, or ``None`` ONLY when the file does not exist.

    ``ENOENT``/``ENOTDIR`` mean "no list configured" — the optional, empty
    case. Every other ``OSError`` (``EACCES``, ``EIO``, sharing violation) is
    an EXISTING list we cannot stat: swallowing it as "missing" made the scan
    report "checked, no hit" without ever reading the list (BUG-077). The
    exception is propagated so the caller can emit the explicit
    ``DOMAIN_BLOCKLIST_UNAVAILABLE`` status.
    """
    try:
        stat = target.stat()
    except OSError as exc:
        if isinstance(exc, (FileNotFoundError, NotADirectoryError)) or exc.errno in (
            errno.ENOENT,
            errno.ENOTDIR,
        ):
            return None
        raise
    return stat.st_mtime, stat.st_size


def load_domain_blocklist_or_error(
    path: Path | None = None,
) -> tuple[frozenset[str], str]:
    """Return entries and a safe error label for an existing unreadable list.

    Missing files are an optional, empty list.  The error label intentionally
    contains no local path: it is later shown in a report.
    """
    target = Path(path) if path is not None else config.DOMAIN_BLOCKLIST_FILE
    try:
        key = _stat_key(target)
    except OSError as exc:
        # The path stays in the log (which has its own privacy filter), never
        # in the result/report shown to the user.
        log.warning("Domain-Blockliste nicht lesbar (%s): %s", target, exc)
        return frozenset(), type(exc).__name__
    if key is None:
        return frozenset(), ""
    cache_key = (key[0], key[1], str(target))
    cached = _DOMAIN_CACHE.get(cache_key)
    if cached is not None:
        return cached, ""

    from .listcache import load_cached, stat_key, store_cached

    # Captured BEFORE the parse: if a feed import replaces the file while the
    # old content is being parsed, the result must not be stored under the
    # new stat key (BUG-010).
    content_key = stat_key(target)
    cached = load_cached(target, "domains")
    if cached is not None:
        _DOMAIN_CACHE.clear()
        _DOMAIN_CACHE[cache_key] = cached
        return cached, ""

    domains: set[str] = set()
    try:
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                text = line.strip().lstrip("\ufeff")
                if not text or text.startswith("#"):
                    continue
                domains.add(_normalize(text))
    except OSError as exc:
        log.warning("Domain-Blockliste nicht lesbar (%s): %s", target, exc)
        return frozenset(), type(exc).__name__

    result = frozenset(d for d in domains if d)
    with suppress(OSError):
        store_cached(target, "domains", result, expected_key=content_key)
    _DOMAIN_CACHE.clear()
    _DOMAIN_CACHE[cache_key] = result
    return result, ""


def load_domain_blocklist(path: Path | None = None) -> frozenset[str]:
    """Backward-compatible entries-only view of the loader."""
    return load_domain_blocklist_or_error(path)[0]


# Ein Hostname: Buchstaben, Ziffern, Bindestriche, mindestens ein Punkt.
# Die letzte Beschriftung muss mit einem Buchstaben beginnen — sonst waere
# "rechnung.php" ein gueltiger "Host", und der Eintrag koennte nie treffen.
_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _normalize(value: str) -> str:
    """Einen Listeneintrag auf die Form bringen, die verglichen wird.

    Zeilen aus Feeds sind nicht immer nur der Name. Gemessen an der echten
    Phishing.Database (391 879 Zeilen, 21.09.2026) kamen fuenf Formen vor, die
    keine Domain sind:

        '%20mandrillapp.com'                 URL-kodiertes Leerzeichen
        '40.70.42.104?rid=8i4dr5f'           Query ohne Schema
        'aarif.coi5sbo7qhrd6j96gk4c9ub6y0.php?rand=...'   Dateiname

    Vorher wurde nur an "://" und "/" getrennt — `?` blieb stehen, und der
    Eintrag konnte nie mit einem Host uebereinstimmen. Jetzt wird dekodiert,
    an `?#` getrennt und das Ergebnis VALIDIERT: was kein Hostname ist, kommt
    gar nicht erst in die Liste. Ein Eintrag, der nie treffen kann, ist
    schlimmer als ein fehlender — er zaehlt in der Statistik mit.
    """
    text = unquote(value).strip().lower()
    if text.startswith("*."):
        text = text[2:]
    if "://" in text:
        text = text.split("://", 1)[1]
    for trenner in ("/", "?", "#"):
        text = text.split(trenner, 1)[0]
    text = text.split("@", 1)[-1]  # user@host
    if ":" in text and not text.startswith("["):
        text = text.split(":", 1)[0]  # host:port
    text = text.strip(".")
    return text if _HOST_RE.match(text) else ""


# DNS limit: a name is at most 253 characters (RFC 1035). That cap is what
# bounds the suffix lookup below: it is quadratic in the LABEL COUNT, and the
# domain comes from attacker-controlled headers — a From: address with 40 000
# labels kept a worker busy for 9.57 s (SEC-037). At 253 characters there can
# be at most 127 labels, so the loop is bounded. Only the TOTAL length is
# capped, not each label: an over-long single label makes the name invalid but
# its parent suffix (e.g. ``evil.example``) still matches a listed domain, and
# rejecting it would lose that detection for no DoS gain.
_MAX_DOMAIN_LENGTH = 253


def is_blocked_domain(domain: str, listed: frozenset[str] | None = None) -> bool:
    """Steht diese Domain (oder eine Domain darueber) auf der Liste?

    Der Name kommt aus angreiferkontrollierten Kopfzeilen: eine kaputte Angabe
    darf keine Ausnahme werfen, sondern gilt als "nicht gelistet".
    """
    text = (domain or "").strip().lower().strip(".")
    if not text or "." not in text or len(text) > _MAX_DOMAIN_LENGTH:
        return False
    entries = listed if listed is not None else load_domain_blocklist()
    if not entries:
        return False
    # Von rechts kuerzen: mail.login.evil.tld -> login.evil.tld -> evil.tld -> tld
    parts = text.split(".")
    return any(
        ".".join(parts[start:]) in entries for start in range(len(parts) - 1)
    )


def parse_domain_list(text: str) -> list[str]:
    """Domainnamen aus einem Feed-Text ziehen (fuer den Import)."""
    found: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        domain = _normalize(line)
        if domain and "." in domain:
            found.append(domain)
    return found
