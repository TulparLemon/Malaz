"""IOC-Extraktion aus den ROHBYTES beliebiger Dateiformate.

Warum dieses Modul existiert
============================
Die Adressprüfung der Generic-Pipeline läuft nur für Texttypen: sie dekodiert
ein Sample und sucht darin nach URLs, IPs und Domains. Ein PE, ein ELF, ein
Mach-O, ein PDF, ein OLE-Container, ein Bild oder ein Archiv wurde damit GAR
NICHT auf Serveradressen geprüft — und genau dort steht die C2-Adresse: als
Zeichenkette in einer Datensektion, in den XMP-Metadaten eines PDF, in einem
Makro-Stream oder in einer angehängten Nutzlast.

Warum auf ``bytes`` statt ``str``
=================================
Die Daten sind angreiferkontrolliert und selten gültiges UTF-8. Ein
``decode(errors="replace")`` macht aus jeder ungültigen Sequenz U+FFFD und
zerstört damit genau die Trennzeichen, an denen die Muster hängen; außerdem
kostet er für ein 2-MB-Sample einen zweiten Puffer. Die Muster arbeiten deshalb
direkt auf Bytes, und nur ein TREFFER wird dekodiert.

Grenzen (die Eingabe ist angreiferkontrolliert)
===============================================
* Durchsucht werden nur die ersten ``config.BINARY_IOC_SCAN_SIZE`` Bytes.
* Höchstens ``config.BINARY_IOC_MAX_HITS`` Adressen JE ART. Der Deckel einer
  Art beendet nicht die Suche nach den anderen Arten: sonst könnte ein
  Angreifer mit 200 harmlosen URLs die Blocklist-Prüfung der eigentlichen
  C2-Domain abschalten (SEC-021). Wird eine Art gedeckelt, steht am Ende ein
  ``IOC_CAP``-Marker. Kein ``findall``: ein präpariertes File kann Millionen
  Minimal-Treffer enthalten und damit den Speicher füllen.
* Alle Quantoren sind beschränkt — ``tests/test_regex_safety.py`` prüft dieses
  Modul mit.

Bewusst NICHT angewandt wird der Entropie-Deckel des Textpfads
(``config.IOC_MAX_ENTROPY``): ein gepacktes PE hat ~7,9 bit/Byte, und genau so
ein Packer ist der Normalfall, in dem eine C2-Adresse in einer Datensektion
steht. Der Schutz gegen Falschmeldungen sitzt hier woanders — eine unbekannte
Adresse ist eine INFORMATION ohne Gewicht (siehe ``split_blocked_iocs``), nur
ein Blocklist-Treffer zählt.
"""

from __future__ import annotations

import ipaddress
import re

from .. import config
from .domain_blocklist import is_blocked_domain, load_domain_blocklist_or_error
from .hashlist import load_blocklist_or_error
from .ipblocklist import is_blocked_ip, load_ip_blocklist_or_error
from .url_reputation import local_blocklist_path, url_hash

# Adressarten, wie ``extract_binary_iocs`` sie zurückgibt (Reihenfolge = die
# Reihenfolge, in der gesucht wird).
IOC_URL = "url"
IOC_IPV4 = "ipv4"
IOC_IPV6 = "ipv6"
IOC_DOMAIN = "domain"

# Marker, wenn der Deckel für eine Adressart erreicht wurde. Der Wert nennt
# die betroffenen Arten (kommagetrennt). Bewusst KEIN Eintrag in
# ``split_blocked_iocs``-Treffern: der Marker ist keine Adresse.
IOC_CAP = "capped"

# Shared finding titles used by both generic_pipeline and pdf_pipeline
# (single source of truth for check_duplicate_logic.py).
BINARY_IOC_BLOCKED_TITLE = "Adresse im Binärinhalt steht auf der Blocklist"
BLOCKLIST_UNAVAILABLE_TITLE = "Lokale Blockliste nicht verfügbar"

# TLD-Auswahl für Domain-Treffer — bewusst DIESELBE Liste wie im Textpfad
# (pipelines/generic_pipeline.py baut sein Muster daraus auf). Zwei getrennte
# Listen liefen auseinander, und dieselbe Adresse bekäme je nach erkanntem
# Dateityp eine andere Antwort auf die Frage "ist das eine Domain?".
#
# Kleine Auswahl statt aller ~1500 TLDs: aufgenommen sind die, unter denen
# Malware real gehostet wird. Endungen, die zugleich Dateiendungen sind (zip,
# mov, app), fehlen absichtlich — "payload.zip" ist ein Dateiname, keine Domain.
#
# Die Klammer gehört dazu: ohne sie wäre die Alternation beim Zusammensetzen
# mit dem Restmuster keine Gruppe mehr, sondern würde das GANZE Muster
# verzweigen.
TLD_ALTERNATION = (
    rb"(?:com|net|org|info|xyz|top|tk|ml|ga|cf|gq|ru|cn|biz|online|site|pw|cc)"
)

# Sperrliste: NAMESPACE-URLs sind keine C2-Adressen.
#
# In Binärformaten stehen massenhaft URLs, die kein Angreifer gesetzt hat,
# sondern das Dateiformat selbst:
#   * PDF/XMP:  http://ns.adobe.com/xap/1.0/
#               http://purl.org/dc/elements/1.1/
#               http://www.w3.org/1999/02/22-rdf-syntax-ns#
#   * OOXML:    http://schemas.openxmlformats.org/wordprocessingml/2006/main
#   * .NET/XML: http://schemas.microsoft.com/... (Namespace-Attribute)
#   * SVG/DTD:  http://www.w3.org/2000/svg
# Ein Namespace ist eine IDENTIFIKATION für ein Schema, keine Adresse, die
# jemand aufruft: er steht in jedem Office-Dokument und in jedem XMP-Block.
# Ohne diesen Filter meldet jede zweite PDF "Adresse im Binärinhalt", und der
# eine echte C2-Treffer geht im Rauschen unter.
#
# Die Hersteller-/Beispielhosts darunter sind dieselben, die schon der
# Textpfad als harmlos führt (pipelines/generic_pipeline.py, ``_BENIGN_HOSTS``)
# — beide Wege sollen dieselbe Datei nicht unterschiedlich beurteilen.
NAMESPACE_HOSTS = (
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "schemas.android.com",
    "ns.adobe.com",
    "adobe.com",
    "w3.org",
    "purl.org",
    "xmlsoap.org",
    "oasis-open.org",
    "openoffice.org",
    "apache.org",
    "apple.com",
    "microsoft.com",
    "windows.com",
    "mozilla.org",
    "example.com",
    "localhost",
)

# URL: Schema plus Adresszeichen. Die Zeichenklasse enthält bewusst keine
# Leerzeichen, Anführungszeichen, spitzen Klammern und keine runden Klammern —
# sonst zöge ein Treffer die umgebende Prosa oder das halbe HTML-Attribut mit.
# ``{4,512}`` begrenzt die Länge; eine unbeschränkte Wiederholung wäre auf
# angreiferkontrollierten Bytes quadratisch.
_URL_RE = re.compile(
    rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&*+,;=%]{4,512}", re.IGNORECASE
)

# IPv4: jedes Oktett auf 0-255 begrenzt (keine führenden Nullen). Die
# Lookarounds lehnen eine Adresse ab, an die direkt eine Ziffer oder ein Punkt
# anschließt — ohne sie trifft "1.2.3.4.5" (Versionsnummern, Zufallsbytes)
# mitten in der Adresse, und die Blocklist-Prüfung bekäme eine erfundene IP.
_IPV4_RE = re.compile(
    rb"(?<![\d.])"
    rb"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    rb"(?![\d.])"
)

# IPv6: Das Muster findet nur KANDIDATEN (Hexziffern und Doppelpunkte,
# begrenzt). Ob es wirklich eine Adresse ist, entscheidet ``ipaddress`` aus der
# Standardbibliothek: die Kompressionsform "::" mit einem Regex vollständig zu
# beschreiben ist notorisch fehleranfällig, und Zufallsbytes sollen keine
# "IPv6-Adresse" erfinden. "12:34:56" (Uhrzeit) und "::" fallen so heraus,
# "2001:db8::1" bleibt.
_IPV6_CANDIDATE_RE = re.compile(rb"[0-9A-Fa-f:]{4,45}")

# Domains: Beschriftungen auf 63 Zeichen (DNS-Grenze) und höchstens 10
# Beschriftungen begrenzt; ohne bekannte TLD liefert jede Binärdatei Müll wie
# "q.RU" oder "p0g9.Pw" aus Zufallsbytes (Feldbericht zu GEN_IOC).
_DOMAIN_RE = re.compile(
    rb"(?<![A-Za-z0-9._-])"
    rb"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}"
    + TLD_ALTERNATION
    + rb"(?![A-Za-z0-9-])",
    re.IGNORECASE,
)

# Satzzeichen, die aus der UMGEBUNG stammen, nicht aus der Adresse: in einer
# Aufzählung ("..., http://x/a.php,") oder am Satzende. Sie würden sonst im
# Befund stehen UND den Hash-Vergleich mit der URL-Blocklist verhindern.
_TRAILING_PUNCTUATION = ".,;:"


def host_of_url(value: str) -> str:
    """Der Host einer URL (ohne Schema, Userinfo, Port, Pfad, Query, Fragment)."""
    rest = value.split("://", 1)[1] if "://" in value else value
    authority = rest.split("/", 1)[0].split("\\", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # Strip attacker-controlled userinfo (e.g. https://w3.org:1@evil.tld/login)
    # BEFORE splitting on ':' so a fake namespace prefix cannot spoof the host.
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):  # IPv6-Literal: [::1]:8080
        return host[1:].split("]", 1)[0].lower().rstrip(".")
    return host.split(":", 1)[0].strip().lower().rstrip(".")


def is_namespace_host(value: str) -> bool:
    """True für Format-Namespaces und Herstellerhosts (siehe NAMESPACE_HOSTS)."""
    host = host_of_url(value) if "://" in value else value.strip(".").lower()
    return host in NAMESPACE_HOSTS or any(
        host.endswith("." + listed) for listed in NAMESPACE_HOSTS
    )


# Backward-compatible private aliases for internal callers/tests.
_host_of_url = host_of_url
_is_namespace = is_namespace_host


def _valid_ipv6(candidate: bytes) -> str | None:
    """Die normalisierte Adresse, oder ``None``, wenn es keine ist."""
    # Zwei Doppelpunkte sind das billigste Vorfilter: "::" braucht sie für die
    # Kompressionsform, und eine unkomprimierte Adresse hat sieben. Damit läuft
    # ``ipaddress`` nicht für jeden Hex-Lauf im Maschinencode.
    if candidate.count(b":") < 2:
        return None
    try:
        address = ipaddress.IPv6Address(candidate.decode("ascii", "replace"))
    except ValueError:
        return None
    # "::" ist die nichtssagende Adresse (kein Host) — kein IOC.
    return None if address.is_unspecified else str(address)


def extract_binary_iocs(data: bytes) -> list[tuple[str, str]]:
    """Adressen aus den Rohbytes ziehen: ``[(art, wert), ...]``.

    ``art`` ist eine der ``IOC_*``-Konstanten. Jeder Wert kommt höchstens
    einmal vor; eine Domain, die schon als Host einer gefundenen URL dasteht,
    wird nicht erneut gemeldet (dieselbe Adresse zweimal im Befund ist
    Rauschen, und der Host steckt in der URL). Namespace-URLs werden verworfen.
    Wurde der Deckel einer Art erreicht, endet die Liste mit
    ``(IOC_CAP, "art1,art2")`` — der Marker ist keine Adresse.
    """
    cap = config.BINARY_IOC_MAX_HITS
    if not data or cap <= 0:
        return []
    scan = data[: config.BINARY_IOC_SCAN_SIZE]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    url_hosts: set[str] = set()
    counts = {IOC_URL: 0, IOC_IPV4: 0, IOC_IPV6: 0, IOC_DOMAIN: 0}
    capped: set[str] = set()

    def add(kind: str, value: str) -> None:
        """Wert einmalig aufnehmen; nach dem Deckel nur die Art markieren.

        Der Deckel gilt JE ART: eine volle URL-Liste darf die IP-/Domain-Suche
        nicht verhindern (SEC-021). ``capped`` macht die Kürzung sichtbar.
        """
        key = value.lower()
        if key in seen:
            return
        if counts[kind] >= cap:
            capped.add(kind)
            return
        seen.add(key)
        out.append((kind, value))
        counts[kind] += 1

    for match in _URL_RE.finditer(scan):
        value = match.group().decode("ascii", "replace").rstrip(_TRAILING_PUNCTUATION)
        if is_namespace_host(value):
            continue
        url_hosts.add(host_of_url(value))
        add(IOC_URL, value)

    for match in _IPV4_RE.finditer(scan):
        add(IOC_IPV4, match.group().decode("ascii"))

    for match in _IPV6_CANDIDATE_RE.finditer(scan):
        address = _valid_ipv6(match.group())
        if address is not None:
            add(IOC_IPV6, address)

    for match in _DOMAIN_RE.finditer(scan):
        value = match.group().decode("ascii", "replace")
        if value.lower() in url_hosts or is_namespace_host(value):
            continue
        add(IOC_DOMAIN, value)

    if capped:
        out.append((IOC_CAP, ",".join(sorted(capped))))
    return out


def _host_is_blocked(host: str, domains: frozenset[str], nets: list) -> bool:
    """Host gegen die Domain-Liste, ein IP-Literal gegen die IP-Netze."""
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return is_blocked_domain(host, domains)
    return bool(nets) and is_blocked_ip(str(address), nets)


def _is_blocked(
    kind: str,
    value: str,
    domains: frozenset[str],
    nets: list,
    url_hashes: frozenset[str],
) -> bool:
    """Steht dieser Wert auf einer der lokalen Listen? Rein offline."""
    if kind == IOC_URL:
        # Derselbe Hash wie beim Link-Abgleich der Mail: eine importierte
        # URL-Liste trifft damit beide Wege gleich.
        if url_hashes and url_hash(value) in url_hashes:
            return True
        # Ein Link ist auch dann ein Treffer, wenn nur sein HOST auf einer
        # Liste steht: die Domain-Liste führt die Absender-/C2-Hosts, und eine
        # gemeldete URL trägt genau diesen Host.
        return _host_is_blocked(host_of_url(value), domains, nets)
    if kind == IOC_DOMAIN:
        return _host_is_blocked(value, domains, nets)
    if kind in (IOC_IPV4, IOC_IPV6):
        return bool(nets) and is_blocked_ip(value, nets)
    return False


def split_blocked_iocs(
    hits: list[tuple[str, str]],
) -> tuple[
    list[tuple[str, str]],
    list[tuple[str, str]],
    list[tuple[str, str]],
]:
    """Split hits and return unavailable blocklist stages separately.

    Missing lists are optional and produce no error. Existing lists that
    cannot be read are reported as incomplete stages instead of being treated
    as an empty, clean lookup.
    """
    if not hits:
        return [], [], []

    # Der Cap-Marker ist keine Adresse: er darf weder als "blockiert" noch als
    # "unauffällig" gezählt werden. Sichtbar wird er über ``capped_ioc_kinds``.
    kinds = {
        kind
        for kind, _value in hits
        if kind != IOC_CAP
    }
    needs_urls = IOC_URL in kinds
    # A URL is also matched by its HOST against the domain/IP lists; a domain
    # may be an IP literal. Load only what these hit kinds can consult —
    # otherwise every PE scan pays for the 55 MB URL hash list even when the
    # file contains no URL at all.
    needs_domains = bool(kinds & {IOC_URL, IOC_DOMAIN})
    needs_nets = bool(kinds & {IOC_URL, IOC_DOMAIN, IOC_IPV4, IOC_IPV6})

    unavailable: list[tuple[str, str]] = []
    if needs_domains:
        domains, domain_error = load_domain_blocklist_or_error()
    else:
        domains, domain_error = frozenset(), ""
    if domain_error:
        unavailable.append(
            (
                "DOMAIN_BLOCKLIST_UNAVAILABLE",
                (
                    "Die lokale Domain-Blockliste konnte nicht gelesen werden; "
                    "Domain-IOCs wurden nicht vollständig geprüft."
                ),
            )
        )
    if needs_nets:
        nets, ip_error = load_ip_blocklist_or_error(config.IP_BLOCKLIST_FILE)
    else:
        nets, ip_error = [], ""
    if ip_error:
        unavailable.append(
            (
                "IP_BLOCKLIST_UNAVAILABLE",
                (
                    "Die lokale IP-Blockliste konnte nicht gelesen werden; "
                    "IP-IOCs wurden nicht vollständig geprüft."
                ),
            )
        )
    url_list = local_blocklist_path()
    url_hashes: frozenset[str]
    if not needs_urls or url_list is None:
        url_hashes = frozenset()
    else:
        url_hashes, url_error = load_blocklist_or_error(url_list)
        if url_error:
            unavailable.append(
                (
                    "URL_BLOCKLIST_UNAVAILABLE",
                    (
                        "Die lokale URL-Hash-Blockliste konnte nicht gelesen werden; "
                        "URL-IOCs wurden nicht vollständig geprüft."
                    ),
                )
            )

    blocked: list[tuple[str, str]] = []
    plain: list[tuple[str, str]] = []
    for kind, value in hits:
        if kind == IOC_CAP:
            continue
        target = blocked if _is_blocked(kind, value, domains, nets, url_hashes) else plain
        target.append((kind, value))
    return blocked, plain, unavailable


def capped_ioc_kinds(hits: list[tuple[str, str]]) -> tuple[str, ...]:
    """Die Adressarten, deren Trefferdeckel erreicht wurde (leer = keine)."""
    for kind, value in hits:
        if kind == IOC_CAP:
            return tuple(sorted(part for part in value.split(",") if part))
    return ()


def extract_binary_iocs_stream(
    source,
    chunk_size: int | None = None,
    overlap: int = 512,
    deadline: float | None = None,
) -> list[tuple[str, str]]:
    """Extract IOCs from a large path-backed file without loading it whole.

    Each chunk is scanned with the same regexes as :func:`extract_binary_iocs`;
    a small overlap keeps addresses that straddle a chunk boundary. The chunk
    size is reduced by the overlap, so ``carry + chunk`` always fits into
    ``config.BINARY_IOC_SCAN_SIZE`` — otherwise the in-memory scan cap would
    cut off exactly the overlap and the last bytes of the file would never be
    scanned (BUG-028).

    Hits and the per-type cap are global, matching the in-memory contract. A
    full type does not stop the other types (SEC-021); the result ends with an
    ``IOC_CAP`` marker when a cap was hit.
    """
    cap = config.BINARY_IOC_MAX_HITS
    if cap <= 0:
        return []
    limit = max(1024, int(config.BINARY_IOC_SCAN_SIZE))
    overlap = max(0, min(int(overlap), limit - 1024))
    step = max(1024, limit - overlap)
    requested = chunk_size if chunk_size else limit
    size = max(1024, min(int(requested), step))
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    counts = {IOC_URL: 0, IOC_IPV4: 0, IOC_IPV6: 0, IOC_DOMAIN: 0}
    capped: set[str] = set()
    carry = b""
    for chunk in source.iter_chunks(size, deadline=deadline):
        data = carry + chunk
        for kind, value in extract_binary_iocs(data):
            if kind == IOC_CAP:
                capped.update(part for part in value.split(",") if part)
                continue
            key = (kind, value)
            if key in seen:
                continue
            if counts[kind] >= cap:
                capped.add(kind)
                continue
            seen.add(key)
            out.append(key)
            counts[kind] += 1
        carry = data[-overlap:] if overlap > 0 else b""
    if capped:
        out.append((IOC_CAP, ",".join(sorted(capped))))
    return out
