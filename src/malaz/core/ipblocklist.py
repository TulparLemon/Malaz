"""Lokale IP-Blockliste (Spamhaus DROP) — Auswertung rein offline.

Eine IP-Adresse aus einer Kopfzeile (``Received:``, ``X-Originating-IP``, …)
ist angreiferkontrolliert. Deshalb gilt hier durchgaengig: eine unlesbare
Eingabe ist "nicht blockiert", niemals eine Ausnahme — ein Absturz waere sonst
ein Denial-of-Service gegen den Scan selbst.

Die Datei ist eine JSON-Zeile pro Netz, dazu Kommentarzeilen, die mit ``;``
beginnen::

    ; Spamhaus DROP v4
    {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}

Der Download laeuft ueber ``core.feeds`` und nur auf ausdruecklichen Klick des
Nutzers; dieses Modul liest ausschliesslich, was schon auf der Platte liegt.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from bisect import bisect_right
from pathlib import Path

log = logging.getLogger(__name__)

# Adressfamilien im Schluesselraum trennen: v4-Adressen liegen unter 2**128,
# v6-Adressen darueber. Ohne die Trennung fiele z. B. ::1 (Zahlenwert 1) in den
# Bereich der v4-Netze und gaelte als "liegt in 0.0.0.0/8".
_V6_OFFSET = 1 << 128


def _key(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
    """Bisektionsschluessel einer Adresse (siehe ``_V6_OFFSET``)."""
    return int(address) + (0 if address.version == 4 else _V6_OFFSET)


def _index(nets) -> tuple[list[int], list[int]]:
    """Startadressen und Praefix-Maximum der Netzenden zu ``nets``.

    ``ends[i]`` ist das groesste Netzende unter ``nets[0..i]``. Eine Adresse
    ist genau dann blockiert, wenn es ein Netz mit Start <= Adresse und
    Ende >= Adresse gibt; mit dem Praefix-Maximum genuegt dafuer ein zweiter
    Bisektionsschritt. Der naheliegende Rueckwaertslauf ab dem Bisektionspunkt
    waere dagegen linear: die DROP-Liste hat ~1700 Eintraege und wird fuer jede
    IP aus jeder Kopfzeile befragt.
    """
    starts: list[int] = []
    max_ends: list[int] = []
    largest = -1
    for net in nets:
        starts.append(_key(net.network_address))
        largest = max(largest, _key(net.broadcast_address))
        max_ends.append(largest)
    return starts, max_ends


class _NetIndex(list):
    """Nach Startadresse sortierte Netze samt vorberechneter Bisektionshilfen.

    Die Liste selbst ist der Vertrag (``list`` von ``ipaddress``-Netzen); die
    beiden Zusatzarrays sind reine Abkuerzung, damit :func:`is_blocked_ip`
    nicht bei jedem Aufruf neu rechnen muss.
    """

    __slots__ = ("_max_ends", "_starts")

    def __init__(self, nets) -> None:
        super().__init__(nets)
        self._starts, self._max_ends = _index(self)


def _parse_line(line: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Ein Netz aus einer Zeile, oder ``None``, wenn die Zeile keins ist.

    Kommentar- und Leerzeilen sowie kaputte JSON-Zeilen werden verworfen statt
    zu werfen: die Datei kommt aus dem Netz und darf den Scan nie anhalten.
    """
    line = line.strip().lstrip("\ufeff")
    # ";" ist die Kommentarform von Spamhaus, "#" die von Malaz selbst (siehe
    # core/feed_import). Beide muessen hier stehen, sonst versucht der Parser
    # eine Ueberschrift als Netz zu lesen.
    if not line or line.startswith((";", "#")):
        return None

    # ZWEI FORMATE, und das ist Absicht: der Downloader legt die Rohdatei von
    # Spamhaus ab (JSON, eine Zeile je Netz), der Import schreibt das geparste
    # Ergebnis als reine CIDR-Zeilen daneben. Wer nur eines davon liest, findet
    # die importierte Liste NICHT — gemessen: 1715 Netze importiert, 0 geladen,
    # weil der Parser ausschliesslich JSON kannte.
    cidr = ""
    if line.startswith("{"):
        try:
            record = json.loads(line)
        except ValueError:
            return None
        if not isinstance(record, dict):
            return None
        wert = record.get("cidr")
        if isinstance(wert, str):
            cidr = wert
    else:
        cidr = line
    if not cidr:
        return None
    try:
        # strict=False: ein Eintrag wie 1.2.3.4/24 meint das umfassende Netz.
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def parse_spamhaus_drop(text: str) -> list:
    """Zerlegt den Spamhaus-DROP-Text in eine sortierte Liste von Netzen.

    Sortiert wird nach Startadresse (v4 vor v6, siehe ``_V6_OFFSET``), weil
    :func:`is_blocked_ip` genau darauf bisektiert.
    """
    nets = {net for net in (_parse_line(line) for line in (text or "").splitlines()) if net is not None}
    return _NetIndex(sorted(nets, key=lambda net: _key(net.network_address)))


# Cache nach (mtime, Groesse): dieselbe Listendatei wird fuer JEDE gepruefte
# Mail gelesen, und bei ~1700 Netzen ist das Parsen nicht umsonst. Das Muster
# ist dasselbe wie in core/hashlist und core/domain_blocklist — ein Import
# frischer Daten wird damit ohne Neustart wirksam.
_NET_CACHE: dict[tuple[float, int, str], list] = {}


def load_ip_blocklist_or_error(path: Path) -> tuple[list, str]:
    """Return networks and a safe error label for an existing unreadable list.

    A missing list is an optional empty list.  An existing list that cannot be
    read is a failed threat-intel stage and must reach the result as such.
    """
    ziel = Path(path)
    try:
        stat = ziel.stat()
    except (FileNotFoundError, NotADirectoryError):
        return [], ""
    except OSError as exc:
        # Existing but untestable (permissions, network share, replace window):
        # this is a failed threat-intel stage, not "list absent".
        return [], type(exc).__name__
    schluessel = (stat.st_mtime, stat.st_size, str(ziel))
    zwischengespeichert = _NET_CACHE.get(schluessel)
    if zwischengespeichert is not None:
        return zwischengespeichert, ""

    try:
        text = ziel.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        # Do not put the local path into an Indicator or report. The privacy
        # filter protects the diagnostic log; the result gets only the class.
        log.warning("IP-Blockliste nicht lesbar (%s): %s", ziel, exc)
        return [], type(exc).__name__
    netze = parse_spamhaus_drop(text)
    _NET_CACHE.clear()
    _NET_CACHE[schluessel] = netze
    return netze, ""


def load_ip_blocklist(path: Path) -> list:
    """Backward-compatible entries-only view of the loader."""
    return load_ip_blocklist_or_error(path)[0]


def is_blocked_ip(ip: str, nets: list) -> bool:
    """True, wenn ``ip`` in einem der Netze liegt; ungueltige IP -> False.

    Bisektiert auf den Startadressen (``O(log n)``); ein Netz kann eine
    Adresse enthalten, deren Startadresse davor liegt (``10.0.0.0/8`` fuer
    ``10.1.2.3``, das hinter einem spaeter beginnenden ``10.1.2.0/24``
    einsortiert ist) — genau dieser Rueckwaertslauf steckt im Praefix-Maximum
    der Enden, siehe :func:`_index`.
    """
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False

    if isinstance(nets, _NetIndex):
        starts, max_ends = nets._starts, nets._max_ends
    else:
        # Handgebaute Liste (z. B. im Test): Hilfsarrays einmal aufbauen.
        starts, max_ends = _index(nets)

    value = _key(address)
    position = bisect_right(starts, value) - 1
    return position >= 0 and max_ends[position] >= value
