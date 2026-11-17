"""Nachladbare Datenbanken (Feed-Registry + Downloader).

WARUM DIESES MODUL EXISTIERT
============================
Malaz arbeitet im Betrieb zu 100 % offline: kein Hintergrundabruf, keine
Telemetrie, kein Kontakt zu Dritten waehrend eines Scans. Genau deshalb darf
das Programm nicht selbst entscheiden, wann es online geht. Diese Datei
liefert nur die eine Haelfte davon: eine feste Liste bekannter Quellen und
eine Funktion, die GENAU EINE davon herunterlaedt — aufgerufen ausschliesslich
aus einer Nutzeraktion (GUI-Knopf, Skript). Wer sie nicht aufruft, loest
keinen einzigen Netzwerkzugriff aus.

Die Registry ist bewusst eine Konstante im Code und keine Konfigurationsdatei:
jede hier eingetragene URL ist damit ein Stueck Angriffsflaeche, das im
Review sichtbar ist. Nutzereingaben erreichen das Netz nie.

LIZENZEN
========
Die Quellen sind unterschiedlich lizenzierbar, und der Unterschied ist keine
Fussnote, sondern eine Vertragsbedingung. Sie gilt UNABHAENGIG davon, unter
welcher Lizenz Malaz selbst steht — die Bedingungen der Quelle binden den
Weitergebenden, nicht die eigene Lizenz:

* abuse.ch (URLhaus, MalwareBazaar) und Spamhaus DROP erlauben die NUTZUNG,
  verbieten aber die Weitergabe. Solche Dateien duerfen deshalb niemals im
  Repository oder in einem Release landen — sie gehoeren ausschliesslich in
  das Nutzerverzeichnis und werden nur zur Laufzeit gelesen.
* Phishing.Database (mitchellkrogza) steht unter MIT und duerfte gebuendelt
  werden. Malaz nutzt trotzdem denselben Weg, damit es nur EINEN Pfad fuer
  Fremddaten gibt — ein zweiter (gebundelter) Weg waere eine zweite Stelle,
  an der Lizenzen geprueft werden muessten.

Jeder Feed traegt seinen Hinweis in :attr:`Feed.license_note`, damit die GUI
ihn am Knopf anzeigen kann, bevor der Nutzer klickt.

WAS HIER NICHT PASSIERT
=======================
Der Downloader prueft den INHALT nicht und importiert nichts. Er legt nur die
Rohdatei ab; das Auswerten (Parsen, Zusammenfuehren, Deduplizieren) ist eine
getrennte Aufgabe, damit ein kaputter Feed nie einen laufenden Scan-Pfad
beeinflusst.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from .atomicwrite import write_text_atomic

# Obergrenze je Feed.
#
# Die groesste Quelle (MalwareBazaar, URLhaus) liegt real bei rund 1 MB; 80 MB
# sind also mehr als das Fuenfzigfache des Erwarteten. Die Grenze ist keine
# Groessenschaetzung, sondern ein Notausstieg: antwortet ein Server mit einem
# unbegrenzten Strom (Fehlkonfiguration, endloser Redirect-Zirkel, oder ein
# untergeschobener Endpunkt), darf der Download nicht den Datentraeger
# fuellen. Geprueft wird waehrend des Lesens, nicht erst am Ende — sonst
# laege die Datei bereits vollstaendig auf der Platte, wenn der Deckel greift.
MAX_FEED_BYTES = 80 * 1024 * 1024

# 64 KiB: gross genug, damit der Syscall-Aufwand verschwindet, klein genug,
# damit die Grenze oben auch bei einem Server ohne Content-Length greift.
_READ_CHUNK_BYTES = 64 * 1024

# Endung der fertigen Datei und Zwischenstand waehrend des Schreibens.
_SUFFIX = ".feed"
_PART_SUFFIX = ".feed.part"

# Ohne User-Agent antworten einige der Quellen mit HTTP 403.
_USER_AGENT = "Malaz feed download"


class FeedError(RuntimeError):
    """Jeder fehlgeschlagene Feed-Download — mit deutscher Meldung fuer die GUI.

    Eine eigene Ausnahme statt ``OSError``/``URLError``, weil der Aufrufer
    (GUI-Knopf) nur EINEN Fehlerfall kennt: "hat nicht geklappt, und zwar aus
    diesem Grund". So muss die Oberflaeche nicht die Ausnahmetypen von
    ``urllib`` kennen.
    """


def _validate_response_url(feed: Feed, response) -> None:
    """Reject a redirect that leaves the registry's HTTPS origin."""
    geturl = getattr(response, "geturl", None)
    final = geturl() if callable(geturl) else feed.url
    expected = urlparse(feed.url)
    actual = urlparse(final or feed.url)
    if actual.scheme != "https" or (actual.hostname or "").lower() != (
        expected.hostname or ""
    ).lower():
        raise FeedError(f"Feed-Weiterleitung unerlaubt: {feed.key}")


@dataclass(frozen=True)
class Feed:
    """Eine nachladbare Quelle. ``frozen``: die Registry ist eine Konstante."""

    key: str  # stabiler Schluessel, zugleich Dateiname (<key>.feed)
    title: str  # deutscher Knopftext
    purpose: str  # ein Satz: wofuer der Feed gut ist
    url: str  # Download-Adresse (immer https)
    size_hint: str  # ungefaehre Groesse, damit der Nutzer den Aufwand sieht
    license_note: str  # Lizenz-/Weitergabehinweis fuer die Oberflaeche
    kind: str  # "url" | "domain" | "sha256" | "cidr"


FEEDS: tuple[Feed, ...] = (
    Feed(
        key="urlhaus",
        title="Boesartige Links (URLhaus)",
        purpose=(
            "Bekannte Verteilerseiten fuer Schadsoftware-Links; gleicht die "
            "Links aus Mails ab."
        ),
        url="https://urlhaus.abuse.ch/downloads/text/",
        size_hint="1 MB",
        license_note="Nutzung nur lokal, keine Weitergabe (abuse.ch)",
        kind="url",
    ),
    Feed(
        key="phishing_links",
        title="Phishing-Links (Phishing.Database)",
        purpose="Aktive Phishing-Adressen zum Abgleich der Links in einer Mail.",
        url=(
            "https://raw.githubusercontent.com/mitchellkrogza/"
            "Phishing.Database/master/phishing-links-ACTIVE.txt"
        ),
        size_hint="0,5 MB",
        license_note="MIT — Weitergabe erlaubt",
        kind="url",
    ),
    Feed(
        key="phishing_domains",
        title="Phishing-Domains (Phishing.Database)",
        purpose=(
            "Aktive Phishing-Domains; gleicht die Domain von Absender und "
            "Links ab, auch wenn der genaue Pfad unbekannt ist."
        ),
        url=(
            "https://raw.githubusercontent.com/mitchellkrogza/"
            "Phishing.Database/master/phishing-domains-ACTIVE.txt"
        ),
        size_hint="0,5 MB",
        license_note="MIT — Weitergabe erlaubt",
        kind="domain",
    ),
    Feed(
        key="malware_hashes_recent",
        title="Malware-Hashes der letzten 48 h (MalwareBazaar)",
        purpose=(
            "SHA-256 frischer Schadproben; erkennt Anhaenge, die aeltere "
            "Signaturen noch nicht kennen."
        ),
        url="https://bazaar.abuse.ch/export/txt/sha256/recent/",
        size_hint="0,1 MB",
        license_note="Nutzung nur lokal, keine Weitergabe (abuse.ch)",
        kind="sha256",
    ),
    Feed(
        key="spamhaus_drop",
        title="Boesartige IP-Netze (Spamhaus DROP)",
        purpose=(
            "Netze, aus denen Spam und Angriffe stammen; gleicht die "
            "Absender-IP einer Mail ab."
        ),
        url="https://www.spamhaus.org/drop/drop_v4.json",
        size_hint="0,1 MB",
        license_note="Kostenlos; Namensnennung Spamhaus Project noetig",
        kind="cidr",
    ),
)


def download_feed(feed: Feed, target_dir: Path, timeout: float = 60.0) -> Path:
    """Laedt EINEN Feed herunter und legt die Rohdatei ab. Netz! Nur auf Klick.

    Schreibt ``<key>.feed`` nach ``target_dir`` und gibt diesen Pfad zurueck.

    Der Download laeuft in zwei Schritten: erst eine ``.part``-Datei, dann
    Umbenennen. Der Grund ist nicht Kosmetik — ein abgebrochener Download
    (Netzabbruch, Zeitueberschreitung, voller Datentraeger) wuerde sonst eine
    halbe Datei hinterlassen, die beim naechsten Start als gueltiger Feed
    gelesen wird. Abgeschnittene Feed-Dateien sind besonders unangenehm, weil
    sie nicht auffallen: die Auswertung findet einfach weniger Treffer, und ein
    fehlender Treffer sieht aus wie eine saubere Datei.

    Bei JEDEM Fehlschlag wird nichts geschrieben: die ``.part``-Datei wird
    entfernt, und ein bereits vorhandener, frueher geladener Feed bleibt
    unangetastet. Ein misslungener Nachladeversuch darf die zuletzt gute
    Datenbank nicht zerstoeren.
    """
    # Die Registry ist fest und quellenkontrolliert; die Pruefung steht hier
    # trotzdem, weil ein kuenftiger Eintrag mit "http://" sonst stillschweigend
    # unverschluesselt geladen wuerde — und ein Feed, der unbemerkt austauschbar
    # ist, waere schlimmer als ein fehlender.
    if not feed.url.startswith("https://"):
        raise FeedError(f"Feed-Adresse muss https sein: {feed.key}")

    directory = Path(target_dir)
    target = directory / f"{feed.key}{_SUFFIX}"
    # SEC-011: one shared ``<key>.feed.part`` let two concurrent downloads
    # write into the same inode. The final rename then published a file that
    # was neither payload — and it was signed as a valid feed. A per-download
    # name keeps each byte stream private; os.replace stays atomic and the
    # last completed download wins with a complete file.
    part = directory / f"{feed.key}.{uuid.uuid4().hex}{_PART_SUFFIX}"
    written = 0

    try:
        directory.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(feed.url, headers={"User-Agent": _USER_AGENT})
        # urlopen auf eine feste Registry-Adresse: keine Nutzereingabe erreicht
        # hier das Netz (siehe Modul-Docstring).
        #
        # nosec B310: Bandit warnt vor file:// ueber urlopen. Hier ist das
        # ausgeschlossen — die Adresse stammt aus FEEDS, einer eingefrorenen
        # Konstante, und jede ist https (nachgeprueft: alle fuenf). Kein
        # Nutzerpfad fuehrt hierher.
        with (
            urllib.request.urlopen(request, timeout=timeout) as response,  # nosec B310
            part.open("wb") as handle,
        ):
            _validate_response_url(feed, response)
            while chunk := response.read(_READ_CHUNK_BYTES):
                written += len(chunk)
                if written > MAX_FEED_BYTES:
                    raise FeedError(
                        f"Feed ist groesser als {MAX_FEED_BYTES // (1024 * 1024)} MB, "
                        f"Download abgebrochen: {feed.title}"
                    )
                handle.write(chunk)
        # Erst jetzt, wo die Datei vollstaendig und geschlossen ist, wird sie
        # sichtbar. os.replace ist auf demselben Datentraeger atomar.
        os.replace(part, target)
    except FeedError:
        part.unlink(missing_ok=True)
        raise
    except urllib.error.HTTPError as exc:
        part.unlink(missing_ok=True)
        raise FeedError(
            f"Server hat den Download abgelehnt (HTTP {exc.code}): {feed.title}"
        ) from exc
    except urllib.error.URLError as exc:
        part.unlink(missing_ok=True)
        raise FeedError(
            f"Keine Verbindung zum Server ({exc.reason}): {feed.title}"
        ) from exc
    except TimeoutError as exc:
        part.unlink(missing_ok=True)
        raise FeedError(
            f"Zeitueberschreitung nach {timeout:.0f} Sekunden: {feed.title}"
        ) from exc
    except OSError as exc:
        part.unlink(missing_ok=True)
        raise FeedError(f"Feed konnte nicht gespeichert werden: {feed.title}") from exc

    return target




# -- Zustand und Faelligkeit ------------------------------------------------- #
#
# Getrennt vom Download, damit die Oberflaeche den Stand OHNE Netz anzeigen
# kann: die Anzeige laeuft beim Aufbau des Fensters — ein Download nie.
#
# Gemessen wird die IMPORTIERTE LISTE, nicht die Rohdatei des Downloads. Das
# war ein Denkfehler in der ersten Fassung: wer die Listen per
# ``import_blocklist.py`` aus eigenen Dateien gefuellt hat, hat gar keine
# Rohdateien — die Anzeige haette "nie geladen" behauptet, obwohl 1,2
# Millionen Eintraege aktiv sind, und die Auffrischung haette bei jedem Start
# erneut 65 MB geholt. Gelesen wird beim Scannen die Liste; also ist SIE der
# maszgebliche Stand.


@dataclass(frozen=True)
class ListState:
    """Eine importierte Blockliste — das, was der Scanner wirklich liest."""

    name: str
    path: Path
    age_days: int | None  # None = Datei fehlt
    size_bytes: int

    @property
    def exists(self) -> bool:
        return self.age_days is not None

    def is_fresh(self, min_age_days: int) -> bool:
        """Wurde innerhalb der Toleranz geschrieben?"""
        return self.age_days is not None and self.age_days < min_age_days


def list_targets() -> list[tuple[str, Path]]:
    """Die vier Blocklisten mit ihrem Anzeigenamen.

    Die Zuordnung Quelle->Ziel steht in ``feed_import``; hier geht es nur um
    die Ziele selbst, weil sie den Stand ausmachen.
    """
    from .. import config

    return [
        ("Datei-Hashes", Path(config.USER_HASH_BLOCKLIST_FILE)),
        ("URL-Hashes", Path(config.URL_BLOCKLIST_FILE)),
        ("Domains", Path(config.DOMAIN_BLOCKLIST_FILE)),
        ("IP-Netze", Path(config.IP_BLOCKLIST_FILE)),
    ]


def feed_dir() -> Path:
    """Ablage der Rohdateien — neben den importierten Blocklisten.

    Dieselbe Regel wie ``config.USER_HASH_BLOCKLIST_FILE``: die Rohdaten sind
    Nutzerzustand und liegen deshalb NICHT im Projektbaum, wo sie in ein
    Release gerieten.
    """
    from .. import config

    return Path(config.USER_HASH_BLOCKLIST_FILE).parent / "feeds"


def source_status_path() -> Path:
    """Return the per-source status manifest in user data."""
    return feed_dir() / "source-status.json"


def source_statuses() -> dict[str, dict[str, object]]:
    """Read source statuses; a damaged manifest is treated as unknown."""
    path = source_status_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def record_source_status(
    feed: Feed,
    *,
    ok: bool,
    imported: int = 0,
    error: str = "",
) -> None:
    """Persist one source's outcome so another source cannot mask its failure."""
    statuses = source_statuses()
    current = statuses.get(feed.key)
    if not isinstance(current, dict):
        current = {}
    now = datetime.now(UTC).isoformat()
    statuses[feed.key] = {
        "title": feed.title,
        "last_success": now if ok else current.get("last_success", ""),
        "last_attempt": now,
        "last_error": "" if ok else (error or "unbekannter Fehler")[:500],
        "entry_count": imported if ok else current.get("entry_count", 0),
    }
    path = source_status_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(path, json.dumps(statuses, ensure_ascii=False, indent=2) + "\n")


def list_states(now: datetime | None = None) -> list[ListState]:
    """Der lokale Stand der Blocklisten. Kein Netz, kein Zaehlen von Zeilen.

    Bewusst nur ``stat``: die groesste Liste hat 845 000 Zeilen und 55 MB —
    sie beim Aufbau des Fensters durchzuzaehlen wuerde den Start verzoegern,
    nur um eine Zahl im Tooltip zu zeigen. Groesse und Alter sagen dasselbe
    auf einen Blick.
    """
    if now is None:
        now = datetime.now(UTC)

    zustaende: list[ListState] = []
    for name, pfad in list_targets():
        try:
            stat = pfad.stat()
        except OSError:
            zustaende.append(ListState(name=name, path=pfad, age_days=None, size_bytes=0))
            continue
        # Wie analysis.clamav_status.db_age_days: UTC, damit das Alter nicht
        # von der Zeitzone des Rechners abhaengt.
        geaendert = datetime.fromtimestamp(stat.st_mtime, UTC)
        alter = max(0, (now - geaendert).days)
        zustaende.append(
            ListState(name=name, path=pfad, age_days=alter, size_bytes=stat.st_size)
        )
    return zustaende


def refresh_due(
    *,
    min_age_days: int | None = None,
    enabled: bool | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Entscheidet, ob beim Start nachgeladen wird. ``(faellig, Begruendung)``.

    Reine Entscheidung: kein Netz, keine Nebenwirkung. Dieselbe Trennung wie
    ``analysis.clamav_update.update_due`` — der Startausloeser bleibt duenn und
    diese Regel bleibt einzeln pruefbar.

    * Haken aus -> nicht faellig,
    * keine einzige Liste vorhanden -> FAELLIG (dann ist die Einrichtung leer),
    * alle Listen juenger als ``min_age_days`` -> nicht faellig,
    * sonst -> FAELLIG mit dem Alter der aeltesten Liste.

    Die Begruendung ist nutzersichtbar (Statuszeile), deutsch wie der Rest
    der Oberflaeche.
    """
    from .. import config

    if enabled is None:
        enabled = config.FEEDS_AUTO_UPDATE_ENABLED_DEFAULT
    if not enabled:
        return False, "Automatisches Nachladen ist aus."
    if min_age_days is None:
        min_age_days = config.FEEDS_AUTO_UPDATE_MIN_AGE_DAYS

    zustaende = list_states(now)
    failed_sources = [
        key for key, value in source_statuses().items()
        if isinstance(value, dict) and value.get("last_error")
    ]
    if failed_sources:
        return True, (
            f"{len(failed_sources)} Feed-Quelle(n) fehlgeschlagen: "
            f"{', '.join(failed_sources[:3])}."
        )
    if not any(z.exists for z in zustaende):
        return True, "Noch keine Liste vorhanden — wird nachgeholt."

    # Maszgeblich ist die AELTESTE Liste: eine frische neben einer vergessenen
    # hilft nicht, die vergessene ist die Luecke.
    veraltet = [z for z in zustaende if not z.is_fresh(min_age_days)]
    if not veraltet:
        juengste = min((z.age_days or 0) for z in zustaende)
        tage = "Tag" if juengste == 1 else "Tage"
        return False, f"Alle Listen sind aktuell (juengste {juengste} {tage} alt)."

    fehlend = [z for z in veraltet if not z.exists]
    alt = [z for z in veraltet if z.exists]
    teile = []
    if alt:
        teile.append(f"aelteste {max(z.age_days or 0 for z in alt)} Tage alt")
    if fehlend:
        teile.append(f"{len(fehlend)} fehlen ganz")
    return True, "Listen veraltet (" + ", ".join(teile) + ") — werden nachgeladen."


def state_badge(min_age_days: int, now: datetime | None = None) -> tuple[str, str, str]:
    """Die Anzeige des Stands als ``(Name, Zustand, Tooltip)``.

    Dieselbe Form wie ``gui.main_window._engine_badges``: der Name steht in der
    Leiste, der Zustand faerbt ihn, der Tooltip nennt jede Liste einzeln.
    Zustaende: ``ok`` (alles frisch), ``warn`` (etwas fehlt oder ist alt),
    ``off`` (nichts vorhanden).
    """
    zustaende = list_states(now)
    geladen = [z for z in zustaende if z.exists]
    if not geladen:
        return (
            "Datenbanken",
            "off",
            "Keine Blockliste vorhanden.\n\n"
            + "\n".join(f"• {z.name}: fehlt" for z in zustaende),
        )

    veraltet = [z for z in zustaende if not z.is_fresh(min_age_days)]
    failed_sources = [
        (key, value)
        for key, value in source_statuses().items()
        if isinstance(value, dict) and value.get("last_error")
    ]
    zustand = "warn" if veraltet or failed_sources else "ok"

    zeilen = []
    for z in zustaende:
        if not z.exists:
            zeilen.append(f"• {z.name}: fehlt")
        else:
            tage = "Tag" if z.age_days == 1 else "Tage"
            mb = z.size_bytes / 1024 / 1024
            zeilen.append(f"• {z.name}: {z.age_days} {tage} alt ({mb:.1f} MB)")
    for key, value in failed_sources:
        zeilen.append(f"• Quelle {key}: FEHLGESCHLAGEN — {str(value['last_error'])[:160]}")

    kopf = f"{len(geladen)} von {len(zustaende)} Listen vorhanden"
    if failed_sources:
        kopf += f", {len(failed_sources)} Quelle(n) fehlgeschlagen"
    if veraltet:
        kopf += f", {len(veraltet)} veraltet"
    return "Datenbanken", zustand, kopf + "\n\n" + "\n".join(zeilen)


def stream_feed(feed: Feed, on_line, timeout: float = 120.0) -> int:
    """Den Feed lesen, OHNE ihn abzulegen. Gibt die Zahl der Zeilen zurueck.

    WARUM ES DIESEN WEG GIBT
    ========================
    ``download_feed`` schreibt die Rohdatei auf die Platte. Fuer die
    URL-Feeds ist das ein Problem, das der Nutzer real erlebt hat: die
    URLhaus-Liste enthaelt tausende LEBENDE Schad-URLs, und CyNet blockierte
    die abgelegte Datei als "Malicious File Dumped on the Disk"
    (``urlhaus.feed.part``). Der Nutzer musste seine Schutz-Konfiguration
    anfassen, um Malaz zu benutzen — und das ist ausdruecklich nicht gewollt.

    Malaz braucht von diesen Feeds ohnehin nur die SHA-256-Werte. Wird schon
    beim Lesen gehasht, liegt die Schadliste nie auf der Platte: was nicht
    existiert, kann kein EDR blockieren.

    ``on_line`` bekommt jede Nutzzeile (ohne Kommentare und Leerzeilen).
    Dieselbe Groessengrenze wie beim Download; ohne Datei gibt es auch keine
    halbe Datei, die als gueltiger Feed gelesen werden koennte.
    """
    if not feed.url.startswith("https://"):
        raise FeedError(f"Feed-Adresse muss https sein: {feed.key}")

    gelesen = 0
    zeilen = 0
    rest = b""
    try:
        request = urllib.request.Request(feed.url, headers={"User-Agent": _USER_AGENT})
        # nosec B310: siehe download_feed — die Adresse kommt aus der
        # eingefrorenen FEEDS-Registry und ist https; die Pruefung steht
        # ausserdem direkt darueber.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            _validate_response_url(feed, response)
            while chunk := response.read(_READ_CHUNK_BYTES):
                gelesen += len(chunk)
                if gelesen > MAX_FEED_BYTES:
                    raise FeedError(
                        f"Feed ist groesser als {MAX_FEED_BYTES // (1024 * 1024)} MB, "
                        f"Abruf abgebrochen: {feed.title}"
                    )
                rest += chunk
                *vollstaendig, rest = rest.split(b"\n")
                for roh in vollstaendig:
                    zeile = roh.decode("utf-8", "replace").strip()
                    if not zeile or zeile.startswith("#"):
                        continue
                    zeilen += 1
                    on_line(zeile)
            # Die letzte Zeile hat keinen Zeilenumbruch abbekommen.
            letzte = rest.decode("utf-8", "replace").strip()
            if letzte and not letzte.startswith("#"):
                zeilen += 1
                on_line(letzte)
    except FeedError:
        raise
    except urllib.error.HTTPError as exc:
        raise FeedError(
            f"Server hat den Abruf abgelehnt (HTTP {exc.code}): {feed.title}"
        ) from exc
    except urllib.error.URLError as exc:
        raise FeedError(f"Keine Verbindung zum Server ({exc.reason}): {feed.title}") from exc
    except TimeoutError as exc:
        raise FeedError(
            f"Zeitueberschreitung nach {timeout:.0f} Sekunden: {feed.title}"
        ) from exc
    return zeilen
