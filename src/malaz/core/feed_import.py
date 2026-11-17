"""Heruntergeladene Feeds in die Datenbanken ueberfuehren.

WARUM DIESE DATEI EXISTIERT
===========================
``core/feeds.download_feed`` holt die ROHDATEI. Gelesen hat sie bis hierher
niemand: der Knopf im Fenster meldete "Gespeichert", und der naechste Scan
fand trotzdem nichts. Ein Download ohne Import ist eine Schaltflaeche, die
nichts bewirkt.

Der Import ist bewusst ein EIGENER Schritt und nicht Teil des Downloads:

* **Sichtbar.** Der Nutzer sieht, wie viele Eintraege uebernommen wurden —
  bei einem Feed, der eine leere Liste liefert, ist das die einzige Warnung,
  die es gibt.
* **Trennbar.** Ein fehlgeschlagener Import laesst die Rohdatei liegen; ein
  erneuter Versuch braucht keinen zweiten Download.
* **Pruefbar.** Der Import ist reine Umformung ohne Netz und damit im Test
  vollstaendig nachvollziehbar.

DIE VIER FORMEN
===============
Je ``Feed.kind`` gibt es genau ein Ziel, und jedes Ziel hat einen Grund:

* ``url``     -> SHA-256 der URL in die URL-Blockliste. Die URL selbst wird
                 NICHT gespeichert: derselbe Abgleich, den auch der
                 Online-Anbieter benutzt (nur der Hash verlaesst je das
                 Geraet), und eine Liste mit 800 000 Klartext-URLs waere
                 ausserdem ein Datenschutzproblem auf der Platte.
* ``domain``  -> Klartext-Domain in die Domain-Blockliste. Hier ist der
                 Klartext noetig, weil von rechts gekuerzt verglichen wird
                 (core/domain_blocklist) — ein Hash liesse das nicht zu.
* ``sha256``  -> direkt in die Datei-Hashliste.
* ``cidr``    -> in die IP-Blockliste (Spamhaus DROP), JSON wird geparst.

WAS NICHT PASSIERT
==================
Es wird nichts bewertet und nichts verworfen, was nicht eindeutig kaputt ist.
Ein Feed mit 400 000 Eintraegen hat keine "falschen" darunter, die dieses
Modul erkennen koennte — die Qualitaet ist Sache der Quelle.
"""

from __future__ import annotations

import logging
import os
import shutil
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .. import config
from .atomicwrite import path_lock, write_text_atomic
from .domain_blocklist import parse_domain_list
from .feeds import Feed, feed_dir, record_source_status
from .hashlist import extract_sha256_hashes
from .ipblocklist import parse_spamhaus_drop
from .url_reputation import url_hash

log = logging.getLogger(__name__)


@dataclass
class ImportResult:
    """Was ein Import bewirkt hat — die Zahlen, die der Nutzer sieht."""

    kind: str
    imported: int
    target: Path
    note: str = ""

    @property
    def summary(self) -> str:
        if self.imported == 0:
            return f"Keine verwertbaren Eintraege ({self.kind})"
        return f"{self.imported} Eintraege uebernommen ({self.kind})"


class ImportError_(RuntimeError):
    """Der Import ist nicht moeglich — mit deutscher Begruendung."""


def refresh_feed(
    feed: Feed,
    target_dir: Path,
    timeout: float = config.FEEDS_DOWNLOAD_TIMEOUT_SECONDS,
) -> tuple[Path, ImportResult]:
    """Holen UND uebernehmen — der Ablauf, den jeder Aufrufer braucht.

    ``timeout`` ist die Grenze JE Quelle und wird an den Download weitergereicht.
    Ohne diesen Parameter griff im GUI-Refresh immer der 60-s-Default von
    ``download_feed``, waehrend ``config.FEEDS_DOWNLOAD_TIMEOUT_SECONDS`` (120 s)
    dokumentiert, aber nirgends wirksam war (BUG-058).
    """
    try:
        if feed.kind == "url":
            ergebnis = _refresh_url_feed_streaming(feed, timeout=timeout)
        else:
            from .feeds import download_feed

            ziel = download_feed(feed, target_dir, timeout=timeout)
            ergebnis = (ziel, import_feed(feed, ziel))
    except Exception as exc:
        with suppress(Exception):
            record_source_status(
                feed, ok=False, error=f"{type(exc).__name__}: {exc}"
            )
        raise
    # Status is diagnostic; a read-only user directory must not turn a
    # successful feed import into a failed scan update.
    with suppress(Exception):
        record_source_status(feed, ok=True, imported=ergebnis[1].imported)
    return ergebnis


def _refresh_url_feed_streaming(
    feed: Feed, timeout: float = config.FEEDS_DOWNLOAD_TIMEOUT_SECONDS
) -> tuple[Path, ImportResult]:
    """URL-Feed im Vorbeistreamen hashen — ohne Rohdatei auf der Platte.

    Der Rueckgabepfad zeigt auf die BLOCKLIST, nicht auf eine Rohdatei: es gibt
    keine. Das ist die einzige Form, in der eine Liste lebender Schad-URLs
    einen Scan des Anwendersystems unbeschadet uebersteht.
    """
    from .feeds import stream_feed

    hashes: list[str] = []
    ohne_schema = 0

    def nimm(zeile: str) -> None:
        nonlocal ohne_schema
        if "://" in zeile:
            hashes.append(url_hash(zeile))
        else:
            ohne_schema += 1

    stream_feed(feed, nimm, timeout=timeout)
    ziel = Path(config.URL_BLOCKLIST_FILE)
    neu = _replace_feed_snapshot(
        feed, "url", hashes, ziel, extract_sha256_hashes, preserve_legacy=True
    )
    note = f"{ohne_schema} Zeilen ohne Schema uebersprungen" if ohne_schema else ""
    return ziel, ImportResult("Schad-URLs", neu, ziel, note)


def import_feed(feed: Feed, raw_path: Path) -> ImportResult:
    """Eine heruntergeladene Rohdatei in ihr Ziel ueberfuehren."""
    if not raw_path.exists():
        raise ImportError_(f"Rohdatei fehlt: {raw_path}")

    if feed.kind == "sha256":
        return _import_hashes(feed, raw_path)
    if feed.kind == "url":
        return _import_urls(feed, raw_path)
    if feed.kind == "domain":
        return _import_domains(feed, raw_path)
    if feed.kind == "cidr":
        return _import_cidrs(feed, raw_path)
    raise ImportError_(f"Unbekannte Feed-Art: {feed.kind!r}")


def _read(raw_path: Path) -> str:
    # Feeds sind Text in unterschiedlichen Kodierungen; "replace" statt eines
    # Fehlers, weil ein einzelnes kaputtes Byte nicht den ganzen Import
    # verhindern darf.
    return raw_path.read_text(encoding="utf-8", errors="replace")



def _replace_feed_snapshot(
    feed: Feed,
    kind: str,
    entries,
    target: Path,
    parser,
    *,
    preserve_legacy: bool = False,
) -> int:
    """Serialize snapshot replacement and aggregate rebuild per target."""
    with path_lock(target):
        count = _replace_feed_snapshot_locked(
            feed, kind, entries, target, parser, preserve_legacy
        )
    # The manifest describes the files the scanner reads. A failure here must
    # not turn a completed import into a failed one; the verify script then
    # reports "missing"/"unsigned" instead of silently claiming integrity.
    try:
        from .feed_manifest import write_manifest

        write_manifest()
    except Exception as exc:
        log.warning("Feed-Manifest nicht geschrieben: %s", exc)
    return count


def _replace_feed_snapshot_locked(
    feed: Feed,
    kind: str,
    entries,
    target: Path,
    parser,
    preserve_legacy: bool,
) -> int:
    """Replace one source snapshot while the target lock is held."""
    values = set(entries)
    source_dir = Path(feed_dir()) / "sources"
    snapshot = source_dir / f"{feed.key}.{kind}.txt"
    snapshot.parent.mkdir(parents=True, exist_ok=True)

    # Rollback: both files are backed up byte-for-byte before the rebuild. The
    # atomic writer makes a single swap all-or-nothing, but this operation
    # writes TWO files (source snapshot + aggregate). If the second write
    # fails, restoring only the first would leave a snapshot the next run
    # recombines — and the aggregate would silently differ from what the
    # scanner read before the update.
    def backup(path: Path) -> Path | None:
        if not path.exists():
            return None
        copy = path.with_name(f".{path.name}.bak-{os.getpid()}")
        shutil.copy2(path, copy)
        return copy

    def restore(path: Path, copy: Path | None, existed: bool) -> None:
        if not existed:
            with suppress(OSError):
                path.unlink()
        elif copy is not None and copy.exists():
            os.replace(copy, path)

    snapshot_existed = snapshot.exists()
    target_existed = target.exists()
    snapshot_backup = backup(snapshot)
    target_backup = backup(target)
    try:
        legacy = source_dir / f"{kind}.manual.txt"
        # Everything the PREVIOUS aggregate was built from, read BEFORE the
        # snapshot below is overwritten. Whatever the target holds that is not
        # covered here was added by hand (hashlist.merge_blocklist or
        # scripts/import_blocklist.py) and has to survive this refresh.
        #
        # The old code only copied the target into the legacy file ONCE
        # ("if not legacy.exists()"). Every manual entry arriving after the
        # first refresh was dropped by the next automatic update — the same
        # file went from red (GEN_HASH_BLOCKLIST) to green without the user
        # touching anything (BUG-008).
        covered: set[str] = set()
        if preserve_legacy:
            for path in source_dir.glob(f"*.{kind}.txt"):
                covered.update(parser(_read(path)))
        write_text_atomic(
            snapshot,
            f"# Feed-Snapshot: {feed.title}\n" + "\n".join(sorted(values)) + "\n",
        )
        manual: set[str] = set()
        if preserve_legacy:
            if target_existed:
                manual.update(set(parser(_read(target))) - covered)
            if legacy.exists():
                manual.update(parser(_read(legacy)))
            # Keep the manual snapshot in step with the target on EVERY
            # refresh; only entries already covered by a feed snapshot are
            # left out, so the aggregate never duplicates a feed entry.
            if manual or legacy.exists():
                write_text_atomic(
                    legacy,
                    "# Manuell gepflegte Eintraege (bleiben bei Feed-Updates).\n"
                    + "\n".join(sorted(manual))
                    + "\n",
                )
        combined: set[str] = set()
        for path in source_dir.glob(f"*.{kind}.txt"):
            combined.update(parser(_read(path)))
        if preserve_legacy:
            combined.update(manual)
        write_text_atomic(
            target,
            "# Automatisch aus getrennten Feed-Snapshots zusammengesetzt.\n"
            + "\n".join(sorted(combined))
            + "\n",
        )
    except BaseException:
        restore(snapshot, snapshot_backup, snapshot_existed)
        restore(target, target_backup, target_existed)
        raise
    finally:
        for copy in (snapshot_backup, target_backup):
            if copy is not None:
                with suppress(OSError):
                    copy.unlink(missing_ok=True)
    return len(values)


def _import_hashes(feed: Feed, raw_path: Path) -> ImportResult:
    """SHA-256-Feed als Snapshot aktualisieren, manuelle Altbestände behalten."""
    hashes = extract_sha256_hashes(_read(raw_path))
    ziel = Path(config.USER_HASH_BLOCKLIST_FILE)
    neu = _replace_feed_snapshot(
        feed,
        "sha256",
        hashes,
        ziel,
        extract_sha256_hashes,
        preserve_legacy=True,
    )
    return ImportResult("Datei-Hashes", neu, ziel)


def _import_urls(feed: Feed, raw_path: Path) -> ImportResult:
    """URLs hashen und in die URL-Blockliste legen."""
    zeilen = [
        line.strip()
        for line in _read(raw_path).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    hashes = [url_hash(z) for z in zeilen if "://" in z]
    verworfen = len(zeilen) - len(hashes)
    ziel = Path(config.URL_BLOCKLIST_FILE)
    neu = _replace_feed_snapshot(
        feed, "url", hashes, ziel, extract_sha256_hashes, preserve_legacy=True
    )
    note = f"{verworfen} Zeilen ohne Schema uebersprungen" if verworfen else ""
    return ImportResult("Schad-URLs", neu, ziel, note)


def _import_domains(feed: Feed, raw_path: Path) -> ImportResult:
    """Domains aus einem getrennten Feed-Snapshot aktualisieren."""
    domains = parse_domain_list(_read(raw_path))
    ziel = Path(config.DOMAIN_BLOCKLIST_FILE)
    neu = _replace_feed_snapshot(
        feed, "domain", domains, ziel, parse_domain_list, preserve_legacy=True
    )
    return ImportResult("Absender-Domains", neu, ziel)


def _import_cidrs(feed: Feed, raw_path: Path) -> ImportResult:
    """Spamhaus-DROP-Netze ablegen.

    Gespeichert wird das GEPARSTE Format (eine CIDR pro Zeile), nicht das
    JSON: die Datei wird bei jedem Scan gelesen, und JSON mit
    Kommentarzeilen zu parsen ist teurer als eine Zeile zu splitten. Der
    Parser liegt trotzdem in ``core/ipblocklist`` — dort wird auch das
    Original gelesen, falls ein Nutzer die Rohdatei selbst ablegt.
    """
    netze = parse_spamhaus_drop(_read(raw_path))
    if not netze:
        raise ImportError_(
            "Die Datei enthielt keine Netze — Format unbekannt oder leer"
        )
    ziel = Path(config.IP_BLOCKLIST_FILE)
    with path_lock(ziel):
        return _write_cidrs(feed, ziel, netze)


def _write_cidrs(feed: Feed, ziel: Path, netze: list) -> ImportResult:
    """Nur unter ``path_lock(ziel)`` aufrufen (Lese-Aendern-Schreiben)."""
    # Atomar, aus demselben Grund wie bei den Domains.
    write_text_atomic(
        ziel,
        "# Boesartige IP-Netze. Eine CIDR pro Zeile.\n"
        f"# Quelle: {feed.title}\n"
        + "\n".join(str(n) for n in netze)
        + "\n",
    )
    return ImportResult("IP-Netze", len(netze), ziel)
