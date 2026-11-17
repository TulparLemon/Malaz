"""Offline SHA-256 blocklist (local threat intelligence).

A line-based file of known-bad SHA-256 hashes. A hit is reported as a CRITICAL
anchor indicator by the generic pipeline. The list is fully local and never
fetched over the network, matching the 100% offline design.

File format (``rules/hashes/blocklist.sha256``):
* one hex hash per line (case-insensitive; whitespace around it is ignored),
* lines starting with ``#`` and empty lines are ignored,
* an optional comment after the hash (separated by whitespace) is allowed.

New hashes can be merged from user-supplied threat feeds with
:func:`extract_sha256_hashes` + :func:`merge_blocklist` (see
``scripts/import_blocklist.py``) — still offline: importing a file the user
already has locally never touches the network.
"""

from __future__ import annotations

import logging
import re
from contextlib import suppress
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from .. import config
from .atomicwrite import path_lock, write_text_atomic

log = logging.getLogger(__name__)

_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Verankertes Muster fuer die ZEILENPRUEFUNG beim Laden. Nicht dasselbe wie
# ``_SHA256_RE`` darueber: das sucht Treffer INNERHALB einer Zeile (Feed-
# Import), dieses prueft, ob die Zeile GENAU ein Hash ist.
#
# GEMESSEN: die vorige Zeichenpruefung
# ``all(c in "0123456789abcdef" for c in token)`` kostete 0,875 s fuer 200 000
# Zeilen, das Muster 0,172 s — Faktor 5,1, bei identischem Ergebnis. Auf der
# echten URL-Liste (845 197 Eintraege) war das der Unterschied zwischen 4,4 s
# und 0,7 s Kaltstart.
# FULLMATCH, nicht match: ``[0-9a-f]{64}`` ist unverankert, und ``.match``
# verankert nur am ANFANG. Gemessen: das Token 'a'*64 + 'x' (65 Zeichen) haette
# mit ``.match`` bestanden, waehrend die vorige Bedingung
# ``len(token) == 64 and all(...)`` es ablehnt. ``.fullmatch`` ist aequivalent.
_HEX64 = re.compile(r"[0-9a-f]{64}")


class _UnreadableError(Exception):
    """Intern: Liste vorhanden, aber nicht lesbar.

    Wird NICHT nach aussen gereicht (siehe :func:`load_blocklist`) und darf
    NICHT zwischengespeichert werden — deshalb eine Ausnahme statt eines
    leeren Ergebnisses. ``lru_cache`` legt bei einer Ausnahme nichts ab,
    bei einem Rueckgabewert schon.
    """


@lru_cache(maxsize=8)
def _load_blocklist(target: Path, mtime: float, size: int) -> frozenset[str]:
    """Read and parse the blocklist file at ``target``.

    The cache key includes mtime and size, so editing the blocklist takes
    effect on the next call without a process restart (important for a
    long-running GUI); stale entries are evicted by ``maxsize``.

    Eine vorhandene, aber unlesbare Datei wirft ``_UnreadableError``, statt
    eine leere Menge zurueckzugeben. Der Grund ist gemessen und unangenehm:
    ``os.replace`` (siehe ``core/atomicwrite``) hat auf Windows einen kurzen
    Moment, in dem ein gleichzeitiges Oeffnen mit ``WinError 5`` scheitert.
    Wuerde das als leere Menge zurueckgegeben, laege sie unter dem NEUEN
    mtime/size-Schluessel im Cache — und die importierte Liste bliebe fuer den
    REST DES PROZESSES leer, ohne dass es jemand merkt. Genau der stille
    Detektionsverlust, den der atomare Schreibweg verhindern soll.
    """
    hashes: set[str] = set()
    try:
        if not target.exists():
            return frozenset()
        from .listcache import load_cached, stat_key, store_cached

        # Captured BEFORE the parse: if the list is replaced while the old
        # content is being parsed, the result must not be stored under the new
        # stat key (BUG-010); store_cached skips the store in that case.
        content_key = stat_key(target)
        cached = load_cached(target, "hashes")
        if cached is not None:
            return cached
        for raw in target.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip().lstrip("\ufeff")
            if not line or line.startswith("#"):
                continue
            token = line.split()[0].lower()
            if _HEX64.fullmatch(token):
                hashes.add(token)
    except OSError as exc:
        log.warning("Could not read hash blocklist %s: %s", target, exc)
        raise _UnreadableError(type(exc).__name__) from exc
    result = frozenset(hashes)
    with suppress(OSError):
        store_cached(target, "hashes", result, expected_key=content_key)
    return result


def _stat_key(target: Path) -> tuple[float, int]:
    """Cache key for a blocklist file: mtime and size, or (-1, -1) if absent."""
    try:
        stat = target.stat()
    except OSError:
        return -1.0, -1
    return stat.st_mtime, stat.st_size


def _configured_lists() -> tuple[Path, Path]:
    """The two blocklist files: curated (shipped) and imported (per user).

    Resolved at call time so a runtime change of either config value takes
    effect. The user list is read as well even when it does not exist — the
    loader then returns an empty set for it.
    """
    return Path(config.HASH_BLOCKLIST_FILE), Path(config.USER_HASH_BLOCKLIST_FILE)


def _read_or_empty(target: Path) -> frozenset[str]:
    """Wie der Vertrag von :func:`load_blocklist`: unlesbar = leer.

    Der Unterschied zu vorher ist nur, WANN das gilt: jetzt fuer diesen einen
    Aufruf, nicht fuer den Rest des Prozesses (siehe ``_UnreadableError``).
    ALLE Aufrufer gehen hier durch — ``load_blocklist``, ``is_listed`` und
    ``matched_source``.
    """
    try:
        return _load_blocklist(target, *_stat_key(target))
    except _UnreadableError:
        return frozenset()


def load_blocklist(path: Path | None = None) -> frozenset[str]:
    """Load the blocklist as a set of lower-case hex hashes.

    Without ``path`` the two configured lists are merged: the curated file
    shipped with the project (:data:`config.HASH_BLOCKLIST_FILE`) plus the
    imported, per-user file (:data:`config.USER_HASH_BLOCKLIST_FILE`). Those
    are kept apart so an import never modifies a git-tracked file — have a
    look at :func:`merge_blocklist`.

    Cached per concrete path and its current mtime/size. Returns an empty set
    when a file is missing or unreadable (that list then simply never
    matches).
    """
    if path is not None:
        target = Path(path)
        return _read_or_empty(target)
    curated, imported = _configured_lists()
    merged: set[str] = set()
    for target in (curated, imported):
        merged |= _read_or_empty(target)
    return frozenset(merged)


def load_blocklist_or_error(path: Path) -> tuple[frozenset[str], str]:
    """Die Liste UND ob sie gelesen werden konnte.

    ``(hashes, fehler)`` — ein leerer Fehlertext heisst: gelesen (die Liste darf
    leer sein). Ein nicht-leerer heisst: VORHANDEN, aber unlesbar, und die
    Hashes sind deshalb leer.

    WARUM DIE UNTERSCHEIDUNG NOETIG IST (Audit-Befund 7): ``load_blocklist``
    uebersetzt "unlesbar" in eine leere Menge. Wer nur die Menge ansieht, kann
    "die Liste ist leer" nicht von "die Liste liess sich nicht lesen"
    unterscheiden — und meldet dann "geprueft, kein Treffer", obwohl gar nicht
    geprueft wurde. ``docs/SECURITY_MODEL.md`` sagt ausdruecklich zu: "Ein
    fehlgeschlagener Abgleich wird NIE als sauber gewertet."
    """
    try:
        return _load_blocklist(path, *_stat_key(path)), ""
    except _UnreadableError as exc:
        return frozenset(), str(exc)


def load_blocklist_status(
    path: Path | None = None,
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Load hashes and report unreadable *existing* lists separately.

    A missing list is an empty, optional stage.  A list that exists but cannot
    be read is a failed stage: callers must surface it as incomplete instead
    of turning it into a clean negative lookup.
    """
    targets = [Path(path)] if path is not None else list(_configured_lists())
    merged: set[str] = set()
    errors: list[str] = []
    for target in targets:
        try:
            merged.update(_load_blocklist(target, *_stat_key(target)))
        except _UnreadableError as exc:
            errors.append(str(exc) or "Lesefehler")
    return frozenset(merged), tuple(dict.fromkeys(errors))


def is_listed_with_status(
    sha256_hex: str, path: Path | None = None
) -> tuple[bool, tuple[str, ...]]:
    """Membership plus unreadable-list status without copying large lists."""
    if not sha256_hex:
        return False, ()
    digest = sha256_hex.lower()
    targets = [Path(path)] if path is not None else list(_configured_lists())
    found = False
    errors: list[str] = []
    for target in targets:
        try:
            if digest in _load_blocklist(target, *_stat_key(target)):
                found = True
        except _UnreadableError as exc:
            errors.append(str(exc) or "Lesefehler")
    return found, tuple(dict.fromkeys(errors))


def is_listed(sha256_hex: str, path: Path | None = None) -> bool:
    """Return True if ``sha256_hex`` is present in the blocklist.

    Without ``path`` both configured lists are consulted with two membership
    tests instead of building the merged set — this runs once per scanned file
    and must not copy the list every time.
    """
    if not sha256_hex:
        return False
    digest = sha256_hex.lower()
    # Ueber _read_or_empty, NICHT direkt: _load_blocklist wirft bei einer
    # unlesbaren Datei (siehe dort). Diese Funktion laeuft einmal je gescanter
    # Datei — eine Ausnahme hier braeche die Hash-Stufe ab, statt wie
    # zugesagt "unlesbar = trifft nie" zu ergeben.
    if path is not None:
        return digest in _read_or_empty(Path(path))
    return any(digest in _read_or_empty(target) for target in _configured_lists())


def matched_source(sha256_hex: str) -> str:
    """Name the list that contains ``sha256_hex``, or ``""`` when none does.

    Findings must not claim a fixed path: a hit can come from the curated file
    shipped with the project or from the user's imported list, and telling the
    user the wrong one sends them looking in the wrong place. Returns a
    short human-readable label ("Projekt-Liste" / "importierte Liste").
    """
    if not sha256_hex:
        return ""
    digest = sha256_hex.lower()
    curated, imported = _configured_lists()
    if digest in _read_or_empty(curated):
        return "Projekt-Liste"
    if digest in _read_or_empty(imported):
        return "importierte Liste"
    return ""


def extract_sha256_hashes(text: str) -> list[str]:
    """Extract every well-formed SHA-256 hash from arbitrary text.

    Tolerates any feed format (CSV, TSV, ``hash description`` lines, JSON
    blobs) as long as the hash itself appears as a standalone 64-char hex
    token. Longer hex strings (SHA-1/512) do NOT match — they are not
    SHA-256 and must not pollute the list.
    """
    return [m.lower() for m in _SHA256_RE.findall(text or "")]


def merge_blocklist(
    hashes,
    source_label: str = "import",
    path: Path | None = None,
    now: datetime | None = None,
) -> int:
    """Append new hashes to the imported blocklist; return how many were added.

    Duplicates (against the existing curated and imported lists, and within
    ``hashes``) are skipped. Invalid tokens are ignored. The append is
    annotated with a comment line carrying the source label and date so the
    file's provenance stays readable. Because ``_load_blocklist`` caches on
    mtime/size, the next ``is_listed`` call sees the new entries without a
    process restart.

    Default target is :data:`config.USER_HASH_BLOCKLIST_FILE`, NOT the curated
    file: imported third-party hashes must stay out of the git-tracked tree so
    they never end up in a release (see the config comment).
    """
    target = Path(path) if path else config.USER_HASH_BLOCKLIST_FILE
    # Lese-Aendern-Schreiben unter EINEM Schloss: zwei gleichzeitige Importe
    # lesen sonst denselben Bestand und der spaetere Schreibvorgang verwirft
    # die Eintraege des anderen (verlorener Update, still).
    with path_lock(target):
        return _merge_blocklist_locked(
            hashes, source_label, target, now, merge_curated=path is None
        )


def _merge_blocklist_locked(
    hashes,
    source_label: str,
    target: Path,
    now: datetime | None,
    *,
    merge_curated: bool,
) -> int:
    """Der eigentliche Ablauf — nur unter ``path_lock(target)`` aufrufen.

    ``merge_curated`` traegt die Bedingung des Aufrufers weiter (``path is
    None``): dann wird gegen BEIDE konfigurierten Listen geprueft, sonst nur
    gegen die genannte.
    """
    # Dedupe against the union: a hash already curated in the tracked file
    # must not be duplicated into the user file.
    seen: set[str] = (
        set(load_blocklist()) if merge_curated else set(load_blocklist(target))
    )
    new: list[str] = []
    for raw in hashes:
        token = str(raw).strip().lower()
        if not _HEX64.fullmatch(token):
            continue
        if token in seen:
            continue
        seen.add(token)
        new.append(token)
    if not new:
        return 0
    stamp = (now or datetime.now(UTC).astimezone()).strftime("%Y-%m-%d")
    # Kein "a"-Anhang: das waren zwei getrennte Schreibvorgaenge, und ein
    # gleichzeitiger Scan konnte die Kommentarzeile ohne Hashes oder eine
    # halbe Zeile sehen. Stattdessen lesen, ergaenzen, atomar ersetzen — die
    # Liste ist damit zu jedem Zeitpunkt vollstaendig.
    bestand = target.read_text(encoding="utf-8") if target.exists() else ""
    # BUG-012: appending the comment to a file whose last line has no trailing
    # newline produced "H1# Import …" — the hash silently vanished from the
    # list. An empty/absent file needs no separator.
    if bestand and not bestand.endswith("\n"):
        bestand += "\n"
    write_text_atomic(
        target,
        bestand + f"# Import {source_label} {stamp}\n" + "\n".join(new) + "\n",
    )
    log.info("Blocklist: %d neue Hashes aus '%s' übernommen", len(new), source_label)
    return len(new)
