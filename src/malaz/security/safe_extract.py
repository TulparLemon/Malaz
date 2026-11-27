"""Path-traversal (Zip-Slip) protection for archive extraction.

A malicious archive entry may carry a name such as ``..\\..\\Windows\\evil.dll``
or an absolute path. Extracting it naively would write outside the intended
target directory. Every member name must be validated with
:func:`is_safe_member_name` before use.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath, PureWindowsPath


def _has_drive_or_absolute(name: str) -> bool:
    """Detect absolute paths or drive letters in either path flavour."""
    if not name:
        return True
    # POSIX absolute
    if name.startswith("/"):
        return True
    # Windows absolute / UNC / drive letter
    if name.startswith(("\\", "//")):
        return True
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return True
    # Path objects can also report absoluteness.
    return PurePosixPath(name).is_absolute() or PureWindowsPath(name).is_absolute()


_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


# WARUM DER ABLEHNUNGSGRUND ZURUECKGEGEBEN WIRD
# =============================================
# Die Pruefung lehnt nicht nur Pfad-Escapes ab, sondern auch Namen, die beim
# Entpacken unter Windows Aerger machen. Beides als "Zip-Slip-Versuch" zu
# melden ist FALSCH, und zwar messbar: eine Datei namens "CON.txt" in einem
# Archiv enthaelt keinen einzigen Traversal, wurde aber als
# "Zip-Slip-Versuch" mit Ankergewicht 50 gemeldet — also ROT, "blockieren".
#
# Die beiden Faelle sind grundverschieden:
#   * Ein PFAD-ESCAPE ist ein ANGRIFF. Kein legitimes Packprogramm erzeugt
#     "..\..\Windows\evil.dll" oder "C:/Windows/x.dll"; wer das baut, will,
#     dass irgendein Entpacker ausserhalb schreibt.
#   * Ein ungewoehnlicher NAME ist meistens SCHLAMPEREI. ":" ist auf Unix ein
#     gueltiges Zeichen (dort entstehen solche Archive), "CON.txt" oder
#     "aux.log" ebenso. Auf Windows scheitert das Entpacken dann fuer diesen
#     einen Eintrag — unangenehm, aber kein Angriff.
#
# Der Aufrufer bekommt deshalb den GRUND und entscheidet ueber die Meldung.
REASON_TRAVERSAL = "traversal"  # Laufwerk, absoluter Pfad, "..", Escape
REASON_DEVICE = "device"  # CON, NUL, COM1 … (Windows-Geraetename)
REASON_ADS = "ads"  # ":" -> NTFS Alternate Data Stream
REASON_EMPTY = "empty"  # Komponente wird nach dem Strippen leer
REASON_DOTNAME = "dotname"  # Name beginnt nach normpath mit ".."
REASON_NUL = "nul"  # Eingebettetes Nullbyte (C-String-Truncation-Angriff)

# Die Gruende, die einen ANGRIFF belegen. Nur sie rechtfertigen einen Anker.
ATTACK_REASONS = frozenset({REASON_TRAVERSAL, REASON_NUL})


def unsafe_name_reason(name: str) -> str | None:
    """Warum der Eintragsname abgelehnt wird — ``None`` heisst: in Ordnung.

    Der Grund ist eine der ``REASON_*``-Konstanten. Reihenfolge nach
    Schwere: ein Pfad-Escape wird zuerst gemeldet, auch wenn der Name
    zusaetzlich einen Geraetenamen traegt.
    """
    if not name or not name.strip():
        return REASON_EMPTY
    if "\x00" in name:
        return REASON_NUL
    if _has_drive_or_absolute(name):
        return REASON_TRAVERSAL

    # Normalise both separators, then check every component.
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    # Drei getrennte Merker, nicht einer: der Nutzer liest den Grund im
    # Befund, und "reservierter Geraetename" waere fuer "..." schlicht falsch.
    # Genau dieses falsche Etikett hatte ich eine Ebene hoeher behoben — hier
    # sass es noch.
    geraet = False
    ads = False
    leer = False
    for part in parts:
        # Windows strips trailing dots AND spaces from every path component
        # when resolving: ".. " and ". ." collapse to "..", "..." collapses
        # to "" (and is then dropped). Reject any component that becomes
        # empty or ".." after that strip — plus NTFS Alternate Data Stream
        # syntax ("file.txt:stream"), which no legitimate archive member
        # needs and which enables hidden persistence.
        # Windows entfernt abschliessende Leerzeichen UND Punkte je
        # Komponente. Fuer die FRAGE, ob etwas ein ".." ist, zaehlt zuerst
        # das Leerzeichen: ".. " wird zu "..", ". ." ebenfalls — beide sind
        # dann der Aufwaerts-Verweis, also ein VERSCHLEIERTER Traversal.
        # "..." dagegen faellt ganz weg (Punkte am Ende), ohne je ".." zu
        # sein: ein ungewoehnlicher Name, kein Traversal.
        #
        # Genau diese Unterscheidung war in meiner ersten Fassung falsch:
        # ".. ".rstrip(". ") ergibt "" — beide Punkte wurden mitentfernt, und
        # ein verschleierter Traversal landete in der milden Klasse. Der
        # eigene Pruefdurchlauf hat es gezeigt.
        ohne_leerzeichen = part.replace(" ", "")
        if ohne_leerzeichen == "..":
            return REASON_TRAVERSAL
        if ohne_leerzeichen == ".":
            continue  # aktuelles Verzeichnis, harmlos
        stripped = part.rstrip(". ")
        if stripped == "":
            leer = True
            continue
        if ":" in stripped:
            ads = True
            continue
        # Windows reserved device names resolve to devices, not files
        # (CON, NUL, COM1 …) — classic archive-extraction hardening. The
        # check applies to the base name before any extension ("CON.txt"
        # is equally reserved on legacy APIs).
        stem = stripped.split(".", 1)[0].upper()
        if stem in _RESERVED_DEVICE_NAMES:
            geraet = True
    # Nach normpath darf das Ergebnis das Zielverzeichnis nicht verlassen.
    #
    # PRAEZISE, nicht per startswith(".."): das traf auch "..." und jeden
    # Namen, der mit zwei Punkten BEGINNT — "..foo.txt" ist aber ein
    # gueltiger Dateiname und kein Escape. Gemessen an "..." (wurde dadurch
    # als Traversal eingeordnet und haette wieder den Anker bekommen).
    collapsed = os.path.normpath(normalized).replace("\\", "/")
    if collapsed == ".." or collapsed.startswith(("../", "/")):
        return REASON_TRAVERSAL
    if collapsed.startswith(".."):
        # "..." oder "..foo.txt": abgelehnt WIE BISHER (die alte Fassung
        # pruefte startswith("..")), aber KEIN Escape — der Name bleibt im
        # Zielverzeichnis. Eigener Grund, weil "Geraetename" hier falsch waere.
        #
        # Die MENGE der abgelehnten Namen bleibt damit unveraendert; geaendert
        # hat sich nur, was gemeldet wird. Das ist Absicht: ueber die
        # Extraktion entscheidet dieser Umbau nicht.
        return REASON_DOTNAME
    if ads:
        return REASON_ADS
    if geraet:
        return REASON_DEVICE
    if leer:
        return REASON_EMPTY
    return None


def is_safe_member_name(name: str) -> bool:
    """Return True if an archive member name is safe to extract.

    A name is unsafe when it is empty, absolute, carries a drive letter, or
    resolves (after normalisation) outside of the current directory via ``..``.

    Windows strips trailing dots/spaces from every path component when
    resolving (``.. `` behaves like ``..``), so components are compared
    AFTER rstripping ``. `` — otherwise ``a/.. /evil.dll`` would pass the
    exact-match check and traverse on Windows. NTFS Alternate Data Stream
    syntax (``file.txt:stream``) is rejected outright.

    Wer den GRUND braucht (um Angriff von Schlamperei zu trennen), nimmt
    :func:`unsafe_name_reason`.
    """
    return unsafe_name_reason(name) is None


