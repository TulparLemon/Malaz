"""Dateien so ersetzen, dass ein paralleler Leser nie einen halben Stand sieht.

WARUM DIESE DATEI EXISTIERT
===========================
Die importierten Blocklisten werden waehrend eines Scans GELESEN und im
Hintergrund GESCHRIEBEN. Ein ``Path.write_text`` truncatet zuerst und
schreibt dann — in diesem Fenster liest ein gleichzeitiger Scan eine leere
oder verkuerzte Liste.

Die Folge ist unangenehm, weil sie nicht auffaellt: die Auswertung findet
einfach weniger Treffer, und ein FEHLENDER Treffer sieht aus wie eine saubere
Datei. Genau derselbe Grund steht im Docstring von ``core.feeds.download_feed``
fuer den zweistufigen Download.

WANN DAS ERREICHBAR IST
=======================
Nicht nur theoretisch, sondern eingeplant: beim Programmstart warmt
``gui.main_window._BlocklistWarmup`` die Listen im Threadpool vor (nach 200 ms),
und die automatische Auffrischung schreibt sie im selben Zeitfenster neu
(nach 700 ms). Bei 11 MB Domains ist der Lesevorgang nicht in Millisekunden
vorbei.

VERHAELTNIS ZU DEN ANDEREN STELLEN
==================================
``feeds.download_feed``, ``yara_update``, ``yara_signature_base`` und
``reporting.pdf_report`` machen dasselbe ebenfalls inline. Sie bleiben so: sie
schreiben BYTES aus einem Datenstrom heraus und brauchen dabei eine
Stueck-fuer-Stueck-Schleife bzw. einen Schreib-Callback. Hier geht es um TEXT,
der bereits vollstaendig im Speicher liegt — dafuer ist eine Funktion die
kuerzere und pruefbare Form.
"""

from __future__ import annotations

import os
import shutil
import time
from contextlib import suppress
from pathlib import Path
from threading import Lock


def write_text_atomic(path: Path, text: str, *, versuche: int = 40) -> None:
    """``text`` nach ``path`` schreiben — sichtbar entweder ganz oder gar nicht.

    Erst in eine .tmp-Datei NEBEN dem Ziel (damit ``os.replace`` auf einem
    Datentraeger bleibt und atomar ist), dann umbenennen. Bei jedem Fehler
    bleibt das Ziel unangetastet: ein misslungener Import darf die zuletzt
    gute Liste nicht zerstoeren.

    ``versuche``: Windows laesst ``os.replace`` mit ``WinError 5`` scheitern,
    SOLANGE ein anderer Leser die Zieldatei offen hat — Pythons ``open``
    fordert kein ``FILE_SHARE_DELETE`` an. Genau das passiert hier real: der
    Scan liest die Liste, waehrend der Import sie ersetzt. Gemessen in
    ``tests/test_atomicwrite.py``: ohne Neuversuch brach das Ersetzen ab.
    Der Lesevorgang eines Scans dauert Millisekunden, deshalb genuegt kurzes
    Warten. Bleibt es nach allen Versuchen blockiert, wird der Fehler
    GEMELDET — nicht verschluckt: eine nicht ersetzte Liste ist sichtbar
    besser als eine halb geschriebene.
    """
    ziel = Path(path)
    ziel.parent.mkdir(parents=True, exist_ok=True)
    temp = ziel.with_name(f".{ziel.name}.tmp-{os.getpid()}")
    try:
        # newline="" : die Zeilenenden kommen aus dem Text; ohne das wuerde
        # Windows jedes "\n" in "\r\n" verwandeln und die Datei waechst bei
        # jedem Import ein Stueck.
        with open(temp, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            # Ohne fsync kann der Umbenenn-Vorgang vor den Daten auf der
            # Platte landen: nach einem Absturz stuende dort eine leere Datei,
            # die als gueltige Liste gelesen wuerde.
            fh.flush()
            os.fsync(fh.fileno())
        _replace_mit_neuversuch(temp, ziel, versuche)
    except BaseException:
        with suppress(OSError):
            temp.unlink(missing_ok=True)
        raise



def replace_tree(staged: Path, target: Path) -> None:
    """Publish a complete staged directory with rollback on failure.

    The directory is moved aside first, so a reader never sees a mixture of
    old and new files. If the second move fails, the old tree is restored.
    """
    staged = Path(staged)
    target = Path(target)
    if not staged.is_dir():
        raise FileNotFoundError(staged)
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_name(f".{target.name}.old-{os.getpid()}")
    if backup.exists():
        shutil.rmtree(backup)
    moved_old = False
    try:
        if target.exists():
            os.replace(target, backup)
            moved_old = True
        os.replace(staged, target)
    except BaseException:
        # The old tree may only be deleted when it really MOVED to the
        # backup: if the first ``os.replace`` failed, ``target`` still IS the
        # old tree, and the unconditional ``rmtree`` here destroyed the last
        # working ruleset without any backup (measured: injected
        # PermissionError -> target gone). The cleanup of a half-published
        # target only makes sense after the swap started.
        if moved_old:
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            if backup.exists():
                os.replace(backup, target)
        raise
    else:
        if moved_old:
            shutil.rmtree(backup, ignore_errors=True)

def _replace_mit_neuversuch(temp: Path, ziel: Path, versuche: int) -> None:
    """``os.replace`` mit kurzem Warten bei belegtem Ziel (Windows)."""
    for versuch in range(max(1, versuche)):
        try:
            os.replace(temp, ziel)
            return
        except PermissionError:
            # Belegt -> kurz warten und erneut. Der letzte Versuch wirft.
            if versuch == versuche - 1:
                raise
            time.sleep(0.025)


# -- Lese-Aendern-Schreiben serialisieren ------------------------------------ #
#
# Atomar schreiben allein genuegt NICHT. Das Muster ist ueberall dasselbe:
# Bestand lesen, Neues ergaenzen, zurueckschreiben. Laufen zwei davon
# gleichzeitig, lesen beide denselben Bestand, und der spaetere os.replace
# verwirft die Eintraege des anderen — ein VERLORENER UPDATE, wieder still:
# die Liste ist danach kuerzer als sie sein muesste, und ein fehlender Treffer
# sieht aus wie eine saubere Datei.
#
# WANN DAS ERREICHBAR IST: der Knopf im Dialog laeuft SYNCHRON im GUI-Thread
# (feeds_dialog._laden), die automatische Auffrischung im Threadpool — beide
# koennen dieselbe Liste gleichzeitig lesen. Zwei Programmfenster sind der
# zweite Weg; dagegen hilft ein prozessinternes Schloss nicht (dafuer waere
# eine Sperrdatei noetig), aber der haeufigere Fall ist der erste.

_LOCKS: dict[str, Lock] = {}
_LOCKS_GUARD = Lock()


def path_lock(path: Path) -> Lock:
    """Das Schloss zu EINER Zieldatei — fuer Lese-Aendern-Schreiben.

    Je Datei ein eigenes Schloss, damit zwei verschiedene Listen einander
    nicht blockieren. Normalisiert (absoluter Pfad, Kleinschreibung), weil
    Windows denselben Pfad in verschiedenen Schreibweisen liefern kann.
    """
    schluessel = os.path.normcase(os.path.abspath(str(path)))
    with _LOCKS_GUARD:
        vorhanden = _LOCKS.get(schluessel)
        if vorhanden is None:
            vorhanden = Lock()
            _LOCKS[schluessel] = vorhanden
        return vorhanden
