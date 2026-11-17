"""Tests fuer das atomare Ersetzen (core.atomicwrite).

WARUM ES DIESEN TEST GIBT
=========================
Der Fehler, den er verhindert, ist unsichtbar: ein Scan, der waehrend eines
Imports liest, bekommt eine leere oder verkuerzte Liste und findet einfach
weniger — ein fehlender Treffer sieht aus wie eine saubere Datei. Ein Test,
der nur "danach steht das Richtige drin" prueft, faengt das NICHT: nach dem
Schreiben stimmt der Inhalt immer. Geprueft werden muss der Zustand WAEHREND
des Schreibens.
"""

from __future__ import annotations

import threading
import time

import pytest

from malaz.core.atomicwrite import write_text_atomic

# Gross genug, dass ein truncatendes Schreiben nicht in einem Syscall
# verschwindet: rund 2,4 MB. Ein kleinerer Text macht das Fenster so kurz,
# dass der Leser es nur mit Glueck trifft — der Test waere dann ein
# Muenzwurf statt einer Pruefung.
_ALT = "a" * 39 + "\n"
_NEU = "b" * 39 + "\n"
_ZEILEN = 60_000


def test_leser_sieht_nie_einen_halben_stand(tmp_path):
    """Der Kern: waehrend des Schreibens ist die Datei IMMER vollstaendig."""
    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, _ALT * _ZEILEN)

    gesehen: list[int] = []
    stop = threading.Event()

    def leser() -> None:
        # Kurze Pause zwischen den Lesungen, und das ist keine Kosmetik:
        # OHNE Pause haelt der Leser die Datei praktisch durchgehend offen und
        # der Ersetzungsvorgang scheitert auf Windows nach dem Neuversuch mit
        # WinError 5 — gemessen im vollen Suite-Lauf. Ein Scan liest die Liste
        # einmal und rechnet dann; er liest sie nicht in einer Endlosschleife.
        # Die Pause aendert am Nachweis nichts: das Schreibfenster ist
        # Millisekunden breit, die Lesungen fallen weiter hinein.
        while not stop.is_set():
            try:
                text = ziel.read_text(encoding="utf-8")
            except OSError:
                gesehen.append(-1)  # Datei kurz weg = ebenfalls ein Fehler
            else:
                gesehen.append(text.count("\n"))
            time.sleep(0.001)

    faden = threading.Thread(target=leser, daemon=True)
    faden.start()
    try:
        for _ in range(8):
            write_text_atomic(ziel, _NEU * _ZEILEN)
            write_text_atomic(ziel, _ALT * _ZEILEN)
    finally:
        stop.set()
        faden.join(timeout=5)

    assert gesehen, "der Leser kam nie zum Zug — der Test prueft nichts"

    # Der eigentliche Vertrag: NIE ein falscher Inhalt. Ein kurzer
    # Oeffnungsfehler ist zulaessig und etwas voellig anderes als eine
    # verkuerzte Liste — er ist LAUT, und die Lader behandeln ihn, ohne das
    # Ergebnis zwischenzuspeichern (siehe
    # test_hashlist.test_unlesbare_liste_vergiert_den_cache_nicht). Er entsteht
    # auf Windows, weil os.replace die Zieldatei in einem Moment austauscht,
    # in dem ein gleichzeitiges Oeffnen scheitert.
    inhalt = [n for n in gesehen if n >= 0]
    abweichend = sorted({n for n in inhalt if n != _ZEILEN})
    assert not abweichend, (
        f"Zwischenstaende GESEHEN: {abweichend[:5]} "
        f"({len([n for n in inhalt if n != _ZEILEN])} von {len(inhalt)} Lesungen "
        f"mit Inhalt) — genau der stille Detektionsverlust"
    )


def test_fehlschlag_laesst_das_ziel_unangetastet(tmp_path, monkeypatch):
    """Ein misslungener Import darf die zuletzt gute Liste nicht zerstoeren."""
    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, "wertvoll\n")

    import malaz.core.atomicwrite as modul

    def kaputt(*_args, **_kwargs):
        raise OSError("Platte voll")

    monkeypatch.setattr(modul.os, "replace", kaputt)
    with pytest.raises(OSError):
        write_text_atomic(ziel, "neu\n")

    assert ziel.read_text(encoding="utf-8") == "wertvoll\n"
    assert list(tmp_path.iterdir()) == [ziel], "temporaere Datei blieb liegen"


def test_keine_temporaere_datei_bleibt_zurueck(tmp_path):
    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, "eins\n")
    write_text_atomic(ziel, "zwei\n")
    assert [p.name for p in tmp_path.iterdir()] == ["liste.txt"]
    assert ziel.read_text(encoding="utf-8") == "zwei\n"


def test_zeilenenden_bleiben_unveraendert(tmp_path):
    """Windows: ohne newline="" waechst die Liste bei jedem Import."""
    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, "a\nb\n")
    write_text_atomic(ziel, ziel.read_text(encoding="utf-8") + "c\n")
    assert ziel.read_bytes() == b"a\nb\nc\n"


def test_ordner_wird_angelegt(tmp_path):
    ziel = tmp_path / "tief" / "drin" / "liste.txt"
    write_text_atomic(ziel, "x\n")
    assert ziel.read_text(encoding="utf-8") == "x\n"


def test_das_fenster_ist_lang_genug_um_es_zu_treffen(tmp_path):
    """Gegenprobe zum Testaufbau selbst.

    Waere das Schreiben so schnell, dass ein truncatendes write_text nie
    beobachtet wird, wuerde ``test_leser_sieht_nie_einen_halben_stand`` auch
    beim alten Code bestehen — und damit nichts beweisen. Hier wird gemessen,
    dass der Leser ueberhaupt oft genug hinsieht.
    """
    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, _ALT * _ZEILEN)

    treffer = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < 0.2:
        ziel.read_text(encoding="utf-8")
        treffer += 1
        # Dieselbe Pause wie im Wettlauf-Test oben: verglichen wird der
        # Abstand zwischen zwei BLICKEN, nicht die reine Lesezeit.
        time.sleep(0.001)
    dauer_je_lesen = 0.2 / max(treffer, 1)

    t0 = time.perf_counter()
    write_text_atomic(ziel, _NEU * _ZEILEN)
    dauer_je_schreiben = time.perf_counter() - t0

    assert treffer >= 5, f"nur {treffer} Lesungen in 200 ms — Aufbau zu langsam"
    assert dauer_je_schreiben > dauer_je_lesen / 2, (
        f"Schreiben {dauer_je_schreiben * 1000:.1f} ms vs Lesen "
        f"{dauer_je_lesen * 1000:.1f} ms — das Fenster ist zu kurz, der "
        "Wettlauf-Test waere ein Muenzwurf"
    )


# -- Verlorener Update (Lese-Aendern-Schreiben) ----------------------------- #


def test_gleichzeitige_importe_verlieren_nichts(tmp_path, monkeypatch):
    """Zwei Importe auf dieselbe Liste duerfen einander nicht ueberschreiben.

    Das Muster ist ueberall dasselbe: Bestand lesen, Neues ergaenzen,
    zurueckschreiben. Atomar schreiben allein genuegt NICHT — lesen beide
    denselben Bestand, verwirft der spaetere ``os.replace`` die Eintraege des
    anderen. Die Liste ist danach kuerzer als sie sein muesste, und ein
    fehlender Treffer sieht aus wie eine saubere Datei.

    Erreichbar ist das ohne kuenstliche Konstruktion: der Knopf im Dialog
    laeuft synchron im GUI-Thread, die automatische Auffrischung im
    Threadpool.
    """
    from malaz.core import hashlist

    ziel = tmp_path / "blocklist.sha256"
    ziel.write_text("# leer\n", encoding="utf-8")
    hashlist._load_blocklist.cache_clear()

    # Zwei Threads, jeder mit eigenen Hashes — insgesamt 60 Eintraege.
    def schreiber(start: int) -> None:
        for i in range(start, start + 30):
            hashlist.merge_blocklist([f"{i:064x}"], source_label=f"T{start}", path=ziel)

    faeden = [threading.Thread(target=schreiber, args=(s,)) for s in (0, 100)]
    for f in faeden:
        f.start()
    for f in faeden:
        f.join(timeout=60)

    inhalt = {
        z.split()[0]
        for z in ziel.read_text(encoding="utf-8").splitlines()
        if z.strip() and not z.startswith("#")
    }
    erwartet = {f"{i:064x}" for i in range(30)} | {f"{i:064x}" for i in range(100, 130)}
    fehlend = erwartet - inhalt
    assert not fehlend, (
        f"{len(fehlend)} von {len(erwartet)} Eintraegen VERLOREN "
        f"(z. B. {sorted(fehlend)[0][:16]}…) — ein gleichzeitiger Import hat "
        "sie ueberschrieben"
    )


def test_zwei_listen_blockieren_einander_nicht(tmp_path):
    """Je Datei ein eigenes Schloss — sonst serialisierte alles global."""
    from malaz.core.atomicwrite import path_lock

    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    assert path_lock(a) is path_lock(a), "gleicher Pfad, gleiches Schloss"
    assert path_lock(a) is not path_lock(b), "verschiedene Listen, verschiedene Schloesser"


def test_schloss_ist_schreibweisen_unabhaengig(tmp_path):
    """Windows liefert denselben Pfad in verschiedenen Schreibweisen."""
    from malaz.core.atomicwrite import path_lock

    ziel = tmp_path / "liste.txt"
    andere = tmp_path / ".." / tmp_path.name / "liste.txt"
    assert path_lock(ziel) is path_lock(andere)


def test_neuversuch_wartet_auf_einen_offenen_leser(tmp_path):
    """Der begrenzte Neuversuch — deterministisch, ohne Wettlauf.

    Windows laesst ``os.replace`` mit ``WinError 5`` scheitern, SOLANGE ein
    anderer Leser die Zieldatei offen hat (Pythons ``open`` fordert kein
    ``FILE_SHARE_DELETE`` an). Genau das passiert real: der Scan liest die
    Liste, waehrend der Import sie ersetzt.

    Hier wird der Halter BEWUSST festgehalten, statt auf ein Zeitfenster zu
    hoffen: ein Wettlauf-Test waere hier ein Muenzwurf, und ``versuche``
    hochzusetzen wuerde nichts loesen — ein durchgehend lesender Faden
    hungert jede endliche Anzahl Versuche aus.
    """
    from malaz.core.atomicwrite import write_text_atomic

    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, "alt\n")

    haelt = threading.Event()
    HALTE_MS = 300  # kurz: so lange dauert ein echter Lesevorgang grob

    def halter() -> None:
        # FESTE Dauer, nicht "bis der Schreiber fertig ist": ein Halter, der
        # nie freigibt, ist von keinem endlichen Neuversuch zu besiegen — das
        # ist auch richtig so und steht im Test darunter. Hier geht es um den
        # realen Fall: der Scan liest einmal und schliesst wieder.
        with ziel.open("rb") as fh:
            fh.read(1)
            haelt.set()
            time.sleep(HALTE_MS / 1000)

    faden = threading.Thread(target=halter, daemon=True)
    faden.start()
    try:
        assert haelt.wait(timeout=5), "der Halter kam nicht hoch"
        # Laeuft der Neuversuch nicht, wirft das hier mit WinError 5.
        # 40 x 25 ms = 1 s Deckel, der Halter gibt nach 300 ms frei.
        write_text_atomic(ziel, "neu\n", versuche=40)
    finally:
        faden.join(timeout=5)

    assert ziel.read_text(encoding="utf-8") == "neu\n"
    assert [p.name for p in tmp_path.iterdir()] == ["liste.txt"]


def test_aufgegebener_neuversuch_meldet_statt_zu_verschlucken(tmp_path):
    """Bleibt das Ziel blockiert, wird der Fehler GEMELDET.

    Eine nicht ersetzte Liste ist sichtbar besser als eine halb geschriebene:
    der Aufrufer zeigt den Fehlschlag an, statt still weniger zu finden.
    """
    from malaz.core.atomicwrite import write_text_atomic

    ziel = tmp_path / "liste.txt"
    write_text_atomic(ziel, "wertvoll\n")

    fertig = threading.Event()
    haelt = threading.Event()

    def halter() -> None:
        with ziel.open("rb") as fh:
            fh.read(1)
            haelt.set()
            fertig.wait(timeout=10)

    faden = threading.Thread(target=halter, daemon=True)
    faden.start()
    try:
        assert haelt.wait(timeout=5)
        with pytest.raises(PermissionError):
            # Ein einziger Versuch: der Halter gibt nicht frei.
            write_text_atomic(ziel, "neu\n", versuche=1)
    finally:
        fertig.set()
        faden.join(timeout=5)

    assert ziel.read_text(encoding="utf-8") == "wertvoll\n", "Ziel beschaedigt"
    assert [p.name for p in tmp_path.iterdir()] == ["liste.txt"], "Temp blieb liegen"


# -- replace_tree: Rollback darf den Altstand nicht loeschen ----------------- #
#
# BUG-009. Vorher loeschte der except-Zweig das Ziel IMMER, also auch dann,
# wenn schon das Umhaengen des Altbaums ins Backup gescheitert war. In dem
# Moment IST das Ziel aber noch der einzige gute Regelsatz.


def test_replace_tree_behaelt_den_altbaum_wenn_das_umhaengen_scheitert(
    tmp_path, monkeypatch
):
    import malaz.core.atomicwrite as modul
    from malaz.core.atomicwrite import replace_tree

    ziel = tmp_path / "external"
    (ziel / "regeln").mkdir(parents=True)
    (ziel / "regeln" / "alt.yar").write_text("alt", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "neu.yar").write_text("neu", encoding="utf-8")

    echt = modul.os.replace

    def scheitert_beim_umhaengen(src, dst):
        if str(src) == str(ziel):
            raise PermissionError("Ziel belegt")
        return echt(src, dst)

    monkeypatch.setattr(modul.os, "replace", scheitert_beim_umhaengen)

    with pytest.raises(PermissionError):
        replace_tree(staging, ziel)

    assert (ziel / "regeln" / "alt.yar").read_text(encoding="utf-8") == "alt", (
        "der alte Regelsatz wurde geloescht, obwohl das Umhaengen scheiterte"
    )
    assert staging.exists(), "der neue Baum darf bei einem Fehlschlag nicht weg sein"
    assert not list(tmp_path.glob(".external.old-*")), "Backup blieb liegen"


def test_replace_tree_stellt_das_backup_wieder_her(tmp_path, monkeypatch):
    import malaz.core.atomicwrite as modul
    from malaz.core.atomicwrite import replace_tree

    ziel = tmp_path / "external"
    ziel.mkdir()
    (ziel / "alt.yar").write_text("alt", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "neu.yar").write_text("neu", encoding="utf-8")

    echt = modul.os.replace

    def scheitert_beim_einspielen(src, dst):
        if str(src) == str(staging):
            raise OSError("Platte voll")
        return echt(src, dst)

    monkeypatch.setattr(modul.os, "replace", scheitert_beim_einspielen)

    with pytest.raises(OSError):
        replace_tree(staging, ziel)

    assert (ziel / "alt.yar").read_text(encoding="utf-8") == "alt", (
        "das Backup wurde nicht zurueckgespielt"
    )
    assert not list(tmp_path.glob(".external.old-*")), "Backup blieb liegen"
