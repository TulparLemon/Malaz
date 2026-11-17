"""Falschpositiv-Pruefung auf ECHTEN Dateien aus dem Netz.

Warum dieses Skript neben der Suite existiert
=============================================
Der committete Testkorpus ist SYNTHETISCH erzeugt. Er kann eine ganze Klasse
von Fehlern strukturell nicht fangen: eine erfundene Datei enthaelt kein
"understanding" (der "tan"-Fehlalarm), keine Mailinglisten-Kopfzeile
(List-Id), keine UTF-8-BOM vor <?xml und kein echtes IRS-Formular mit
eingebetteten Arbeitsblaettern. Genau diese Faelle waren alle unentdeckt, bis
echte Dateien durchliefen.

Dieses Skript holt echte, frei lizenzierte Dateien und misst. Es laeuft NICHT
in der Suite: es braucht Netz, und ein Test, der fremde Server anfragt, ist
rot, wenn dort jemand etwas aendert.

Aufruf:
    python scripts/run_fp_check.py            # holen (falls noetig) + messen
    python scripts/run_fp_check.py --nur-messen
    python scripts/run_fp_check.py --verzeichnis <pfad>

Exit: 0 = gemessen und nichts ROT, 1 = mindestens eine Datei ROT,
2 = keine einzige Datei gemessen (kein Urteil moeglich).

Dateien direkt unter dem Basisverzeichnis werden mitgemessen; nur
Unterordner zu durchlaufen machte aus einem flachen Korpus ein stilles
"0 ROT" bei Exit 0.

Die Dateien liegen unter %LocalAppData%\\Malaz\\fp_korpus (gitignoriert, nicht
im Repo, nicht in einer Distribution).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import corpus_determinism as _det  # noqa: E402

_USER_AGENT = "Malaz-Triage-Kalibrierung/1.0 (lokaler Testkorpus)"
PRO_ART = 20
# NUR Autoren-/Bibliotheksquellen und echte Dokumente. KEINE Malware-Testkits
# (oletools & Co. liefern echte Schadproben — das verletzt die Vorgabe und
# wuerde die Erkennung verwaessern).
_GITHUB = {
    "docx": [("python-openxml/python-docx", "tests/test_files"),
             ("apache/poi", "test-data/document")],
    "pptx": [("scanny/python-pptx", "tests/test_files"),
             ("apache/poi", "test-data/slideshow")],
    "xlsx": [("pandas-dev/pandas", "pandas/tests/io/data/excel"),
             ("apache/poi", "test-data/spreadsheet")],
}


def hole(url: str, timeout: int = 60) -> bytes:
    with urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}), timeout=timeout
    ) as a:
        return a.read()


def _liste(repo: str, pfad: str) -> list[dict]:
    try:
        daten = json.loads(
            hole(f"https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(pfad)}", 30)
        )
        return daten if isinstance(daten, list) else []
    except Exception:
        return []


def _github_holen(art: str, ordner: Path, endung: str) -> int:
    ordner.mkdir(parents=True, exist_ok=True)
    n = len([f for f in ordner.iterdir() if f.is_file()])
    for repo, pfad in _GITHUB.get(art, ()):
        if n >= PRO_ART:
            break
        for e in _liste(repo, pfad):
            if n >= PRO_ART:
                break
            if e.get("type") != "file" or not e["name"].lower().endswith(endung):
                continue
            try:
                (ordner / e["name"]).write_bytes(hole(e["download_url"]))
                n += 1
            except Exception:
                continue
    return n


def _ham_holen(ordner: Path) -> int:
    """Echte, saubere Mails aus dem SpamAssassin-Korpus (Apache-2.0)."""
    import io
    import tarfile

    ordner.mkdir(parents=True, exist_ok=True)
    n = len([f for f in ordner.iterdir() if f.is_file()])
    for datei in ("20030228_easy_ham.tar.bz2", "20030228_easy_ham_2.tar.bz2"):
        if n >= PRO_ART:
            break
        try:
            roh = hole(f"https://spamassassin.apache.org/old/publiccorpus/{datei}", 120)
            with tarfile.open(fileobj=io.BytesIO(roh), mode="r:bz2") as tf:
                for m in tf.getmembers():
                    if n >= PRO_ART:
                        break
                    if not m.isfile() or not 0 < m.size <= 200_000:
                        continue
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    (ordner / Path(m.name).name).write_bytes(f.read())
                    n += 1
        except Exception as exc:
            print(f"  eml: {datei} — {type(exc).__name__}")
    return n


def _commons_holen(art: str, ordner: Path, endungen: tuple[str, ...]) -> int:

    ordner.mkdir(parents=True, exist_ok=True)
    n = len([f for f in ordner.iterdir() if f.is_file()])
    gesehen: set[str] = set()
    for _ in range(30):
        if n >= PRO_ART:
            break
        try:
            daten = json.loads(hole(
                "https://commons.wikimedia.org/w/api.php?action=query&format=json"
                "&generator=random&grnnamespace=6&grnlimit=40&prop=imageinfo&iiprop=url%7Csize", 30
            ))
        except Exception:
            continue
        for seite in (daten.get("query", {}).get("pages", {}) or {}).values():
            info = (seite.get("imageinfo") or [{}])[0]
            u = info.get("url", "").split("?")[0]
            if not u or u in gesehen or not u.lower().endswith(endungen):
                continue
            if info.get("size", 0) > 15_000_000:
                continue
            gesehen.add(u)
            try:
                name = urllib.parse.unquote(u.rsplit("/", 1)[-1])[:60]
                (ordner / name).write_bytes(hole(u, 90))
                n += 1
            except Exception:
                continue
            if n >= PRO_ART:
                break
    return n


def korpus_bauen(basis: Path) -> None:
    print(f"Korpus nach {basis}")
    print(f"  docx  {_github_holen('docx', basis / 'docx', '.docx')}")
    print(f"  pptx  {_github_holen('pptx', basis / 'pptx', '.pptx')}")
    print(f"  xlsx  {_github_holen('xlsx', basis / 'xlsx', '.xlsx')}")
    print(f"  eml   {_ham_holen(basis / 'eml')}")
    print(f"  jpg   {_commons_holen('jpg', basis / 'jpg', ('.jpg', '.jpeg'))}")


def _mess_dateien(basis: Path):
    """(Art, Pfad) aller zu messenden Dateien — Unterordner UND direkt in ``basis``.

    Vorher wurden ausschliesslich ``basis.iterdir()``-UNTERORDNER durchlaufen.
    Ein flaches Verzeichnis (Dateien direkt unter ``basis``) ergab damit null
    Messungen, und ``main`` meldete „Keine einzige ROT." mit Exit 0 — ein
    Freispruch ohne eine einzige gepruefte Datei.
    """
    eintraege = list(basis.iterdir())
    for ordner in sorted(p for p in eintraege if p.is_dir()):
        for datei in sorted(ordner.iterdir()):
            if datei.is_file():
                yield ordner.name, datei
    for datei in sorted(p for p in eintraege if p.is_file()):
        yield "(direkt)", datei


def messen(basis: Path) -> tuple[int, int]:
    """Alle Dateien scannen und die Falschpositive ausweisen.

    Gibt ``(gemessene_dateien, rot)`` zurueck. Die Zahl der GEMESSENEN Dateien
    ist eigenstaendig wichtig: „0 ROT" bei 0 Messungen ist kein Ergebnis,
    sondern eine Datenluecke, und der Aufrufer muss sie von einem sauberen
    Korpus unterscheiden koennen.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    gemessen = 0
    with _det.pin_user_threat_intel():
        d = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        gesamt: Counter[str] = Counter()
        je_art: dict[str, Counter[str]] = defaultdict(Counter)
        auffaellig: list[tuple[str, str, str, int, list[tuple[str, int]]]] = []
        for art, f in _mess_dateien(basis):
            r = d.scan_path(f)
            gemessen += 1
            gesamt[r.risk_level.name] += 1
            je_art[art][r.risk_level.name] += 1
            if r.risk_level.name != "GREEN":
                regeln = sorted(
                    {(i.rule_id, i.weight or 0) for i in r.all_indicators() if i.weight},
                    key=lambda x: -x[1],
                )
                auffaellig.append((art, f.name[:30], r.risk_level.name, r.score, regeln))

    print(f"\n  {sum(gesamt.values())} echte Dateien: {dict(gesamt)}\n")
    for art in sorted(je_art):
        z = je_art[art]
        print(f"    {art:8} GRUEN {z['GREEN']:3}  GELB {z['YELLOW']:3}  ROT {z['RED']:3}")
    print()
    for art, name, lvl, score, regeln in auffaellig:
        kurz = ", ".join(f"{r}({w})" for r, w in regeln[:4])
        print(f"    {art:8} {name:32} {lvl:7} {score:3}  {kurz}")
    return gemessen, int(gesamt["RED"])


def main(argv: list[str] | None = None) -> int:
    t = argparse.ArgumentParser(description="Falschpositiv-Pruefung auf echten Dateien")
    t.add_argument("--nur-messen", action="store_true", help="nichts holen")
    t.add_argument("--verzeichnis", type=Path, help="eigenen Korpus messen")
    args = t.parse_args(argv)

    basis = args.verzeichnis or Path(
        os.path.expandvars(r"%LocalAppData%\Malaz\fp_korpus")
    )
    if not args.nur_messen and args.verzeichnis is None:
        korpus_bauen(basis)
    if not basis.is_dir():
        print(f"  Kein Korpus unter {basis} — erst holen lassen.")
        return 2

    gemessen, rot = messen(basis)
    print()
    if gemessen == 0:
        # „0 ROT" ohne Messung ist kein Freispruch. Der Aufrufer (Mensch oder
        # Batch) muss den Unterschied zwischen „sauberer Korpus" und „nichts
        # geprueft" an Exit-Code und Meldung sehen.
        print(
            f"  FEHLER: 0 Dateien gemessen unter {basis} — "
            "kein Urteil ueber Falschpositive moeglich.",
            file=sys.stderr,
        )
        return 2
    if rot:
        print(f"  {rot} Datei(en) ROT — jede einzelne ansehen: ist sie WIRKLICH auffaellig?")
        return 1
    print(f"  Keine von {gemessen} Dateien ROT.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
