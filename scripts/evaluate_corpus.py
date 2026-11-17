"""evaluate_corpus.py — misst die echte Trefferquote und False-Positive-Rate.

Scannt zwei Verzeichnisse mit dem echten Dispatcher (inkl. lokalem Defender
und ClamAV); die Logik selbst lebt in ``malaz.evaluation``.

    python scripts/evaluate_corpus.py known_bad/ known_good/
    python scripts/evaluate_corpus.py known_bad/ known_good/ --static-only
    python scripts/evaluate_corpus.py known_bad/ known_good/ --json ergebnis.json
    python scripts/evaluate_corpus.py known_bad/ known_good/ --csv ergebnis.csv

``--static-only`` schaltet Defender und ClamAV ab: die Messung ist dann
schnell, deterministisch und ohne AV-Subprozesse. ``--with-av`` ist der
Standard und verlangt die Engines ausdrücklich. ``--json`` schreibt zusätzlich
einen maschinenlesbaren Bericht; ``unchecked`` (nicht geprüft) ist dort ein
eigener Zähler und fliegt aus dem Nenner — ein GRÜN mit
``CORE_READ_TRUNCATED``, ``CORE_READ_SHORT``, ``CORE_FILE_CHANGED`` oder
einem sonstigen ``*_SKIPPED`` zählt nie als sauber. Ausnahme ist die
ausdrücklich gewählte Einstellung: mit ``--static-only`` sind
``AV_SKIPPED``/``CLAMAV_SKIPPED`` Konfiguration, kein Prüfloch (siehe
``mode.ignored_skips`` im JSON).

Ohne Python (VM/portabler Ordner) fährt der Standalone-Build dieselbe
Messung:  Malaz.exe --evaluate BAD GOOD --csv … --report … --json …
(genau das nutzt ``scripts/vm_portable_test.bat``).

SCHRITT-FÜR-SCHRITT (isolierter Laptop / VM):

1. Laptop frisch aufsetzen, Windows + Defender aktuell; KEIN Firmennetz,
   KEINE Cloud-Sync, KEIN Backup. Flugmodus nur für Testläufe.
2. Netz AN: Samples von https://bazaar.abuse.ch ziehen (50-100 Stück,
   verteilt über PDF/Office/PE/Archive/EML) in known_bad/ — die Zips bleiben
   passwortgeschützt ("infected"), nur im Zielordner entpacken.
   Harmlose Vergleichsdateien (Dokumente, Installer, PDFs) in known_good/.
3. Netz AUS. Entweder Python + venv + pip install -r requirements.txt und
   dieses Skript laufen lassen, ODER den portablen Malaz-Ordner nehmen und
   scripts/vm_portable_test.bat doppelklicken (kein Python nötig).
4. Ergebnisse als CSV/HTML per USB-Stick zurückholen; Samples danach löschen.

Regeln: NICHTS auf den Samples ausführen/öffnen (nur dieses Skript scannt
sie statisch); Samples nie auf dem Arbeits-PC entpacken.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from malaz.evaluation import evaluate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("known_bad", type=Path, help="Ordner mit bösartigen Samples")
    parser.add_argument("known_good", type=Path, help="Ordner mit harmlosen Dateien")
    parser.add_argument("--csv", type=Path, default=None, help="Ergebnis-CSV schreiben")
    parser.add_argument("--json", type=Path, default=None, help="Ergebnis-JSON schreiben")
    parser.add_argument("--report", type=Path, default=None, help="HTML-Report schreiben")
    engines = parser.add_mutually_exclusive_group()
    engines.add_argument(
        "--static-only",
        action="store_true",
        help="ohne Defender/ClamAV messen (schnell, deterministisch)",
    )
    engines.add_argument(
        "--with-av",
        action="store_true",
        help="mit Defender/ClamAV messen (Standard)",
    )
    args = parser.parse_args()
    return evaluate(
        args.known_bad,
        args.known_good,
        csv_path=args.csv,
        report_path=args.report,
        with_av=not args.static_only,
        json_path=args.json,
    )


if __name__ == "__main__":
    raise SystemExit(main())
