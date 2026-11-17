"""Realwelt-Auswertung: Recall, FP-Rate, Fehlerquote, p95 und Wilson-95 %.

Liest das Manifest und die Ergebnisdatei eines Laborlaufs und schreibt
Markdown + JSON. Die Logik lebt in ``malaz.lab.report`` (wird auch vom
Standalone-Build genutzt); dieses Skript ist nur der Aufruf.

    python scripts/realworld_report.py manifest.json ergebnis.csv \
        --json ergebnis.json --markdown ergebnis.md

Die Ergebnisdatei darf die CSV von ``scripts/evaluate_corpus.py`` sein
(Spalten Gruppe/Datei/Typ/Urteil/Score/Top-Findings) oder ein JSON mit
``{"rows": [...]}``. Eine optionale Spalte ``Dauer_ms`` liefert die p95.

Keine Probe wird geöffnet; gelesen werden nur Metadaten.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _main(argv: list[str] | None = None) -> int:
    from malaz.lab.report import main

    return main(argv)


if __name__ == "__main__":
    raise SystemExit(_main())
