"""Gemeinsames Gerüst der Atheris-Harnesses.

Warum diese Datei existiert
===========================

Die Harnesses laufen unter Linux/WSL mit Atheris (``requirements-fuzz.txt``)
und müssen auf Windows trotzdem **importierbar** sein: dort fehlt Atheris,
und ``scripts/run_fuzz_smoke.py`` sowie ``tests/test_fuzz_harnesses.py`` fahren
dieselben Eingabefunktionen ohne Instrumentierung. Die Import-Weiche steht
deshalb hier an einer Stelle statt in jedem Harness.

Grenzen
--------

Die Harnesses importieren ausschließlich Parser-Module (``malaz.core.*``,
``malaz.pipelines.*``). Dispatcher, GUI und AV-Engines bleiben draußen: ein
Fuzz-Lauf startet keine Subprozesse, öffnet keine Netzwerkverbindung und
schreibt keine Dateien außer den Crash-Repros des Smoke-Treibers. Die
Pfade in den Analyse-Kontexten sind absichtlich **nicht existent**
(``<fuzz-input>.pdf``), damit keine Stufe eine echte Datei nachlädt — die
spitzen Klammern sind unter Windows in Dateinamen verboten.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def load(module: str, *names: str) -> tuple:
    """Import ``names`` from ``module``; instrumentiert, wenn Atheris da ist.

    ``atheris.instrument_imports()`` deckt nur den Import *innerhalb* des
    Kontexts ab. Darum wird das Zielmodul hier importiert und nicht im
    Harness-Modulkopf.
    """
    import importlib

    try:
        import atheris
    except ImportError:
        mod = importlib.import_module(module)
    else:
        with atheris.instrument_imports():
            mod = importlib.import_module(module)
    return tuple(getattr(mod, name) for name in names)


def context(data: bytes, name: str, detected_type: str):
    """Analyse-Kontext für einen Fuzz-Puffer — Pfad existiert absichtlich nicht."""
    from malaz.models import AnalysisContext

    return AnalysisContext(
        path=Path(name), data=data, detected_type=detected_type, size=len(data)
    )


def drain(iterator, limit: int = 32) -> int:
    """Zieht höchstens ``limit`` Einträge und schließt den Generator.

    Die Container-Iteratoren halten ``zipfile``/``tarfile``-Handles offen. Ein
    abgebrochener Walk ohne ``close()`` würde sie erst beim GC freigeben — bei
    zehntausend Läufen ist das ein Leak, kein Stilproblem.
    """
    count = 0
    engine = iter(iterator)
    try:
        for _ in itertools.islice(engine, limit):
            count += 1
    finally:
        close = getattr(engine, "close", None)
        if close is not None:
            close()
    return count


def run(one_input) -> None:
    """Atheris-Einstieg; ohne Atheris eine klare Anleitung statt Traceback."""
    try:
        import atheris
    except ImportError:
        print(
            "Atheris ist auf dieser Plattform nicht installiert (Windows: kein\n"
            "libFuzzer/Clang). Der Windows-Weg ist der deterministische Treiber:\n\n"
            "    .venv\\Scripts\\python.exe scripts\\run_fuzz_smoke.py --runs 10000\n\n"
            "Siehe .github/CONTRIBUTING.md.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()
