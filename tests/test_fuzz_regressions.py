"""Crash-Eingaben aus dem Fuzz-Lauf, festgenagelt als Regressionstests.

``scripts/run_fuzz_smoke.py`` legt jede Eingabe, die einen Parser zum Werfen
bringt, unter ``tests/data/fuzz_regressions/<ziel>-<sha256[:16]>.bin`` ab. Der
Dateiname beginnt mit dem Ziel, damit dieser Test sie ohne Metadatendatei
wieder dem richtigen Harness zuordnen kann.

Der erste Eintrag ist kein Konstrukt für später: ein 131-Byte-ZIP mit
gemeldeter Version 14.8 ließ ``zipfile.ZipFile`` mit ``NotImplementedError``
abbrechen, statt die sichtbare Container-Notiz zu erzeugen. Der Fix steht in
``core/archive.iter_zip_members``; dieser Test hält ihn fest.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for _path in (ROOT / "fuzz", ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import run_fuzz_smoke as smoke  # noqa: E402

_CRASH_DIR = ROOT / "tests" / "data" / "fuzz_regressions"
_MODULES = dict(smoke.HARNESSES)
_CRASHES = sorted(_CRASH_DIR.glob("*.bin")) if _CRASH_DIR.is_dir() else []


@pytest.mark.parametrize("path", _CRASHES, ids=[p.name for p in _CRASHES])
def test_saved_crash_input_no_longer_raises(path):
    target = path.name.split("-", 1)[0]
    module = importlib.import_module(_MODULES[target])
    assert module.fuzz_one(path.read_bytes()) is None


def test_every_saved_crash_file_has_a_known_target():
    """Ein Tippfehler im Zielnamen würde den Test oben still überspringen."""
    for path in _CRASHES:
        assert path.name.split("-", 1)[0] in _MODULES, path.name
