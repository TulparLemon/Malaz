"""AP3: Die Fuzz-Harnesses müssen ohne Atheris importierbar und lauffähig sein.

Atheris ist unter Windows nicht installierbar. Genau dort laufen aber die
Entwicklung und die CI. Dieser Test hält deshalb fest, dass jeder Harness in
``fuzz/`` mit echten Korpus-Bytes und mit Mutationen durchläuft — ohne
Atheris, ohne Subprozess, ohne Netz. Er ist die Windows-Seite derselben
Eingabefunktionen, die Linux/WSL unter Atheris fährt.
"""

from __future__ import annotations

import importlib
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for _path in (ROOT / "fuzz", ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import run_fuzz_smoke as smoke  # noqa: E402

_TARGETS = [(target, module) for target, module in smoke.HARNESSES]


@pytest.fixture(scope="module")
def seeds() -> dict[str, list[bytes]]:
    return smoke._load_seeds()


@pytest.mark.parametrize(("target", "module_name"), _TARGETS)
def test_harness_runs_on_synthetic_corpus(target, module_name, seeds):
    module = importlib.import_module(module_name)
    assert target == module.TARGET
    assert callable(module.fuzz_one)
    rng = random.Random(20261101)
    samples = [b"", b"\x00" * 32, b"%PDF-1.7\n%%EOF\n"]
    samples += [seed[: smoke.ENTRY_LIMIT] for seed in seeds[target][:2]]
    samples += [
        smoke._mutate(rng, seeds[target], smoke.DICTIONARIES.get(target, ()), 4096)
        for _ in range(2)
    ]
    for data in samples:
        assert module.fuzz_one(data) is None


def test_replay_runs_a_saved_input(tmp_path):
    """Der dokumentierte Regressionsweg: eine gespeicherte Eingabe erneut fahren."""
    sample = tmp_path / "crash.bin"
    sample.write_bytes(b"{\\rtf1\\objdata 41424344}")
    assert smoke.main(["--replay", str(sample), "--targets", "rtf"]) == 0


def test_replay_rejects_unknown_target(tmp_path):
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"x")
    with pytest.raises(SystemExit):
        smoke.main(["--replay", str(sample), "--targets", "gibtsnicht"])
