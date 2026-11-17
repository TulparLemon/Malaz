"""SEC-042: nur ein echter Testfehlschlag ist ein Fang.

Die Bisspruefung wertete jeden Exit-Code ungleich 0 als "rot wie erwartet".
pytest endet aber mit 2/3 bei Collection-/Import-/Syntaxfehlern, mit 4 bei
einer unbekannten Node-ID und mit 5, wenn gar nichts lief — in allen vier
Faellen hat kein Test etwas geprueft. Ein geloeschter/umbenannter Test oder
ein Syntaxfehler machte das Gate damit gruen.
"""

import shutil
import tempfile
from pathlib import Path

import pytest

from scripts import check_tests_bite as bite

NODEID = "tests/test_probe.py::test_value"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture()
def probe_tree():
    """Kleiner Baum, in dem ``bite.run`` wirklich pytest startet."""
    tree = Path(tempfile.mkdtemp(prefix="malaz_bite_probe_"))
    try:
        _write(
            tree / "pyproject.toml",
            '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        )
        _write(tree / "src" / "target.py", "VALUE = 1\n")
        _write(
            tree / "tests" / "test_probe.py",
            "from pathlib import Path\n\n"
            "def test_value():\n"
            "    text = Path('src/target.py').read_text(encoding='utf-8')\n"
            "    assert text.strip() == 'VALUE = 1'\n",
        )
        yield tree
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def test_real_mutation_is_caught(probe_tree):
    mutation = bite.Mutation(
        name="probe",
        file="src/target.py",
        old="VALUE = 1",
        new="VALUE = 2",
        test=NODEID,
        why="Eine echte Assertion muss weiterhin als Fang zaehlen.",
    )

    caught, note = bite.run(mutation, probe_tree)

    assert caught, note
    # run() stellt die Datei im finally wieder her.
    assert (probe_tree / "src" / "target.py").read_text(encoding="utf-8") == "VALUE = 1\n"


def test_missing_nodeid_is_not_caught(probe_tree):
    mutation = bite.Mutation(
        name="fehlt",
        file="src/target.py",
        old="VALUE = 1",
        new="VALUE = 2",
        test="tests/does_not_exist.py::test_gone",
        why="Exit 4 heisst: der Test existiert nicht und hat nichts geprueft.",
    )

    caught, note = bite.run(mutation, probe_tree)

    assert not caught
    assert "Exit 4" in note


def test_syntax_error_in_the_test_is_not_caught(probe_tree):
    mutation = bite.Mutation(
        name="syntax",
        file="tests/test_probe.py",
        old="def test_value():",
        new="def test_value(:",
        test=NODEID,
        why="Ein Collection-Fehler ist kein Testfehlschlag.",
    )

    caught, note = bite.run(mutation, probe_tree)

    assert not caught
    # pytest kann die Node-ID nicht sammeln und endet mit Exit 4 (bei einer
    # Verzeichnisauswahl waere es 2). Beides darf kein Fang sein; 2/3/4/5
    # deckt zusaetzlich test_non_failure_exits_are_not_a_catch ab.
    assert "Exit 4" in note


@pytest.mark.parametrize("returncode", [2, 3, 4, 5])
def test_non_failure_exits_are_not_a_catch(returncode):
    caught, note = bite._caught(returncode, "ERROR collecting probe\n", NODEID)

    assert not caught
    assert str(returncode) in note


def test_only_exit_one_with_a_failed_test_counts():
    assert bite._caught(0, "1 passed in 0.01s", NODEID)[0] is False
    assert bite._caught(1, "1 failed in 0.01s", NODEID)[0] is True
    assert (
        bite._caught(
            1, f"FAILED {NODEID} - AssertionError\n1 failed in 0.01s", NODEID
        )[0]
        is True
    )
    # Exit 1 ohne FAILED-Zeile und ohne "1 failed" ist kein belegter Fang.
    assert bite._caught(1, "1 passed in 0.01s", NODEID)[0] is False
    # Ein Fixture-/Setup-Fehler ("1 error") hat den Test nie ausgefuehrt.
    assert (
        bite._caught(
            1, f"ERROR {NODEID}\n1 error in 0.01s", NODEID
        )[0]
        is False
    )
    # "11 failed" darf die 1 nicht als Treffer vortaeuschen.
    assert bite._caught(1, "11 failed in 0.01s", NODEID)[0] is False
