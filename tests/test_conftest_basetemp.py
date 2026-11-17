"""Regression: a fresh checkout must be able to use ``--basetemp=<missing>/<dir>``."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

_CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"


def _load_root_conftest():
    spec = importlib.util.spec_from_file_location("_malaz_root_conftest", _CONFTEST)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_basetemp_parent_is_created_but_not_the_basetemp_itself(tmp_path):
    conftest = _load_root_conftest()
    target = tmp_path / "fresh-clone" / ".pytest-tmp" / "ci"
    conftest.pytest_configure(SimpleNamespace(option=SimpleNamespace(basetemp=str(target))))
    assert target.parent.is_dir()
    assert not target.exists()


def test_without_basetemp_nothing_happens(tmp_path, monkeypatch):
    conftest = _load_root_conftest()
    monkeypatch.chdir(tmp_path)
    conftest.pytest_configure(SimpleNamespace(option=SimpleNamespace(basetemp=None)))
    assert list(tmp_path.iterdir()) == []
