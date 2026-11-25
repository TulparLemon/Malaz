"""Unit tests for scripts/arch_gate.py facade-submodule DAG checks (Spec 012)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import arch_gate  # noqa: E402


def _write_pkg(base: Path, files: dict[str, str]) -> Path:
    src = base / "src" / "malaz"
    (src / "core").mkdir(parents=True, exist_ok=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "core" / "__init__.py").write_text("", encoding="utf-8")
    for rel, content in files.items():
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return src


def test_real_repository_passes_arch_gate() -> None:
    problems = arch_gate.check_architecture(arch_gate.DEFAULT_SRC)
    assert problems == []


@pytest.mark.parametrize(
    "back_import",
    [
        "from .facade import helper\n",
        "from . import facade\n",
        "from malaz.core import facade\n",
        "import malaz.core.facade\n",
        "def f():\n    from .facade import helper\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from .facade import helper\n",
    ],
)
def test_facade_dag_blocks_direct_and_hidden_back_imports(
    tmp_path: Path, back_import: str
) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub import X as X\nhelper = 1\n",
            "core/sub.py": f"X = 1\n{back_import}",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("Rueckimport" in p and "core/sub.py" in p for p in problems), problems


@pytest.mark.parametrize(
    "helper_import",
    [
        "from .facade import X\n",
        "from .facade import *\n",
    ],
)
def test_facade_dag_blocks_transitive_back_import(
    tmp_path: Path, helper_import: str
) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub import X as X\n",
            "core/sub.py": "from .helper import Y\nX = Y\n",
            "core/helper.py": f"{helper_import}Y = 1\n",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("Rueckimport" in p and "core/sub.py" in p for p in problems), problems


def test_facade_dag_blocks_sibling_cycle(tmp_path: Path) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub_a import A as A\nfrom .sub_b import B as B\n",
            "core/sub_a.py": "from .sub_b import B\nA = B\n",
            "core/sub_b.py": "from .sub_a import A\nB = A\n",
        },
    )
    problems = arch_gate._check_facade_dag(
        src, (("core/facade.py", ("core/sub_a.py", "core/sub_b.py")),)
    )
    assert any("Zyklus" in p for p in problems), problems


def test_facade_dag_ignores_unrelated_third_party_cycle(tmp_path: Path) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub import X as X\n",
            "core/sub.py": "from .other_a import A\nX = A\n",
            "core/other_a.py": "from .other_b import B\nA = 1\n",
            "core/other_b.py": "from .other_a import A\nB = 2\n",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert problems == []


def test_facade_dag_blocks_wildcard_import_inside_group(tmp_path: Path) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub import *\n",
            "core/sub.py": "X = 1\n",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("Wildcard-Import" in p for p in problems), problems


def test_facade_dag_reports_missing_declared_file(tmp_path: Path) -> None:
    src = _write_pkg(tmp_path, {"core/facade.py": "X = 1\n"})
    problems = arch_gate._check_facade_dag(
        src, (("core/facade.py", ("core/does_not_exist.py",)),)
    )
    assert any("does_not_exist.py" in p for p in problems), problems


@pytest.mark.parametrize(
    "facade_body",
    [
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from .sub import X\n",
        "def load():\n    from .sub import X\n    return X\n",
        "try:\n    from .sub import X\nexcept ImportError:\n    X = 0\n",
    ],
)
def test_facade_dag_requires_direct_top_level_import_for_nuitka(
    tmp_path: Path, facade_body: str
) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": facade_body,
            "core/sub.py": "X = 1\n",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("Top-Level" in p and "core/sub.py" in p for p in problems), problems


def test_facade_dag_reports_syntax_error_in_facade_without_crash(tmp_path: Path) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "def broken(:\n",
            "core/sub.py": "X = 1\n",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("core/facade.py" in p and "Syntaxfehler" in p for p in problems), problems


def test_facade_dag_reports_syntax_error_in_submodule_and_neighbor(tmp_path: Path) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub import X as X\n",
            "core/sub.py": "def broken(:\n",
            "core/neighbor.py": "class AlsoBroken(:\n",
        },
    )
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("core/sub.py" in p and "Syntaxfehler" in p for p in problems), problems
    assert any("core/neighbor.py" in p and "Syntaxfehler" in p for p in problems), problems


def test_facade_dag_reports_invalid_utf8_without_crash(tmp_path: Path) -> None:
    src = _write_pkg(
        tmp_path,
        {
            "core/facade.py": "from .sub import X as X\n",
            "core/sub.py": "X = 1\n",
        },
    )
    (src / "core" / "sub.py").write_bytes(b"\xff\xfe\x00broken")
    problems = arch_gate._check_facade_dag(src, (("core/facade.py", ("core/sub.py",)),))
    assert any("core/sub.py" in p and "Lesefehler" in p for p in problems), problems
