#!/usr/bin/env python3
"""Static AST architecture layer gate for Malaz (src/malaz).

Enforces the documented 7-layer boundaries from docs/ARCHITECTURE.md and the
facade-submodule DAG invariants from Spec 012:
1. security/ must not import pipelines, analysis, reporting, workers, gui, lab, or PySide6.
2. core/, pipelines/, analysis/, lab/ must not import gui, workers, or PySide6.
3. reporting/ must not import gui, workers, or PySide6.QtWidgets
   (only reporting/pdf_report.py may import PySide6.QtCore / PySide6.QtGui for QPdfWriter).
4. workers/ must not import gui or PySide6.QtWidgets.
5. Declared facade-submodule groups remain strictly acyclic, never back-import
   their facade (directly or transitively), forbid wildcard imports, and import
   every submodule statically at top level for Nuitka discovery.
"""

from __future__ import annotations

import argparse
import ast
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "src" / "malaz"

#: Declarative (facade_posix, (submodule_posix, ...)) registry (Spec 012 §4).
FACADE_SUBMODULE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("core/eml_analysis.py", ("core/eml_parser.py",)),
    ("core/dispatcher.py", ("core/container_dispatch.py",)),
    (
        "pipelines/pdf_pipeline.py",
        (
            "pipelines/pdf_streams.py",
            "pipelines/pdf_links.py",
            "pipelines/pdf_javascript.py",
        ),
    ),
)


def _resolve_relative_base(rel_parts: tuple[str, ...], level: int, module: str | None) -> str:
    pkg_parts = ["malaz", *rel_parts[:-1]]
    up = level - 1
    anchor = pkg_parts[: max(0, len(pkg_parts) - up)]
    if module:
        anchor.append(module)
    return ".".join(anchor)


def _extract_imports(tree: ast.AST, rel_parts: tuple[str, ...]) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            base = (
                _resolve_relative_base(rel_parts, node.level, node.module)
                if node.level > 0
                else (node.module or "")
            )
            if base:
                found.append((node.lineno, base))
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = f"{base}.{alias.name}" if base else alias.name
                found.append((node.lineno, target))
    return found


def _matches_pkg(imported: str, target: str) -> bool:
    return imported in {target, f"malaz.{target}"} or imported.startswith(
        (f"{target}.", f"malaz.{target}.")
    )


def _module_to_rel_posix(dotted: str, known_files: set[str]) -> str | None:
    """Resolve a dotted import path (e.g. ``malaz.core.eml_parser``) to a posix rel path."""
    cleaned = dotted.strip(".")
    if cleaned == "malaz":
        return "__init__.py" if "__init__.py" in known_files else None
    if cleaned.startswith("malaz."):
        sub = cleaned[len("malaz.") :]
    else:
        return None
    parts = sub.split(".")
    for length in range(len(parts), 0, -1):
        prefix = "/".join(parts[:length])
        for candidate in (f"{prefix}.py", f"{prefix}/__init__.py"):
            if candidate in known_files:
                return candidate
    return None


def _extract_canonical_edges(
    tree: ast.AST,
    rel_parts: tuple[str, ...],
    known_files: set[str],
    *,
    top_level_only: bool = False,
) -> tuple[set[str], list[tuple[int, str]]]:
    """Return ``(target_files, star_imports)`` for ``tree``.

    Resolves all import forms (``import malaz.x.y``, ``from malaz.x import y``,
    ``from . import y``, ``from .y import z``, ``from ..x import y``) including
    wildcard edges (``from .y import *`` -> edge to ``y``).
    When ``top_level_only=True``, inspects only direct ``tree.body`` import nodes
    (excluding ``if TYPE_CHECKING:``, ``try:``, and function bodies).
    """
    nodes = tree.body if (top_level_only and isinstance(tree, ast.Module)) else ast.walk(tree)
    targets: set[str] = set()
    stars: list[tuple[int, str]] = []
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                resolved = _module_to_rel_posix(alias.name, known_files)
                if resolved:
                    targets.add(resolved)
        elif isinstance(node, ast.ImportFrom):
            base = (
                _resolve_relative_base(rel_parts, node.level, node.module)
                if node.level > 0
                else (node.module or "")
            )
            if base:
                resolved = _module_to_rel_posix(base, known_files)
                if resolved:
                    targets.add(resolved)
            for alias in node.names:
                if alias.name == "*":
                    stars.append((node.lineno, base or "."))
                    continue
                dotted = f"{base}.{alias.name}" if base else alias.name
                resolved = _module_to_rel_posix(dotted, known_files)
                if resolved:
                    targets.add(resolved)
    return targets, stars


def _reachable_from(start: str, graph: dict[str, set[str]]) -> set[str]:
    """Nodes reachable from ``start`` in >= 1 directed step."""
    visited: set[str] = set()
    stack = list(graph.get(start, ()))
    while stack:
        curr = stack.pop()
        if curr in visited:
            continue
        visited.add(curr)
        stack.extend(graph.get(curr, ()))
    return visited


def _check_facade_dag(
    src_malaz: Path,
    groups: Sequence[tuple[str, tuple[str, ...]]] = FACADE_SUBMODULE_GROUPS,
) -> list[str]:
    """Verify DAG, no-back-import, no-star-import, and top-level Nuitka import rules."""
    if not groups:
        return []

    py_files = [
        p for p in sorted(src_malaz.rglob("*.py")) if "__pycache__" not in p.parts
    ]
    known_files = {p.relative_to(src_malaz).as_posix() for p in py_files}
    trees: dict[str, tuple[ast.Module, tuple[str, ...]]] = {}
    graph: dict[str, set[str]] = {}
    stars_by_file: dict[str, list[tuple[int, str]]] = {}
    problems: list[str] = []

    for py_file in py_files:
        rel_path = py_file.relative_to(src_malaz)
        rel = rel_path.as_posix()
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=rel)
        except UnicodeDecodeError as exc:
            problems.append(
                f"{rel}: Lesefehler (UTF-8) beim DAG-Scan: {exc.reason}"
            )
            continue
        except SyntaxError as exc:
            problems.append(
                f"{rel}:{exc.lineno}: Syntaxfehler beim DAG-Scan: {exc.msg}"
            )
            continue
        trees[rel] = (tree, rel_path.parts)
        edges, stars = _extract_canonical_edges(tree, rel_path.parts, known_files)
        edges.discard(rel)
        graph[rel] = edges
        stars_by_file[rel] = stars

    for raw_facade, raw_subs in groups:
        facade = Path(raw_facade).as_posix()
        subs = tuple(Path(s).as_posix() for s in raw_subs)
        missing = [f for f in (facade, *subs) if f not in known_files]
        if missing:
            for item in missing:
                problems.append(
                    f"FACADE_SUBMODULE_GROUPS: Datei fehlt unter {src_malaz}: '{item}'"
                )
            continue

        # 1. No wildcard imports inside facade or submodules
        for member in (facade, *subs):
            for lineno, target in stars_by_file.get(member, ()):
                problems.append(
                    f"{member}:{lineno}: Wildcard-Import 'from {target} import *' "
                    f"ist in Fassaden-Gruppen verboten"
                )

        # 2. Static top-level import from facade -> every submodule (Nuitka discovery)
        if facade in trees:
            facade_tree, facade_parts = trees[facade]
            top_edges, _ = _extract_canonical_edges(
                facade_tree, facade_parts, known_files, top_level_only=True
            )
            for sub in subs:
                if sub not in top_edges:
                    problems.append(
                        f"{facade}: Teilmodul '{sub}' muss statisch auf Top-Level "
                        f"(direkt in tree.body, fuer Nuitka) importiert werden"
                    )

        # 3. Reachability per submodule: no back-import to facade, no self-cycle
        for sub in subs:
            if sub not in trees:
                continue
            reached = _reachable_from(sub, graph)
            if facade in reached:
                problems.append(
                    f"{sub}: verbotener Rueckimport auf Fassade '{facade}' "
                    f"(direkt oder transitiv)"
                )
            if sub in reached:
                problems.append(
                    f"{sub}: Import-Zyklus innerhalb/ueber Teilmodul '{sub}' erkannt"
                )

    return problems


def check_architecture(src_malaz: Path) -> list[str]:
    if not src_malaz.is_dir():
        return [f"Quellverzeichnis fehlt: {src_malaz}"]

    problems: list[str] = []
    for py_file in sorted(src_malaz.rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue
        rel_path = py_file.relative_to(src_malaz)
        rel = rel_path.as_posix()
        parts = rel_path.parts
        layer = parts[0] if len(parts) > 1 else "<root>"

        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=rel)
        except UnicodeDecodeError as exc:
            problems.append(f"{rel}: Lesefehler (UTF-8) beim Architektur-Scan: {exc.reason}")
            continue
        except SyntaxError as exc:
            problems.append(f"{rel}:{exc.lineno}: Syntaxfehler beim Architektur-Scan: {exc.msg}")
            continue

        seen_file_errors: set[tuple[int, str]] = set()
        for lineno, mod in _extract_imports(tree, parts):
            err: str | None = None
            if layer == "security":
                for forbidden in ("pipelines", "analysis", "reporting", "workers", "gui", "lab"):
                    if _matches_pkg(mod, forbidden):
                        err = f"{rel}:{lineno}: Basis-Schicht 'security' darf '{mod}' nicht importieren"
                        break
                if err is None and (mod == "PySide6" or mod.startswith("PySide6.")):
                    err = f"{rel}:{lineno}: 'security' darf kein PySide6 importieren ('{mod}')"

            elif layer in {"core", "pipelines", "analysis", "lab"}:
                for forbidden in ("gui", "workers"):
                    if _matches_pkg(mod, forbidden):
                        err = f"{rel}:{lineno}: Schicht '{layer}' darf '{mod}' nicht importieren"
                        break
                if err is None and (mod == "PySide6" or mod.startswith("PySide6.")):
                    err = f"{rel}:{lineno}: Schicht '{layer}' muss UI-frei bleiben (Import '{mod}')"

            elif layer == "reporting":
                for forbidden in ("gui", "workers"):
                    if _matches_pkg(mod, forbidden):
                        err = f"{rel}:{lineno}: Schicht 'reporting' darf '{mod}' nicht importieren"
                        break
                if err is None and mod.startswith("PySide6.QtWidgets"):
                    err = f"{rel}:{lineno}: 'reporting' darf keine QtWidgets importieren ('{mod}')"
                elif (
                    err is None
                    and (mod == "PySide6" or mod.startswith("PySide6."))
                    and rel != "reporting/pdf_report.py"
                ):
                    err = (
                        f"{rel}:{lineno}: PySide6 in 'reporting' ist nur fuer QPdfWriter in "
                        f"reporting/pdf_report.py erlaubt (gefunden: '{mod}')"
                    )

            elif layer == "workers" and (
                _matches_pkg(mod, "gui") or mod.startswith("PySide6.QtWidgets")
            ):
                err = f"{rel}:{lineno}: 'workers' darf weder 'gui' noch 'QtWidgets' importieren ('{mod}')"

            if err and (lineno, err) not in seen_file_errors:
                seen_file_errors.add((lineno, err))
                problems.append(err)

    problems.extend(_check_facade_dag(src_malaz))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", type=Path, default=DEFAULT_SRC, help="Pfad zu src/malaz")
    args = parser.parse_args(argv)

    problems = check_architecture(args.src.resolve())
    if problems:
        print(f"ARCHITECTURE GATE BLOCKED ({len(problems)} Verstoss/Verstoesse):")
        for item in problems:
            print(f"  !! {item}")
        return 1
    print("  Architektur-Schichten-Gate gruen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
