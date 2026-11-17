#!/usr/bin/env python3
"""Static AST architecture layer gate for Malaz (src/malaz).

Enforces the documented 7-layer boundaries from docs/ARCHITECTURE.md:
1. security/ must not import pipelines, analysis, reporting, workers, gui, lab, or PySide6.
2. core/, pipelines/, analysis/, lab/ must not import gui, workers, or PySide6.
3. reporting/ must not import gui, workers, or PySide6.QtWidgets
   (only reporting/pdf_report.py may import PySide6.QtCore / PySide6.QtGui for QPdfWriter).
4. workers/ must not import gui or PySide6.QtWidgets.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "src" / "malaz"


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

            elif layer == "workers":
                if _matches_pkg(mod, "gui") or mod.startswith("PySide6.QtWidgets"):
                    err = f"{rel}:{lineno}: 'workers' darf weder 'gui' noch 'QtWidgets' importieren ('{mod}')"

            if err and (lineno, err) not in seen_file_errors:
                seen_file_errors.add((lineno, err))
                problems.append(err)

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
