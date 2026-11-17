"""Precompile the YARA rule sets to ``.yarc`` for a faster application start.

Usage (from the project root, venv active):

    python scripts/compile_yara.py            # compile *.yar -> *.yarc
    python scripts/compile_yara.py --force    # overwrite existing .yarc
    python scripts/compile_yara.py --clean    # remove all generated .yarc

The engine (core.yara_engine) prefers a ``.yarc`` over the ``.yar`` with the
same stem, so compiled rules never duplicate the source rules. The build
(build_nuitka.bat) calls this automatically before compiling the exe — the
generated files live in ``rules/yara`` and are bundled with it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Make `malaz` importable when the package is not installed (source layout).
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from malaz import config  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="compile_yara",
        description="YARA-Regeln nach rules/yara/*.yarc vorkompilieren (schnellerer Start).",
    )
    parser.add_argument("--force", action="store_true", help="vorhandene .yarc überschreiben")
    parser.add_argument("--clean", action="store_true", help="generierte .yarc-Dateien löschen")
    args = parser.parse_args(argv)

    rules_dir = config.YARA_RULES_DIR
    if args.clean:
        removed = 0
        failed = 0
        for yarc in rules_dir.glob("*.yarc"):
            try:
                yarc.unlink()
            except OSError as exc:
                failed += 1
                print(f"!! {yarc.name} nicht löschbar: {exc}", file=sys.stderr)
                continue
            removed += 1
            print(f"[entfernt] {yarc.name}")
        if failed:
            print(
                f"!! {failed} .yarc-Datei(en) blieben liegen, {removed} entfernt.",
                file=sys.stderr,
            )
            return 1
        print(f"[OK] {removed} .yarc-Dateien gelöscht.")
        return 0

    if not rules_dir.is_dir():
        print(f"!! Regelverzeichnis fehlt: {rules_dir}", file=sys.stderr)
        return 1

    # Stems already covered by a .yarc — refreshed while compiling, so a
    # x.yar AND x.yara cannot silently overwrite each other's x.yarc.
    # normcase: on Windows "Foo.yar" and an existing "foo.yarc" are the SAME
    # file; a case-sensitive set let Foo.yar overwrite foo.yarc silently.
    def _stem_key(path: Path) -> str:
        return os.path.normcase(path.stem)

    existing = {_stem_key(p) for p in rules_dir.glob("*.yarc")}
    compiled, skipped, failed = 0, 0, 0
    for pattern in ("*.yar", "*.yara"):
        for source in sorted(rules_dir.glob(pattern)):
            target = source.with_suffix(".yarc")
            if _stem_key(source) in existing and not args.force:
                skipped += 1
                continue
            try:
                import yara

                yara.compile(filepath=str(source)).save(str(target))
            except Exception as exc:
                failed += 1
                print(f"!! {source.name}: {exc}", file=sys.stderr)
                continue
            compiled += 1
            existing.add(_stem_key(source))  # schützt vor x.yar-über-x.yara-Overwrite
            print(f"[ok] {source.name} -> {target.name}")

    print(
        f"Ergebnis: {compiled} kompiliert, {skipped} übersprungen (bereits vorhanden)"
        if not failed
        else f"Ergebnis: {compiled} kompiliert, {failed} FEHLER",
        file=sys.stderr if failed else sys.stdout,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
