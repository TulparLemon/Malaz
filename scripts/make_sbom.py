"""make_sbom.py — CycloneDX-SBOM der Runtime-Abhängigkeiten erzeugen.

Quelle ist die **Build-Umgebung**: die direkten Runtime-Pakete aus
``requirements.txt`` und ihre aufgelöste ``Requires-Dist``-Hülle. Keine
Pfade, keine Benutzernamen, keine Umgebungsvariablen — die Datei darf einem
Release beiliegen.

    python scripts/make_sbom.py --output artifacts/sbom.json
    python scripts/make_sbom.py --output dist/Malaz-2.1/sbom.json --check

Exit 1, wenn ein Runtime-Paket nicht installiert ist oder keine Version hat:
eine SBOM mit Lücken ist schlimmer als keine.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from malaz import __version__  # noqa: E402


def _normalise(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _requirement_include(line: str) -> str | None:
    """Return the path of a ``-r``/``--requirement`` line, else ``None``."""
    for prefix in ("-r", "--requirement"):
        if line == prefix:
            return ""
        if line.startswith((prefix + " ", prefix + "=")):
            return line[len(prefix) + 1 :].strip()
    return None


def _roots(requirements: Path, seen: set[Path] | None = None) -> list[str]:
    roots: list[str] = []
    seen = set() if seen is None else seen
    current = requirements.resolve()
    if current in seen:
        return roots
    seen.add(current)
    for raw in requirements.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-"):
            # ``-r other.txt`` ist eine echte Anforderungsquelle und wurde
            # vorher wie jede andere Optionszeile verworfen (BUG-096).
            include = _requirement_include(line)
            if include is not None:
                nested = (requirements.parent / include).resolve()
                if not nested.is_file():
                    print(
                        f"!! Eingebundene Anforderungsdatei fehlt: {nested}",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                roots.extend(_roots(nested, seen))
            continue
        try:
            from packaging.requirements import Requirement

            roots.append(_normalise(Requirement(line).name))
        except Exception as exc:
            print(f"!! Anforderung nicht lesbar: {line!r} ({exc})", file=sys.stderr)
            raise SystemExit(1) from None
    return roots


_SPDX_ID = r"[A-Za-z0-9][A-Za-z0-9.+-]*"
# A single SPDX id or a simple AND/OR/WITH expression. "MIT License" fails
# (second token is not an operator), "MIT" and "Apache-2.0 OR MIT" pass.
_SPDX_EXPRESSION = re.compile(
    rf"^\(*\s*{_SPDX_ID}\s*\)*(?:\s+(?:AND|OR|WITH)\s+\(*\s*{_SPDX_ID}\s*\)*)*$"
)


def _licence(meta: metadata.PackageMetadata) -> tuple[str, bool]:
    """Return ``(value, is_spdx_expression)`` for one distribution.

    CycloneDX 1.5 distinguishes a licence NAME (``licenses[].license.name``)
    from an SPDX EXPRESSION (``licenses[].expression``). The old code put
    every value into the name field, including real expressions from the
    ``License-Expression`` metadata (PEP 639) and single SPDX ids.
    """
    expression = meta.get("License-Expression")
    if expression and expression.strip() and expression.strip().upper() != "UNKNOWN":
        return expression.strip(), True
    for key in ("License",):
        value = meta.get(key)
        if value and value.strip() and value.strip().upper() != "UNKNOWN":
            text = value.strip()
            return text, bool(_SPDX_EXPRESSION.fullmatch(text))
    classifiers = meta.get_all("Classifier") or []
    for classifier in classifiers:
        if classifier.startswith("License ::"):
            parts = [part.strip() for part in classifier.split("::")[1:]]
            if parts:
                return parts[-1], False
    return "NOASSERTION", False


def collect(requirements: Path) -> list[dict]:
    search_path = [p for p in sys.path if "_vendor" not in Path(p).parts]
    installed: dict[str, metadata.Distribution] = {}
    for dist in metadata.distributions(path=search_path):
        name = dist.metadata.get("Name")
        if name:
            installed.setdefault(_normalise(name), dist)

    needed: set[str] = set()
    pending = _roots(requirements)
    while pending:
        name = pending.pop()
        if name in needed:
            continue
        needed.add(name)
        dist = installed.get(name)
        if dist is None:
            print(f"!! Runtime-Paket nicht installiert: {name}", file=sys.stderr)
            raise SystemExit(1)
        for raw in dist.requires or []:
            try:
                from packaging.requirements import Requirement

                req = Requirement(raw)
            except Exception:
                continue
            # Extras gehören nicht zum Laufzeit-Basispaket; Marker ohne Extra
            # auswerten (Windows/CPython ist die Build-Umgebung).
            if req.marker is not None and not req.marker.evaluate({"extra": ""}):
                continue
            pending.append(_normalise(req.name))

    components: list[dict] = []
    for name in sorted(needed):
        dist = installed[name]
        version = dist.version
        if not version:
            print(f"!! Paket ohne Version: {name}", file=sys.stderr)
            raise SystemExit(1)
        licence, is_expression = _licence(dist.metadata)
        licence_entry = (
            {"expression": licence} if is_expression else {"license": {"name": licence}}
        )
        components.append(
            {
                "type": "library",
                "name": dist.metadata.get("Name") or name,
                "version": version,
                "licenses": [licence_entry],
                "purl": f"pkg:pypi/{_normalise(name)}@{version}",
            }
        )
    return components


def build_document(components: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "Malaz",
                "version": __version__,
            },
            "tools": [
                {"vendor": "Malaz", "name": "make_sbom", "version": __version__}
            ],
            "properties": [
                {"name": "malaz:python", "value": sys.version.split()[0]},
                {"name": "malaz:platform", "value": sys.platform},
            ],
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=Path("artifacts/sbom.json"))
    parser.add_argument("--requirements", type=Path, default=_ROOT / "requirements.txt")
    parser.add_argument("--check", action="store_true",
                        help="nur prüfen, dass eine SBOM mit Komponenten existiert")
    args = parser.parse_args(argv)

    if args.check:
        if not args.output.is_file():
            print(f"!! SBOM fehlt: {args.output}", file=sys.stderr)
            return 1
        try:
            document = json.loads(args.output.read_text(encoding="utf-8"))
        except ValueError as exc:
            print(f"!! SBOM ist kein JSON: {exc}", file=sys.stderr)
            return 1
        components = document.get("components") or []
        if document.get("bomFormat") != "CycloneDX" or not components:
            print("!! SBOM ohne CycloneDX-Komponenten", file=sys.stderr)
            return 1
        print(f"SBOM ok: {len(components)} Komponenten")
        return 0

    try:
        components = collect(args.requirements)
    except SystemExit:
        return 1
    document = build_document(components)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"SBOM: {args.output} ({len(components)} Komponenten)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
