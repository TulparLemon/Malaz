#!/usr/bin/env python3
"""Runtime dependency, SBOM, & GPL-3.0 compatibility gate for Malaz.

Verifies:
1. Every runtime requirement declared in requirements.txt appears in the runtime
   sections of THIRD_PARTY_NOTICES.md and carries verified GPL-3.0-compatible
   free software license metadata.
2. THIRD_PARTY_LICENSES/ contains zero commercial license placeholders
   (e.g. LicenseRef-Qt-Commercial.txt) and every <pkg>-<ver>.dist-info folder
   matches an entry and exact version in the SBOM table of THIRD_PARTY_NOTICES.md
   (blocking accidental inclusion of dev-only wheels).
3. With --strict-venv-versions, the installed runtime closure from make_sbom.py
   matches the SBOM table 1:1 in package set and versions.
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_LICENSE_TOKENS = (
    "proprietary",
    "commercial",
    "sspl",
    "busl",
    "business source license",
    "cc-by-nc",
    "cc by-nc",
    "non-commercial",
    "noncommercial",
    "detection rule license",
    "eula",
)

ALLOWED_FREE_LICENSE_TOKENS = (
    "gpl",
    "lgpl",
    "mit",
    "bsd",
    "apache",
    "mpl-2.0",
    "mozilla public license 2.0",
    "isc",
    "psf",
    "python software foundation",
    "0bsd",
    "zlib",
    "cc0",
    "unlicense",
    "osi approved",
)

UNKNOWN_LICENSE_VALUES = {
    "",
    "unknown",
    "none",
}

REQ_NAME_RE = re.compile(r"^([A-Za-z0-9_.-]+)")
DIST_INFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")
SBOM_SECTION_HEADERS = {
    "## complete runtime components (sbom)",
    "## vollständige laufzeitkomponenten (sbom)",
    "## vollstaendige laufzeitkomponenten (sbom)",
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _is_runtime_header(line_lower: str) -> bool:
    return (
        line_lower.startswith(("## included runtime", "## mitgelieferte software"))
        or line_lower in SBOM_SECTION_HEADERS
    )


def parse_runtime_requirements(req_file: Path) -> list[str]:
    names: list[str] = []
    for raw in req_file.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQ_NAME_RE.match(line)
        if match:
            names.append(match.group(1))
    return names


def extract_documented_runtime_packages(notices_text: str) -> set[str]:
    documented: set[str] = set()
    in_runtime_section = False
    for raw_line in notices_text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            in_runtime_section = _is_runtime_header(line.lower())
            continue
        if not in_runtime_section or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0].strip("`* ")
        if not first or first.lower() in {"component", "komponente", "---"} or set(first) <= {"-", ":"}:
            continue
        head = first.split("(", 1)[0]
        for token in re.split(r"[/,]", head):
            tok = token.strip()
            if tok:
                documented.add(_norm(tok))
    return documented


def extract_sbom_versions(notices_text: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    in_sbom = False
    for raw_line in notices_text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            in_sbom = line.lower() in SBOM_SECTION_HEADERS
            continue
        if line.startswith("### "):
            in_sbom = False
            continue
        if not in_sbom or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        first = cells[0].strip("`* ")
        ver = cells[1].strip("`* ")
        if not first or first.lower() in {"component", "komponente", "---"} or set(first) <= {"-", ":"}:
            continue
        versions[_norm(first)] = ver
    return versions


def check_third_party_licenses_dir(
    licenses_dir: Path,
    sbom_versions: dict[str, str],
) -> list[str]:
    problems: list[str] = []
    if not licenses_dir.is_dir():
        return [f"THIRD_PARTY_LICENSES-Verzeichnis fehlt: {licenses_dir}"]

    for path in sorted(licenses_dir.rglob("*")):
        if path.is_file() and "commercial" in path.name.lower():
            rel = path.relative_to(licenses_dir).as_posix()
            problems.append(
                f"Verbotene kommerzielle Lizenzdatei unter THIRD_PARTY_LICENSES/: '{rel}'"
            )

    for entry in sorted(licenses_dir.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_dir():
            continue
        match = DIST_INFO_RE.match(entry.name)
        if not match:
            problems.append(
                f"Unerwartetes Verzeichnis unter THIRD_PARTY_LICENSES/: '{entry.name}'"
            )
            continue
        pkg_norm = _norm(match.group(1))
        ver = match.group(2)
        if pkg_norm not in sbom_versions:
            problems.append(
                f"Nicht-Laufzeit-Paket unter THIRD_PARTY_LICENSES/: '{entry.name}' "
                "(fehlt in der SBOM-Tabelle von THIRD_PARTY_NOTICES.md)"
            )
            continue
        if sbom_versions[pkg_norm] != ver:
            problems.append(
                f"Versions-Drift fuer '{entry.name}': THIRD_PARTY_LICENSES hat {ver}, "
                f"THIRD_PARTY_NOTICES.md listet {sbom_versions[pkg_norm]}"
            )
        has_file = any(p.is_file() for p in entry.rglob("*"))
        if not has_file:
            problems.append(f"Leeres Lizenzverzeichnis unter THIRD_PARTY_LICENSES/: '{entry.name}'")

    return problems


def _check_strict_venv_versions(
    req_file: Path,
    sbom_versions: dict[str, str],
) -> list[str]:
    sbom_script = ROOT / "scripts" / "make_sbom.py"
    spec = importlib.util.spec_from_file_location("_malaz_make_sbom", sbom_script)
    if spec is None or spec.loader is None:
        return [f"make_sbom.py konnte nicht geladen werden: {sbom_script}"]
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    installed = {_norm(c["name"]): str(c["version"]) for c in mod.collect(req_file)}
    problems: list[str] = []
    for pkg_norm, ver in sorted(installed.items()):
        if pkg_norm not in sbom_versions:
            problems.append(
                f"Laufzeit-Komponente '{pkg_norm}=={ver}' aus make_sbom.py fehlt in "
                "THIRD_PARTY_NOTICES.md"
            )
        elif sbom_versions[pkg_norm] != ver:
            problems.append(
                f"SBOM-Versions-Drift fuer '{pkg_norm}': .venv hat {ver}, "
                f"THIRD_PARTY_NOTICES.md hat {sbom_versions[pkg_norm]}"
            )
    for pkg_norm in sorted(set(sbom_versions) - set(installed)):
        problems.append(
            f"Verwaiste Komponente '{pkg_norm}' in THIRD_PARTY_NOTICES.md "
            "(nicht mehr im Laufzeit-Graphen von requirements.txt)"
        )
    return problems


def check_licenses(
    req_file: Path,
    notices_file: Path,
    extra_license_texts: dict[str, str] | None = None,
    *,
    licenses_dir: Path | None = None,
    strict_venv_versions: bool = False,
) -> list[str]:
    if not req_file.is_file():
        return [f"requirements.txt fehlt: {req_file}"]
    if not notices_file.is_file():
        return [f"THIRD_PARTY_NOTICES.md fehlt: {notices_file}"]

    notices_text = notices_file.read_text(encoding="utf-8")
    documented_pkgs = extract_documented_runtime_packages(notices_text)
    sbom_versions = extract_sbom_versions(notices_text)

    problems: list[str] = []
    reqs = parse_runtime_requirements(req_file)
    for pkg in reqs:
        pkg_norm = _norm(pkg)
        if pkg_norm not in documented_pkgs:
            problems.append(
                f"Laufzeit-Paket '{pkg}' aus requirements.txt fehlt in den Laufzeit-Tabellen "
                "von THIRD_PARTY_NOTICES.md"
            )

        if extra_license_texts is not None and pkg in extra_license_texts:
            lic_summary = extra_license_texts[pkg]
        else:
            try:
                meta = md.metadata(pkg)
                classifiers = [c for c in (meta.get_all("Classifier") or []) if "License" in c]
                lic_summary = " | ".join(
                    part.strip()
                    for part in [
                        meta.get("License-Expression") or "",
                        meta.get("License") or "",
                        *classifiers,
                    ]
                    if part and part.strip()
                )
            except md.PackageNotFoundError:
                problems.append(
                    f"Laufzeit-Paket '{pkg}' ist in der aktiven Umgebung nicht installiert"
                )
                continue

        cleaned_parts = [
            p.strip().lower()
            for p in lic_summary.split("|")
            if p.strip().lower() not in UNKNOWN_LICENSE_VALUES
        ]
        if not cleaned_parts:
            problems.append(
                f"Unbekannte/ungepruefte Lizenz-Metadaten fuer Laufzeit-Paket '{pkg}' "
                "(leere oder UNKNOWN-Angabe)"
            )
            continue

        lower_lic = " | ".join(cleaned_parts)
        forbidden_hit = False
        for bad in FORBIDDEN_LICENSE_TOKENS:
            if bad in lower_lic:
                problems.append(
                    f"Inkompatible/unfreie Lizenzkennung ('{bad}') in Paket '{pkg}': "
                    f"{lic_summary[:120]}"
                )
                forbidden_hit = True
        if not forbidden_hit and not any(
            good in lower_lic for good in ALLOWED_FREE_LICENSE_TOKENS
        ):
            problems.append(
                f"Keine verifizierte freie Lizenzkennung fuer Laufzeit-Paket '{pkg}': "
                f"{lic_summary[:120]}"
            )

    resolved_lic_dir = licenses_dir or (notices_file.parent / "THIRD_PARTY_LICENSES")
    is_real_notices = notices_file.resolve() == (ROOT / "THIRD_PARTY_NOTICES.md").resolve()
    if licenses_dir is not None or is_real_notices or resolved_lic_dir.exists():
        problems.extend(check_third_party_licenses_dir(resolved_lic_dir, sbom_versions))

    if strict_venv_versions:
        problems.extend(_check_strict_venv_versions(req_file, sbom_versions))

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", type=Path, default=ROOT / "requirements.txt")
    parser.add_argument("--notices", type=Path, default=ROOT / "THIRD_PARTY_NOTICES.md")
    parser.add_argument("--licenses-dir", type=Path, default=None)
    parser.add_argument(
        "--strict-venv-versions",
        action="store_true",
        help="Prueft zusaetzlich 1:1-Versionsgleichheit zwischen .venv und SBOM-Tabelle",
    )
    args = parser.parse_args(argv)

    problems = check_licenses(
        args.requirements.resolve(),
        args.notices.resolve(),
        licenses_dir=args.licenses_dir.resolve() if args.licenses_dir else None,
        strict_venv_versions=args.strict_venv_versions,
    )
    if problems:
        print(f"LICENSE GATE BLOCKED ({len(problems)} Befund(e)):")
        for item in problems:
            print(f"  !! {item}")
        return 1
    print("  Lizenz- & Notices-Gate gruen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
