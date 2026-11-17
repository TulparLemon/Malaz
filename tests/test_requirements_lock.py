"""Ensure requirements.lock covers all runtime & dev dependencies with exact == pins (T12)."""

from __future__ import annotations

from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def _parse_reqs(path: Path) -> list[Requirement]:
    reqs: list[Requirement] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        reqs.append(Requirement(line))
    return reqs


def test_requirements_lock_is_complete_consistent_and_pinned():
    lock_path = ROOT / "requirements.lock"
    assert lock_path.is_file(), "requirements.lock fehlt im Projekt-Root"

    locked: dict[str, str] = {}
    for lineno, raw in enumerate(lock_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        assert "@" not in line, f"Lokale @-Referenz in requirements.lock:{lineno}: {line}"
        assert "==" in line, f"Ungepinnte Zeile in requirements.lock:{lineno}: {line}"
        req = Requirement(line)
        specs = list(req.specifier)
        assert len(specs) == 1 and specs[0].operator == "==", line
        name = canonicalize_name(req.name)
        assert name not in locked, f"Doppelter Eintrag in requirements.lock: {name}"
        locked[name] = specs[0].version

    assert "nuitka" in locked, "nuitka muss in requirements.lock gesperrt sein"

    for req in _parse_reqs(ROOT / "requirements.txt"):
        name = canonicalize_name(req.name)
        assert name in locked, f"Runtime-Paket {req.name} fehlt in requirements.lock"
        assert req.specifier.contains(locked[name], prereleases=True), (
            f"requirements.lock ({name}=={locked[name]}) verletzt {req}"
        )

    for req in _parse_reqs(ROOT / "requirements-dev.txt"):
        name = canonicalize_name(req.name)
        specs = list(req.specifier)
        assert len(specs) == 1 and specs[0].operator == "==", (
            f"Dev-Werkzeug {req} muss in requirements-dev.txt exakt mit == gepinnt sein"
        )
        assert locked.get(name) == specs[0].version, (
            f"Drift: requirements-dev.txt ({req}) vs requirements.lock ({locked.get(name)})"
        )
