"""Assemble a complete, gate-verified Malaz release set from a single annotated Git tag."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
import check_release  # noqa: E402
import make_sbom  # noqa: E402
import write_checksums  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_INIT_VER_RE = re.compile(r'__version__\s*=\s*"([^"]+)"')


class TagConfigError(Exception):
    """Exit-2 configuration / tag mismatch error."""


class ReleaseIntegrityError(Exception):
    """Exit-1 integrity / gate verification error."""


def _git_run(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    git = check_release._git_exe(root)
    return subprocess.run([git, "-C", str(root), *args], capture_output=True, check=False)


def check_tag(root: Path, tag: str) -> str:
    """Verify ``refs/tags/<tag>`` is an annotated tag matching ``__version__``."""
    if not tag.startswith("v"):
        raise TagConfigError(f"Tag muss mit 'v' beginnen: {tag!r}")
    version = tag[1:]
    if not _SEMVER_RE.fullmatch(version):
        raise TagConfigError(f"Ungueltige SemVer-Version aus Tag {tag!r}: {version!r}")

    ref = f"refs/tags/{tag}"
    t_proc = _git_run(root, "cat-file", "-t", ref)
    obj_type = t_proc.stdout.decode("utf-8", errors="replace").strip()
    if t_proc.returncode != 0 or obj_type != "tag":
        raise TagConfigError(f"{ref} muss ein annotiertes Git-Tag sein (gefunden: {obj_type or 'fehlt'}).")

    init_proc = _git_run(root, "show", f"{ref}:src/malaz/__init__.py")
    if init_proc.returncode != 0:
        raise TagConfigError(f"src/malaz/__init__.py in {ref} nicht lesbar.")
    init_text = init_proc.stdout.decode("utf-8", errors="replace")
    match = _INIT_VER_RE.search(init_text)
    if match is None or match.group(1) != version:
        found = match.group(1) if match else "<unbekannt>"
        raise TagConfigError(f"Versionskonflikt: Tag {tag} verlangt {version}, __init__.py hat {found}.")
    return version


def build_source_zip(root: Path, tag: str, version: str, tmp: Path) -> Path:
    out_zip = tmp / f"Malaz-{version}-source.zip"
    proc = _git_run(
        root,
        "archive",
        "--format=zip",
        f"--prefix=Malaz-{version}/",
        "-o",
        str(out_zip),
        f"refs/tags/{tag}",
    )
    if proc.returncode != 0 or not out_zip.is_file():
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseIntegrityError(f"git archive (source) fehlgeschlagen: {err}")
    return out_zip


def verify_source_zip(root: Path, tag: str, zip_path: Path, prefix: str) -> list[str]:
    """Compare non-directory entries in ``zip_path`` 1:1 against ``git ls-tree``."""
    ls_proc = _git_run(root, "ls-tree", "-r", "-z", "--name-only", f"refs/tags/{tag}")
    if ls_proc.returncode != 0:
        return ["git ls-tree fehlgeschlagen"]
    tag_files = {
        raw.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        for raw in ls_proc.stdout.split(b"\x00")
        if raw
    }

    zip_files: set[str] = set()
    bad_prefix: list[str] = []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            norm = name.replace("\\", "/")
            if norm.endswith("/"):
                continue
            if not norm.startswith(prefix):
                bad_prefix.append(norm)
            else:
                zip_files.add(norm[len(prefix) :])

    diffs: list[str] = []
    if bad_prefix:
        diffs.append(f"Eintraege ohne Praefix {prefix!r}: {sorted(bad_prefix)[:10]}")
    only_zip = sorted(zip_files - tag_files)
    only_tag = sorted(tag_files - zip_files)
    if only_zip:
        diffs.append(f"Nur im Source-ZIP ({len(only_zip)}): {only_zip[:10]}")
    if only_tag:
        diffs.append(f"Nur im Tag-Baum ({len(only_tag)}): {only_tag[:10]}")
    return diffs


def build_licenses_zip(root: Path, tag: str, version: str, tmp: Path) -> Path:
    out_zip = tmp / f"Malaz-{version}-licenses.zip"
    prefix = f"Malaz-{version}-licenses/"
    proc = _git_run(
        root,
        "archive",
        "--format=zip",
        f"--prefix={prefix}",
        "-o",
        str(out_zip),
        f"refs/tags/{tag}",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "THIRD_PARTY_LICENSES",
    )
    if proc.returncode != 0 or not out_zip.is_file():
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseIntegrityError(f"git archive (licenses) fehlgeschlagen: {err}")
    with zipfile.ZipFile(out_zip) as zf:
        names = {n.replace("\\", "/") for n in zf.namelist()}
    if f"{prefix}LICENSE" not in names:
        raise ReleaseIntegrityError(f"{prefix}LICENSE fehlt in {out_zip.name}")
    return out_zip


def _read_pe_versions(exe_path: Path) -> tuple[str, str]:
    import pefile

    with pefile.PE(str(exe_path), fast_load=True) as pe:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        if not hasattr(pe, "VS_FIXEDFILEINFO") or not pe.VS_FIXEDFILEINFO:
            raise ReleaseIntegrityError("Malaz.exe enthaelt keine VS_FIXEDFILEINFO-Ressource")
        fi = pe.VS_FIXEDFILEINFO[0]
        pv = (
            f"{fi.ProductVersionMS >> 16}.{fi.ProductVersionMS & 0xFFFF}."
            f"{fi.ProductVersionLS >> 16}.{fi.ProductVersionLS & 0xFFFF}"
        )
        fv = (
            f"{fi.FileVersionMS >> 16}.{fi.FileVersionMS & 0xFFFF}."
            f"{fi.FileVersionLS >> 16}.{fi.FileVersionLS & 0xFFFF}"
        )
        return pv, fv


def verify_binary_zip(zip_path: Path, version: str, tmp: Path) -> None:
    findings = check_release.scan_archive(zip_path, source=False)
    if findings:
        details = "; ".join(f"{f.path}:{f.kind}" for f in findings[:5])
        raise ReleaseIntegrityError(f"Binary-ZIP vom Release-Gate abgewiesen: {details}")

    extract_dir = tmp / "_x"
    extract_dir.mkdir(parents=True, exist_ok=True)
    exe_out = extract_dir / "Malaz.exe"
    with zipfile.ZipFile(zip_path) as zf:
        if "Malaz.exe" not in zf.namelist():
            raise ReleaseIntegrityError("Malaz.exe fehlt auf oberster Ebene des Binary-ZIPs")
        with zf.open("Malaz.exe") as src, exe_out.open("wb") as dst:
            shutil.copyfileobj(src, dst)

    expected_ver4 = f"{version}.0"
    pv, fv = _read_pe_versions(exe_out)
    if pv != expected_ver4 or fv != expected_ver4:
        raise ReleaseIntegrityError(
            f"PE-Versionskonflikt in Malaz.exe: erwartet {expected_ver4}, "
            f"ProductVersion={pv}, FileVersion={fv}"
        )


def extract_sbom(zip_path: Path, version: str, tmp: Path) -> Path:
    sbom_out = tmp / "sbom.json"
    with zipfile.ZipFile(zip_path) as zf:
        if "sbom.json" not in zf.namelist():
            raise ReleaseIntegrityError("sbom.json fehlt auf oberster Ebene des Binary-ZIPs")
        sbom_out.write_bytes(zf.read("sbom.json"))

    if make_sbom.main(["--output", str(sbom_out), "--check"]) != 0:
        raise ReleaseIntegrityError("make_sbom --check schlug fuer extrahierte sbom.json fehl")

    doc = json.loads(sbom_out.read_text(encoding="utf-8"))
    comp_ver = doc.get("metadata", {}).get("component", {}).get("version")
    if comp_ver != version:
        raise ReleaseIntegrityError(
            f"SBOM-Komponentenversion ({comp_ver!r}) stimmt nicht mit {version!r} ueberein"
        )
    return sbom_out


def assemble_release(root: Path, tag: str, binary_zip: Path, out: Path) -> int:
    if out.exists():
        print(f"FEHLER: Zielordner existiert bereits: {out}")
        return 2
    if not binary_zip.is_file():
        print(f"FEHLER: Binary-ZIP existiert nicht: {binary_zip}")
        return 2

    tmp = out.parent / f"{out.name}.tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True, exist_ok=True)

    succeeded = False
    try:
        version = check_tag(root, tag)
        tree_findings = check_release.scan_tree_ref(root, f"refs/tags/{tag}")
        if tree_findings:
            details = "; ".join(f"{f.path}:{f.kind}" for f in tree_findings[:5])
            raise ReleaseIntegrityError(f"Tag-Baum {tag} enthaelt verbotene Eintraege: {details}")

        src_zip = build_source_zip(root, tag, version, tmp)
        prefix = f"Malaz-{version}/"
        diffs = verify_source_zip(root, tag, src_zip, prefix)
        if diffs:
            raise ReleaseIntegrityError("Source-ZIP weicht vom Tag-Baum ab: " + " | ".join(diffs))
        src_findings = check_release.scan_archive(src_zip, source=True)
        if src_findings:
            details = "; ".join(f"{f.path}:{f.kind}" for f in src_findings[:5])
            raise ReleaseIntegrityError(f"Source-ZIP vom Release-Gate abgewiesen: {details}")

        build_licenses_zip(root, tag, version, tmp)

        target_bin = tmp / f"Malaz-{version}.zip"
        shutil.copy2(binary_zip, target_bin)
        verify_binary_zip(target_bin, version, tmp)
        extract_sbom(target_bin, version, tmp)

        scratch_x = tmp / "_x"
        if scratch_x.exists():
            shutil.rmtree(scratch_x)

        write_checksums.write_sums(tmp, version, write_checksums.release_assets(version))
        os.replace(tmp, out)
        succeeded = True
        print(f"Release-Set {version} vollstaendig erzeugt unter: {out}")
        return 0
    except TagConfigError as exc:
        print(f"FEHLER (Konfiguration): {exc}")
        return 2
    except Exception as exc:
        print(f"FEHLER (Release-Integritaet): {exc}")
        return 1
    finally:
        if not succeeded and tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", required=True, help="Annotiertes Release-Tag, z. B. v1.0.0")
    ap.add_argument("--binary-zip", required=True, type=Path, help="Pfad zu Malaz-<ver>.zip")
    ap.add_argument("--out", required=True, type=Path, help="Neuer Ausgabeordner (z. B. dist/release-out)")
    ap.add_argument("--repo", type=Path, default=ROOT, help="Git-Repository-Wurzel")
    args = ap.parse_args(argv)
    return assemble_release(args.repo.resolve(), args.tag, args.binary_zip, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
