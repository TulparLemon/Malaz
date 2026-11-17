"""Tests for scripts/make_release.py (T5, T6, T7, T8 + end-to-end assembly)."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

from scripts import check_release, make_release, verify_release_set


def _init_tagged_repo(repo: Path, *, init_ver: str = "1.0.0", include_license: bool = True) -> str:
    git = check_release._git_exe(repo)
    subprocess.run([git, "init", "-b", "main", str(repo)], check=True, capture_output=True)
    subprocess.run([git, "-C", str(repo), "config", "user.name", "t"], check=True)
    subprocess.run([git, "-C", str(repo), "config", "user.email", "t@t"], check=True)

    (repo / "src" / "malaz").mkdir(parents=True)
    (repo / "src" / "malaz" / "__init__.py").write_text(f'__version__ = "{init_ver}"\n', encoding="utf-8")
    if include_license:
        (repo / "LICENSE").write_text("GPL-3.0-or-later\n", encoding="utf-8")
    (repo / "THIRD_PARTY_NOTICES.md").write_text("# Notices\n", encoding="utf-8")
    (repo / "THIRD_PARTY_LICENSES").mkdir()
    (repo / "THIRD_PARTY_LICENSES" / "README.md").write_text("wheels\n", encoding="utf-8")
    (repo / "README.md").write_text("# Malaz\n", encoding="utf-8")

    subprocess.run([git, "-C", str(repo), "add", "."], check=True)
    subprocess.run([git, "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)
    return git


def _make_dummy_binary_zip(path: Path, ver: str = "1.0.0") -> Path:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "Malaz", "version": ver}},
        "components": [{"type": "library", "name": "pikepdf", "version": "10.17.0"}],
    }
    with zipfile.ZipFile(path, "w") as zf:
        zf.write(sys.executable, "Malaz.exe")
        zf.writestr("sbom.json", json.dumps(sbom))
        zf.writestr("LICENSE", "GPL-3.0-or-later\n")
    return path


def _run_mr(repo: Path, tag: str, bin_zip: Path, out: Path) -> int:
    return make_release.main(
        [
            "--repo",
            str(repo),
            "--tag",
            tag,
            "--binary-zip",
            str(bin_zip),
            "--out",
            str(out),
        ]
    )


def test_tag_validation_rejects_lightweight_branch_and_version_mismatch(tmp_path: Path):
    """T5: lightweight tag, branch of same name, version mismatch, existing <out> -> Exit 2."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git = _init_tagged_repo(repo, init_ver="1.0.0")
    bin_zip = _make_dummy_binary_zip(tmp_path / "Malaz-1.0.0.zip")

    subprocess.run([git, "-C", str(repo), "branch", "v1.0.0"], check=True)
    assert _run_mr(repo, "v1.0.0", bin_zip, tmp_path / "out1") == 2

    subprocess.run([git, "-C", str(repo), "tag", "v1.0.0"], check=True)
    assert _run_mr(repo, "v1.0.0", bin_zip, tmp_path / "out2") == 2
    subprocess.run([git, "-C", str(repo), "tag", "-d", "v1.0.0"], check=True)

    subprocess.run([git, "-C", str(repo), "tag", "-a", "v1.0.1", "-m", "mismatch"], check=True)
    assert _run_mr(repo, "v1.0.1", bin_zip, tmp_path / "out3") == 2

    existing_out = tmp_path / "existing"
    existing_out.mkdir()
    assert _run_mr(repo, "v1.0.1", bin_zip, existing_out) == 2


def test_verify_source_zip_catches_extra_missing_and_unprefixed_entries(tmp_path: Path):
    """T6: 1:1 parity between source ZIP and git ls-tree."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git = _init_tagged_repo(repo)
    subprocess.run([git, "-C", str(repo), "tag", "-a", "v1.0.0", "-m", "rel"], check=True)

    src_zip = make_release.build_source_zip(repo, "v1.0.0", "1.0.0", tmp_path)
    assert make_release.verify_source_zip(repo, "v1.0.0", src_zip, "Malaz-1.0.0/") == []

    with zipfile.ZipFile(src_zip, "a") as zf:
        zf.writestr("Malaz-1.0.0/SNEAKY_EXTRA.md", "extra")
        zf.writestr("NO_PREFIX.txt", "bad")
    diffs = make_release.verify_source_zip(repo, "v1.0.0", src_zip, "Malaz-1.0.0/")
    assert any("SNEAKY_EXTRA.md" in d for d in diffs)
    assert any("NO_PREFIX.txt" in d for d in diffs)


def test_missing_license_and_pe_mismatch_and_tmp_cleanup(tmp_path: Path, monkeypatch):
    """T7 & T8: missing LICENSE or mid-run failure leaves neither <out> nor <out>.tmp."""
    repo_nolic = tmp_path / "repo_nolic"
    repo_nolic.mkdir()
    git = _init_tagged_repo(repo_nolic, include_license=False)
    subprocess.run([git, "-C", str(repo_nolic), "tag", "-a", "v1.0.0", "-m", "rel"], check=True)
    bin_zip = _make_dummy_binary_zip(tmp_path / "Malaz-1.0.0.zip")
    out_nolic = tmp_path / "out.nolic"
    assert _run_mr(repo_nolic, "v1.0.0", bin_zip, out_nolic) == 1
    assert not out_nolic.exists()
    assert not (tmp_path / "out.nolic.tmp").exists()

    repo = tmp_path / "repo"
    repo.mkdir()
    git = _init_tagged_repo(repo, include_license=True)
    subprocess.run([git, "-C", str(repo), "tag", "-a", "v1.0.0", "-m", "rel"], check=True)
    out_pe = tmp_path / "out.pe"
    assert _run_mr(repo, "v1.0.0", bin_zip, out_pe) == 1
    assert not out_pe.exists()
    assert not (tmp_path / "out.pe.tmp").exists()

    monkeypatch.setattr(
        make_release.check_release,
        "scan_archive",
        lambda p, *, source=False: [check_release.Finding("x", "forbidden-runtime-file", "injected")],
    )
    out_fail = tmp_path / "out.fail"
    assert _run_mr(repo, "v1.0.0", bin_zip, out_fail) == 1
    assert not out_fail.exists()
    assert not (tmp_path / "out.fail.tmp").exists()


def test_happy_path_assembles_complete_verified_release_set(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = _init_tagged_repo(repo)
    subprocess.run([git, "-C", str(repo), "tag", "-a", "v1.0.0", "-m", "Malaz 1.0.0"], check=True)
    bin_zip = _make_dummy_binary_zip(tmp_path / "Malaz-1.0.0.zip")

    monkeypatch.setattr(make_release, "_read_pe_versions", lambda _exe: ("1.0.0.0", "1.0.0.0"))
    out = tmp_path / "release-out"
    assert _run_mr(repo, "v1.0.0", bin_zip, out) == 0
    assert out.is_dir()
    assert not (tmp_path / "release-out.tmp").exists()
    assert verify_release_set.main([str(out)]) == 3
