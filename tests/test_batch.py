"""Tests for batch path expansion (CLI folder argument / dropped folders)."""

from pathlib import Path

from malaz.core.dispatcher import expand_scan_paths


def _mk(root: Path, rel: str, data: bytes = b"x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_single_file(tmp_path):
    f = _mk(tmp_path, "a.txt")
    files, truncated = expand_scan_paths([f])
    assert files == [f]
    assert truncated is False


def test_directory_is_walked_recursively(tmp_path):
    _mk(tmp_path, "top.txt")
    _mk(tmp_path, "sub/inner.txt")
    _mk(tmp_path, "sub/deep/leaf.txt")
    files, truncated = expand_scan_paths([tmp_path])
    names = {f.name for f in files}
    assert names == {"top.txt", "inner.txt", "leaf.txt"}
    assert truncated is False


def test_dedup_file_and_its_parent_dir(tmp_path):
    f = _mk(tmp_path, "a.txt")
    _mk(tmp_path, "b.txt")
    # a.txt is reachable both directly and via the directory walk.
    files, _ = expand_scan_paths([f, tmp_path])
    assert sorted(f.name for f in files) == ["a.txt", "b.txt"]
    assert len(files) == 2


def test_dedup_repeated_file(tmp_path):
    f = _mk(tmp_path, "a.txt")
    files, _ = expand_scan_paths([f, f, f])
    assert files == [f]


def test_truncation_at_cap(tmp_path):
    for i in range(5):
        _mk(tmp_path, f"f{i}.txt")
    files, truncated = expand_scan_paths([tmp_path], max_files=3)
    assert len(files) == 3
    assert truncated is True


def test_missing_path_is_skipped(tmp_path):
    f = _mk(tmp_path, "a.txt")
    files, truncated = expand_scan_paths([tmp_path / "nope.txt", f])
    assert files == [f]
    assert truncated is False


def test_mixed_files_and_dirs(tmp_path):
    loose = _mk(tmp_path, "loose.txt")
    _mk(tmp_path, "dir/in_dir.txt")
    files, _ = expand_scan_paths([loose, tmp_path / "dir"])
    assert sorted(f.name for f in files) == ["in_dir.txt", "loose.txt"]


def test_directory_walk_does_not_follow_junctions(tmp_path):
    """SEC-031: ``rglob`` folgte einer Junction aus dem gewaehlten Ordner heraus.

    Eine einzige Junction in einem fallengelassenen Ordner zog den gesamten
    Zielbaum (z. B. ``C:\\Windows``) in den Batch-Scan — der Auftrag
    "diesen Ordner scannen" weitete sich auf ein angreifergewaehltes
    Verzeichnis aus. ``os.scandir`` mit ``follow_symlinks=False`` sieht den
    Eintragstyp vor dem Absteigen und schneidet ihn ab.
    """
    import subprocess

    import pytest

    outside = tmp_path / "aussen"
    outside.mkdir()
    (outside / "ausserhalb.txt").write_bytes(b"x")
    root = tmp_path / "eingang"
    root.mkdir()
    (root / "harmlos.txt").write_bytes(b"y")

    link = root / "verknuepfung"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        capture_output=True,
        check=False,
    )
    if not link.exists():
        pytest.skip("Junction liess sich hier nicht anlegen (Rechte/Dateisystem)")

    files, truncated = expand_scan_paths([root])
    assert sorted(f.name for f in files) == ["harmlos.txt"], (
        "die Junction wurde verfolgt — fremder Baum im Scan"
    )
    assert truncated is False
