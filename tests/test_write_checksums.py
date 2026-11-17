"""Tests for scripts/write_checksums.py (T9)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import write_checksums


def test_write_and_parse_sums_roundtrip_four_assets(tmp_path: Path):
    ver = "1.0.0"
    names = write_checksums.release_assets(ver)
    assert names == [
        "Malaz-1.0.0.zip",
        "Malaz-1.0.0-source.zip",
        "Malaz-1.0.0-licenses.zip",
        "sbom.json",
    ]
    for idx, name in enumerate(names, 1):
        (tmp_path / name).write_bytes(b"x" * (idx * 10))

    manifest = write_checksums.write_sums(tmp_path, ver, names)
    raw_bytes = manifest.read_bytes()
    assert b"\r\n" not in raw_bytes
    parsed = write_checksums.parse_sums(manifest)
    assert list(parsed.keys()) == names
    for idx, name in enumerate(names, 1):
        digest, size = parsed[name]
        assert len(digest) == 64 and digest == digest.upper()
        assert size == idx * 10

    rc = write_checksums.main(["--version", ver, "--dist", str(tmp_path), "--include-sbom"])
    assert rc == 0


@pytest.mark.parametrize(
    "bad_content",
    [
        "",
        "   \n\n",
        "not-a-valid-line\n",
        "A" * 64 + "  ../evil.zip  (10 Bytes)\n",
        "A" * 64 + "  dup.zip  (10 Bytes)\n" + "B" * 64 + "  dup.zip  (10 Bytes)\n",
    ],
)
def test_parse_sums_rejects_empty_malformed_unsafe_and_duplicate(tmp_path: Path, bad_content: str):
    p = tmp_path / "SHA256SUMS-1.0.0.txt"
    p.write_text(bad_content, encoding="utf-8")
    with pytest.raises(ValueError):
        write_checksums.parse_sums(p)


def test_cli_returns_2_when_asset_missing(tmp_path: Path):
    assert write_checksums.main(["--version", "1.0.0", "--dist", str(tmp_path)]) == 2
