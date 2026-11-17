"""AP11: CAB/ISO members go through the 7-Zip recursion.

The runtime 7-Zip binary is not installed on this machine, so the extraction
path is proven with a mocked member iterator; the missing-binary path is proven
against the real `find_7z_binary` contract. Both sides matter: without 7-Zip
the container must stay visibly unexamined (YELLOW), never "clean".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core import sevenzip
from malaz.core.dispatcher import Dispatcher

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import make_test_corpus_extended as ext  # noqa: E402


def _dispatcher() -> Dispatcher:
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("archiv.cab", "cab"),
        ("abbild.iso", "iso"),
    ],
)
def test_missing_7zip_is_visible_and_not_clean(tmp_path, monkeypatch, name, kind):
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: None)
    path = tmp_path / name
    path.write_bytes(ext.cab_archive() if kind == "cab" else ext.iso_image())
    result = _dispatcher().scan_path(path)
    assert result.children, "der Container wurde nicht als Container erkannt"
    child = result.children[0]
    hit = next(i for i in child.indicators if i.rule_id == "ARCH_7Z_MISSING")
    assert hit.weight == 20
    assert "nicht als 'sauber'" in hit.detail
    assert child.risk_level.name != "GREEN"
    # TEST-039: the child was checked, the AGGREGATED verdict was not — a
    # regression that turns the container GREEN again stayed invisible.
    assert result.risk_level.name != "GREEN", (
        f"Container {name} ist {result.risk_level.name} ({result.score}) — "
        "ein ungeprüfter Inhalt darf nie GRÜN sein"
    )


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("archiv.cab", "cab"),
        ("abbild.iso", "iso"),
    ],
)
def test_cab_iso_members_are_scanned_when_7zip_exists(
    tmp_path, monkeypatch, name, kind
):
    members = [
        ("readme.txt", b"hello from the container", None),
        (
            "inner.pdf",
            b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n",
            None,
        ),
    ]
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("7z.exe"))
    monkeypatch.setattr(
        sevenzip,
        "iter_7z_members",
        lambda _data, _suffix, _passwords=None: iter(members),
    )
    path = tmp_path / name
    path.write_bytes(ext.cab_archive() if kind == "cab" else ext.iso_image())
    result = _dispatcher().scan_path(path)
    types = {child.detected_type for child in result.children}
    assert "text" in types, [c.detected_type for c in result.children]
    assert "pdf" in types, [c.detected_type for c in result.children]
    assert not any(
        i.rule_id == "ARCH_7Z_MISSING"
        for child in result.children
        for i in child.indicators
    )


def test_embedded_payload_is_not_reported_at_the_container(tmp_path):
    """CAB/ISO are recursed — no duplicate GEN_EMBEDDED on the container.

    `_embedded_signatures` deliberately skips every already-recursed container
    (zip/rar/7z/…). Before CAB/ISO joined that branch, an ISO holding an EXE
    produced a HIGH/30 container finding and the extracted member finding for
    the same bytes.
    """
    pe = (
        b"MZ"
        + b"\x00" * 58
        + (64).to_bytes(4, "little")
        + b"PE\x00\x00"
        + b"\x00" * 200
    )
    path = tmp_path / "payload.iso"
    path.write_bytes(ext.iso_image() + pe)
    result = _dispatcher().scan_path(path)
    ids = {i.rule_id for i in result.indicators}
    assert "GEN_EMBEDDED" not in ids, "Container meldet den extrahierten Inhalt doppelt"


def test_member_dropped_by_7zip_is_reported_not_clean(tmp_path, monkeypatch):
    """A member 7-Zip refuses to write must be visible, not silently gone.

    Measured with 7-Zip 26.05: a ZIP member named "evil.exe/" carrying 88
    bytes of PowerShell cradle lists as a file but extracts as an EMPTY
    DIRECTORY — the payload is dropped. The walk over the extraction directory
    then sees only the innocent member, and the archive scored clean.
    """
    members = [("evil.exe/", 88), ("ok.txt", 2)]

    def fake_extract(_binary, _archive, out_dir, _password, _timeout):
        (out_dir / "ok.txt").write_bytes(b"hi")  # the slash member is dropped
        return 0, ""

    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("7z.exe"))
    monkeypatch.setattr(
        sevenzip, "_list_members", lambda *_a, **_k: (0, members, "")
    )
    monkeypatch.setattr(sevenzip, "_extract", fake_extract)
    path = tmp_path / "archiv.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c")

    got = list(sevenzip.iter_7z_members(path.read_bytes(), ".7z"))
    errors = [e for _n, _p, e in got if e]
    assert errors, got
    assert "NICHT entpackt" in errors[0], errors
    assert "evil.exe" in errors[0], errors


def test_relative_7zip_candidate_is_ignored(tmp_path, monkeypatch):
    """A relative candidate must not resolve against the CWD.

    The promise is "never the current working directory": a 7z.exe dropped in
    the directory the scan was started from would otherwise be executed.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "7z.exe").write_bytes(b"MZ")
    monkeypatch.setattr(sevenzip.config, "SEVENZIP_CANDIDATES", ("7z.exe",))
    monkeypatch.setattr(sevenzip, "which_absolute", lambda _name: None)
    assert sevenzip.find_7z_binary() is None


def test_listing_timeout_mid_retry_stops_the_loop(monkeypatch, tmp_path):
    """A timeout during a password retry must abort, not try the next one.

    Measured cost without the break: len(candidate_passwords) x
    SEVENZIP_TIMEOUT_SECONDS = 8 x 120 s = 16 minutes for one archive.
    """
    calls = []

    def fake_list(_binary, _archive, _timeout, password=None):
        calls.append(password)
        return (-1, None, "timeout") if password is not None else (2, None, "no password")

    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("7z.exe"))
    monkeypatch.setattr(sevenzip, "_list_members", fake_list)
    monkeypatch.setattr(sevenzip.config, "load_zip_passwords", lambda: ["a", "b", "c", "d"])
    path = tmp_path / "archiv.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c")

    list(sevenzip.iter_7z_members(path.read_bytes(), ".7z"))
    assert len(calls) == 2, calls  # the first listing plus ONE retry


def test_undisplayable_password_does_not_escape(tmp_path):
    """A password with lone surrogates must not raise out of the listing.

    Measured: _list_members caught only TimeoutExpired/OSError, so the
    UnicodeEncodeError from .encode("utf-8") escaped and replaced the scan.
    """
    result = sevenzip._list_members(
        Path("7z.exe"), tmp_path / "x.7z", 5, "\udcff\udcfe"
    )
    assert result[0] == -1, result
    assert result[1] is None, result


def test_member_named_like_the_archive_is_still_listed(tmp_path, monkeypatch):
    """A member name may equal the archive's own absolute path.

    The listing parser dropped every entry whose Path equalled the archive
    path, on the theory that only the header block can look like that. ZIP
    allows any bytes in a name, so a real member was silently removed from the
    bomb pre-check (measured: an 86-byte member vanished, only ok.txt listed).
    """
    archive = tmp_path / "a.zip"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
    listing = (
        "Path = " + str(archive) + "\n"
        "Physical Size = 377\n"
        "----------\n"
        "Path = " + str(archive) + "\n"
        "Size = 86\n"
        "Path = ok.txt\n"
        "Size = 2\n"
    )
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("7z.exe"))
    monkeypatch.setattr(sevenzip, "_extract", lambda *_a, **_k: (1, "stop"))
    monkeypatch.setattr(
        sevenzip,
        "run_tool",
        lambda *_a, **_k: (0, listing.encode(), b""),
    )
    rc, members, _out = sevenzip._list_members(Path("7z.exe"), archive, 5)
    assert rc == 0, rc
    names = [name for name, _size in members]
    assert str(archive) in names, names
    assert "ok.txt" in names, names


def test_dropped_member_is_visible_even_with_a_twin(tmp_path, monkeypatch):
    """A harmless twin must not mask the dropped member.

    An archive can carry both "evil.exe/" (whose payload 7-Zip drops) and a
    harmless "evil.exe" (which lands on disk). A set lookup finds the
    normalised name and reports nothing — measured bypass. Counts are compared
    now.
    """
    members = [("evil.exe/", 88), ("evil.exe", 2), ("ok.txt", 2)]

    def fake_extract(_binary, _archive, out_dir, _password, _timeout):
        (out_dir / "evil.exe").write_bytes(b"hi")
        (out_dir / "ok.txt").write_bytes(b"hi")
        return 0, ""

    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("7z.exe"))
    monkeypatch.setattr(sevenzip, "_list_members", lambda *_a, **_k: (0, members, ""))
    monkeypatch.setattr(sevenzip, "_extract", fake_extract)
    path = tmp_path / "archiv.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c")

    got = list(sevenzip.iter_7z_members(path.read_bytes(), ".7z"))
    errors = [e for _n, _p, e in got if e]
    assert errors, got
    assert "NICHT entpackt" in errors[0], errors


def test_listing_without_member_block_is_not_trusted(tmp_path, monkeypatch):
    """rc=0 without a member block must not look like an empty archive.

    The caller treats an empty list as "listing fine" and runs its bomb
    pre-check over zero entries — extraction without any volume measurement.
    """
    monkeypatch.setattr(
        sevenzip, "run_tool", lambda *_a, **_k: (0, b"7-Zip 26.05\nPath = x\n", b"")
    )
    rc, members, _out = sevenzip._list_members(Path("7z.exe"), tmp_path / "a.7z", 5)
    assert rc == 0, rc
    assert members is None, members
