"""Large-file streaming: bounded memory, full hash, visible partial stages."""

from __future__ import annotations

import hashlib

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.filesource import FileSource


def _dispatcher() -> Dispatcher:
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def test_file_source_chunks_are_bounded(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"x" * 100_000)
    source = FileSource.from_path(path)
    chunks = list(source.iter_chunks(8_192))
    assert sum(len(chunk) for chunk in chunks) == 100_000
    assert max(len(chunk) for chunk in chunks) <= 8_192


def test_large_file_uses_prefix_but_full_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_LARGE_FILE_SIZE", 1024 * 1024)
    monkeypatch.setattr(config, "MAX_LARGE_PREFIX_SIZE", 64 * 1024)
    data = b"x" * (2 * 1024 * 1024)
    path = tmp_path / "big.bin"
    path.write_bytes(data)
    result = _dispatcher().scan_path(path)
    assert result.size == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    ids = {indicator.rule_id for indicator in result.indicators}
    assert "CORE_READ_TRUNCATED" in ids
    assert result.risk_level.name == "YELLOW"  # partial, never GREEN
    # The streaming stages still ran over the whole file.
    names = {timing.name for timing in result.stage_timings}
    assert {"generic", "read+hash", "type"} <= names


def test_time_budget_stops_streaming_and_is_visible(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_LARGE_FILE_SIZE", 1024)
    monkeypatch.setattr(config, "MAX_LARGE_PREFIX_SIZE", 1024)
    monkeypatch.setattr(config, "MAX_FILE_SCAN_SECONDS", 0)
    path = tmp_path / "big.bin"
    path.write_bytes(b"y" * (2 * 1024 * 1024))
    result = _dispatcher().scan_path(path)
    ids = {indicator.rule_id for indicator in result.indicators}
    assert "CORE_TIME_BUDGET" in ids
    assert result.risk_level.name != "GREEN"


def test_file_source_complete_read_never_sets_budget(tmp_path, monkeypatch):
    """BUG-004: a deadline that expired at EOF is not a budget cut.

    The old check ran BEFORE the EOF read; after the final chunk it set
    ``budget_exceeded`` although all 32 of 32 bytes had been delivered.
    """
    from malaz.core import filesource

    path = tmp_path / "tiny.bin"
    path.write_bytes(b"x" * 32)
    source = FileSource.from_path(path)
    # The old code called monotonic() once before EVERY read: after the final
    # chunk the second call returned past the deadline and set the flag. The
    # first value must be inside the budget, the next one outside.
    times = iter([0.0, 999.0])
    monkeypatch.setattr(filesource.time, "monotonic", lambda: next(times, 999.0))

    chunks = list(source.iter_chunks(8_192, deadline=10.0))

    assert b"".join(chunks) == b"x" * 32
    assert source.budget_exceeded is False


def test_fast_large_scan_has_no_time_budget_marker(tmp_path, monkeypatch):
    """TEST-009: counter-test to CORE_TIME_BUDGET on a generous budget.

    Without it, a regression that always puts the deadline in the past stayed
    green: every existing test only asserted the POSITIVE marker.
    """
    monkeypatch.setattr(config, "MAX_LARGE_FILE_SIZE", 1024)
    monkeypatch.setattr(config, "MAX_LARGE_PREFIX_SIZE", 1024)
    monkeypatch.setattr(config, "MAX_FILE_SCAN_SECONDS", 3_600)
    path = tmp_path / "big.bin"
    path.write_bytes(b"z" * (2 * 1024 * 1024))

    result = _dispatcher().scan_path(path)

    ids = {indicator.rule_id for indicator in result.all_indicators()}
    assert "CORE_TIME_BUDGET" not in ids, sorted(ids)


def test_sparse_file_size_is_accepted_by_the_guard(tmp_path):
    path = tmp_path / "sparse.bin"
    with path.open("wb") as handle:
        handle.truncate(600 * 1024 * 1024)
    source = FileSource.from_path(path)
    assert source.size == 600 * 1024 * 1024
    assert len(source.prefix(1024)) == 1024
