"""Tests for the resource-limit guards (security/limits.py)."""

import pytest

from malaz import config
from malaz.security.limits import (
    LimitExceeded,
    guard_file_size,
    guard_ratio,
    guard_read_size,
)


def test_guard_file_size_ok_and_exceeded(monkeypatch):
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 100)
    guard_file_size(100)  # exactly at the limit is allowed
    with pytest.raises(LimitExceeded) as exc:
        guard_file_size(101)
    assert exc.value.limit_kind == "file_size"


def test_guard_read_size_caps():
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(config, "MAX_READ_SIZE", 100)
    assert guard_read_size(50) == 50
    assert guard_read_size(10_000) == 100
    with pytest.raises(LimitExceeded):
        guard_read_size(-1)
    monkeypatch.undo()


def test_guard_ratio_ignores_non_positive_compressed(monkeypatch):
    monkeypatch.setattr(config, "MAX_COMPRESSION_RATIO", 100)
    # Cannot reason about a ratio with no compressed bytes: no exception.
    guard_ratio(0, 999_999)
    guard_ratio(-5, 999_999)


def test_guard_ratio_exceeded(monkeypatch):
    monkeypatch.setattr(config, "MAX_COMPRESSION_RATIO", 10)
    guard_ratio(100, 1000)  # ratio 10 is allowed
    with pytest.raises(LimitExceeded) as exc:
        guard_ratio(100, 1001)
    assert exc.value.limit_kind == "compression_ratio"


