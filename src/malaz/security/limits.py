"""Resource-exhaustion (DoS) guards.

These guards enforce hard limits on file size, read volume and archive
expansion so that oversized files or zip bombs cannot exhaust memory or disk.
Callers translate :class:`LimitExceeded` into a (usually HIGH) indicator rather
than crashing.
"""

from __future__ import annotations

from .. import config


class LimitExceeded(Exception):
    """Raised when a configured resource limit is exceeded."""

    def __init__(self, message: str, limit_kind: str = "generic"):
        super().__init__(message)
        self.limit_kind = limit_kind


def guard_file_size(size: int) -> None:
    """Reject files larger than ``config.MAX_FILE_SIZE``."""
    if size > config.MAX_FILE_SIZE:
        raise LimitExceeded(
            f"Datei zu groß: {size} Bytes > Limit {config.MAX_FILE_SIZE} Bytes",
            limit_kind="file_size",
        )


def guard_read_size(size: int) -> int:
    """Return the number of bytes safe to read into memory (capped)."""
    if size < 0:
        raise LimitExceeded("Negative Dateigröße", limit_kind="file_size")
    return min(size, config.MAX_READ_SIZE)


def guard_ratio(compressed: int, uncompressed: int) -> None:
    """Reject archives whose expansion ratio exceeds the configured maximum."""
    if compressed <= 0:
        # Cannot reason about ratio; rely on absolute size guards instead.
        return
    ratio = uncompressed / compressed
    if ratio > config.MAX_COMPRESSION_RATIO:
        raise LimitExceeded(
            f"Kompressionsverhältnis zu hoch: {ratio:.0f}:1 > "
            f"{config.MAX_COMPRESSION_RATIO}:1 (Zip-Bomben-Verdacht)",
            limit_kind="compression_ratio",
        )


