"""A path-backed source for files too large to hold in one buffer.

The dispatcher historically read every file into ``ctx.data``. That is fine
for ordinary documents and the short-prefix AV staging path, but it does not
scale to 2 GB. ``FileSource`` keeps the path and size, and exposes small,
bounded reads:

* ``prefix(n)`` for format detection and deep parsers that need a header,
* ``iter_chunks()`` for streaming hash/entropy/IOC passes.

It never allocates the whole file. A file that changes during the scan is
still caught by the dispatcher's pre/post stat check; consumers that read
later may see a newer revision, which is why the result reports a short/change
finding rather than claiming a coherent snapshot.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .. import config


@dataclass
class FileSource:
    path: Path
    size: int
    # Set when a streaming consumer stopped early because the per-file time
    # budget was reached. The dispatcher turns this into a visible finding;
    # silently returning a shorter scan would be a false all-clear.
    budget_exceeded: bool = field(default=False)

    @classmethod
    def from_path(cls, path: Path | str) -> FileSource:
        target = Path(path)
        return cls(target, target.stat().st_size)

    def prefix(self, limit: int) -> bytes:
        """Read at most ``limit`` bytes from the start (bounded)."""
        if limit <= 0:
            return b""
        with self.path.open("rb") as handle:
            return handle.read(limit)

    def iter_chunks(
        self,
        chunk_size: int | None = None,
        deadline: float | None = None,
    ) -> Iterator[bytes]:
        """Yield the file in bounded chunks; a short final chunk is normal.

        ``deadline`` is a ``time.monotonic()`` value. When it is reached the
        iterator stops and sets ``budget_exceeded``; callers must surface
        that as "not fully checked", never as a clean result.
        """
        size = max(1, int(chunk_size or config.MAX_STREAM_CHUNK))
        with self.path.open("rb") as handle:
            # An already-expired budget means the stage must not start at all.
            # Checked once, BEFORE the first read; an empty file is complete
            # without reading, so it is exempt.
            if (
                deadline is not None
                and self.size > 0
                and time.monotonic() >= deadline
            ):
                self.budget_exceeded = True
                return
            # One chunk of lookahead: the deadline is only meaningful when a
            # chunk is still WAITING behind it. Checking before the read made
            # a complete file end with ``budget_exceeded=True`` whenever the
            # budget ran out exactly at EOF (BUG-004) — a false "not
            # everything was checked" finding for 32 of 32 bytes read.
            pending = handle.read(size)
            while pending:
                following = handle.read(size)
                if not following:
                    # EOF is already proven: the last chunk is complete, the
                    # file was read in full, the budget did not cut anything.
                    yield pending
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    self.budget_exceeded = True
                    return
                yield pending
                pending = following
