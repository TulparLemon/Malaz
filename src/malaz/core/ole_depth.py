"""How deep olefile's recursive directory walk can go, and the stack it needs.

This module exists because **two** sibling call sites drive the same library:
the Office stages (``pipelines/office_pipeline.py``) and the Outlook/``.msg``
probe (``core/mail_view.py``). Hardening only one of them is a detection hole
with a familiar shape — the same control applied at one of two places, so the
untouched path stays the quiet way around it. Measured: after the Office stages
were given the headroom below, a container with 496 nested storages was walked
by them, while ``probe_outlook_msg`` still raised ``RecursionError`` on the very
same bytes and reported the container as unreadable.

The two facts live here, together, because they are one decision:

* :func:`directory_frames` estimates — *iteratively*, before the library is
  called — how many Python frames ``olefile.append_kids`` will need for this
  container's directory tree. The tree's shape is file content, so this is the
  attacker's number, not ours.
* :func:`ensure_walk_limit` gives the walk the interpreter stack it needs —
  once, at import, because ``sys.setrecursionlimit`` is process-global and the
  scanner walks containers from a thread pool. :func:`walk_headroom` is the
  per-call marker every olefile caller carries.

Why raising the recursion limit is the right lever here: on CPython 3.12 a
pure-Python recursion (``append_kids`` is pure Python) no longer consumes C
stack per call, the interpreter's own limit is the only bound, and the depth is
measured beforehand. Measured with the limit raised to the estimate: 496, 700,
1200 and 2000 nested storages all walked without a ``RecursionError``. Refusing
at a fixed depth was wrong in both directions — round 3's 500-frame ceiling let
a macro document padded with 476 storages lose its entire macro evidence, and a
ceiling read from ``sys.getrecursionlimit()`` made the same bytes pass or fail
depending only on how deep the caller happened to be — and raising it *per walk*
was wrong a third time, because that read-modify-restore on a process-global
lost one thread's headroom to another thread's restore (see
:func:`ensure_walk_limit`).

Beyond :data:`HARD_MAX_FRAMES` the walk gets no further headroom and the caller
must report "not checked" — a refusal that is visible and weighted, never
silent. The bound is structural: the directory read is capped at
:data:`MAX_DIRECTORY_SECTORS`, so a tree cannot be padded without limit.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
CFB_FREESECT = 0xFFFFFFFF
CFB_ENDOFCHAIN = 0xFFFFFFFE
CFB_NOSTREAM = 0xFFFFFFFF
CFB_DIR_ENTRY = 128
# Directory sectors read for the depth estimate (2 MiB = 16k entries — orders
# of magnitude above any real document, and far beyond the depth that matters).
MAX_DIRECTORY_SECTORS = 4096

# Hard ceiling for the walk: beyond it the caller reports "not checked" instead
# of extending the interpreter further.
HARD_MAX_FRAMES = 8192


def ensure_walk_limit() -> int:
    """Make the interpreter able to walk the deepest container we accept.

    The limit is process-global, so this is a one-time decision rather than a
    per-walk one. Per walk it was a read-modify-restore on that global with no
    lock, and the scanner walks containers from a thread pool: measured, thread
    A's ``finally`` put the limit back to 1000 while thread B was still inside
    the walk it had been granted (B saw A's raised limit, found it sufficient
    and raised nothing itself) — 3 of 40 parallel scans lost their DDE stage to
    a ``RecursionError``, against 0 of 10 sequential ones. Same bytes, same
    code, verdict decided by the order of parallel scans.

    Installing the ceiling once removes the race without a lock: the only value
    ever written is the constant :data:`HARD_MAX_FRAMES`, so a concurrent
    second writer writes the same number — and nothing is ever *lowered*, which
    is what took the headroom away. The height is exactly the bound the callers
    already refuse at: a walk that was accepted before (caller depth + needed
    frames <= ``HARD_MAX_FRAMES``) fits this limit, and one beyond it still
    fails in the library, visibly, exactly as it did then. Because the limit no
    longer depends on where the caller stands, the measurement that motivated
    it (476 storages = 954 walk frames: fine from a bare script, ``RecursionError``
    under pytest) stops deciding the outcome.

    Not a stack risk on CPython 3.12: a higher *Python* limit does not raise the
    C stack guard, which is counted separately — measured with the limit at
    8192, ``repr()`` of a 6000-deep nested list and ``json.dumps`` of it still
    raise ``RecursionError`` instead of crashing. Pure-Python frames are
    heap-allocated there, the same reason raising the limit was the right lever
    for ``append_kids`` at all.
    """
    limit = sys.getrecursionlimit()
    if limit < HARD_MAX_FRAMES:
        sys.setrecursionlimit(HARD_MAX_FRAMES)
        return HARD_MAX_FRAMES
    return limit


@contextmanager
def walk_headroom(frames: int | None):
    """Announce a walk of ``frames`` frames and make sure it has the stack.

    ``frames`` comes from :func:`directory_frames`. ``None`` or a non-positive
    value means "not measurable": nothing is raised, the library is tried as
    before and its own failure is the caller's news to report.

    Every caller that hands an attacker-controlled directory tree to olefile
    goes through here — the Office stages, ``parse_msg``/``probe_outlook_msg``
    and the ``.msg`` attachment walk. The marker is the point: the third caller
    was missing it, and the same container was readable in two paths and
    "unreadable" in the third. The headroom itself is installed once (see
    :func:`ensure_walk_limit`), so this no longer raises and restores the limit
    per walk; it re-asserts it should anything else have lowered it.
    """
    if frames is not None and frames > 0:
        ensure_walk_limit()
    yield


def directory_too_deep(frames: int | None) -> bool:
    """Can olefile's recursive walk not be attempted at all?

    ``None`` means "not measurable here" and answers ``False``: the library is
    then tried as before and its own failure is reported by the caller.
    """
    return frames is not None and frames > HARD_MAX_FRAMES


def directory_frames(blob: bytes) -> int | None:
    """Frames olefile needs to walk this container's directory tree.

    Estimated *iteratively* from the raw header/FAT/directory sectors — before
    the library is called and without touching its recursion. ``sid_left``,
    ``sid_right`` and ``sid_child`` of every entry are followed; entries
    reached twice count once, mirroring olefile's ``used`` flag.

    ``None`` means "not measurable here" (not a CFB, broken FAT, no directory
    chain): the library is then tried as before and its own failure is reported
    by the caller.
    """
    size = len(blob)
    if size < 2 * 512 or blob[:8] != CFB_MAGIC:
        return None
    shift = int.from_bytes(blob[30:32], "little")
    if shift not in (9, 12):  # only the two sector sizes MS-CFB defines
        return None
    sector = 1 << shift

    def sector_bytes(sid: int) -> bytes | None:
        start = (sid + 1) * sector
        if sid < 0 or start + sector > size:
            return None
        return blob[start : start + sector]

    # FAT sector ids: the first 109 sit in the header, the rest in the DIFAT
    # chain (bounded — a hostile DIFAT length must not become the DoS).
    fat_ids: list[int] = []
    for i in range(109):
        sid = int.from_bytes(blob[76 + 4 * i : 80 + 4 * i], "little")
        if sid == CFB_FREESECT:
            break
        fat_ids.append(sid)
    difat = int.from_bytes(blob[68:72], "little")
    for _ in range(min(int.from_bytes(blob[72:76], "little"), 1024)):
        raw = sector_bytes(difat)
        if raw is None:
            break
        for i in range(sector // 4 - 1):
            sid = int.from_bytes(raw[4 * i : 4 * i + 4], "little")
            if sid != CFB_FREESECT:
                fat_ids.append(sid)
        difat = int.from_bytes(raw[-4:], "little")
    fat = bytearray()
    for sid in fat_ids:
        chunk = sector_bytes(sid)
        if chunk is None:
            break
        fat += chunk
    if not fat:
        return None

    def chain(start: int) -> list[int]:
        seen: set[int] = set()
        out: list[int] = []
        sid = start
        while sid not in (CFB_ENDOFCHAIN, CFB_FREESECT) and sid not in seen:
            if sector_bytes(sid) is None:
                break
            seen.add(sid)
            out.append(sid)
            off = 4 * sid
            if off + 4 > len(fat):
                break
            sid = int.from_bytes(fat[off : off + 4], "little")
        return out

    dirent = b"".join(
        sector_bytes(s) or b""
        for s in chain(int.from_bytes(blob[48:52], "little"))[:MAX_DIRECTORY_SECTORS]
    )
    count = len(dirent) // CFB_DIR_ENTRY
    if count < 2:  # root entry + at least one more
        return None

    def sid_field(idx: int, offset: int) -> int:
        base = idx * CFB_DIR_ENTRY + offset
        return int.from_bytes(dirent[base : base + 4], "little")

    root_child = sid_field(0, 76)
    frames: dict[int, int] = {}
    claimed: set[int] = set()
    stack: list[tuple[int, bool]] = []
    if root_child != CFB_NOSTREAM and 0 <= root_child < count:
        stack.append((root_child, False))
        claimed.add(root_child)
    while stack:
        sid, children_done = stack.pop()
        if children_done:
            deepest = max(
                frames.get(sid_field(sid, 68), 0),
                frames.get(sid_field(sid, 72), 0),
                # sid_child is entered through build_storage_tree (one more frame).
                1 + frames.get(sid_field(sid, 76), 0),
            )
            frames[sid] = 1 + deepest
            continue
        stack.append((sid, True))
        for nxt in (sid_field(sid, 68), sid_field(sid, 72), sid_field(sid, 76)):
            if nxt != CFB_NOSTREAM and 0 <= nxt < count and nxt not in claimed:
                claimed.add(nxt)
                stack.append((nxt, False))
    return frames.get(root_child, 0)


# The process is ready to walk the deepest container we accept as soon as this
# module is imported — the install cannot be forgotten at a call site, which is
# the failure mode this module exists for.
ensure_walk_limit()

