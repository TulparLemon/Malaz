"""RTF embedded-object extraction (OLE payloads inside rich text).

RTF documents can embed OLE objects (``\\objdata`` / ``\\objemb``), the
classic CVE-2017-11882 delivery vehicle: a malicious equation-editor object
whose payload is a full OLE compound document, hex-encoded inside the RTF
source. Until now RTF files only received the generic surface checks, so the
embedded Office payload was never analysed.

This module scans the RTF source for ``\\objdata`` hex blobs, decodes them and
yields each blob whose content looks like an embedded container (OLE CFB, ZIP,
or any other magic signature). The dispatcher feeds them back into the normal
analysis loop, where an OLE payload runs through the Office/VBA pipeline.

Security notes:
* pure static decoding of hex data — nothing is ever executed or written to
  disk;
* blob size is bounded by the configured limits before decoding;
* the RTF source is attacker-controlled text; the hex parser is defensive;
* a blob only counts against the object limit once it decodes to a container
  (decoys cannot fill the cap), and a tripped limit is reported as a name-less
  container note instead of ending the walk silently.
"""

from __future__ import annotations

import binascii
import re
from collections.abc import Iterator

from .. import config
from .archive import BUDGET_STOP_PREFIX

# \objdata<hex> — real RTF writers wrap the hex block with \r\n and spaces,
# so the pattern must tolerate whitespace inside the blob (it is stripped
# before decoding). The run ends at the next backslash command or brace.
_OBJDATA_RE = re.compile(rb"\\objdata\s+([0-9a-fA-F\s]+)")

# Known container magics worth recursing into (>= 4 bytes, no false-positive
# magnets like "MZ"/"BM").
_CONTAINER_MAGICS = (
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
)

_MAX_OBJECTS = config.MAX_ARCHIVE_ENTRIES


def iter_rtf_objects(data: bytes) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(name, payload, error)`` for every embedded RTF object.

    Only blobs that decode to a known container magic are yielded (the generic
    pipeline already scans the raw RTF text otherwise). Blobs larger than the
    per-object limit yield an error entry instead of their content.

    Both limits yield a name-less ``BUDGET_STOP_PREFIX`` note when they trip:
    a walk that stops early leaves objects unexamined, and an empty iterator
    for a file full of ``\\objdata`` blobs reads as "nothing inside".
    """
    if not data:
        return
    per_object = config.MAX_EXTRACTED_FILE_SIZE
    processed = 0
    total = 0
    for match in _OBJDATA_RE.finditer(data):
        hex_blob = re.sub(rb"\s+", b"", match.group(1))
        if len(hex_blob) // 2 > per_object:
            # Declared but undecodable: this IS an object, so it counts.
            if processed >= _MAX_OBJECTS:
                yield _object_limit_note()
                return
            processed += 1
            yield (
                f"objdata_{processed}.bin",
                b"",
                (f"Eingebettetes Objekt zu groß "
                 f"({len(hex_blob) // 2} Bytes > {per_object})"),
            )
            continue
        try:
            payload = binascii.unhexlify(hex_blob)
        except (binascii.Error, ValueError):
            continue  # not a clean hex run; ignore this match
        if not payload:
            continue
        label = _container_label(payload)
        if label is None:
            continue  # not a container worth recursing into
        # Only a blob that survived every filter above counts against the
        # limit. Counting raw regex matches made the cap attacker-fillable:
        # `\objdata 00 ` costs 12 bytes, decodes to a byte that is no
        # container, and still consumed one slot of MAX_ARCHIVE_ENTRIES.
        # Measured: 10 005 such decoys in front of a real embedded object
        # turned RED 100 into GREEN 0 — the payload was never decoded.
        if processed >= _MAX_OBJECTS:
            yield _object_limit_note()
            return
        if total + len(payload) > config.MAX_UNCOMPRESSED_SIZE:
            yield (
                "",
                b"",
                (f"{BUDGET_STOP_PREFIX} Gesamtvolumen {config.MAX_UNCOMPRESSED_SIZE} "
                 "Bytes erreicht — weitere eingebettete Objekte wurden NICHT "
                 "analysiert."),
            )
            return
        processed += 1
        total += len(payload)
        yield (f"embedded_{label}_{processed}.bin", payload, None)


def _object_limit_note() -> tuple[str, bytes, str]:
    """The name-less container note for a tripped object cap.

    Same convention as ZIP/TAR/7z: the dispatcher turns it into a visible
    "archive not fully analysed" finding (ARCH_MEMBER_STOP, weight 25).
    """
    return (
        "",
        b"",
        (f"{BUDGET_STOP_PREFIX} Objekt-Limit {_MAX_OBJECTS} erreicht — weitere "
         "eingebettete Objekte wurden NICHT analysiert."),
    )


def _container_label(payload: bytes) -> str | None:
    """Return the container label when ``payload`` starts with a known
    magic; ``None`` otherwise (payload is not worth recursing into)."""
    for magic, label in _CONTAINER_MAGICS:
        if payload.startswith(magic):
            return label
    return None
