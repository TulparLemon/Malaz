"""Microsoft OneNote (.one) embedded FileDataStoreObject extraction.

Implements static MS-ONESTORE ``FileDataStoreObject`` carving (Spec 014):
scans the raw ``.one`` byte stream linearly for embedded attachment blocks
framed by the fixed 16-byte header and footer GUIDs and yields each payload
back to the dispatcher for full recursive pipeline scanning.

Security notes:
* Pure static binary slicing — nothing is ever executed or written to disk.
* Strictly linear O(N) scan via ``bytes.find`` (zero regex backtracking).
* Bounded by ``config.MAX_ARCHIVE_ENTRIES``, ``config.MAX_EXTRACTED_FILE_SIZE``
  and ``config.MAX_UNCOMPRESSED_SIZE``; hitting a cap yields a name-less
  ``BUDGET_STOP_PREFIX`` note instead of ending silently.
* Corrupt, truncated or invalid-footer objects emit an explicit error entry
  (``ONENOTE_OBJ_ERROR``, marked incomplete) so damaged containers never appear
  as clean GREEN.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

from .. import config
from . import magic
from .archive import BUDGET_STOP_PREFIX

# MS-ONESTORE FileDataStoreObject GUIDs (little-endian binary layout):
# Header: {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
# Footer: {71FBA722-0F79-4A0B-BB13-899256426B24}
_FDSO_HEADER = b"\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac"
_FDSO_FOOTER = b"\x22\xa7\xfb\x71\x79\x0f\x0b\x4a\xbb\x13\x89\x92\x56\x42\x6b\x24"
_FDSO_HEADER_SIZE = 36  # guidHeader(16) + cbLength(8) + unused(4) + reserved(8)
_FDSO_FOOTER_SIZE = 16

_BINARY_EXT_MAP: dict[str, str] = {
    "pe": ".exe",
    "zip": ".zip",
    "rar": ".rar",
    "7z": ".7z",
    "cab": ".cab",
    "iso": ".iso",
    "chm": ".chm",
    "vhdx": ".vhdx",
    "ntfs": ".ntfs",
    "fat": ".fat",
    "onenote": ".one",
    "lnk": ".lnk",
    "pdf": ".pdf",
    "ole": ".ole",
    "rtf": ".rtf",
    "eml": ".eml",
    "png": ".png",
    "jpeg": ".jpg",
    "gif": ".gif",
    "bmp": ".bmp",
    "webp": ".webp",
    "gzip": ".gz",
    "bzip2": ".bz2",
    "xz": ".xz",
    "tar": ".tar",
    "elf": ".elf",
    "macho": ".macho",
    "url": ".url",
}


def _infer_ext(payload: bytes) -> str:
    """Infer a safe canonical file extension from payload magic/text heuristics."""
    ftype = magic.detect(payload[:65536]).type
    ext = _BINARY_EXT_MAP.get(ftype)
    if ext is not None:
        return ext
    if ftype in ("text", "html", "xml"):
        text = payload[:32768].decode("utf-8", errors="replace")
        low = text.lower()
        if "<hta:application" in low:
            return ".hta"
        if "<job" in low and "<script" in low:
            return ".wsf"
        if magic.is_svg_root(text):
            return ".svg"
        if ftype == "html":
            return ".html"
        if ftype == "xml":
            return ".xml"
        if any(
            tok in low
            for tok in ("wscript.shell", "createobject(", "end sub")
        ):
            return ".vbs"
        if any(
            tok in low
            for tok in ("@echo off", "setlocal", "goto :")
        ):
            return ".bat"
        if any(
            tok in low
            for tok in (
                "invoke-expression",
                "iex ",
                "downloadstring",
                "start-process",
                "frombase64string",
                "powershell",
            )
        ):
            return ".ps1"
        if any(tok in low for tok in ("dim ", "sub ")):
            return ".vbs"
        if any(tok in low for tok in ("cmd.exe", "cmd /c")):
            return ".bat"
        if any(
            tok in low
            for tok in (
                "activexobject",
                "wscript.createobject",
                "function ",
                "var ",
                "const ",
            )
        ):
            return ".js"
        return ".txt"
    return ".bin"


def iter_onenote_objects(data: bytes) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(name, payload, error)`` for every embedded FileDataStoreObject."""
    if not data:
        return

    max_entries = config.MAX_ARCHIVE_ENTRIES
    per_object = config.MAX_EXTRACTED_FILE_SIZE
    max_total = config.MAX_UNCOMPRESSED_SIZE

    processed = 0
    total = 0
    pos = 0
    n = len(data)

    while pos < n:
        found = data.find(_FDSO_HEADER, pos)
        if found == -1:
            break
        pos = found

        # Enforce cap only once another header is actually encountered so
        # exactly ``max_entries`` valid objects never emit a false budget note.
        if processed >= max_entries:
            yield (
                "",
                b"",
                (
                    f"{BUDGET_STOP_PREFIX}Objekt-Limit ({max_entries}) erreicht — "
                    "restliche OneNote-Objekte wurden nicht geprüft."
                ),
            )
            return

        if pos + _FDSO_HEADER_SIZE > n:
            processed += 1
            yield (
                f"onenote_obj_{processed}.bin",
                b"",
                "Abgeschnittener OneNote-Objektheader — Objekt nicht lesbar.",
            )
            break

        (cb_length,) = struct.unpack_from("<Q", data, pos + 16)

        if cb_length == 0:
            footer_pos = pos + _FDSO_HEADER_SIZE
            if (
                footer_pos + _FDSO_FOOTER_SIZE <= n
                and data[footer_pos : footer_pos + _FDSO_FOOTER_SIZE] == _FDSO_FOOTER
            ):
                # Genuine zero-length placeholder: skip cleanly without alarm.
                pos = footer_pos + _FDSO_FOOTER_SIZE
                continue
            processed += 1
            yield (
                f"onenote_obj_{processed}.bin",
                b"",
                "Beschädigtes OneNote-Objekt (Länge 0 ohne gültigen Footer).",
            )
            pos += len(_FDSO_HEADER)
            continue

        if cb_length > per_object:
            processed += 1
            yield (
                f"onenote_obj_{processed}.bin",
                b"",
                (
                    f"Eingebettetes OneNote-Objekt überschreitet Größenlimit "
                    f"({cb_length} > {per_object} Bytes) — nicht geprüft."
                ),
            )
            pos += len(_FDSO_HEADER)
            continue

        if total + cb_length > max_total:
            yield (
                "",
                b"",
                (
                    f"{BUDGET_STOP_PREFIX}Gesamtgrößen-Limit ({max_total} Bytes) erreicht — "
                    "restliche OneNote-Objekte wurden nicht geprüft."
                ),
            )
            return

        payload_start = pos + _FDSO_HEADER_SIZE
        payload_end = payload_start + cb_length
        pad = (-cb_length) % 8
        footer_pos = payload_end + pad

        if (
            footer_pos + _FDSO_FOOTER_SIZE > n
            or data[footer_pos : footer_pos + _FDSO_FOOTER_SIZE] != _FDSO_FOOTER
        ):
            processed += 1
            yield (
                f"onenote_obj_{processed}.bin",
                b"",
                "Abgeschnittenes oder beschädigtes OneNote-Objekt (Footer fehlt/abweichend).",
            )
            pos += len(_FDSO_HEADER)
            continue

        payload = data[payload_start:payload_end]
        processed += 1
        total += cb_length
        pos = footer_pos + _FDSO_FOOTER_SIZE
        yield (f"onenote_obj_{processed}{_infer_ext(payload)}", payload, None)
