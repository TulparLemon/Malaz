"""AP8: entropy baselines for the new media types.

WebP/MP3/MP4 are compressed by specification, so a normal file sits near
8 bit/byte and GEN_ENTROPY must not score it. TIFF and ICO can carry
*uncompressed* payloads, so the same high entropy must stay a finding there —
otherwise the suppression would swallow embedded content.
"""

from __future__ import annotations

import random
import struct

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.scoring import BASE_WEIGHTS


def _noise(seed: int, size: int = 8192) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


def _box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def _webp(payload: bytes) -> bytes:
    return b"RIFF" + struct.pack("<I", 8 + len(payload)) + b"WEBP" + b"VP8 " + payload


def _mp3(payload: bytes) -> bytes:
    return b"ID3\x03\x00\x00\x00\x00\x00\x0a" + payload


def _mp4(payload: bytes) -> bytes:
    return (
        _box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"mp42")
        + _box(b"mdat", payload)
    )


def _tiff(payload: bytes) -> bytes:
    return b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 0) + payload


def _ico(payload: bytes) -> bytes:
    return (
        b"\x00\x00\x01\x00"
        + struct.pack("<H", 1)
        + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(payload), 22)
        + payload
    )


def _scan(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(path)


@pytest.mark.parametrize(
    ("name", "builder", "ftype"),
    [
        ("noise.webp", _webp, "webp"),
        ("noise.mp3", _mp3, "mp3"),
        ("noise.mp4", _mp4, "mp4"),
    ],
)
def test_compressed_media_does_not_score_entropy(tmp_path, name, builder, ftype):
    result = _scan(tmp_path, name, builder(_noise(101)))
    assert result.detected_type == ftype
    entropie = [i for i in result.all_indicators() if i.rule_id == "GEN_ENTROPY"]
    assert entropie, "die Entropie-Stufe lief gar nicht"
    assert all(i.effective_weight(BASE_WEIGHTS) == 0 for i in entropie)
    assert result.risk_level.name == "GREEN", f"{result.risk_level.name}/{result.score}"


@pytest.mark.parametrize(
    ("name", "builder", "ftype"),
    [
        ("noise.tiff", _tiff, "tiff"),
        ("noise.ico", _ico, "ico"),
    ],
)
def test_uncompressed_images_keep_the_entropy_finding(tmp_path, name, builder, ftype):
    result = _scan(tmp_path, name, builder(_noise(102)))
    assert result.detected_type == ftype
    entropie = [
        i
        for i in result.all_indicators()
        if i.rule_id == "GEN_ENTROPY" and i.effective_weight(BASE_WEIGHTS) > 0
    ]
    assert entropie, (
        f"{name}: hohe Entropie wurde pauschal unterdrückt — TIFF/ICO sind "
        "nicht spezifikationskomprimiert"
    )
    assert result.risk_level.name in ("YELLOW", "RED")
