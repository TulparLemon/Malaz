"""Vectorized Shannon entropy.

High entropy (> 7.5 on the 0..8 byte scale) indicates encrypted, packed or
otherwise hidden payloads. The hot path uses NumPy's ``bincount`` which is
10-100x faster than a pure-Python loop; a pure-Python fallback keeps the feature
available when NumPy is missing.
"""

from __future__ import annotations

import math

from .. import config

try:  # optional dependency
    import numpy as _np

    _HAVE_NUMPY = True
except Exception:  # pragma: no cover - exercised only without numpy
    _np = None  # type: ignore[assignment]
    _HAVE_NUMPY = False


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0

    if _HAVE_NUMPY:
        arr = _np.frombuffer(data, dtype=_np.uint8)
        counts = _np.bincount(arr, minlength=256).astype(_np.float64)
        probs = counts[counts > 0] / arr.size
        return float(-(probs * _np.log2(probs)).sum())

    # Pure-Python fallback.
    length = len(data)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy_chunks(chunks) -> float:
    """Shannon entropy over an iterable of byte chunks, without joining them."""
    if _HAVE_NUMPY:
        counts = _np.zeros(256, dtype=_np.int64)
        total = 0
        for chunk in chunks:
            if not chunk:
                continue
            arr = _np.frombuffer(chunk, dtype=_np.uint8)
            counts += _np.bincount(arr, minlength=256)
            total += int(arr.size)
        if total == 0:
            return 0.0
        nonzero = counts[counts > 0].astype(_np.float64)
        probs = nonzero / total
        return float(-(probs * _np.log2(probs)).sum())

    freq = [0] * 256
    total = 0
    for chunk in chunks:
        for byte in chunk:
            freq[byte] += 1
            total += 1
    if not total:
        return 0.0
    entropy = 0.0
    for count in freq:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def entropy_indicator_weight(entropy: float) -> int:
    """Map an entropy value to a score weight (0 when unremarkable).

    Scales linearly between the configured thresholds so that borderline values
    do not jump straight to the maximum weight.
    """
    if entropy < config.ENTROPY_HIGH:
        return 0
    if entropy >= config.ENTROPY_VERY_HIGH:
        return 30
    # Linear ramp between ENTROPY_HIGH (->5) and ENTROPY_VERY_HIGH (->30).
    span = config.ENTROPY_VERY_HIGH - config.ENTROPY_HIGH
    if span <= 0:
        return 30
    frac = (entropy - config.ENTROPY_HIGH) / span
    return round(5 + frac * 25)
