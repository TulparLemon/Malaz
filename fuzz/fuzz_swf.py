"""Atheris-Harness: SWF-Entpackung (CWS/ZWS → LZMA/Zlib, begrenzt)."""

from _support import drain, load, run

(iter_swf_payloads,) = load("malaz.core.swf_extract", "iter_swf_payloads")

TARGET = "swf"

_DRAIN = 8


def fuzz_one(data: bytes) -> None:
    drain(iter_swf_payloads(data), _DRAIN)


if __name__ == "__main__":
    run(fuzz_one)
