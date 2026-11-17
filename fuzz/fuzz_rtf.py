"""Atheris-Harness: RTF-Objektextraktion (``\\objdata``, Hex-Dekodierung)."""

from _support import drain, load, run

(iter_rtf_objects,) = load("malaz.core.rtf_extract", "iter_rtf_objects")

TARGET = "rtf"

_DRAIN = 16


def fuzz_one(data: bytes) -> None:
    drain(iter_rtf_objects(data), _DRAIN)


if __name__ == "__main__":
    run(fuzz_one)
