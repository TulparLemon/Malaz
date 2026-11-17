"""Atheris-Harness: Bild-Pipeline (PNG-IEND, JPEG-EOI, HEIC-Boxen, EXIF).

Die Bildroute wählt im Dispatcher über ``magic.detect``; der Harness bildet
das nach und fällt für unbekannte Typen deterministisch auf die
Bildvarianten zurück (erster Byte-Wert), damit alle Zweige erreichbar sind.
"""

from _support import context, load, run

(ImagePipeline,) = load("malaz.pipelines.image_pipeline", "ImagePipeline")
(detect,) = load("malaz.core.magic", "detect")

TARGET = "images"

_PIPELINE = ImagePipeline()
_TYPES = (
    ("png", ".png"),
    ("jpeg", ".jpg"),
    ("heic", ".heic"),
    ("avif", ".avif"),
    ("gif", ".gif"),
    ("tiff", ".tif"),
    ("ico", ".ico"),
    ("webp", ".webp"),
)
_IMAGE_TYPES = frozenset(kind for kind, _ in _TYPES)


def fuzz_one(data: bytes) -> None:
    detected = detect(data)
    if detected.type in _IMAGE_TYPES:
        kind = detected.type
    else:
        kind = _TYPES[data[0] % len(_TYPES)][0] if data else "png"
    suffix = dict(_TYPES)[kind]
    _PIPELINE.analyze(context(data, f"<fuzz-input>{suffix}", kind))


if __name__ == "__main__":
    run(fuzz_one)
