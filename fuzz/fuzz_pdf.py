"""Atheris-Harness: PDF-Pipeline (pikepdf/pypdf-Parser, JS-Dekodierung).

Der Harness deckt den In-Process-Pfad ab: Metadaten, Objekt-Streams,
JavaScript-Erkennung, Struktur-/Bomben-Heuristiken. Er startet keine
Subprozesse und liest keine Datei von der Platte.
"""

from _support import context, load, run

(PdfPipeline,) = load("malaz.pipelines.pdf_pipeline", "PdfPipeline")

TARGET = "pdf"

_PIPELINE = PdfPipeline()


def fuzz_one(data: bytes) -> None:
    _PIPELINE.analyze(context(data, "<fuzz-input>.pdf", "pdf"))


if __name__ == "__main__":
    run(fuzz_one)
