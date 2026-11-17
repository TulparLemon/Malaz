"""Atheris-Harness: OOXML-/OLE-Container.

Bewusst *nicht* die komplette ``OfficePipeline``: deren VBA-/DDE-/XLM-Stufen
materialisieren eine Temp-Datei und laufen durch oletools — langsam und nicht
der Byte-Parser, der hier gehärtet werden soll. Der Harness fährt die reinen
In-Memory-Stufen, die dieselben Containerbytes lesen:

* OLE-Verzeichnis (``core.ole_depth``) — Rekursionstiefe/Frames
* OOXML-Relationships (``core.ooxml_rels``) — externe Ziele
* Bombenschutz und Metadaten der Office-Pipeline
* Container-Lesbarkeit für beide Routen (``zip``/``ole``)

Die Pfad-Stufen (olevba/msodde/XLM) sind über den Korpus abgedeckt
(``tests/test_office_stages.py``, ``tests/test_corpus_v2.py``).
"""

from _support import load, run

(directory_frames,) = load("malaz.core.ole_depth", "directory_frames")
(external_relationships,) = load("malaz.core.ooxml_rels", "external_relationships")
(
    _ooxml_bomb_guard,
    _ooxml_metadata,
    _ole_metadata,
    _container_readable,
) = load(
    "malaz.pipelines.office_pipeline",
    "_ooxml_bomb_guard",
    "_ooxml_metadata",
    "_ole_metadata",
    "_container_readable",
)

TARGET = "ooxml"


def fuzz_one(data: bytes) -> None:
    directory_frames(data)
    external_relationships(data)
    _ooxml_bomb_guard(data)
    _ooxml_metadata(data)
    _ole_metadata(data)
    _container_readable(data, "ole")
    _container_readable(data, "zip")


if __name__ == "__main__":
    run(fuzz_one)
