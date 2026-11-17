"""Atheris-Harness: ZIP/TAR/GZIP/BZIP2/XZ-Extraktion und Namensprüfung.

Ziel ist die In-Memory-Extraktion (``core.archive``), nicht der 7-Zip-Pfad:
der startet einen Prozess und ist auf Windows ohne 7-Zip ohnehin inaktiv.
Geprüft werden Zip-Slip-/ADS-/Gerätenamen, Bombenlimits, kaputte zentrale
Verzeichnisse und Tar-Mitglieder.
"""

from _support import context, drain, load, run

(iter_zip_members, iter_compressed_members) = load(
    "malaz.core.archive", "iter_zip_members", "iter_compressed_members"
)
(ArchivePipeline,) = load("malaz.pipelines.archive_pipeline", "ArchivePipeline")
(is_safe_member_name, unsafe_name_reason) = load(
    "malaz.security.safe_extract", "is_safe_member_name", "unsafe_name_reason"
)

TARGET = "zip"

_KINDS = ("tar", "gzip", "bzip2", "xz")
_DRAIN = 16
_PIPELINE = ArchivePipeline()


def fuzz_one(data: bytes) -> None:
    # Namensprüfung zuerst: sie läuft für jeden Eintrag jedes Containers und
    # ist die letzte Instanz vor einem Schreibpfad.
    is_safe_member_name(data[:256].decode("latin-1"))
    unsafe_name_reason(data[:256].decode("latin-1"))

    drain(iter_zip_members(data, ["infected"]), _DRAIN)
    for kind in _KINDS:
        drain(iter_compressed_members(data, kind), _DRAIN)
    # Die Pipeline liest dasselbe Zentralverzeichnis für Namens-/Bomben-/
    # Verschachtelungsregeln (inkl. ARCH_NESTED_ARCHIVE). Sie schreibt nur
    # Indikatoren, keine Dateien.
    _PIPELINE.analyze(context(data, "<fuzz-input>.zip", "zip"))


if __name__ == "__main__":
    run(fuzz_one)
