"""Labor-Bausteine für den Realwelt-Test (Vorbereitung, keine Proben).

Dieses Paket enthält ausschließlich Werkzeuge, die ohne echte Schadproben
laufen: Manifest-Validierung, Auswertung der Ergebnisdateien und die
Trockenlauf-Erzeugung synthetischer Fixtures. Es gibt hier bewusst keinen
Download, keine Ausführung und keinen Netzwerkpfad.
"""

from .manifest import (
    Manifest,
    ManifestEntry,
    ManifestError,
    load_manifest,
    sha256_file,
    validate_document,
    verify_files,
)
from .report import (
    ResultRow,
    build_report,
    load_results,
    render_markdown,
)

__all__ = [
    "Manifest",
    "ManifestEntry",
    "ManifestError",
    "ResultRow",
    "build_report",
    "load_manifest",
    "load_results",
    "render_markdown",
    "sha256_file",
    "validate_document",
    "verify_files",
]
