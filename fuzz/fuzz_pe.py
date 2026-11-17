"""Atheris-Harness: PE-Pipeline (pefile, Strings, Ressourcen, Rich-Header).

Die drei externen Stufen (Authenticode/PowerShell, DIE, capa) sind hier
ersetzt: sie starten Subprozesse und parsen keine Bytes dieses Puffers. ALLES
andere — Sektionen, Importe, Mitigations, Manifest, VS_VERSIONINFO,
Ressourcen, Exporte, Delay-Importe, .NET, Rich-Header, Strings — läuft echt.

Der Kontextpfad existiert nicht (``<fuzz-input>.exe``), damit auch der
Authenticode-Aufruf in ``_structure`` früh ``None`` liefert statt PowerShell
zu starten.
"""

from _support import context, load, run

(PePipeline,) = load("malaz.pipelines.pe_pipeline", "PePipeline")

TARGET = "pe"

_PIPELINE = PePipeline()


def _no_external_stage(_ctx) -> list:
    return []


# Instanz-Attribute statt Produktionscode: der Fuzzer braucht die reinen
# Parser, nicht deren Prozess-Aufrufer.
_PIPELINE._authenticode = _no_external_stage
_PIPELINE._die = _no_external_stage
_PIPELINE._capa = _no_external_stage


def fuzz_one(data: bytes) -> None:
    _PIPELINE.analyze(context(data, "<fuzz-input>.exe", "pe"))


if __name__ == "__main__":
    run(fuzz_one)
