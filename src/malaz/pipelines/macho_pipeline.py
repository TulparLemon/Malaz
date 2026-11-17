"""Mach-O structure pipeline (AP12)."""

from __future__ import annotations

from ..core.macho import CPU_NAMES, FILETYPE_NAMES, parse_macho
from ..models import CAT_FORMAT, CAT_STRUCTURE, AnalysisContext, Indicator, Severity
from .base import Pipeline


class MachoPipeline(Pipeline):
    name = "macho"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        if ctx.detected_type != "macho":
            return []
        info = parse_macho(ctx.data)
        if not info.valid:
            return [
                self._indicator(
                    "MACHO_PARSE_WARN",
                    "Mach-O konnte nicht geparst werden",
                    detail=(
                        f"{info.error or 'unbekannter Fehler'} — Header, Segmente "
                        "und Overlay wurden nicht geprüft; das Ergebnis ist "
                        "nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.LOW,
                    category=CAT_STRUCTURE,
                    weight=5,
                )
            ]

        fat = f", Fat-Binary mit {len(info.fat_arches)} Architekturen" if info.fat_arches else ""
        out: list[Indicator] = [
            self._indicator(
                "MACHO_HEADER",
                f"Mach-O {info.bits}-bit {info.endian}-endian",
                detail=(
                    f"Dateityp {FILETYPE_NAMES.get(info.filetype, hex(info.filetype))}, "
                    f"CPU {CPU_NAMES.get(info.cputype, hex(info.cputype))}, "
                    f"{info.ncmds} Load-Commands{fat}"
                ),
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        ]

        if info.segments:
            names = []
            for segment in info.segments[:8]:
                marks = []
                if segment.writable:
                    marks.append("W")
                if segment.executable:
                    marks.append("X")
                names.append(
                    f"{segment.name}({segment.filesize}"
                    f"{',' + ''.join(marks) if marks else ''})"
                )
            out.append(
                self._indicator(
                    "MACHO_SEGMENTS",
                    f"Mach-O-Segmente: {len(info.segments)}",
                    detail="Segmente: " + ", ".join(names),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        if info.dylibs:
            out.append(
                self._indicator(
                    "MACHO_DYLIB",
                    f"Geladene Bibliotheken: {len(info.dylibs)}",
                    detail=" | ".join(info.dylibs[:6]),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        if not info.code_signature:
            out.append(
                self._indicator(
                    "MACHO_NO_CODE_SIGNATURE",
                    "Mach-O ohne Code-Signatur",
                    detail=(
                        "Kein LC_CODE_SIGNATURE vorhanden. Auf macOS ist eine "
                        "Signatur Voraussetzung für die normale Ausführung; "
                        "ihr Fehlen ist ein Hinweis, kein Beweis."
                    ),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        if info.overlay:
            out.append(
                self._indicator(
                    "MACHO_OVERLAY",
                    f"Daten hinter dem letzten Segment ({info.overlay} Bytes)",
                    detail=(
                        "Die Datei ist größer als die Summe der Segmente — "
                        "möglicher angehängter Inhalt."
                    ),
                    severity=Severity.INFO,
                    category=CAT_FORMAT,
                    weight=0,
                )
            )

        if info.error:
            out.append(
                self._indicator(
                    "MACHO_STRUCTURE_WARN",
                    "Mach-O-Struktur unvollständig",
                    detail=f"{info.error} — Teile der Struktur wurden nicht geprüft.",
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )
        return out
