"""ELF structure pipeline (AP12).

Header, program/section headers, NX/WX, interpreter and overlay — all static
and bounded. Findings start at weight 0; only a malformed header is scored
(LOW/5), because "not analysable" must never look clean.
"""

from __future__ import annotations

from ..core.elf import ET_NAMES, MACHINE_NAMES, PT_GNU_STACK, parse_elf
from ..models import CAT_FORMAT, CAT_STRUCTURE, AnalysisContext, Indicator, Severity
from .base import Pipeline


class ElfPipeline(Pipeline):
    name = "elf"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        if ctx.detected_type != "elf":
            return []
        info = parse_elf(ctx.data)
        if not info.valid:
            return [
                self._indicator(
                    "ELF_PARSE_WARN",
                    "ELF konnte nicht geparst werden",
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

        out: list[Indicator] = [
            self._indicator(
                "ELF_HEADER",
                f"ELF{info.bits} {info.endian}-endian",
                detail=(
                    f"Typ {ET_NAMES.get(info.e_type, hex(info.e_type))}, "
                    f"Maschine {MACHINE_NAMES.get(info.machine, hex(info.machine))}, "
                    f"Entry 0x{info.entry:x}, {len(info.segments)} Segmente, "
                    f"{len(info.sections)} Sektionen"
                ),
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        ]

        if info.sections:
            names = []
            for section in info.sections[:8]:
                if not section.name:
                    continue
                flags = []
                if section.flags & 0x1:
                    flags.append("W")
                if section.flags & 0x4:
                    flags.append("X")
                names.append(
                    f"{section.name}({section.size}{',' + ''.join(flags) if flags else ''})"
                )
            if names:
                out.append(
                    self._indicator(
                        "ELF_SECTIONS",
                        f"ELF-Sektionen: {len(info.sections)}",
                        detail="Sektionen: " + ", ".join(names),
                        severity=Severity.INFO,
                        category=CAT_STRUCTURE,
                        weight=0,
                    )
                )

        if info.interpreter:
            out.append(
                self._indicator(
                    "ELF_INTERP",
                    "ELF-Interpreter vorhanden",
                    detail=f"PT_INTERP: {info.interpreter}",
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        wx = [
            segment
            for segment in info.segments
            if segment.executable and segment.writable
        ]
        if wx:
            out.append(
                self._indicator(
                    "ELF_WX_SEGMENT",
                    f"ELF-Segment(e) schreibbar und ausführbar ({len(wx)})",
                    detail=(
                        "PT_LOAD/PT_GNU_STACK mit WRITE+EXECUTE an "
                        + ", ".join(f"0x{s.vaddr:x}" for s in wx[:6])
                        + " — selbstmodifizierender Code oder JIT."
                    ),
                    severity=Severity.INFO,
                    category=CAT_FORMAT,
                    weight=0,
                )
            )

        gnu_stack = [s for s in info.segments if s.type == PT_GNU_STACK]
        if gnu_stack and any(s.executable for s in gnu_stack):
            out.append(
                self._indicator(
                    "ELF_NO_NX",
                    "ELF ohne NX-Stack",
                    detail=(
                        "PT_GNU_STACK ist ausführbar markiert (PF_X) — der "
                        "Stack ist nicht als nicht-ausführbar gehärtet."
                    ),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        if info.overlay:
            out.append(
                self._indicator(
                    "ELF_OVERLAY",
                    f"Daten hinter dem letzten Ladesegment ({info.overlay} Bytes)",
                    detail=(
                        "Die Datei ist größer als die Summe der PT_LOAD-Bereiche — "
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
                    "ELF_STRUCTURE_WARN",
                    "ELF-Struktur unvollständig",
                    detail=f"{info.error} — Teile der Struktur wurden nicht geprüft.",
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )
        return out
