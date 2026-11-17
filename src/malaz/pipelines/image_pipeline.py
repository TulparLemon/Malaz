"""Image & container analysis pipeline.

1. Magic-byte vs. extension consistency (format spoofing).
2. PNG trailer scan — data appended after the ``IEND`` chunk
   (CRC32 ``\\xaeB\\x60\\x82``).
3. JPEG EOI analysis — data after the final ``\\xFF\\xD9`` marker, with context
   about legitimate EXIF thumbnails.
4. EXIF metadata extraction (rendered escaped in the report).
"""

from __future__ import annotations

from ..models import (
    CAT_FORMAT,
    CAT_METADATA,
    CAT_STEGO,
    AnalysisContext,
    Indicator,
    Severity,
)
from .base import Pipeline

_PNG_IEND = b"IEND"
_PNG_IEND_CRC = b"\xae\x42\x60\x82"  # CRC32 of an empty IEND chunk
_JPEG_SOI = b"\xff\xd8"


# Unterhalb dessen ist ein Rest Auffuellung und traegt kein Gewicht mehr —
# gemeldet wird er trotzdem, damit ein frueh gesetztes EOI nicht still wird.
# Gemessen: 3 Bytes bei einem echten Word-Dokument.
_TRAILER_MIN_BYTES = 64

# Bounded walk over top-level ISO-BMFF boxes. A hostile file can declare an
# endless chain of tiny boxes; the cap keeps the stage linear.
_MAX_HEIF_BOXES = 256


class ImagePipeline(Pipeline):
    name = "image"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        indicators: list[Indicator] = []
        if ctx.detected_type == "png":
            indicators.extend(self._png_trailer(ctx))
        elif ctx.detected_type == "jpeg":
            indicators.extend(self._jpeg_eoi(ctx))
        elif ctx.detected_type in ("heic", "avif"):
            indicators.extend(self._heif_boxes(ctx))
            # No HEIF decoder is bundled (Pillow has no HEIC plugin here), so
            # "no EXIF finding" must never be read as "no EXIF present".
            indicators.extend(self._exif(ctx, failure_rule="HEIC_EXIF_UNCHECKED"))
            return indicators
        indicators.extend(self._exif(ctx))
        return indicators

    # -- PNG --------------------------------------------------------------- #

    def _png_trailer(self, ctx: AnalysisContext) -> list[Indicator]:
        data = ctx.data
        # Locate the FIRST REAL IEND chunk after the 8-byte signature. A bare
        # find of the CRC could collide with compressed IDAT bytes (~2^-32 per
        # position), so a hit is only accepted when preceded by the IEND
        # chunk header: 4-byte length 0x00000000 + 'IEND'. rfind would be
        # trivially bypassable (payload + fake trailing IEND).
        idx = 8
        end = -1
        while True:
            idx = data.find(_PNG_IEND_CRC, idx)
            if idx == -1:
                break
            if data[idx - 5 : idx] == b"\x00\x00\x00\x00IEND":
                end = idx + len(_PNG_IEND_CRC)
                break
            idx += 1
        if end == -1:
            # No validated IEND chunk: truncated or not a clean PNG.
            iend = data.find(_PNG_IEND, 8)
            if iend == -1:
                return [
                    self._indicator(
                        "PNG_NO_IEND",
                        "PNG ohne gültigen IEND-Chunk",
                        detail="Kein IEND-Marker gefunden — Datei ist abgeschnitten oder manipuliert.",
                        severity=Severity.MEDIUM,
                        category=CAT_FORMAT,
                        weight=15,
                    )
                ]
            # 'IEND' present but its 4-byte CRC missing → cut-off file.
            if len(data) - (iend + len(_PNG_IEND)) < 4:
                return [
                    self._indicator(
                        "PNG_NO_IEND",
                        "PNG ohne gültigen IEND-Chunk",
                        detail="IEND-Marker vorhanden, aber CRC abgeschnitten — Datei ist unvollständig.",
                        severity=Severity.MEDIUM,
                        category=CAT_FORMAT,
                        weight=15,
                    )
                ]
            end = iend + len(_PNG_IEND) + 4

        trailer = data[end:]
        if trailer:
            return [
                self._indicator(
                    "PNG_TRAILER",
                    f"Daten hinter PNG-IEND ({len(trailer)} Bytes)",
                    detail=(
                        "Nach dem regulären Bildende (IEND) folgen zusätzliche Daten — "
                        "mögliches verstecktes Payload. Anfang: "
                        + repr(trailer[:32])
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_STEGO,
                    weight=15,
                )
            ]
        return []

    # -- JPEG -------------------------------------------------------------- #

    def _jpeg_eoi(self, ctx: AnalysisContext) -> list[Indicator]:
        data = ctx.data
        # Walk the marker structure to find the TRUE end of the primary
        # image (the first EOI outside any nested thumbnail stream). A bare
        # rfind is trivially bypassable: payload + a fake trailing \xff\xd9
        # makes the trailer look empty. Markers are two bytes; the second is
        # never 0xFF, so scanning for \xff<not-\xff> cannot desynchronise.
        i = 2  # skip SOI
        end = -1
        n = len(data)
        while i + 1 < n:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker == 0xD9:  # EOI — primary image ends here
                end = i + 2
                break
            if marker in (0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                # Standalone markers (TEM, RSTn): no length field.
                i += 2
                continue
            if marker == 0xFF:
                # Fill byte inside entropy-coded data.
                i += 1
                continue
            if 0xC0 <= marker <= 0xFE:
                if i + 4 > n:
                    break
                seg_len = int.from_bytes(data[i + 2 : i + 4], "big")
                if seg_len < 2 or i + 2 + seg_len > n:
                    # Malformed segment: the marker structure can no longer
                    # be trusted — fail closed (NO_EOI below) instead of
                    # guessing an end offset an attacker could steer.
                    break
                i += 2 + seg_len
                continue
            # 0x00 stuffing / stray byte inside entropy-coded data.
            i += 1

        if end == -1:
            return [
                self._indicator(
                    "JPEG_NO_EOI",
                    "JPEG ohne EOI-Marker",
                    detail="Kein \\xFF\\xD9 End-of-Image gefunden — Datei ist abgeschnitten.",
                    severity=Severity.MEDIUM,
                    category=CAT_FORMAT,
                    weight=15,
                )
            ]

        trailer = data[end:]
        if not trailer:
            return []
        # KLEINE RESTE WERDEN GEMELDET, ABER OHNE GEWICHT — nicht unterdrueckt.
        #
        # GEMESSEN an having-images.docx (echtes Word-Dokument aus dem
        # Testbestand von python-docx): hinter dem Ende des JPEG standen DREI
        # Bytes Fuellmaterial (b'\x0bO\x00'), und die Regel meldete daraus
        # MEDIUM/15 — ein Dokument mit Bildern kam auf GELB.
        #
        # Die erste Fassung dieser Korrektur verlangte eine Mindestgroesse.
        # Das war der FALSCHE Hebel: ein Angreifer setzt ein FRUEHES EOI und
        # haengt dahinter an — genau der Bypass, den der Test
        # test_jpeg_trailer_bypass_with_fake_eoi_is_detected bewacht. Die
        # Erkennung zu beschneiden macht ihn wieder still.
        #
        # Richtig ist die Trennung von SICHTBARKEIT und WERTUNG, wie bei
        # /JS, /ObjStm und der erklaerten Entropie: der Befund bleibt, nur
        # das Urteil haengt an der Aussagekraft. Drei Bytes Auffuellung sind
        # ein Hinweis, kein Verdacht; ein angehaengtes Bild bleibt MEDIUM.

        looks_like_thumb = trailer.lstrip().startswith(_JPEG_SOI)
        # Zwei Stufen, nicht drei: ein angehaengtes BILD oder ein
        # nennenswerter Rest ist ein Verdacht (15); wenige Bytes sind
        # Auffuellung und werden nur noch gezeigt (0).
        gewicht = 15 if (looks_like_thumb or len(trailer) >= _TRAILER_MIN_BYTES) else 0
        detail = (
            f"{len(trailer)} Bytes nach dem Ende des Hauptbildes (EOI). "
            + (
                "Beginnt mit einem JPEG-SOI (\\xFF\\xD8) — möglicherweise ein "
                "angehängtes Bild."
                if looks_like_thumb
                else "Beginnt nicht mit einem JPEG-Header — verdächtig."
            )
            + " Anfang: " + repr(trailer[:32])
        )
        return [
            self._indicator(
                "JPEG_TRAILER",
                f"Daten hinter JPEG-EOI ({len(trailer)} Bytes)",
                detail=detail,
                severity=Severity.MEDIUM if gewicht else Severity.LOW,
                category=CAT_STEGO,
                weight=gewicht,
            )
        ]

    # -- HEIC/AVIF (ISO-BMFF) ---------------------------------------------- #

    def _heif_boxes(self, ctx: AnalysisContext) -> list[Indicator]:
        """Walk top-level ISO-BMFF boxes and report trailing data.

        Only the *container* structure is checked: no codec, no pixels. The
        walk is bounded (box count, file bytes already capped by the
        dispatcher) and never allocates per box beyond a slice for the
        trailer. A declared box that runs past the END OF THE FILE (not just
        past the loaded prefix) is malformed; bytes after the last complete
        box are reported as an append payload.
        """
        data = ctx.data
        offset = 0
        count = 0
        while offset + 8 <= len(data):
            declared = int.from_bytes(data[offset : offset + 4], "big")
            box_type = data[offset + 4 : offset + 8]
            header = 8
            if declared == 1:
                if offset + 16 > len(data):
                    if ctx.size > len(data):
                        # Bounded read prefix, not a malformed file: the
                        # streaming stage marks the scan incomplete.
                        return []
                    return [self._heif_truncated(ctx, box_type, offset, None)]
                declared = int.from_bytes(data[offset + 8 : offset + 16], "big")
                header = 16
            elif declared == 0:
                # "Box extends to end of file": nothing can follow, and a
                # bounded read prefix legitimately stops inside it.
                return []
            if declared < header:
                return [
                    self._indicator(
                        "HEIC_BOX_INVALID",
                        "HEIC/AVIF: ungültige Box-Größe",
                        detail=(
                            f"Box '{_box_name(box_type)}' bei Offset {offset} "
                            f"deklariert {declared} Bytes, kleiner als der "
                            f"{header}-Byte-Kopf. Die Struktur ist beschädigt."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_FORMAT,
                        weight=15,
                    )
                ]
            if offset + declared > len(data):
                if ctx.size > len(data):
                    # Only a bounded prefix was read; CORE_READ_TRUNCATED
                    # already marks the scan as incomplete.
                    return []
                if declared > ctx.size or not _printable_box_type(box_type):
                    # The declared box is larger than the whole file (or the
                    # "type" is not ASCII): this is appended data, not a box.
                    return self._heif_trailer(ctx, data[offset:])
                return [self._heif_truncated(ctx, box_type, offset, declared)]
            count += 1
            if count > _MAX_HEIF_BOXES:
                return [
                    self._indicator(
                        "HEIC_BOX_LIMIT",
                        f"HEIC/AVIF: mehr als {_MAX_HEIF_BOXES} Boxen",
                        detail=(
                            f"Die Strukturprüfung stoppt nach {_MAX_HEIF_BOXES} "
                            "Top-Level-Boxen; der Rest wurde NICHT geprüft."
                        ),
                        severity=Severity.INFO,
                        category=CAT_FORMAT,
                        weight=0,
                    )
                ]
            offset += declared
        if offset < len(data):
            if ctx.size > len(data):
                # Only a 1-7 byte cut box header at the prefix edge; the
                # streaming stage already marks the read as truncated.
                return []
            return self._heif_trailer(ctx, data[offset:])
        return []

    def _heif_trailer(self, ctx: AnalysisContext, trailer: bytes) -> list[Indicator]:
        gewicht = 15 if len(trailer) >= _TRAILER_MIN_BYTES else 0
        return [
            self._indicator(
                "HEIC_TRAILER",
                f"Daten hinter dem HEIC/AVIF-Container ({len(trailer)} Bytes)",
                detail=(
                    "Nach der letzten vollständigen ISO-BMFF-Box folgen "
                    "zusätzliche Daten — möglicherweise ein angehängtes "
                    f"Payload. Anfang: {trailer[:32]!r}"
                ),
                severity=Severity.MEDIUM if gewicht else Severity.LOW,
                category=CAT_STEGO,
                weight=gewicht,
            )
        ]

    def _heif_truncated(
        self,
        ctx: AnalysisContext,
        box_type: bytes,
        offset: int,
        declared: int | None,
    ) -> Indicator:
        if declared is None:
            detail = (
                f"Box '{_box_name(box_type)}' bei Offset {offset}: Der "
                f"64-Bit-Größenkopf ist abgeschnitten (Datei endet bei "
                f"{ctx.size} Bytes). Die Struktur ist unvollständig."
            )
        else:
            detail = (
                f"Box '{_box_name(box_type)}' bei Offset {offset} deklariert "
                f"{declared} Bytes, die Datei endet jedoch vorher "
                f"({ctx.size} Bytes). Die Struktur ist unvollständig."
            )
        return self._indicator(
            "HEIC_BOX_TRUNCATED",
            "HEIC/AVIF: Box reicht über das Dateiende",
            detail=detail,
            severity=Severity.MEDIUM,
            category=CAT_FORMAT,
            weight=15,
        )

    # -- EXIF -------------------------------------------------------------- #

    def _exif(
        self, ctx: AnalysisContext, *, failure_rule: str | None = None
    ) -> list[Indicator]:
        def unavailable(reason: str) -> list[Indicator]:
            if not failure_rule:
                return []
            return [
                self._indicator(
                    failure_rule,
                    "EXIF-Prüfung nicht möglich",
                    detail=(
                        f"{reason} EXIF wurde NICHT geprüft; das Fehlen eines "
                        "EXIF-Befunds belegt nicht, dass keine EXIF-Daten "
                        "vorhanden sind."
                    ),
                    severity=Severity.INFO,
                    category=CAT_METADATA,
                    weight=0,
                )
            ]

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
        except Exception as exc:
            return unavailable(f"{type(exc).__name__}: Pillow fehlt.")

        out: list[Indicator] = []
        try:
            import io

            with Image.open(io.BytesIO(ctx.data)) as img:
                exif = img.getexif()
                if not exif:
                    return []
                fields = []
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    # Keep the excerpt small and printable; escaping happens at
                    # render time.
                    text = str(value)
                    if len(text) > 120:
                        text = text[:120] + "…"
                    fields.append(f"{tag}={text}")
                if fields:
                    out.append(
                        self._indicator(
                            "IMG_EXIF",
                            f"EXIF-Metadaten vorhanden ({len(fields)} Felder)",
                            detail=" | ".join(fields[:20]),
                            severity=Severity.INFO,
                            category=CAT_METADATA,
                            weight=0,
                        )
                    )
        except Exception as exc:
            # Unparseable EXIF is not itself an error worth surfacing loudly —
            # unless the caller asked for a visible "not checked" statement.
            return unavailable(f"{type(exc).__name__}: Bild nicht lesbar.")
        return out


def _box_name(box_type: bytes) -> str:
    return box_type.decode("latin-1", "replace").replace("\x00", "?")


def _printable_box_type(box_type: bytes) -> bool:
    return all(0x20 <= byte <= 0x7E for byte in box_type)
