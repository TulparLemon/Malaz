"""Erzeugt assets/malaz.ico aus dem Tulpar-Logo (weiß auf transparent).

Das weiße Logo wird auf einen dunklen, abgerundeten Quadrat-Hintergrund
komponiert (Malaz-Dark-Theme #1c1e25), damit es in Taskleiste, Explorer
und Titelzeile sichtbar bleibt. Mehrere ICO-Größen für Windows.

Aufruf (Projekt-Root):
    python scripts/make_icon.py <quelle.png>
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
BG = (28, 30, 37, 255)          # PANEL_BG des Malaz-Themes
CORNER = 0.18                    # Eckradius relativ zur Kantenlänge
LOGO_FRACTION = 0.78             # Logo-Anteil an der Icon-Kante
SIZES = [16, 24, 32, 48, 64, 128, 256]


def build_base(size: int = 512) -> Image.Image:
    base = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(base)
    radius = int(size * CORNER)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=BG)
    return base


def main(source: str) -> int:
    src_path = Path(source)
    if not src_path.is_file():
        print(f"FEHLER: {src_path} nicht gefunden", file=sys.stderr)
        return 1

    ASSETS.mkdir(exist_ok=True)
    logo = Image.open(src_path).convert("RGBA")

    base = build_base()
    logo_size = int(512 * LOGO_FRACTION)
    logo_scaled = logo.resize((logo_size, logo_size), Image.LANCZOS)
    offset = (512 - logo_size) // 2
    base.alpha_composite(logo_scaled, (offset, offset))
    base.save(ASSETS / "malaz_logo.png")

    ico_images = []
    for s in SIZES:
        frame = build_base(s)
        ls = max(1, int(s * LOGO_FRACTION))
        ls_scaled = logo.resize((ls, ls), Image.LANCZOS)
        off = (s - ls) // 2
        frame.alpha_composite(ls_scaled, (off, off))
        ico_images.append(frame)
    ico_images[-1].save(
        ASSETS / "malaz.ico", format="ICO",
        append_images=ico_images[:-1],
    )
    print(f"OK: {ASSETS/'malaz.ico'} ({len(SIZES)} Groessen) + malaz_logo.png")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Nutzung: python scripts/make_icon.py <logo.png>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
