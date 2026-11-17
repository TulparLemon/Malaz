"""Golden Images: haelt fest, dass die Oberflaeche ueberhaupt etwas zeichnet.

Der Golden-Snapshot sichert Zahlen und Urteile. Er sieht NICHT, ob die
Oberflaeche noch etwas anzeigt — ein kaputtes Stylesheet, eine Karte ohne
Farbe, ein zusammengefallenes Layout: die Suite bleibt gruen, der Nutzer sieht
eine leere Flaeche.

Geprueft wird deshalb nicht pixelgenau (Schriftarten, DPI und Qt-Version
erzeugen auf jedem Rechner andere Bilder, ein solcher Test wird abgeschaltet
statt repariert), sondern auf das, was die Aussage traegt:

* das Bild ist nicht leer,
* die Risikofarbe der Stufe kommt tatsaechlich vor,
* die Groesse ist plausibel.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import make_golden_images  # noqa: E402


def test_golden_images_render_and_carry_the_verdict(qapp):
    """Die drei Ansichten rendern und tragen ihre Risikofarbe."""
    beanstandungen = make_golden_images.pruefe()
    assert not beanstandungen, "\n".join(beanstandungen)


def test_golden_image_check_notices_a_blank_screen(qapp, monkeypatch, tmp_path):
    """Die Pruefung muss eine leere Flaeche ERKENNEN — sonst schuetzt sie nichts.

    Beissprobe: das Rendern wird durch einen leeren Block ersetzt. Bliebe die
    Pruefung gruen, waere sie ein Test, der nur seine eigene Anwesenheit
    bestaetigt.
    """
    from PySide6.QtGui import QImage

    leeres_bild = tmp_path / "ergebnis_rot.png"
    bild = QImage(1180, 860, QImage.Format_RGB32)
    bild.fill(0x000000)
    bild.save(str(leeres_bild))

    monkeypatch.setattr(
        make_golden_images,
        "erzeuge",
        lambda ziel=None: {"ergebnis_rot": leeres_bild},
    )
    beanstandungen = make_golden_images.pruefe()
    assert beanstandungen, "eine leere Flaeche wurde nicht beanstandet"
    assert any("leer" in b or "Risikofarbe" in b for b in beanstandungen), beanstandungen


def test_golden_images_exist_in_the_repository():
    """Die Referenzbilder liegen im Baum — sonst ist der Diff nicht sichtbar."""
    fehlend = [
        name
        for name in (
            "empty_state.png", "scanning.png", "result_green.png",
            "result_yellow.png", "result_red.png", "engines_threat.png",
            "engines_clean.png", "engines_skipped.png", "batch_summary.png",
            "archive_tree.png", "mail_panel.png", "mail_viewer.png",
            "options.png", "capabilities.png", "report_html.png",
            "report_pdf.png",
        )
        if not (make_golden_images.BILD_DIR / name).exists()
    ]
    assert not fehlend, (
        f"Referenzbilder fehlen: {fehlend} — "
        f"scripts/make_golden_images.py erzeugt sie"
    )
