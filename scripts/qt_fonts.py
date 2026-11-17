"""Systemschriften für Qt unter der ``offscreen``-Plattform laden.

WARUM ES DIESE DATEI GIBT
=========================
Qt liefert seit Jahren keine Schriften mehr mit, und unter ``offscreen`` ist
die Schriftdatenbank leer: jeder Text kommt als Kästchen heraus. Für Tests,
die Text prüfen (PDF-Bericht), und für das Rendern der Oberfläche zu
Design-Zwecken ist das dasselbe Problem — und es stand zweimal im Baum:
``tests/test_pdf_report.py`` und ``scripts/render_ui.py``. Eine Kopie in einer
Funktion findet ``check_duplicate_logic.py`` nicht (siehe den Hinweis zu
RISK_MARKS in ``gui/theme.py``), also lag die zweite Fassung unbemerkt daneben.

DIE REIHENFOLGE IST NICHT BELIEBTIG
===================================
``QApplication`` MUSS vorher existieren. GEMESSEN: ohne sie beendet sich der
Prozess beim Laden der Schrift hart — Exit 9, keine Ausgabe, kein Traceback.
Wer das nicht weiß, sucht an der falschen Stelle.
"""

from __future__ import annotations

import os

# Reihenfolge nach Nützlichkeit: Segoe UI ist die Windows-Systemschrift und
# deckt die deutschen Umlaute; die anderen sind Rückfalllinien.
FONT_CANDIDATES = (
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\tahoma.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
)


def ensure_fonts() -> bool:
    """Schriften laden, falls die Datenbank leer ist.

    Gibt zurück, ob danach Schriften verfügbar sind. Wirft nie — der Aufrufer
    entscheidet, ob das ein Fehler ist (im Test ein ``skip``, beim Rendern ein
    Abbruch, denn ein Bild mit Kästchen ist als Design-Beleg wertlos).
    """
    from PySide6.QtGui import QFontDatabase
    from PySide6.QtWidgets import QApplication

    if QApplication.instance() is None:
        QApplication([])
    if QFontDatabase.families():
        return True
    for kandidat in FONT_CANDIDATES:
        if (
            os.path.exists(kandidat)
            and QFontDatabase.addApplicationFont(kandidat) >= 0
            and QFontDatabase.families()
        ):
            return True
    return bool(QFontDatabase.families())
