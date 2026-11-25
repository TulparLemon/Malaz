"""Endungen, die als ANHANG oder EINBETTUNG gefaehrlich sind — EINE Quelle.

Warum diese Datei existiert
===========================
Die Liste stand zweimal im Baum, und beide Fassungen sind auseinandergelaufen:

* ``core/eml_analysis._RISKY_ATTACHMENT_SUFFIXES`` (Mail-Anhaenge)
* ``pipelines/pdf_pipeline._EMBEDDED_DANGEROUS_SUFFIXES`` (PDF-Anhaenge)

GEMESSEN: der PDF-Fassung fehlte ``.hwp`` (eine echte Erkennungsluecke — das
Format ist ein bekannter Makro-Traeger), der Mail-Fassung fehlten
``.sh/.py/.apk/.zip/.rar/.7z``. Zwei Listen derselben Sicherheitsaussage laufen
immer auseinander; ``check_duplicate_logic.py`` findet Datenlisten nicht.

Die Vereinigung beider Fassungen ist deshalb hier zusammengefuehrt. Wer eine
Endung ergaenzt, ergaenzt sie EINMAL.

Ein TUPEL, kein frozenset: ``str.endswith`` nimmt nur Tupel entgegen, und die
Mail-Seite prueft damit. ``in`` funktioniert bei beiden.
"""

from __future__ import annotations

# Die Endungen, die in einer Mail oder einem PDF-Anhang nichts zu suchen haben:
# ausfuehrbar, Skript, Installer, Makro-Traeger oder ein Container, der die
# Pruefung umgeht, indem er seinen Inhalt erst beim Entpacken zeigt.
RISKY_SUFFIXES: tuple[str, ...] = (
    # Direkt ausfuehrbar
    ".exe", ".scr", ".com", ".pif", ".msi", ".dll", ".cpl", ".reg", ".xll",
    # Skript
    ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1",
    ".psm1", ".hta",
    # Verknuepfung / Autostart
    ".lnk",
    # Makro-traegende Office-Formate (das Dokumentformat selbst, .docx/.xlsx,
    # steht bewusst NICHT hier: ohne Makros ist es der Normalfall)
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".hwp",
    # Makro-faehige Binaer-/Template-/Add-in-Formate (BUG-027): .xlsb ist ein
    # OOXML-Binaerbuch, .sldm/.xlam sind makrofaehige Vorlage/Add-in.
    ".xlsb", ".sldm", ".xlam",
    # Datentraeger-Abbild und Java-Archiv: umgehen die Pruefung, indem sie
    # ihren Inhalt erst beim Oeffnen zeigen
    ".iso", ".img", ".vhd", ".vhdx", ".jar",
    # Hilfe-, Notiz- und App-Installer-Container (Spec 014)
    ".chm", ".one", ".onepkg", ".msix", ".appx", ".appinstaller",
    # Explorer-/Shell-/MMC-/Setup-Vektoren (Spec 014)
    ".scf", ".library-ms", ".search-ms", ".settingcontent-ms", ".msc", ".inf",
)
