"""Einstellungen des Fensters — an EINER Stelle, damit Tests sie kapseln koennen.

WARUM DIESE DATEI EXISTIERT
===========================
Die Haken des Fensters lagen bisher direkt auf ``QSettings("Malaz", "Malaz")``,
also auf der Windows-Registry. Das hat zwei Folgen, die in dieser Sitzung
gemessen wurden:

* **Der Testlauf liest den Entwickler-Zustand.** Wer den capa-Haken in der App
  einmal setzt, bekommt im Testprozess ``config.CAPA_ENABLED = True`` — global,
  fuer alle folgenden Tests.
* **Der Testlauf schreibt hinein.** ``main_window`` setzt beim Aufbau
  ``config.CAPA_ENABLED`` aus der Einstellung und schreibt sie beim Klick
  zurueck; gemessen stand ``capa_enabled`` danach in ``HKCU\\Software\\Malaz``.

``QSettings.setDefaultFormat(IniFormat)`` + ``setPath`` loesen das NICHT: in
PySide6 blieb ``fileName()`` trotz gesetztem Format die Registry
(``\\HKEY_CURRENT_USER\\...``), die Umleitung greift dort nicht.

Deshalb diese Naht: **eine** Funktion, die das Einstellungsobjekt liefert.
Tests ersetzen sie und bekommen eine INI-Datei im Temp-Verzeichnis — Lesen und
Schreiben gekapselt, ohne die Registry anzufassen.
"""

from __future__ import annotations

from PySide6.QtCore import QSettings

_ORGANISATION = "Malaz"
_APPLICATION = "Malaz"


def app_settings() -> QSettings:
    """Das Einstellungsobjekt der Anwendung.

    Die EINE Stelle, die den Ablageort kennt. Tests tauschen diese Funktion
    aus (siehe ``conftest._isolate_settings``).
    """
    return QSettings(_ORGANISATION, _APPLICATION)


def apply_saved_opt_ins() -> None:
    """Die gespeicherten Opt-ins in die Config uebernehmen — beim START.

    WARUM DAS NÖTIG IST
    ===================
    Die Schalter wurden bisher NUR durch das ``toggled``-Signal ihres
    Kaestchens in ``config`` geschrieben. Im Fenster ging das gut — ``setChecked``
    loest das Signal aus —, aber ``--cli`` baut kein Fenster. GEMESSEN: der
    Nutzer schaltet "SPF/DMARC über DNS" ein, scannt headless, und die
    Pruefung laeuft **still** nicht. Der Schalter stand auf an, die Wirkung
    fehlte.

    Hier steht die Zuordnung EINMAL, fuer beide Wege. Ein neuer Opt-in gehoert
    in diese Liste — sonst gilt er nur im Fenster.
    """
    from .. import config

    s = app_settings()
    config.CAPA_ENABLED = s.value("capa_enabled", config.CAPA_ENABLED, bool)
    config.DNS_AUTH_ENABLED = s.value("dns_auth_enabled", config.DNS_AUTH_ENABLED, bool)
