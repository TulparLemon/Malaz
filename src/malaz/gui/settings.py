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


_LANGUAGE_KEY = "ui/language"
_ACTIVE_LANG_PREF: str | None = None


def saved_language_preference() -> str:
    """Return persisted UI language preference (``system | de | en``)."""
    val = str(app_settings().value(_LANGUAGE_KEY, "system", str) or "system").strip().lower()
    return val if val in ("system", "de", "en", "tr") else "system"


def active_language_preference() -> str:
    """Return active session language preference (ephemeral CLI override or saved)."""
    if _ACTIVE_LANG_PREF in ("system", "de", "en", "tr"):
        return _ACTIVE_LANG_PREF
    return saved_language_preference()


def apply_language(pref: str, *, persist: bool = True) -> str:
    """Apply ``system | de | en`` language preference and optionally persist it."""
    from ..i18n import resolve_language, set_language

    global _ACTIVE_LANG_PREF
    clean = (pref or "system").strip().lower()
    if clean not in ("system", "de", "en", "tr"):
        clean = "system"
    _ACTIVE_LANG_PREF = clean
    if persist:
        app_settings().setValue(_LANGUAGE_KEY, clean)
    return set_language(resolve_language(clean))
