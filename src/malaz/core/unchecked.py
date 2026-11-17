"""Regel-IDs, die „nicht (vollständig) geprüft" bedeuten — eine Definition.

Warum das eine eigene Datei ist
===============================

Ein GRÜN auf einer Datei, deren Tiefenparser nur ein 8-MiB-Präfix gesehen
haben (``CORE_READ_TRUNCATED``) oder deren AV-Engine übersprungen wurde
(``*_SKIPPED``), ist **kein** sauberer Negativbefund. Diese Aussage brauchen
zwei Messungen:

* ``malaz.evaluation`` (Trefferquote/False-Positive-Rate, ``--evaluate``),
* ``malaz.lab.report`` (Realwelt-Lauf, Recall/FP/p95).

Vorher stand die Menge in ``lab/report.py`` und die Auswertung hatte sie
nicht — eine Messung hätte GRÜN als sauber gezählt, die andere nicht. Zwei
Abschriften derselben Regel sind genau die Drift, die dieses Projekt an
anderer Stelle schon zweimal korrigiert hat. Deshalb: eine Definition hier,
beide importieren sie.

Die Menge bleibt bewusst schmal: nur Regeln, deren Name selbst „ungeprüft"
sagt. Ein gewichteter Befund mit Teilprüfung (z. B. ``ARCH_MEMBER_SKIP``)
bleibt ein Befund und wird nicht aus dem Nenner geworfen.
"""

from __future__ import annotations

from collections.abc import Iterable

# ``*_SKIPPED`` wird zusätzlich per Suffix erkannt (AV_SKIPPED,
# CLAMAV_SKIPPED, EXT_<tag>_SKIPPED, CAPA_SKIPPED, DIE_SKIPPED, …).
UNCHECKED_RULE_IDS = frozenset(
    {
        "CORE_READ_TRUNCATED",
        # Datei schrumpfte zwischen stat() und Lesen, bzw. wuchs/änderte sich
        # während des Scans: analysiert wurde eine andere Revision als
        # angekündigt (dispatcher.py, gleiche Klasse wie READ_TRUNCATED).
        "CORE_READ_SHORT",
        "CORE_FILE_CHANGED",
        "CORE_TIME_BUDGET",
        "CORE_LIMIT",
        "CLAMAV_SIZE_LIMIT",
    }
)


def is_unchecked_rule(rule_id: str) -> bool:
    """True, wenn die Regel-ID „nicht geprüft" bedeutet."""
    return rule_id in UNCHECKED_RULE_IDS or rule_id.endswith("_SKIPPED")


def has_unchecked_markers(rule_ids: Iterable[str]) -> bool:
    """True, wenn mindestens eine Regel-ID eine Teil-/Nichtprüfung belegt."""
    return any(is_unchecked_rule(rule_id) for rule_id in rule_ids)
