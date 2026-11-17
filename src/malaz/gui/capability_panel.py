"""Der Faehigkeiten-Reiter: was KANN dieses Programm?

WARUM DIESE DATEI EXISTIERT
===========================
capa nennt Faehigkeiten in ganzen Saetzen — "legt einen Dienst an", "baut eine
Verbindung nach aussen auf", "versteckt sich vor Analyse". Das ist die Frage,
die ein Laie bei einer .exe stellt, und die Malaz vorher nicht beantworten
konnte: YARA findet Signaturen, DIE nennt Format und Packer.

Bis hierher standen die Faehigkeiten als eine Semikolon-Zeile im Befundtext.
Fachlich richtig, aber nicht lesbar: acht Faehigkeiten ergeben eine Zeile ueber
zwei Bildschirmbreiten, und die Gruppierung (gehoert "Schutz vor Debuggern" zu
"Verstecken vor Analyse"?) geht darin unter.

WAS DIESER REITER NICHT BEHAUPTET
=================================
capa ist eine AUSRICHTUNG, kein Urteil. Die Regelbasis beschreibt, was ein
Programm technisch kann — ein Installer "legt einen Dienst an", ein
Texteditor "liest Dateien". Viele Faehigkeiten treffen auf voellig normale
Software zu. Das steht deshalb als Satz ueber der Liste, nicht als Kleingedrucktes:
ohne ihn liest der Nutzer eine Liste von Faehigkeiten als Beweis fuer
Schadsoftware.

DIE GRUPPIERUNG
===============
Gruppiert wird nach dem obersten Namensraum der Regel (`persistence`,
`communication`, `anti-analysis`, ...). Diese Namen sind der stabilste Teil
der capa-Ausgabe; die einzelnen Regelnamen sind englisch und technisch und
werden uebersetzt, soweit eine Uebersetzung bekannt ist. Eine unbekannte Regel
wird NICHT verschwiegen — sie erscheint unuebersetzt unter "Weitere".
"""

from __future__ import annotations

from collections import defaultdict

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..analysis.capa import _GROUP_DE, _NAMESPACE_DE
from ..core.mail_view import MAX_DISPLAY_CHARS, _clip
from ..models import ScanResult

# Reihenfolge der Gruppen: was ein Programm TUN kann, in der Reihenfolge, in
# der es einen Nutzer betrifft. Eine feste Ordnung ist besser als eine
# alphabetische — "Verstecken vor Analyse" gehoert nach oben, auch wenn es mit
# A anfaengt.
_GROUP_ORDER = (
    "persistence",
    "communication",
    "anti-analysis",
    "host-interaction",
    "data-manipulation",
    "load-code",
    "runtime",
)

_GROUP_FALLBACK = "Weitere Faehigkeiten"


def _group_label(namespace: str) -> str:
    """Kurze deutsche Ueberschrift aus dem capa-Namensraum.

    Aus ``_GROUP_DE``, NICHT aus ``_NAMESPACE_DE``: dort stehen Verbsaetze, die
    den Namen EINES Befunds bilden. Als Ueberschrift ueber einer Liste las sich
    das falsch ("Einrichten einer dauerhaften Autostart-Funktion (2)").
    """
    oberster = (namespace or "").split("/", 1)[0].strip()
    if not oberster:
        return _GROUP_FALLBACK
    return _GROUP_DE.get(oberster, _FALLBACK_GROUP_NAMES.get(oberster, _GROUP_FALLBACK))


# Rueckfall: ein Namensraum, den _GROUP_DE nicht kennt, bekommt die
# ausfuehrlichere Ueberschrift aus _NAMESPACE_DE — lieber lang als gar keine.
_FALLBACK_GROUP_NAMES = _NAMESPACE_DE


def _group_rank(label: str) -> int:
    """Sortierschluessel der Gruppen (siehe _GROUP_ORDER)."""
    for index, namespace in enumerate(_GROUP_ORDER):
        if label == _GROUP_DE.get(namespace, namespace):
            return index
    return len(_GROUP_ORDER)


class CapabilityPanel(QScrollArea):
    """Der Inhalt des Faehigkeiten-Reiters."""

    def __init__(self) -> None:
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self._body = QWidget()
        self._layout = QVBoxLayout(self._body)
        self._layout.setContentsMargins(16, 12, 16, 12)
        self._layout.setSpacing(8)
        self.setWidget(self._body)

    def clear(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def show_result(self, result: ScanResult) -> None:
        self.clear()
        faehigkeiten = list(getattr(result, "capa_capabilities", None) or [])
        if not faehigkeiten:
            self._add(
                "Für diese Datei liegen keine Fähigkeiten vor. Das heißt nicht, "
                "dass sie harmlos ist: capa erkennt gepackte Programme und "
                "unbekannte Formate nicht.",
                object_name="panelValue",
            )
            self._layout.addStretch(1)
            return

        self._add(
            f"Was dieses Programm technisch kann — {len(faehigkeiten)} "
            f"Fähigkeiten erkannt.",
            object_name="panelHeading",
        )
        self._add(
            "Das ist eine Einordnung, kein Urteil: viele dieser Fähigkeiten "
            "treffen auch auf völlig normale Programme zu. Ob die Datei "
            "gefährlich ist, steht oben im Ergebnis.",
            object_name="panelValue",
        )
        # Die Gruppen sind deutsch, die Einzelnamen sind capas eigene
        # Bezeichner und bleiben englisch. Das zu sagen ist besser, als den
        # Nutzer raten zu lassen — und besser, als tausend Regelnamen zu
        # uebersetzen, die mit jeder capa-Version wandern.
        self._add(
            "Die Gruppennamen sind übersetzt; die Einzelnamen stammen aus dem "
            "Regelwerk von capa und stehen dort auf Englisch.",
            object_name="panelKey",
        )

        gruppen: dict[str, list[str]] = defaultdict(list)
        for eintrag in faehigkeiten:
            # ``name`` (kurz), nicht ``display`` (mit Namensraum als Praefix):
            # die Gruppe steht schon in der Ueberschrift.
            gruppen[_group_label(str(eintrag.get("namespace", "")))].append(
                str(eintrag.get("name") or eintrag.get("display") or "")
            )

        for label in sorted(gruppen, key=_group_rank):
            namen = gruppen[label]
            self._add(
                _clip(f"{label} ({len(namen)})", MAX_DISPLAY_CHARS),
                object_name="panelHeading",
            )
            for name in namen[:40]:
                # Gekuerzt wie ueberall sonst (core/mail_view.MAX_DISPLAY_CHARS):
                # ein 5000-Zeichen-Name erzeugte ein 5006-Zeichen-Label. capa
                # liefert die Namen aus seinem Regelwerk, aber die Ausgabe
                # kommt von einem externen Werkzeug, das eine
                # angreiferkontrollierte Datei beschreibt — die Grenze gehoert
                # an die Senke, nicht ins Vertrauen.
                self._add(f"    • {_clip(name, MAX_DISPLAY_CHARS)}", object_name="panelValue")
            if len(namen) > 40:
                self._add(
                    f"    … und {len(namen) - 40} weitere", object_name="panelValue"
                )
        self._layout.addStretch(1)

    def _add(self, text: str, *, object_name: str) -> None:
        label = QLabel(text)
        label.setObjectName(object_name)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._layout.addWidget(label)
