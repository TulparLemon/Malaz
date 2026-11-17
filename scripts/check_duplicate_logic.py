"""Findet dieselbe Logik in mehreren Modulen — mein haeufigster Fehler.

WARUM DIESES SKRIPT EXISTIERT
=============================
Der Fehler, den ich in dieser Sitzung am oeftesten gemacht habe, ist nicht ein
falscher Ausdruck. Es ist: **eine Stelle reparieren und die Schwesterstelle
uebersehen.** Belegt im Verlauf:

* Der Adress-Ausdruck `[\\w.+-]+@...` stand in `core/eml_analysis.py` UND in
  `core/mail_view.py`. Repariert wurde zuerst nur eine — die andere lief
  weiter mit dem quadratischen Muster.
* Der Deckel fuer den Kopfblock stand in `core/magic.py` und in
  `core/eml_analysis.py`. Entfernt wurde zuerst nur einer.
* `olefile`-Aufrufe: zweimal dieselbe Ausnahme-Behandlung an zwei Stellen.
* `tempfile.mkstemp`: dieselbe Aufraeum-Luecke an mehreren Aufrufern.

Ein Test kann das nicht finden, weil jeder Einzeltest nur seine eine Stelle
kennt. Was es findet: dieselbe Zeichenkette, dieselbe Zahl, dasselbe Muster an
mehreren Orten. Genau das prueft dieses Skript — es verbietet die Dopplung
nicht, es VERLANGT eine Entscheidung: zusammenfuehren oder begruenden.

WAS GEMELDET WIRD
=================
1. Regex-Literale, die in zwei oder mehr Modulen wortgleich vorkommen.
2. Modulweite Konstanten mit gleichem Namen ODER gleichem Wert in zwei oder
   mehr Modulen (Zahlen ab zwei Ziffern, Zeichenketten ab acht Zeichen).

Triviale Werte (`""`, `"utf-8"`, `"sha256"`, `0`, `1`) werden ignoriert —
sonst waere der Bericht Rauschen und wuerde weggeklickt.

WIE MAN EINE MELDUNG LOSWIRD
============================
Entweder die Dopplung aufloesen (gemeinsame Funktion/Konstante), oder den Fall
in `scripts/duplicate_logic_allow.txt` mit Begruendung eintragen. Eine
Ausnahme ohne Begruendung ist selbst ein Fehler und wird gemeldet.
"""

from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "malaz"
ALLOWLIST = ROOT / "scripts" / "duplicate_logic_allow.txt"

# Namen, unter denen ein Regex-Literal stehen darf, damit es als Muster zaehlt.
_REGEX_HINT = re.compile(r"(RE|REGEX|PATTERN|_RX$)", re.IGNORECASE)
# Aufrufe, deren erstes Argument ein Muster ist.
_RE_FUNCS = {"compile", "search", "match", "findall", "finditer", "sub", "split", "fullmatch"}
# Werte, die als Konstanten zu trivial fuer eine Meldung sind.
_TRIVIAL = {"", "utf-8", "utf8", "sha256", "sha1", "md5", "ascii", "r", "rb", "w", "wb"}


def _is_interesting_regex(text: str) -> bool:
    """Nur Muster, deren Dopplung wirklich gefaehrlich ist.

    Ein Literal ohne Metazeichen (etwa `"__attach_"`) ist ein Name, kein
    Muster; solche Dopplungen sind harmlos und wuerden den Bericht fluten.
    """
    if len(text) < 8:
        return False
    return any(ch in text for ch in ".+*?[](){}|\\^$")


def _is_interesting_const(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) >= 10
    if isinstance(value, str):
        return len(value) >= 8 and value.strip().lower() not in _TRIVIAL
    # Sammlungen. Bis hierher sah der Pruefer NUR Skalare
    # (isinstance(node.value, ast.Constant)) — ein dict-Literal ist ein
    # ast.Dict und wurde nie verglichen. Folge: _AUTH_LABELS stand wortgleich
    # in core/mail_view.py und reporting/mail_section.py, und der Pruefer
    # meldete "Keine unbegruendeten Dopplungen". Genau die Fehlerklasse, fuer
    # die es dieses Skript gibt, war damit unsichtbar.
    if isinstance(value, dict):
        return len(value) >= 3 and all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return len(value) >= 3 and all(isinstance(v, str) for v in value)
    return False


def _regex_literals(tree: ast.AST) -> list[tuple[str, int]]:
    """Alle Regex-Literale einer Datei als ``(muster, zeile)``."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        # re.search("...", ...) und Verwandte
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in _RE_FUNCS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                text = node.args[0].value
                if _is_interesting_regex(text):
                    found.append((text, node.lineno))
        # REGEX = "..." / _PATTERN = "..."
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and _REGEX_HINT.search(target.id)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and _is_interesting_regex(node.value.value)
                ):
                    found.append((node.value.value, node.lineno))
    return found


def _literal_of(node: ast.AST):
    """Wert eines Literals — Skalar ODER dict/list/tuple, sonst ``None``.

    ``ast.literal_eval`` lehnt alles ab, was Ausdruecke enthaelt; genau das ist
    hier gewuenscht, denn nur feste Literale sind vergleichbar.
    """
    if not isinstance(node, (ast.Constant, ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        return None


def _module_constants(tree: ast.AST) -> list[tuple[str, object, int]]:
    """Modulweite Konstanten als ``(name, wert, zeile)``."""
    found: list[tuple[str, object, int]] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                value = _literal_of(node.value)
                if value is not None and _is_interesting_const(value):
                    found.append((target.id, value, node.lineno))
    return found


def _load_allowlist() -> set[str]:
    """Erlaubte Dopplungen; jede Zeile braucht ``#`` und eine Begruendung."""
    if not ALLOWLIST.exists():
        return set()
    allowed: set[str] = set()
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry, _, reason = line.partition("#")
        allowed.add(entry.strip())
        if not reason.strip():
            print(f"  FEHLER: Ausnahme ohne Begruendung: {entry.strip()!r}")
            return None
    return allowed


def main() -> int:
    allowed = _load_allowlist()
    if allowed is None:
        return 1

    regex_sites: dict[str, list[str]] = defaultdict(list)
    const_sites: dict[str, list[str]] = defaultdict(list)
    const_by_name: dict[str, list[tuple[str, object]]] = defaultdict(list)

    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            print(f"  FEHLER: {rel} nicht lesbar: {exc}")
            return 1
        for text, line in _regex_literals(tree):
            regex_sites[text].append(f"{rel}:{line}")
        for name, value, line in _module_constants(tree):
            # Schluessel je nach Typ.
            #
            # SAMMLUNGEN nach dem WERT: eine Tabelle aus drei oder mehr
            # Zeichenketten beschreibt sich selbst, und ihr Name ist beliebig.
            # Mit dem Namen im Schluessel entkam eine umbenannte Kopie — die
            # Tabelle hiess hier AUTH_LABELS und dort _AUTH_LABELS und galt
            # damit als zwei Konstanten. Gemessen mit einer Beissprobe, die
            # genau das wieder einbaute und GRUEN blieb.
            #
            # SKALARE nach NAME=WERT: die 4096 in einem Modul ist eine andere
            # Grenze als die 4096 in einem anderen. Nur der Wert als Schluessel
            # meldete vier Zahlenpaare als "Dopplung", die nichts miteinander
            # zu tun haben.
            if isinstance(value, (dict, list, tuple, set)):
                const_sites[repr(value)].append(f"{rel}:{line} ({name})")
            else:
                const_sites[f"{name}={value!r}"].append(f"{rel}:{line}")
            const_by_name[name].append((rel, value))

    problems: list[str] = []

    for text, sites in sorted(regex_sites.items()):
        files = {site.split(":")[0] for site in sites}
        if len(files) < 2 or text in allowed:
            continue
        problems.append(
            f"Regex in {len(files)} Modulen wortgleich: {text!r}\n"
            + "\n".join(f"    {site}" for site in sites)
        )

    for key, sites in sorted(const_sites.items()):
        files = {site.split(":")[0] for site in sites}
        if len(files) < 2 or key in allowed:
            continue
        problems.append(
            f"Derselbe Wert in {len(files)} Modulen: {key[:120]}\n"
            + "\n".join(f"    {site}" for site in sites)
        )

    # Gleicher Name, unterschiedlicher Wert: die klassische Falle, bei der eine
    # Aenderung an einer Stelle die andere still zuruecklaesst.
    for name, entries in sorted(const_by_name.items()):
        # `__all__` ist die Exportliste EINES Moduls und deshalb absichtlich
        # je Modul verschieden — kein Drift, sondern die Definition.
        if name.startswith("__"):
            continue
        # repr() statt der Werte selbst: dict/list sind nicht hashbar, und
        # verglichen wird ohnehin die Darstellung.
        values = {repr(value) for _, value in entries}
        if len(values) < 2:
            continue
        files = {rel for rel, _ in entries}
        if len(files) < 2:
            continue
        key = f"NAME:{name}"
        if key in allowed:
            continue
        shown = "\n".join(f"    {rel}: {value!r}" for rel, value in entries)
        problems.append(f"Konstante {name} hat in mehreren Modulen ANDERE Werte:\n{shown}")

    if problems:
        print(f"\n  {len(problems)} Dopplung(en) mit Entscheidungsbedarf:\n")
        for problem in problems:
            print(f"  - {problem}\n")
        print(
            "  Entweder zusammenfuehren oder in scripts/duplicate_logic_allow.txt\n"
            "  mit Begruendung eintragen.\n"
        )
        return 1

    print("  Keine unbegruendeten Dopplungen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
