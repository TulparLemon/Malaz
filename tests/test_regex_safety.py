"""Regex-Zeittest: findet quadratische Muster, bevor sie im Betrieb auffallen.

Warum es diesen Test gibt
=========================

In dieser Sitzung wurden **drei** katastrophal backtrackende Muster gefunden —
und alle drei von Hand, jedes erst nach einem Vorfall:

1. ``_ANCHOR_RE`` (Runde 3): ``(?P<text>.*?)</a>`` mit DOTALL — eine 65-KB-Mail
   ohne ``</a>`` blockierte den Scan 24 s.
2. Der Adress-Check im Anzeigenamen (diese Runde): ``[\\w.+-]+@`` — EIN
   ``findall`` brauchte 10,98 s bei 40 000 Zeichen, 276,9 s bei 200 000.
3. ``_split_address`` (vorbestehend): ``<[^>]+>`` — 80 000 ``<`` kosteten
   28,28 s.

Die gemeinsame Form: eine **unbeschränkte Wiederholung**, die an jeder Position
ansetzen kann und dann bis ans Ende der Zeichenkette läuft, weil das erwartete
Literal nicht kommt. Alle drei Eingaben sind angreiferkontrolliert und über ein
ZIP-Mitglied für wenige Angreiferbytes erreichbar (Deflate solcher Zeilen ist
~1000:1).

Dieser Test probiert jedes Muster der angreifernahen Module gegen pathologische
Eingaben aus und verlangt eine Zeitgrenze. Er kennt die Muster nicht namentlich —
er findet sie per AST im Quelltext, damit ein **neues** Muster automatisch
mitgeprüft wird.
"""

from __future__ import annotations

import ast
import re
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "malaz"

# Module, deren Regexe auf angreiferkontrollierte Bytes oder Kopfzeilen laufen.
# TEST-019: pdf_pipeline/js_deobf/script_deobf/rtf_extract/generic_pipeline
# fehlten — genau die Module mit den gehaerteten Mustern aus dieser Runde
# blieben damit ungeprueft.
_MODULES = (
    "core/eml_analysis.py",
    "core/mail_view.py",
    "core/email_extract.py",
    "core/magic.py",
    "core/archive.py",
    "core/ooxml_rels.py",
    "core/binary_iocs.py",
    "core/js_deobf.py",
    "core/script_deobf.py",
    "core/rtf_extract.py",
    "pipelines/generic_pipeline.py",
    "pipelines/pdf_pipeline.py",
    "security/escaping.py",
)

# Compile flags from the AST. ``re.compile(pattern)`` alone loses e.g.
# ``re.IGNORECASE``/``re.DOTALL``, and a DOTALL pattern can be quadratic only
# WITH its flag — testing it without the flag hides exactly that (TEST-019).
_FLAG_NAMES = {
    "IGNORECASE": re.IGNORECASE,
    "I": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "M": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "S": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "X": re.VERBOSE,
    "ASCII": re.ASCII,
    "A": re.ASCII,
}

# Eingabelänge je Muster. 20 000 Zeichen ist weit über allem, was ein echter
# Header oder Dateiname hat, und klein genug, dass ein lineares Muster unter der
# Millisekunde bleibt.
_PROBE = 20_000
# Gemessen wird das VERHÄLTNIS, nicht eine absolute Zeit. Eine absolute Grenze
# ist lastabhängig: der langsamste lineare Vertreter kostet hier 0,044 s, das
# lässt nur ~25x Luft — und ein Commit während eines Nuitka-Builds (200 s,
# CPU-gesättigt) könnte die Prüfung falsch rot machen. Das Verhältnis trennt
# quadratisch von linear unabhängig von der Maschinengeschwindigkeit: linear
# verdoppelt sich, quadratisch vervierfacht sich.
_RATIO_LIMIT = 3.0
# Untergrenze, damit die Messung nicht in Rauschen rechnet. Mit CPU-Zeit und dem
# Minimum aus drei Laeufen liegt ein lineares Muster hier bei exakt 2,00 (das
# beschraenkte Adressmuster misst 0,0156 -> 0,0312 s) — die 3,1, die eine
# Einzellauf-Wanduhrmessung einmal lieferte, waren Rauschen und sind mit dieser
# Messweise weg. Die Grenze wird NICHT angehoben, um Falschpositive zu
# vermeiden: dann rutschte ein schwach ueberlineares Muster durch.
_MIN_SECONDS = 0.005
# Netz zusaetzlich zum Verhaeltnis: sind BEIDE Messungen gross, kann ein
# gedaempftes Verhaeltnis ein langsames Muster verdecken.
_MAX_SECONDS = 10.0

# Pathologische Formen. Bewusst generisch: eine lange Wiederholung eines
# Zeichens, das in irgendeiner Klasse vorkommt, aber das gesuchte Literal nicht
# enthält — genau der Fall, in dem die Wiederholung bis ans Ende läuft.
_FILLERS = ("A", "<", "-", " ", "0", ".", "a@", "\u202e")


def _flag_value(node: ast.AST) -> int:
    """Resolve ``re.IGNORECASE`` / ``A | B`` symbolic flags, else 0.

    Literal integers are deliberately NOT interpreted: positional slots are
    call-signature dependent (``re.sub``'s fourth argument is a COUNT), and a
    count of 2 would otherwise be mistaken for ``re.IGNORECASE``.
    """
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "re":
            return _FLAG_NAMES.get(node.attr, 0)
        return 0
    if isinstance(node, ast.Name):
        return _FLAG_NAMES.get(node.id, 0)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _flag_value(node.left) | _flag_value(node.right)
    return 0


def _pattern_flags(node: ast.Call) -> int:
    # ``re.sub(pattern, repl, text, count, flags)`` puts flags later than the
    # second argument; scanning every positional slot after the pattern is the
    # only call-signature-independent way to see them.
    flags = 0
    for arg in node.args[1:]:
        flags |= _flag_value(arg)
    for keyword in node.keywords:
        if keyword.arg == "flags":
            flags |= _flag_value(keyword.value)
    return flags


def _patterns() -> list[tuple[str, str, int]]:
    """``(datei, muster, flags)`` für jedes Regex-Literal der Module."""
    out: list[tuple[str, str, int]] = []
    for rel in _MODULES:
        path = _SRC / rel
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else None
            if name not in ("compile", "search", "match", "fullmatch", "findall", "finditer", "sub"):
                continue
            if not node.args:
                continue
            try:
                pattern = ast.literal_eval(node.args[0])
            except (ValueError, SyntaxError):
                continue  # dynamisch gebaut (f-String) — hier nicht prüfbar
            if isinstance(pattern, bytes):
                pattern = pattern.decode("utf-8", "replace")
            if isinstance(pattern, str):
                out.append((rel, pattern, _pattern_flags(node)))
    return out


def test_pattern_scan_covers_the_attacker_facing_modules():
    """TEST-019: a module outside ``_MODULES`` was silently unexamined."""
    covered = {rel for rel, _pattern, _flags in _patterns()}
    required = {
        "core/eml_analysis.py",
        "core/js_deobf.py",
        "core/script_deobf.py",
        "core/rtf_extract.py",
        "pipelines/generic_pipeline.py",
        "pipelines/pdf_pipeline.py",
    }
    missing = required - covered
    assert not missing, f"nicht geprüfte Module: {sorted(missing)}"


def test_compile_flags_reach_the_compiled_pattern():
    """TEST-019: ``re.compile(pattern)`` dropped the pattern's flags.

    ``generic_pipeline._URL_RE`` is compiled with ``re.IGNORECASE``; the AST
    scan must carry that flag or it tests a different pattern than production.
    """
    url_patterns = {
        (pattern, flags)
        for rel, pattern, flags in _patterns()
        if rel == "pipelines/generic_pipeline.py" and "https?://" in pattern
    }
    assert url_patterns, "URL-Muster nicht gefunden"
    assert any(flags & re.IGNORECASE for _pattern, flags in url_patterns)


def test_no_attacker_facing_regex_is_quadratic():
    """Jedes Muster bleibt bei pathologischer Eingabe unter der Zeitgrenze."""
    patterns = _patterns()
    assert len(patterns) >= 10, (
        f"nur {len(patterns)} Muster gefunden — die AST-Suche greift ins Leere"
    )

    slow: list[str] = []
    for rel, pattern, flags in patterns:
        try:
            compiled = re.compile(pattern, flags)
        except re.error:
            continue  # kein gültiges Muster an dieser Stelle (z. B. dynamisch)
        for filler in _FILLERS:
            def run(length: int, fill: str = filler, rx=compiled) -> float:
                # ``fill`` als Default bindet den Schleifenwert; ohne das sieht
                # der spaetere Aufruf den letzten Wert der Schleife.
                #
                # CPU-Zeit statt Wanduhr und das MINIMUM aus mehreren Laeufen:
                # eine absolute Grenze auf der Wanduhr war lastabhaengig (ein
                # Commit waehrend eines Nuitka-Builds haette sie falsch rot
                # gemacht), und ein einzelner Lauf rauscht — das beschraenkte
                # Muster kam damit auf 3,1 statt ~2.
                #
                # THREAD-Zeit statt Prozesszeit: ``process_time`` zaehlt die
                # CPU aller Threads, und der Prozess hat einen QThreadPool.
                probe = (fill * (length // max(len(fill), 1)))[:length]
                best = float("inf")
                for _ in range(3):
                    started = time.thread_time()
                    try:
                        rx.search(probe)
                    except Exception:
                        return 0.0  # ein Fehler ist schnell; hier zählt die Zeit
                    best = min(best, time.thread_time() - started)
                return best

            small = run(_PROBE)
            large = run(_PROBE * 2)
            if small < _MIN_SECONDS or large < _MIN_SECONDS:
                continue  # zu schnell fuer eine belastbare Aussage
            ratio = large / small
            if ratio > _RATIO_LIMIT or large > _MAX_SECONDS:
                slow.append(
                    f"{rel}: {pattern[:60]!r} — {small:.3f}s auf {_PROBE} Zeichen "
                    f"{filler!r}, {large:.3f}s auf {_PROBE * 2} (Faktor "
                    f"{ratio:.1f}, quadratisch waere ~4)"
                )
                break

    assert not slow, (
        "quadratische Muster gefunden — eine unbeschraenkte Wiederholung laeuft "
        "bis ans Ende der Zeichenkette, wenn das erwartete Literal fehlt:\n  "
        + "\n  ".join(slow)
    )
