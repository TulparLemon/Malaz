"""One-shot corpus overview: what does the analyser say about every fixture?

The test suite answers "did anything change?". This answers the human question
"what does it actually detect right now?" — a single command that prints both
corpora with verdict, score and the rules that fired.

Usage:
    python scripts/run_corpus.py              # both corpora
    python scripts/run_corpus.py --benign     # only the harmless side
    python scripts/run_corpus.py --malicious  # only the malware-looking side
    python scripts/run_corpus.py --csv out.csv

Runs with the AV engines disabled, so the result is deterministic and depends
only on the static pipelines — the same configuration the tests use.
"""

from __future__ import annotations

import csv
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import corpus_determinism as _det  # noqa: E402
import make_benign_corpus as benign  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402

from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402
from malaz.core.scoring import BASE_WEIGHTS  # noqa: E402

_MARK = {"GREEN": "OK ", "YELLOW": "~~ ", "RED": "!! "}


def _rules(result, limit: int = 5) -> str:
    # effective_weight statt i.weight: ein Befund ohne explizites Gewicht
    # traegt sein Severity-Gewicht (z. B. GEN_FORMAT_MISMATCH HIGH -> 30) und
    # fiel mit ``if i.weight`` komplett aus der Uebersicht — der Score zeigte
    # 30, die Regelliste aber nichts. Dieselbe Quelle wie compute_score.
    inds = sorted(
        (
            (i, i.effective_weight(BASE_WEIGHTS))
            for i in result.all_indicators()
        ),
        key=lambda pair: (pair[0].severity, pair[1]),
        reverse=True,
    )
    return ", ".join(f"{i.rule_id}({weight})" for i, weight in inds[:limit])


def _children(result) -> str:
    if not result.children:
        return ""
    types = Counter(c.detected_type for c in result.children)
    return " | " + ", ".join(f"{n}x {t}" for t, n in sorted(types.items()))


def run(groups: dict[str, object]) -> int:
    # Same isolation as the golden snapshot: the imported lists and rule feeds
    # are per-machine state, so the overview shows the project's own detection
    # and not what this developer fetched.
    with _det.pin_user_threat_intel(), _det.pin_no_7zip():
        dispatcher = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        rows: list[list[str]] = [["Gruppe", "Datei", "Typ", "Urteil", "Score", "Regeln"]]

        with tempfile.TemporaryDirectory() as tmp:
            for group, builder in groups.items():
                paths = builder(Path(tmp) / group)  # type: ignore[operator]
                print(f"\n=== {group.upper()} ({len(paths)} Dateien) ===")
                counter: Counter[str] = Counter()
                for path in paths:
                    result = dispatcher.scan_path(path)
                    counter[result.risk_level.name] += 1
                    print(
                        f"  {_MARK.get(result.risk_level.name, '?  ')}"
                        f"{path.name:26s} {result.risk_level.name:6s} "
                        f"{result.score:3d}  {result.detected_type:8s} "
                        f"{_rules(result)}{_children(result)}"
                    )
                    rows.append(
                        [
                            group,
                            path.name,
                            result.detected_type or "",
                            result.risk_level.name,
                            str(result.score),
                            _rules(result, 99),
                        ]
                    )
                total = max(sum(counter.values()), 1)
                print(
                    f"  --> GRÜN {counter['GREEN']:3d}  GELB {counter['YELLOW']:3d}  "
                    f"ROT {counter['RED']:3d}   "
                    f"(ROT {counter['RED'] / total:.0%})"
                )

    if "--csv" in sys.argv:
        target = Path(sys.argv[sys.argv.index("--csv") + 1])
        target.parent.mkdir(parents=True, exist_ok=True)
        # safe_cell + utf-8-sig wie in evaluation.py und reporting/export.py.
        # AUDIT-BEFUND 9: die Zellen tragen Dateinamen, also
        # angreiferkontrollierten Inhalt — ein Name "=HYPERLINK(...)" waere
        # beim Oeffnen eine Formel (CWE-1236). Dritte Senke derselben Klasse.
        sys.path.insert(0, str(ROOT / "src"))
        from malaz.reporting.export import safe_cell

        with target.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerows([safe_cell(str(z)) for z in zeile] for zeile in rows)
        print(f"\nCSV: {target}")
    return 0


def main() -> int:
    only_benign = "--benign" in sys.argv
    only_malicious = "--malicious" in sys.argv
    groups: dict[str, object] = {}
    if not only_malicious:
        groups["harmlos"] = benign.build_corpus
    if not only_benign:
        groups["bösartig"] = ext.build_extended_corpus
    if "--v2" in sys.argv:
        import make_corpus_v2

        groups["v2"] = make_corpus_v2.write_corpus
    return run(groups)


if __name__ == "__main__":
    raise SystemExit(main())
