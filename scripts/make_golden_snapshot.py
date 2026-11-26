"""Regenerate the golden snapshot for both corpora.

Run this AFTER an intended change to the detection logic, then review the JSON
diff — it lists exactly which files changed verdict, score or rule set. A large
unexplained diff means something moved that you did not mean to move.

Usage:
    python scripts/make_golden_snapshot.py [--check]

``--check`` reports drift without writing (same comparison as the test, but
prints the full list instead of failing on the first assertion).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import corpus_determinism as _det  # noqa: E402
import make_benign_corpus as benign  # noqa: E402
import make_corpus_v2 as corpus_v2  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402

from malaz import config  # noqa: E402
from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402
from malaz.core.scoring import BASE_WEIGHTS  # noqa: E402

SNAPSHOT = ROOT / "tests" / "data" / "golden_snapshot.json"


def _verdict(result) -> dict[str, object]:
    """The observable outcome of one scan.

    ``rules`` lists every rule that carried weight (it moved the score);
    ``notes`` lists the zero-weight ones. Both are recorded because the
    zero-weight findings are not noise — PE_PDB leaking a developer path,
    PE_TLS_EMPTY, PE_OVERLAY_SIGNATURE and the mitigation note are facts the
    report shows. Filtering them out made those code paths invisible to the
    snapshot: they could stop firing without a single test noticing.

    ``*_SKIPPED`` markers are excluded: they describe the ENGINE configuration
    (the corpus runs with AV engines off for determinism), not the file. They
    appear in all 91 entries, so including them would turn any engine-setting
    change into a 91-line diff and bury the real drift. The same holds for
    ``config.ENGINE_STATUS_RULE_IDS`` (``CAPA_UNAVAILABLE``): capa is not
    installed here, so it would ride along in every PE entry.
    """
    indicators = list(result.all_indicators())

    def keep(rule_id: str) -> bool:
        return not rule_id.endswith("_SKIPPED") and (
            rule_id not in config.ENGINE_STATUS_RULE_IDS
        )

    return {
        "risk": result.risk_level.name,
        "score": result.score,
        "type": result.detected_type,
        # effective_weight statt i.weight: Indicator.weight bleibt None, wenn
        # die Regel ihr Gewicht aus der SEVERITY bezieht (BASE_WEIGHTS:
        # MEDIUM 15, HIGH 30). GEMESSEN: ARCH_7Z_MISSING (20) und
        # GEN_FORMAT_MISMATCH landeten dadurch unter "notes", obwohl sie den
        # Score treiben — der Snapshot stufte score-treibende Befunde als
        # Notizen ein.
        #
        # EINE QUELLE: tests/test_corpus_golden.py importiert diese Funktion.
        # Vorher stand sie zweimal im Baum, mit demselben Fehler.
        "rules": sorted(
            {
                i.rule_id
                for i in indicators
                if i.effective_weight(BASE_WEIGHTS) and keep(i.rule_id)
            }
        ),
        # DAS KOMPLEMENT VON "rules", nicht "not i.weight".
        #
        # GEMESSEN: mit "not i.weight" stand GEN_FORMAT_MISMATCH in BEIDEN
        # Mengen. Ein Befund, dessen Gewicht aus der Severity kommt, hat
        # weight=None — er erfuellte "rules" (effective_weight) UND "notes"
        # (not i.weight). Die beiden Felder sind zwei Praedikate ueber
        # dieselbe Liste, also muss das zweite das Komplement des ersten sein.
        "notes": sorted(
            {
                i.rule_id
                for i in indicators
                if not i.effective_weight(BASE_WEIGHTS) and keep(i.rule_id)
            }
        ),
    }


def build(tmp: Path) -> dict[str, dict[str, object]]:
    # Shipped rules only — the optional third-party feeds are user-side
    # downloads, and so are the imported blocklists; letting either into the
    # snapshot would make the tripwire depend on what the developer has on his
    # machine. Mirrors the AV engines running disabled (see
    # tests/test_corpus_golden.py for the measured drift).
    with _det.pin_user_threat_intel(), _det.pin_no_7zip():
        dispatcher = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        snap: dict[str, dict[str, object]] = {}
        for group, builder in (
            ("benign", benign.build_corpus),
            # Signatur-Fixtures (rar/rpm/cab): sie sind nicht gruen, weil ein
            # nicht parsebarer Container kein Freispruch ist. Sie gehoeren
            # trotzdem in den Snapshot — sonst faellt eine kaputte Erkennung
            # fuer diese Typen niemandem auf.
            ("benign", benign.build_type_coverage),
            ("malicious", ext.build_extended_corpus),
            # Expanded corpus: 458 additional fixtures across scripts, PDF,
            # office, PE, images, archives, mail, LNK/RTF/SWF and edge cases.
            # Same shipped-rule, AV-off profile as the rest of the snapshot.
            ("v2", corpus_v2.write_corpus),
        ):
            for path in builder(tmp / group):
                snap[f"{group}/{path.name}"] = _verdict(dispatcher.scan_path(path))
    return snap


def main(argv: list[str] | None = None) -> int:
    # Nur bekannte Flags: ein Tippfehler (--chek, -c) darf nicht in den
    # Schreibzweig fallen und den Snapshot ueberschreiben (BUG-101).
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="nur mit dem vorhandenen Snapshot vergleichen (nichts schreiben)",
    )
    args = parser.parse_args(argv)
    check_only = args.check
    with tempfile.TemporaryDirectory() as tmp:
        actual = build(Path(tmp))

    if check_only:
        if not SNAPSHOT.exists():
            print("Kein Snapshot vorhanden.")
            return 1
        expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        drift = 0
        for key in sorted(set(expected) | set(actual)):
            want, got = expected.get(key), actual.get(key)
            if want == got:
                continue
            drift += 1
            print(f"{key}:")
            print(f"  erwartet: {want}")
            print(f"  aktuell : {got}")
        print(f"\n{drift} Abweichungen von {len(actual)} Dateien.")
        # CI-Gate: Drift ist ein Fehlschlag. Vorher stand hier immer 0 — der
        # Schritt lief damit gruen, waehrend der Snapshot abwich; nur der
        # pytest-Test fing es noch. Ein Gate muss selbst scheitern.
        return 1 if drift else 0

    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(
        json.dumps(actual, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Snapshot mit {len(actual)} Dateien nach {SNAPSHOT} geschrieben.")
    red = sum(1 for v in actual.values() if v["risk"] == "RED")
    yellow = sum(1 for v in actual.values() if v["risk"] == "YELLOW")
    green = sum(1 for v in actual.values() if v["risk"] == "GREEN")
    print(f"  GRÜN {green}  GELB {yellow}  ROT {red}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
