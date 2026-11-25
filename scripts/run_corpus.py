"""One-shot corpus overview & deterministic benchmark report generator/checker.

The test suite answers "did anything change?". This answers the human question
"what does it actually detect right now?" - and provides the CI-verified
deterministic benchmark measurements embedded in ``docs/BENCHMARKS.md``.

Usage:
    python scripts/run_corpus.py                          # console overview (both legacy corpora)
    python scripts/run_corpus.py --benign                 # only harmless fixtures
    python scripts/run_corpus.py --malicious              # only malicious fixtures
    python scripts/run_corpus.py --v2                     # include corpus_v2 in console overview
    python scripts/run_corpus.py --csv out.csv            # export CSV table
    python scripts/run_corpus.py --json out.json          # full 5-corpus deterministic JSON
    python scripts/run_corpus.py --update-doc docs/BENCHMARKS.md
    python scripts/run_corpus.py --check-doc docs/BENCHMARKS.md

Runs with external AV/CLI engines and user feeds deterministically disabled/pinned
so results depend exclusively on Malaz's built-in static pipelines and YARA rules.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import check_tests_bite  # noqa: E402
import corpus_determinism as _det  # noqa: E402
import make_benign_corpus as benign  # noqa: E402
import make_corpus_v2 as corpus_v2  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402

from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402
from malaz.core.scoring import BASE_WEIGHTS  # noqa: E402
from malaz.core.unchecked import is_unchecked_rule  # noqa: E402

_MARK = {"GREEN": "OK ", "YELLOW": "~~ ", "RED": "!! "}

BENCHMARK_START_MARKER = "<!-- BENCHMARK_STATS_START -->"
BENCHMARK_END_MARKER = "<!-- BENCHMARK_STATS_END -->"

#: Skip rules that are explicitly configured by the deterministic static-only profile.
_CONFIGURED_STATIC_SKIP_RULES = frozenset(
    {
        "AV_SKIPPED",
        "CLAMAV_SKIPPED",
        "ARCH_7Z_MISSING",
        "DIE_SKIPPED",
        "CAPA_SKIPPED",
    }
)

_BENCHMARK_ROWS: tuple[tuple[str, str, str], ...] = (
    (
        "malicious",
        "Malicious fixtures (`scripts/make_test_corpus_extended.py`)",
        "flagged",
    ),
    (
        "benign",
        "Benign fixtures (`scripts/make_benign_corpus.py`)",
        "benign",
    ),
    (
        "v2_malicious",
        "Broad corpus v2 - malicious (`scripts/make_corpus_v2.py`)",
        "flagged",
    ),
    (
        "v2_benign",
        "Broad corpus v2 - benign (`scripts/make_corpus_v2.py`)",
        "benign",
    ),
    (
        "v2_edge",
        "Broad corpus v2 - edge cases (`scripts/make_corpus_v2.py`)",
        "flagged",
    ),
)


def _pct(num: int, total: int) -> float:
    return 0.0 if total <= 0 else round((num / total) * 100.0, 1)


def _write_v2_subset(target_dir: Path, kind: str) -> list[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for fx in corpus_v2.build_fixtures():
        if fx.kind != kind:
            continue
        out = target_dir / fx.name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(fx.data)
        paths.append(out)
    return paths


def _default_benchmark_groups() -> dict[str, Callable[[Path], list[Path]]]:
    return {
        "malicious": ext.build_extended_corpus,
        "benign": benign.build_corpus,
        "v2_malicious": lambda d: _write_v2_subset(d, "malicious"),
        "v2_benign": lambda d: _write_v2_subset(d, "benign"),
        "v2_edge": lambda d: _write_v2_subset(d, "edge"),
    }


def _rules(result, limit: int = 5) -> str:
    inds = sorted(
        ((i, i.effective_weight(BASE_WEIGHTS)) for i in result.all_indicators()),
        key=lambda pair: (pair[0].severity, pair[1]),
        reverse=True,
    )
    return ", ".join(f"{i.rule_id}({weight})" for i, weight in inds[:limit])


def _children(result) -> str:
    if not result.children:
        return ""
    types = Counter(c.detected_type for c in result.children)
    return " | " + ", ".join(f"{n}x {t}" for t, n in sorted(types.items()))


def _has_unexpected_incomplete(result) -> bool:
    return any(
        is_unchecked_rule(ind.rule_id)
        and ind.rule_id not in _CONFIGURED_STATIC_SKIP_RULES
        for ind in result.all_indicators()
    )


def measure_corpora(
    groups: dict[str, Callable[[Path], list[Path]]] | None = None,
    *,
    dispatcher: Dispatcher | None = None,
) -> dict[str, Any]:
    """Run deterministic static-only measurements across all benchmark corpora."""
    selected = _default_benchmark_groups() if groups is None else groups
    with _det.pin_user_threat_intel(), _det.pin_no_7zip():
        active_dispatcher = (
            dispatcher
            if dispatcher is not None
            else Dispatcher(
                av_scanner=WindowsDefenderScanner(enabled=False),
                clam_scanner=ClamAVScanner(enabled=False),
            )
        )
        yara_active = bool(active_dispatcher.yara.available)
        active_engines = ["static_pipelines"]
        skipped_engines = [
            "windows_defender",
            "clamav",
            "7zip",
            "die",
            "capa",
            "user_threat_intel_feeds",
        ]
        if yara_active:
            active_engines.append("yara_builtin")
        else:
            skipped_engines.insert(0, "yara_builtin")

        corpora_out: dict[str, dict[str, Any]] = {}
        with tempfile.TemporaryDirectory(prefix="malaz_bench_") as tmp:
            for group_name, builder in selected.items():
                paths = builder(Path(tmp) / group_name)
                red = yellow = green = crashes = incomplete_unexpected = 0
                for path in paths:
                    try:
                        result = active_dispatcher.scan_path(path)
                    except Exception:
                        crashes += 1
                        continue
                    risk = result.risk_level.name
                    if risk == "RED":
                        red += 1
                    elif risk == "YELLOW":
                        yellow += 1
                    else:
                        green += 1
                    if _has_unexpected_incomplete(result):
                        incomplete_unexpected += 1

                total = len(paths)
                entry: dict[str, Any] = {
                    "total": total,
                    "red": red,
                    "yellow": yellow,
                    "green": green,
                    "crashes": crashes,
                    "incomplete_unexpected": incomplete_unexpected,
                }
                if group_name in ("benign", "v2_benign"):
                    entry["red_fp_rate_pct"] = _pct(red, total)
                    entry["yellow_rate_pct"] = _pct(yellow, total)
                else:
                    entry["flagged_rate_pct"] = _pct(red + yellow, total)
                    entry["red_rate_pct"] = _pct(red, total)
                corpora_out[group_name] = entry

    return {
        "schema_version": 1,
        "profile": "deterministic_static_only",
        "active_engines": active_engines,
        "skipped_engines": skipped_engines,
        "mutations_registered": len(check_tests_bite.MUTATIONS),
        "corpora": corpora_out,
    }


def render_benchmark_block(stats: dict[str, Any]) -> str:
    """Render the deterministic Markdown statistics block for docs/BENCHMARKS.md."""
    active_str = ", ".join(f"`{e}`" for e in stats["active_engines"])
    skipped_str = ", ".join(f"`{e}`" for e in stats["skipped_engines"])
    mutations = int(stats["mutations_registered"])
    corpora = stats["corpora"]

    lines = [
        BENCHMARK_START_MARKER,
        f"- **Profile:** `{stats['profile']}` (offline, no external AV/CLI subprocesses)",
        f"- **Active engines:** {active_str}",
        f"- **Intentionally disabled/pinned engines:** {skipped_str}",
        (
            f"- **Registered mutation checks:** {mutations} "
            "(verified separately in CI via `scripts/check_tests_bite.py`)"
        ),
        "",
        (
            "| Synthetic Corpus | Files | RED | YELLOW | GREEN | Crashes "
            "| Unexpected Incomplete | Key Rates (denominator = all files) |"
        ),
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
    ]
    for key, label, mode in _BENCHMARK_ROWS:
        if key not in corpora:
            continue
        c = corpora[key]
        if mode == "benign":
            rates = (
                f"{float(c['red_fp_rate_pct']):.1f}% `RED` FP, "
                f"{float(c['yellow_rate_pct']):.1f}% `YELLOW`"
            )
        else:
            rates = (
                f"{float(c['flagged_rate_pct']):.1f}% flagged (`RED+YELLOW`), "
                f"{float(c['red_rate_pct']):.1f}% `RED`"
            )
        lines.append(
            f"| {label} | {int(c['total'])} | {int(c['red'])} | {int(c['yellow'])} "
            f"| {int(c['green'])} | {int(c['crashes'])} | {int(c['incomplete_unexpected'])} | {rates} |"
        )
    lines.append(BENCHMARK_END_MARKER)
    return "\n".join(lines)


def _find_marker_span(text: str) -> tuple[int, int]:
    """Validate marker structure and return ``(start_idx, end_exclusive_idx)``."""
    starts: list[int] = []
    pos = 0
    while True:
        idx = text.find(BENCHMARK_START_MARKER, pos)
        if idx == -1:
            break
        starts.append(idx)
        pos = idx + len(BENCHMARK_START_MARKER)

    ends: list[int] = []
    pos = 0
    while True:
        idx = text.find(BENCHMARK_END_MARKER, pos)
        if idx == -1:
            break
        ends.append(idx)
        pos = idx + len(BENCHMARK_END_MARKER)

    if len(starts) != 1 or len(ends) != 1:
        raise ValueError(
            f"Expected exactly 1 start and 1 end marker "
            f"(found {len(starts)} start, {len(ends)} end)"
        )
    if starts[0] >= ends[0]:
        raise ValueError("Benchmark markers are inverted (END appears before START)")
    return starts[0], ends[0] + len(BENCHMARK_END_MARKER)


def validate_benchmark_markers(doc_path: Path) -> None:
    """Fail-fast check that ``doc_path`` exists and has a valid marker pair."""
    raw = doc_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    _find_marker_span(raw)


def update_benchmark_doc(doc_path: Path, stats: dict[str, Any]) -> None:
    """Atomically replace the benchmark statistics block in ``doc_path`` with LF endings."""
    raw = doc_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    start, end = _find_marker_span(raw)
    rendered = render_benchmark_block(stats)
    updated = raw[:start] + rendered + raw[end:]
    if not updated.endswith("\n"):
        updated += "\n"

    fd, tmp_name = tempfile.mkstemp(
        dir=str(doc_path.parent), prefix=".malaz_bench_", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(updated)
        os.replace(tmp_name, doc_path)
    except Exception:
        with suppress(OSError):
            os.unlink(tmp_name)
        raise


def check_benchmark_doc(doc_path: Path, stats: dict[str, Any]) -> tuple[bool, str]:
    """Compare the marker block in ``doc_path`` 1:1 against freshly measured ``stats``."""
    raw = doc_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    try:
        start, end = _find_marker_span(raw)
    except ValueError as exc:
        return False, str(exc)

    actual = raw[start:end].strip()
    expected = render_benchmark_block(stats).strip()
    if actual == expected:
        return True, ""

    diff = "\n".join(
        difflib.unified_diff(
            actual.splitlines(),
            expected.splitlines(),
            fromfile=f"{doc_path.name} (committed)",
            tofile="measured (current)",
            lineterm="",
        )
    )
    return False, diff


def run(groups: dict[str, object], *, csv_path: Path | None = None) -> int:
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

    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        from malaz.reporting.export import safe_cell

        with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerows([safe_cell(str(z)) for z in zeile] for zeile in rows)
        print(f"\nCSV: {csv_path}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deterministic corpus overview & benchmark doc report/check."
    )
    parser.add_argument("--benign", action="store_true", help="Console overview: benign only")
    parser.add_argument("--malicious", action="store_true", help="Console overview: malicious only")
    parser.add_argument("--v2", action="store_true", help="Console overview: also include corpus_v2")
    parser.add_argument("--csv", type=Path, default=None, help="Export console overview as CSV")
    parser.add_argument("--json", type=Path, default=None, help="Write deterministic benchmark JSON")
    parser.add_argument(
        "--update-doc",
        type=Path,
        default=None,
        help="Atomically update the benchmark marker block in a Markdown file",
    )
    parser.add_argument(
        "--check-doc",
        type=Path,
        default=None,
        help="Verify the benchmark marker block in a Markdown file matches fresh measurements",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    structured_mode = any(x is not None for x in (args.json, args.update_doc, args.check_doc))
    if structured_mode:
        if args.update_doc is not None and args.check_doc is not None:
            print("Error: --update-doc and --check-doc are mutually exclusive.", file=sys.stderr)
            return 2
        if args.benign or args.malicious or args.v2 or args.csv is not None:
            print(
                "Error: --json, --update-doc, and --check-doc require the full default benchmark "
                "corpus and cannot be combined with --benign, --malicious, --v2, or --csv.",
                file=sys.stderr,
            )
            return 2

        doc_target = args.check_doc or args.update_doc
        if doc_target is not None:
            if not doc_target.is_file():
                print(f"Error: benchmark doc not found: {doc_target}", file=sys.stderr)
                return 2
            try:
                validate_benchmark_markers(doc_target)
            except OSError as exc:
                print(f"Error reading {doc_target}: {exc}", file=sys.stderr)
                return 2
            except ValueError as exc:
                print(f"Benchmark marker error in {doc_target}: {exc}", file=sys.stderr)
                return 1

        stats = measure_corpora()

        if args.json is not None:
            try:
                args.json.parent.mkdir(parents=True, exist_ok=True)
                args.json.write_text(
                    json.dumps(stats, indent=2) + "\n", encoding="utf-8", newline="\n"
                )
            except OSError as exc:
                print(f"Error writing JSON {args.json}: {exc}", file=sys.stderr)
                return 2

        if args.update_doc is not None:
            try:
                update_benchmark_doc(args.update_doc, stats)
            except ValueError as exc:
                print(f"Benchmark marker error in {args.update_doc}: {exc}", file=sys.stderr)
                return 1
            except OSError as exc:
                print(f"Error updating {args.update_doc}: {exc}", file=sys.stderr)
                return 2
            print(f"Updated benchmark block in {args.update_doc}")
            return 0

        if args.check_doc is not None:
            try:
                ok, detail = check_benchmark_doc(args.check_doc, stats)
            except OSError as exc:
                print(f"Error reading {args.check_doc}: {exc}", file=sys.stderr)
                return 2
            if not ok:
                print(f"Benchmark doc drift detected in {args.check_doc}:\n{detail}", file=sys.stderr)
                return 1
            print(f"Benchmark block in {args.check_doc} matches current measurements.")
            return 0

        return 0

    groups: dict[str, object] = {}
    if not args.malicious:
        groups["harmlos"] = benign.build_corpus
    if not args.benign:
        groups["bösartig"] = ext.build_extended_corpus
    if args.v2:
        groups["v2"] = corpus_v2.write_corpus
    return run(groups, csv_path=args.csv)


if __name__ == "__main__":
    raise SystemExit(main())
