#!/usr/bin/env python3
"""Split-filtered lab comparison, regression gate, and allowlisted public summary.

Implements Spec 017 §3.4:
* Compares ``--baseline <dir>`` and ``--current <dir>`` (each requiring valid
  ``report.json`` + ``lab_meta.json``).
* Always includes ``missing``, ``unchecked``, and ``error`` entries in the
  denominator of ``recall_red`` and ``fp_red`` (Completeness Invariant).
* Fails closed (Exit 2) on invalid metadata, ``sandbox_status != "ok"``,
  ``dryrun == true`` without ``--allow-dryrun``, ``--public-summary`` on any
  ``dryrun == true`` run (even with ``--allow-dryrun``!), ``engine_profile``
  mismatch, or ``manifest_sha256`` mismatch without ``--allow-corpus-change``.
* Applies ``malaz.lab.opsec.find_opsec_leaks()`` before writing
  ``--public-summary``.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
for _p in (ROOT / "src", ROOT / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from malaz.lab.opsec import find_opsec_leaks  # noqa: E402
from malaz.lab.report import wilson_interval  # noqa: E402

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SAFE_ENGINES_RE = re.compile(r"^[A-Za-z0-9_.,-]{1,64}$")


class CompareInputError(ValueError):
    """Fail-closed input/schema violation (maps to Exit 2)."""


def _load_json_obj(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise CompareInputError(f"{label} fehlt: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CompareInputError(f"{label} nicht lesbar: {exc}") from exc
    if not isinstance(data, dict):
        raise CompareInputError(f"{label}: JSON-Objekt erwartet")
    return data


def _load_run(run_dir: Path, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    report = _load_json_obj(run_dir / "report.json", f"{label}/report.json")
    meta = _load_json_obj(run_dir / "lab_meta.json", f"{label}/lab_meta.json")

    files = report.get("files")
    if not isinstance(files, list):
        raise CompareInputError(f"{label}/report.json: 'files'-Liste fehlt")

    # Strict lab_meta.json validation
    if not isinstance(meta.get("dryrun"), bool):
        raise CompareInputError(f"{label}/lab_meta.json: 'dryrun' muss bool sein")
    for req_str in ("run_date_utc", "engine_profile", "av_engines", "manifest_sha256", "sandbox_status"):
        val = meta.get(req_str)
        if not isinstance(val, str) or not val.strip():
            raise CompareInputError(f"{label}/lab_meta.json: Feld '{req_str}' fehlt/leer")
    if not _DATE_RE.fullmatch(meta["run_date_utc"]):
        raise CompareInputError(f"{label}/lab_meta.json: 'run_date_utc' muss YYYY-MM-DD sein")
    if not _SHA256_RE.fullmatch(meta["manifest_sha256"].lower()):
        raise CompareInputError(f"{label}/lab_meta.json: 'manifest_sha256' ungültig")
    rej = meta.get("ingest_rejected")
    if isinstance(rej, bool) or not isinstance(rej, int) or rej < 0:
        raise CompareInputError(f"{label}/lab_meta.json: 'ingest_rejected' muss int >= 0 sein")
    if meta["sandbox_status"] != "ok":
        raise CompareInputError(
            f"{label}: sandbox_status ist {meta['sandbox_status']!r} (erwartet 'ok')"
        )
    return report, meta


def _filter_files(files: list[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    if split == "all":
        return [f for f in files if isinstance(f, dict)]
    return [f for f in files if isinstance(f, dict) and f.get("split") == split]


def _rate_and_ci(num: int, den: int) -> tuple[float | None, list[float | None]]:
    if den <= 0:
        return None, [None, None]
    lo, hi = wilson_interval(num, den)
    return num / den, [lo, hi]


def _compute_metrics(files: list[dict[str, Any]]) -> dict[str, Any]:
    mal = [f for f in files if f.get("label") == "malicious"]
    ben = [f for f in files if f.get("label") == "benign"]

    mal_red = sum(
        1 for f in mal if f.get("status") == "detected" and f.get("verdict") == "RED"
    )
    ben_red = sum(
        1 for f in ben if f.get("status") == "flagged" and f.get("verdict") == "RED"
    )
    missing = sum(1 for f in files if f.get("status") == "missing")
    unchecked = sum(1 for f in files if f.get("status") == "unchecked")

    recall_red, recall_ci = _rate_and_ci(mal_red, len(mal))
    fp_red, fp_ci = _rate_and_ci(ben_red, len(ben))

    return {
        "malicious_total": len(mal),
        "malicious_red": mal_red,
        "recall_red": recall_red,
        "recall_red_ci": recall_ci,
        "benign_total": len(ben),
        "benign_red": ben_red,
        "fp_red": fp_red,
        "fp_red_ci": fp_ci,
        "missing_results": missing,
        "unchecked": unchecked,
    }


def _bucket_rates(files: list[dict[str, Any]], key: str) -> dict[str, tuple[int, int]]:
    buckets: dict[str, list[int]] = {}
    for f in files:
        if f.get("label") != "malicious":
            continue
        val = str(f.get(key) or "unknown")
        pair = buckets.setdefault(val, [0, 0])
        pair[1] += 1
        if f.get("status") == "detected" and f.get("verdict") == "RED":
            pair[0] += 1
    return {k: (v[0], v[1]) for k, v in buckets.items()}


def _compare_buckets(
    base_files: list[dict[str, Any]], curr_files: list[dict[str, Any]], key: str
) -> dict[str, dict[str, Any]]:
    base_map = _bucket_rates(base_files, key)
    curr_map = _bucket_rates(curr_files, key)
    out: dict[str, dict[str, Any]] = {}
    for name in sorted(set(base_map) | set(curr_map)):
        in_b = name in base_map
        in_c = name in curr_map
        b_num, b_den = base_map.get(name, (0, 0))
        c_num, c_den = curr_map.get(name, (0, 0))
        b_rate = (b_num / b_den) if b_den > 0 else None
        c_rate = (c_num / c_den) if c_den > 0 else None
        if in_c and not in_b:
            status = "added"
            delta_pp = None
        elif in_b and not in_c:
            status = "removed"
            delta_pp = None
        elif b_rate is None or c_rate is None:
            status = "unchanged"
            delta_pp = None
        else:
            delta_pp = round((c_rate - b_rate) * 100.0, 2)
            if delta_pp > 0:
                status = "improved"
            elif delta_pp < 0:
                status = "regressed"
            else:
                status = "unchanged"
        out[name] = {
            "status": status,
            "n_baseline": b_den,
            "n_current": c_den,
            "recall_red_baseline": b_rate,
            "recall_red_current": c_rate,
            "recall_red_pp": delta_pp,
        }
    return out


def _delta_pp(base: float | None, curr: float | None) -> float | None:
    if base is None or curr is None:
        return None
    return round((curr - base) * 100.0, 2)


def _fmt_pct(val: float | None) -> str:
    return "N/A" if val is None else f"{val * 100.0:.2f}%"


def _fmt_ci(pair: list[float | None]) -> str:
    if pair[0] is None or pair[1] is None:
        return "N/A"
    return f"[{pair[0] * 100.0:.2f}%, {pair[1] * 100.0:.2f}%]"


def _fmt_pp(val: float | None) -> str:
    return "N/A" if val is None else f"{val:+.2f} pp"


def render_markdown(comp: dict[str, Any]) -> str:
    curr = comp["current"]
    base = comp["baseline"]
    delta = comp["delta"]
    lines = [
        f"# Malaz Lab Comparison (`{comp['split']}` split)",
        "",
        f"- **Engine profile:** `{comp['engine_profile']}` (AV engines: `{comp['av_engines']}`)",
        f"- **Baseline date:** `{base['run_date_utc']}` | **Current date:** `{curr['run_date_utc']}`",
        f"- **Regression gate:** `{'PASS' if not comp['regressed'] else 'FAIL'}`",
        "",
        "| Metric | Baseline | Current | Delta |",
        "| :--- | ---: | ---: | ---: |",
        (
            f"| Recall (RED) | {_fmt_pct(base['recall_red'])} "
            f"| {_fmt_pct(curr['recall_red'])} | {_fmt_pp(delta['recall_red_pp'])} |"
        ),
        (
            f"| False Positive (RED) | {_fmt_pct(base['fp_red'])} "
            f"| {_fmt_pct(curr['fp_red'])} | {_fmt_pp(delta['fp_red_pp'])} |"
        ),
        (
            f"| Missing results | {base['missing_results']} "
            f"| {curr['missing_results']} | {delta['delta_missing']:+d} |"
        ),
        f"| Unchecked | {base['unchecked']} | {curr['unchecked']} | {delta['delta_unchecked']:+d} |",
        (
            f"| Ingest rejected (corpus) | {base['ingest_rejected']} "
            f"| {curr['ingest_rejected']} | {delta['delta_ingest_rejected']:+d} |"
        ),
    ]
    if comp["regression_reasons"]:
        lines.extend(["", "## Regression Reasons", ""])
        for reason in comp["regression_reasons"]:
            lines.append(f"- {reason}")
    return "\n".join(lines) + "\n"


def render_public_summary(comp: dict[str, Any]) -> str:
    """Render strictly allowlisted public Markdown summary (no free-text fields)."""
    curr = comp["current"]
    run_date = str(curr["run_date_utc"])
    split = str(comp["split"])
    engine_profile = str(comp["engine_profile"])
    av_engines = str(comp["av_engines"])

    if not _DATE_RE.fullmatch(run_date):
        raise CompareInputError("Ungültiges run_date_utc für public-summary")
    for field_name, val, pattern in (
        ("split", split, _SAFE_TOKEN_RE),
        ("engine_profile", engine_profile, _SAFE_TOKEN_RE),
        ("av_engines", av_engines, _SAFE_ENGINES_RE),
    ):
        if not pattern.fullmatch(val):
            raise CompareInputError(f"Ungültiger Wert für {field_name} in public-summary")

    lines = [
        "# Malaz Real-World Benchmark Summary",
        "",
        f"- **Run Date (UTC):** `{run_date}`",
        f"- **Split:** `{split}`",
        f"- **Engine Profile:** `{engine_profile}`",
        f"- **AV Engines:** `{av_engines}`",
        "",
        "| Metric | Value | 95% Wilson CI |",
        "| :--- | ---: | :--- |",
        f"| Malicious Samples (`n`) | {int(curr['malicious_total'])} | — |",
        f"| Benign Samples (`n`) | {int(curr['benign_total'])} | — |",
        f"| Recall (RED) | {_fmt_pct(curr['recall_red'])} | {_fmt_ci(curr['recall_red_ci'])} |",
        f"| False Positives (RED) | {_fmt_pct(curr['fp_red'])} | {_fmt_ci(curr['fp_red_ci'])} |",
        f"| Missing Results | {int(curr['missing_results'])} | — |",
        f"| Unchecked | {int(curr['unchecked'])} | — |",
        f"| Ingest Rejected (Corpus) | {int(curr['ingest_rejected'])} | — |",
    ]
    return "\n".join(lines) + "\n"


def compare_runs(
    baseline_dir: Path,
    current_dir: Path,
    *,
    split: str = "test",
    max_recall_drop: float = 0.0,
    allow_corpus_change: bool = False,
    allow_dryrun: bool = False,
    public_summary_requested: bool = False,
) -> dict[str, Any]:
    if split not in ("test", "dev", "all"):
        raise CompareInputError(f"Ungültiger Split: {split!r}")
    if not math.isfinite(max_recall_drop) or max_recall_drop < 0.0:
        raise CompareInputError("--max-recall-drop muss endlich und >= 0.0 sein")

    base_rep, base_meta = _load_run(baseline_dir, "baseline")
    curr_rep, curr_meta = _load_run(current_dir, "current")

    any_dryrun = bool(base_meta["dryrun"] or curr_meta["dryrun"])
    if public_summary_requested and any_dryrun:
        raise CompareInputError(
            "--public-summary ist bei dryrun=true (baseline oder current) strikt verboten."
        )
    if any_dryrun and not allow_dryrun:
        raise CompareInputError(
            "Mindestens ein Lauf ist ein synthetischer DryRun (dryrun=true); "
            "nutze --allow-dryrun für lokale Trockenlauf-Tests."
        )
    if curr_meta["engine_profile"] != base_meta["engine_profile"]:
        raise CompareInputError(
            f"engine_profile weicht ab: baseline={base_meta['engine_profile']!r} "
            f"vs current={curr_meta['engine_profile']!r}"
        )
    if (
        curr_meta["manifest_sha256"].lower() != base_meta["manifest_sha256"].lower()
        and not allow_corpus_change
    ):
        raise CompareInputError(
            "manifest_sha256 weicht ab (anderer Korpus); nutze --allow-corpus-change "
            "bei bewusster Korpus-Erweiterung."
        )

    base_files = _filter_files(base_rep["files"], split)
    curr_files = _filter_files(curr_rep["files"], split)
    base_m = _compute_metrics(base_files)
    curr_m = _compute_metrics(curr_files)
    base_m["run_date_utc"] = base_meta["run_date_utc"]
    base_m["ingest_rejected"] = int(base_meta["ingest_rejected"])
    curr_m["run_date_utc"] = curr_meta["run_date_utc"]
    curr_m["ingest_rejected"] = int(curr_meta["ingest_rejected"])

    recall_red_pp = _delta_pp(base_m["recall_red"], curr_m["recall_red"])
    fp_red_pp = _delta_pp(base_m["fp_red"], curr_m["fp_red"])
    delta_unchecked = curr_m["unchecked"] - base_m["unchecked"]
    delta_missing = curr_m["missing_results"] - base_m["missing_results"]
    delta_ingest_rejected = curr_m["ingest_rejected"] - base_m["ingest_rejected"]

    raw_fp_pp = (
        (curr_m["fp_red"] - base_m["fp_red"]) * 100.0
        if base_m["fp_red"] is not None and curr_m["fp_red"] is not None
        else None
    )
    raw_recall_pp = (
        (curr_m["recall_red"] - base_m["recall_red"]) * 100.0
        if base_m["recall_red"] is not None and curr_m["recall_red"] is not None
        else None
    )

    reasons: list[str] = []
    if raw_fp_pp is not None and raw_fp_pp > 1e-12:
        reasons.append(f"fp_red_pp={raw_fp_pp:+.4f} pp (> 0)")
    if raw_recall_pp is not None and raw_recall_pp < -(max_recall_drop + 1e-12):
        reasons.append(
            f"recall_red_pp={raw_recall_pp:+.4f} pp (< -{max_recall_drop:.2f} pp)"
        )
    if delta_unchecked > 0:
        reasons.append(f"delta_unchecked={delta_unchecked:+d} (> 0)")
    if delta_missing > 0:
        reasons.append(f"delta_missing={delta_missing:+d} (> 0)")
    if delta_ingest_rejected > 0:
        reasons.append(f"delta_ingest_rejected={delta_ingest_rejected:+d} (> 0)")

    return {
        "schema_version": 1,
        "split": split,
        "engine_profile": curr_meta["engine_profile"],
        "av_engines": curr_meta["av_engines"],
        "dryrun": any_dryrun,
        "baseline": base_m,
        "current": curr_m,
        "delta": {
            "recall_red_pp": recall_red_pp,
            "fp_red_pp": fp_red_pp,
            "delta_unchecked": delta_unchecked,
            "delta_missing": delta_missing,
            "delta_ingest_rejected": delta_ingest_rejected,
        },
        "by_type": _compare_buckets(base_files, curr_files, "type"),
        "by_family": _compare_buckets(base_files, curr_files, "family"),
        "regressed": bool(reasons),
        "regression_reasons": reasons,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Compare two Malaz Lab evaluation runs.")
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--current", type=Path, required=True)
    ap.add_argument("--split", choices=("test", "dev", "all"), default="test")
    ap.add_argument("--json", dest="json_out", type=Path, default=None)
    ap.add_argument("--markdown", dest="md_out", type=Path, default=None)
    ap.add_argument("--public-summary", dest="public_out", type=Path, default=None)
    ap.add_argument("--max-recall-drop", type=float, default=0.0)
    ap.add_argument("--fail-on-regression", action="store_true")
    ap.add_argument("--allow-corpus-change", action="store_true")
    ap.add_argument("--allow-dryrun", action="store_true")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        comp = compare_runs(
            args.baseline,
            args.current,
            split=args.split,
            max_recall_drop=args.max_recall_drop,
            allow_corpus_change=args.allow_corpus_change,
            allow_dryrun=args.allow_dryrun,
            public_summary_requested=(args.public_out is not None),
        )
    except CompareInputError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2

    if args.public_out is not None:
        try:
            rendered = render_public_summary(comp)
        except CompareInputError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            return 2
        leaks = find_opsec_leaks(rendered)
        if leaks:
            print(
                f"FEHLER: OpSec-Prüfung für --public-summary fehlgeschlagen: {leaks}",
                file=sys.stderr,
            )
            return 2
        args.public_out.parent.mkdir(parents=True, exist_ok=True)
        args.public_out.write_text(rendered, encoding="utf-8")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(comp, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.md_out is not None:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(render_markdown(comp), encoding="utf-8")

    if args.fail_on_regression and comp["regressed"]:
        print(
            "REGRESSION: " + "; ".join(comp["regression_reasons"]),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
