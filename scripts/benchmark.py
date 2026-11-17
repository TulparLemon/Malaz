"""Measure scan throughput and per-stage cost.

Usage:
    python scripts/benchmark.py
    python scripts/benchmark.py --files C:\\Windows\\System32\\notepad.exe
    python scripts/benchmark.py --av --json out.json
    python scripts/benchmark.py --cold --warm

The script is deliberately a measurement tool, not a test: timings depend on
the machine, the OS cache, the signature database and the AV engines. It
prints p50/p95 and the stage breakdown stored in ``ScanResult.stage_timings``.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402

DEFAULT_FILES = (
    ROOT / "assets" / "malaz_logo.png",
    Path("C:/Windows/System32/notepad.exe"),
)


def _scan(dispatcher: Dispatcher, path: Path) -> dict:
    started = time.perf_counter()
    result = dispatcher.scan_path(path)
    elapsed = (time.perf_counter() - started) * 1000
    return {
        "path": str(path),
        "duration_ms": round(elapsed, 1),
        "score": result.score,
        "risk": result.risk_level.name,
        "type": result.detected_type,
        "stages": [
            {"name": timing.name, "duration_ms": timing.duration_ms} for timing in result.stage_timings
        ],
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", nargs="*", type=Path)
    parser.add_argument("--av", action="store_true", help="enable Defender/ClamAV")
    parser.add_argument("--cold", action="store_true", help="one pass only")
    parser.add_argument("--warm", action="store_true", help="two passes (default)")
    parser.add_argument("--json", type=Path, help="write the raw results here")
    args = parser.parse_args(argv)

    files = args.files or list(DEFAULT_FILES)
    files = [path for path in files if Path(path).is_file()]
    if not files:
        print("No files found.", file=sys.stderr)
        return 1

    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=args.av),
        clam_scanner=ClamAVScanner(enabled=args.av),
    )
    passes = 1 if args.cold else 2
    runs: list[dict] = []
    for pass_no in range(passes):
        label = "cold" if pass_no == 0 else "warm"
        for path in files:
            row = _scan(dispatcher, Path(path))
            row["pass"] = label
            runs.append(row)
            stages = ", ".join(f"{stage['name']}={stage['duration_ms']}ms" for stage in row["stages"])
            print(
                f"{label:4s} {Path(path).name:28s} {row['duration_ms']:8.1f} ms  "
                f"{row['risk']:6s} {row['score']:3d}  {stages}"
            )

    durations = [row["duration_ms"] for row in runs]
    print(
        f"\nn={len(durations)} p50={_percentile(durations, 0.50):.1f} ms "
        f"p95={_percentile(durations, 0.95):.1f} ms "
        f"mean={statistics.mean(durations):.1f} ms"
    )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(runs, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
