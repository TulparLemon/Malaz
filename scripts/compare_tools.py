"""Compare Malaz against the tools installed on this machine.

The comparison is deliberately offline and reproducible:

* Malaz (static pipelines, AV off)
* YARA (the project's shipped rules)
* ClamAV (daemon if available, else clamscan)
* Windows Defender (opt-in; on-demand scan from disk)
* oletools (olevba / mraptor / rtfobj, only for Office/RTF files)
* optional DIE/capa/7-Zip are not comparable verdict engines and are skipped

The corpus is synthetic; a comparison is a measurement of THIS corpus, not a
claim that one product is "better". See docs/ARCHITECTURE.md for the caveats.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import corpus_determinism as det  # noqa: E402
import make_benign_corpus as benign  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402

from malaz import config  # noqa: E402
from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402
from malaz.core.yara_engine import YaraEngine  # noqa: E402
from malaz.models import RiskLevel  # noqa: E402


@dataclass
class Row:
    tool: str
    group: str  # malicious | benign
    path: str
    detected: bool
    duration_ms: int
    error: str = ""


@dataclass
class Summary:
    tool: str
    malicious_total: int = 0
    malicious_detected: int = 0
    benign_total: int = 0
    benign_flagged: int = 0
    errors: int = 0
    durations: list[int] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.malicious_detected / max(1, self.malicious_total)

    @property
    def false_positive_rate(self) -> float:
        return self.benign_flagged / max(1, self.benign_total)

    def p95(self) -> int:
        if not self.durations:
            return 0
        ordered = sorted(self.durations)
        return ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]


def _scan_malaz(dispatcher: Dispatcher, path: Path) -> tuple[bool, str]:
    result = dispatcher.scan_path(path)
    return result.risk_level >= RiskLevel.YELLOW, result.error or ""


def _scan_yara(engine: YaraEngine, path: Path) -> tuple[bool, str]:
    outcome = engine.scan_file_with_status(path)
    if outcome.scan_error:
        return False, outcome.scan_error
    return bool(outcome.matches), ""


def _scan_clam(scanner: ClamAVScanner, path: Path) -> tuple[bool, str]:
    result = scanner.scan_path(path)
    return bool(result.threat_found), result.skipped_reason or ""


def _scan_defender(scanner: WindowsDefenderScanner, path: Path) -> tuple[bool, str]:
    result = scanner.scan_path(path)
    return bool(result.threat_found), result.skipped_reason or ""


def _which_tool(name: str) -> str | None:
    local = Path(sys.executable).with_name(name + ".exe")
    if local.is_file():
        return str(local)
    return shutil.which(name)


def _scan_oletools(path: Path) -> tuple[bool, str]:
    suffix = path.suffix.lower()
    if suffix in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".docx", ".xlsx", ".pptx"}:
        tool = _which_tool("olevba")
        if tool is None:
            return False, "olevba not installed"
        proc = subprocess.run(
            [tool, str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        # olevba prints "No VBA macros found." for a clean file; a bare
        # substring check on "VBA"/"Macro" would flag every Office file.
        import re

        return bool(re.search(r"VBA\s+MACRO", text, re.IGNORECASE)), ""
    if suffix == ".rtf":
        tool = _which_tool("rtfobj")
        if tool is None:
            return False, "rtfobj not installed"
        proc = subprocess.run(
            [tool, str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        return ("Object" in text and "extracted" in text), ""
    return False, ""


def _run_group(
    tool: str,
    group: str,
    paths: list[Path],
    scanner,
    summary: Summary,
) -> list[Row]:
    rows: list[Row] = []
    for path in paths:
        started = time.perf_counter()
        try:
            detected, error = scanner(path)
        except Exception as exc:  # one broken tool must not abort the report
            detected, error = False, f"{type(exc).__name__}: {exc}"
        duration = int((time.perf_counter() - started) * 1000)
        summary.durations.append(duration)
        if group == "malicious":
            summary.malicious_total += 1
            summary.malicious_detected += int(detected)
        else:
            summary.benign_total += 1
            summary.benign_flagged += int(detected)
        summary.errors += int(bool(error))
        rows.append(Row(tool, group, path.name, detected, duration, error))
    return rows


def _markdown(summaries: list[Summary], rows: list[Row]) -> str:
    lines = [
        "# Tool comparison",
        "",
        "| Tool | Malicious detected | Benign flagged | Errors | p95 ms |",
        "|---|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        lines.append(
            f"| {summary.tool} | {summary.malicious_detected}/{summary.malicious_total} "
            f"({summary.detection_rate:.0%}) | "
            f"{summary.benign_flagged}/{summary.benign_total} "
            f"({summary.false_positive_rate:.0%}) | {summary.errors} | {summary.p95()} |"
        )
    lines += [
        "",
        (
            "The corpus is synthetic. Detection means Malaz >= YELLOW, YARA any "
            "match, ClamAV/Defender a threat verdict, oletools a macro/object "
            "finding. A missing engine is reported as an error, never as clean."
        ),
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", default="malaz,yara,clamav,oletools")
    parser.add_argument("--v2", action="store_true", help="use the expanded corpus")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)
    tools = {name.strip().lower() for name in args.tools.split(",") if name.strip()}

    old_feeds = config.YARA_FEED_DIRS
    old_die = config.DIE_ENABLED
    config.YARA_FEED_DIRS = ()
    config.DIE_ENABLED = False
    summaries: list[Summary] = []
    rows: list[Row] = []
    try:
        with tempfile.TemporaryDirectory(prefix="malaz_compare_") as tmp, det.pin_user_threat_intel():
            base = Path(tmp)
            malicious = ext.build_extended_corpus(base / "malicious")
            benign_paths = benign.build_corpus(base / "benign")
            if args.v2:
                import make_corpus_v2 as v2

                # Split by Fixture.kind: appending every v2 path to the
                # "malicious" list counted 127 benign and 37 edge fixtures as
                # missed malware. Edge cases are skipped in a comparison.
                v2_dir = base / "v2"
                v2_dir.mkdir(parents=True, exist_ok=True)
                for fixture in v2.build_fixtures():
                    path = v2_dir / fixture.name
                    path.write_bytes(fixture.data)
                    if fixture.kind == "malicious":
                        malicious.append(path)
                    elif fixture.kind == "benign":
                        benign_paths.append(path)
            if args.limit:
                malicious = malicious[: args.limit]
                benign_paths = benign_paths[: max(1, args.limit // 2)]

            dispatcher = Dispatcher(
                av_scanner=WindowsDefenderScanner(enabled=False),
                clam_scanner=ClamAVScanner(enabled=False),
            )
            engines = {
                "malaz": lambda p: _scan_malaz(dispatcher, p),
                "yara": lambda p: _scan_yara(YaraEngine(), p),
                "clamav": lambda p: _scan_clam(ClamAVScanner(), p),
                "defender": lambda p: _scan_defender(WindowsDefenderScanner(disable_remediation=True), p),
                "oletools": _scan_oletools,
            }
            for name in sorted(tools):
                if name not in engines:
                    print(f"unknown tool: {name}", file=sys.stderr)
                    return 2
                summary = Summary(name)
                scanner = engines[name]
                # oletools only applies to Office/RTF; counting PDFs as
                # "errors" would make the comparison look broken.
                relevant = malicious
                relevant_benign = benign_paths
                if name == "oletools":
                    suffix = {
                        ".doc",
                        ".docm",
                        ".xls",
                        ".xlsm",
                        ".ppt",
                        ".pptm",
                        ".docx",
                        ".xlsx",
                        ".pptx",
                        ".rtf",
                    }
                    relevant = [p for p in malicious if p.suffix.lower() in suffix]
                    relevant_benign = [p for p in benign_paths if p.suffix.lower() in suffix]
                rows += _run_group(name, "malicious", relevant, scanner, summary)
                rows += _run_group(name, "benign", relevant_benign, scanner, summary)
                summaries.append(summary)
                print(
                    f"{name:9s} malicious {summary.malicious_detected}/{summary.malicious_total} "
                    f"benign-flagged {summary.benign_flagged}/{summary.benign_total} "
                    f"errors {summary.errors} p95 {summary.p95()} ms"
                )
    finally:
        config.YARA_FEED_DIRS = old_feeds
        config.DIE_ENABLED = old_die

    markdown = _markdown(summaries, rows)
    print("\n" + markdown)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "summaries": [
                        {
                            "tool": s.tool,
                            "malicious_total": s.malicious_total,
                            "malicious_detected": s.malicious_detected,
                            "benign_total": s.benign_total,
                            "benign_flagged": s.benign_flagged,
                            "errors": s.errors,
                            "p95_ms": s.p95(),
                        }
                        for s in summaries
                    ],
                    "rows": [row.__dict__ for row in rows],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
