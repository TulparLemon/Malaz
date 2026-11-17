"""Smoke-test a built Malaz.exe against a real PDF pipeline.

The release gate checks files, not engine function. This script generates a
PDF whose JavaScript lives in an object stream, runs the BUILT executable with
``--cli``, and requires the PDF structure stage (``PDF_OBJSTM``) to appear.
A missing qpdf/pikepdf shows up as ``PDF_LIB_MISSING`` or ``PDF_PARSE_WARN``
instead, so a distribution that merely unpacked can no longer pass silently.

Usage:
    python scripts/smoke_build.py --exe dist/Malaz-2.1-dev/Malaz.exe
"""

from __future__ import annotations

import argparse
import io
import re
import subprocess
import sys
import tempfile
from contextlib import suppress
from pathlib import Path


def make_pdf(path: Path) -> None:
    import pikepdf

    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792]))
    )
    pdf.Root.Names = pikepdf.Dictionary(
        JavaScript=pikepdf.Dictionary(
            Names=[
                pikepdf.String("x"),
                pikepdf.Dictionary(
                    S=pikepdf.Name.JavaScript,
                    JS=pikepdf.String("app.alert('smoke-build')"),
                ),
            ]
        )
    )
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate, deterministic_id=True)
    path.write_bytes(buf.getvalue())


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        with suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    exe = args.exe.resolve()
    if not exe.is_file():
        print(f"FEHLER: exe nicht gefunden: {exe}", file=sys.stderr)
        return 2

    # The portable build writes malaz.log NEXT TO the EXE (by design). A smoke
    # run must not leave that file inside the release folder — the release
    # gate correctly rejects logs, and a build that gates after the smoke would
    # fail on its own test output. Remove only files this run created.
    before = _log_snapshot(exe)
    try:
        version = subprocess.run(
            [str(exe), "--version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=args.timeout,
        )
        print(f"--version: {version.stdout.strip() or version.stderr.strip()}")
        if version.returncode != 0:
            print("FEHLER: --version fehlgeschlagen", file=sys.stderr)
            return 1

        with tempfile.TemporaryDirectory(prefix="malaz_smoke_") as tmp:
            pdf = Path(tmp) / "object_stream.pdf"
            make_pdf(pdf)
            # Run with --static-only so the smoke gate verifies the bundled
            # binary (pikepdf/qpdf, compiled YARA rules, frozen runtime) rather
            # than whether ClamAV is installed or %TEMP% is excluded in Defender
            # on the build host. Because --static-only emits AV_SKIPPED /
            # CLAMAV_SKIPPED (completeness invariant -> CLI exit 3), exit 3 is
            # accepted ONLY when every printed indicator is in the closed
            # smoke allowlist and bundled YARA is active.
            run = subprocess.run(
                [str(exe), "--static-only", "--cli", str(pdf)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=args.timeout,
                cwd=tmp,
            )
            output = (run.stdout or "") + (run.stderr or "")
            print(output.strip())
            rule_ids = set(
                re.findall(
                    r"(?m)^[ \t]*-[ \t]*\[[^\]\r\n]+\][ \t]*([^\s:]+):",
                    output,
                )
            )
            host_av_skips = {"AV_SKIPPED", "CLAMAV_SKIPPED"}
            allowed_smoke_rules = {
                "PDF_KW_ObjStm",
                "PDF_OBJSTM",
                "PDF_JS_EXTRACTED",
                "AV_SKIPPED",
                "CLAMAV_SKIPPED",
                "DIE_SKIPPED",
                "CAPA_SKIPPED",
            }
            unexpected_rules = sorted(rule_ids - allowed_smoke_rules)
            yara_broken = "YARA=aus/fehlt" in output or "YARA=Regelfehler" in output
            static_only_ok = (
                run.returncode == 3
                and "[FEHLER]" not in output
                and "[GRÜN]" in output
                and "score=0/100" in output
                and re.search(r"\bYARA=an\b", output) is not None
                and "PDF_OBJSTM" in rule_ids
                and bool(rule_ids & host_av_skips)
                and not unexpected_rules
            )
            if yara_broken or unexpected_rules or (run.returncode != 0 and not static_only_ok):
                detail = {
                    0: "OK",
                    1: "keine Ergebnisse",
                    2: "Urteil RED",
                    3: "Scan unvollständig",
                }.get(run.returncode, "unbekannter Fehler")
                extra = (
                    f" (unerwartete Regeln: {unexpected_rules})"
                    if unexpected_rules
                    else (" (YARA im Build defekt)" if yara_broken else "")
                )
                print(
                    f"FEHLER: CLI meldet Exit {run.returncode} ({detail}){extra} — "
                    "der Build ist nicht freigabefähig.",
                    file=sys.stderr,
                )
                return 1
            if "PDF_OBJSTM" not in output:
                print(
                    "FEHLER: PDF-Strukturstufe lief nicht (PDF_OBJSTM fehlt) — "
                    "pikepdf/qpdf im Build prüfen.",
                    file=sys.stderr,
                )
                return 1
            if "PDF_LIB_MISSING" in output or "PDF_PARSE_WARN" in output:
                print(
                    "FEHLER: PDF-Stufe meldet einen Ausfall (PDF_LIB_MISSING/"
                    "PDF_PARSE_WARN) — der Build ist nicht PDF-fähig.",
                    file=sys.stderr,
                )
                return 1
        print("OK: PDF-Strukturstufe und Engine-Urteile im gebauten EXE vorhanden.")
        return 0
    finally:
        _remove_new_logs(exe, before)


def _log_snapshot(exe: Path) -> set[Path]:
    return {
        path
        for pattern in ("malaz.log", "malaz.log.*")
        for path in exe.parent.glob(pattern)
        if path.exists()
    }


def _remove_new_logs(exe: Path, before: set[Path]) -> None:
    for pattern in ("malaz.log", "malaz.log.*"):
        for path in exe.parent.glob(pattern):
            if path not in before:
                with suppress(OSError):
                    path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
