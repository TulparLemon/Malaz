"""Generate reproducible README showcase screenshots & animated GIF for Malaz.

Renders the real PySide6 ``MainWindow`` (with native OS fonts when run on a
desktop session) across four canonical views:

- ``malaz-ui.png``       — Dark mode, dangerous file detail view (verdict hero + engines)
- ``malaz-overview.png`` — Dark mode, Folder Overview (KPI cards + action required list)
- ``malaz-light.png``    — Light mode, clean/PDF file detail view
- ``malaz-options.png``  — Dark mode, Options & Auto-Update view (showing Language & Theme)
- ``malaz-demo.gif``     — 6-frame smooth showcase loop (empty -> overview -> bad -> mail -> light -> options)

Usage::

    python scripts/make_showcase_assets.py --lang en
    python scripts/make_showcase_assets.py --lang tr --out artifacts/tr_preview --no-gif
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from PIL import Image  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402
from malaz.core.engine_verdicts import build_engine_verdicts  # noqa: E402
from malaz.gui.main_window import MainWindow  # noqa: E402
from malaz.gui.settings import apply_language  # noqa: E402
from malaz.gui.theme import apply_theme  # noqa: E402
from malaz.models import (  # noqa: E402
    CAT_ARCHIVE,
    CAT_AV,
    CAT_FORMAT,
    CAT_IOC,
    CAT_MACRO,
    CAT_MAIL,
    CAT_SCRIPT,
    Indicator,
    RiskLevel,
    ScanResult,
    Severity,
)

WIDTH = 1280
HEIGHT = 720


def _make_sample_results() -> list[ScanResult]:
    """Deterministic sample batch covering dangerous, suspicious, unchecked, and clean files."""
    r_bad = ScanResult(
        path=r"C:\Downloads\Invoice_2026_04.pdf.exe",
        size=428_032,
        sha256="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        md5="098f6bcd4621d373cade4e832627b4f6",
        detected_type="pe",
        mime_hint="application/x-dosexec",
        duration_ms=142,
        score=95,
        risk_level=RiskLevel.RED,
        anchored=True,
        indicators=[
            Indicator(
                rule_id="AV_THREAT",
                title="Windows Defender: Trojan:Win32/AgentTesla!ml",
                detail="Trojan:Win32/AgentTesla!ml",
                severity=Severity.CRITICAL,
                category=CAT_AV,
                weight=60,
                source="defender",
            ),
            Indicator(
                rule_id="PE_DISGUISED_EXT",
                title="Ausführbare Datei getarnt (.pdf.exe)",
                detail="PE-Header trotz .pdf-Endung",
                severity=Severity.HIGH,
                category=CAT_FORMAT,
                weight=35,
                source="pe",
            ),
            Indicator(
                rule_id="PE_IMPORT_INJECTION",
                title="Prozess-Injektions-APIs",
                detail="VirtualAllocEx, WriteProcessMemory, CreateRemoteThread",
                severity=Severity.HIGH,
                category=CAT_SCRIPT,
                weight=25,
                source="pe",
            ),
            Indicator(
                rule_id="CLAMAV_THREAT",
                title="ClamAV: Bedrohung erkannt (Win.Trojan.AgentTesla-991)",
                detail="Win.Trojan.AgentTesla-991",
                severity=Severity.CRITICAL,
                category=CAT_AV,
                weight=60,
                source="clamav",
            ),
        ],
    )
    r_bad.engine_verdicts = build_engine_verdicts(r_bad, yara_available=True)

    r_mail = ScanResult(
        path=r"C:\Downloads\Urgent_Wire_Transfer.eml",
        size=18_432,
        sha256="4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        detected_type="eml",
        mime_hint="message/rfc822",
        duration_ms=64,
        score=42,
        risk_level=RiskLevel.YELLOW,
        mail_security={"spf": "fail", "dkim": "none", "dmarc": "fail", "sender": "mismatch", "has_from": "1"},
        indicators=[
            Indicator(
                rule_id="MAIL_AUTH_FAIL",
                title="Mail-Authentifizierung fehlgeschlagen",
                detail="SPF=fail, DMARC=fail",
                severity=Severity.HIGH,
                category=CAT_MAIL,
                weight=25,
                source="eml",
            ),
            Indicator(
                rule_id="MAIL_DISPLAY_NAME_SPOOF",
                title="Absendername passt nicht zur Domain",
                detail="Anzeigename imitiert vertraute Bank",
                severity=Severity.MEDIUM,
                category=CAT_MAIL,
                weight=17,
                source="eml",
            ),
            Indicator(
                rule_id="AV_CLEAN",
                title="Windows Defender: keine Bedrohung",
                detail="",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="defender",
            ),
            Indicator(
                rule_id="CLAMAV_CLEAN",
                title="ClamAV: keine Bedrohung",
                detail="",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="clamav",
            ),
        ],
    )
    r_mail.engine_verdicts = build_engine_verdicts(r_mail, yara_available=True)

    r_docm = ScanResult(
        path=r"C:\Downloads\Q3_Budget_Macros.docm",
        size=94_208,
        sha256="6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
        md5="c4ca4238a0b923820dcc509a6f75849b",
        detected_type="zip",
        mime_hint="application/vnd.ms-word.document.macroEnabled.12",
        duration_ms=89,
        score=35,
        risk_level=RiskLevel.YELLOW,
        indicators=[
            Indicator(
                rule_id="OFFICE_AUTOEXEC",
                title="Auto-Exec-Trigger: AutoOpen",
                detail="AutoOpen startet Makro beim Öffnen",
                severity=Severity.HIGH,
                category=CAT_MACRO,
                weight=25,
                source="office",
            ),
            Indicator(
                rule_id="OFFICE_MACRO",
                title="VBA-Makros vorhanden",
                detail="vbaProject.bin",
                severity=Severity.MEDIUM,
                category=CAT_MACRO,
                weight=10,
                source="office",
            ),
            Indicator(
                rule_id="AV_CLEAN",
                title="Windows Defender: keine Bedrohung",
                detail="",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="defender",
            ),
            Indicator(
                rule_id="CLAMAV_CLEAN",
                title="ClamAV: keine Bedrohung",
                detail="",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="clamav",
            ),
        ],
    )
    r_docm.engine_verdicts = build_engine_verdicts(r_docm, yara_available=True)

    r_enc = ScanResult(
        path=r"C:\Downloads\Confidential_Archive.zip",
        size=215_040,
        sha256="d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
        md5="c81e728d9d4c2f636f067f89cc14862c",
        detected_type="zip",
        mime_hint="application/zip",
        duration_ms=31,
        score=0,
        risk_level=RiskLevel.GREEN,
        indicators=[
            Indicator(
                rule_id="ARCH_ENCRYPTED",
                title="Passwortgeschützte Einträge (3)",
                detail="3 Einträge verschlüsselt",
                severity=Severity.MEDIUM,
                category=CAT_ARCHIVE,
                weight=0,
                source="archive",
            ),
            Indicator(
                rule_id="AV_SKIPPED",
                title="Windows Defender: Scan übersprungen",
                detail="Passwortgeschütztes Archiv",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="defender",
            ),
        ],
    )
    r_enc.engine_verdicts = build_engine_verdicts(r_enc, yara_available=True)

    r_clean = ScanResult(
        path=r"C:\Downloads\Annual_Report_2026.pdf",
        size=1_482_752,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5="eccbc87e4b5ce2fe28308fd9f2a7baf3",
        detected_type="pdf",
        mime_hint="application/pdf",
        duration_ms=54,
        score=0,
        risk_level=RiskLevel.GREEN,
        indicators=[
            Indicator(
                rule_id="PDF_LINK",
                title="Links im PDF (2)",
                detail="hxxps://example.org/docs · hxxps://example.org/contact",
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
                source="pdf",
            ),
            Indicator(
                rule_id="AV_CLEAN",
                title="Windows Defender: keine Bedrohung",
                detail="",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="defender",
            ),
            Indicator(
                rule_id="CLAMAV_CLEAN",
                title="ClamAV: keine Bedrohung",
                detail="",
                severity=Severity.INFO,
                category=CAT_AV,
                weight=0,
                source="clamav",
            ),
        ],
    )
    r_clean.engine_verdicts = build_engine_verdicts(r_clean, yara_available=True)
    return [r_bad, r_mail, r_docm, r_enc, r_clean]


def _grab_png(win: MainWindow, path: Path) -> Path:
    QApplication.processEvents()
    win.repaint()
    QApplication.processEvents()
    win.grab().save(str(path))
    return path


def generate_assets(out_dir: Path, *, lang: str = "en", make_gif: bool = True) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    apply_theme(app, "dark", persist=False)
    apply_language(lang, persist=False)

    disp = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    win = MainWindow(dispatcher=disp, fixed_size=(WIDTH, HEIGHT))
    win.show()
    QApplication.processEvents()
    # Wait for startup _EngineProbe so it cannot overwrite showcase badges mid-capture
    win.thread_pool.waitForDone(5000)
    QApplication.processEvents()

    # Populate sample results
    results = _make_sample_results()
    for res in results:
        win._on_result(res)
    win._on_engine_status(
        "",
        [
            ("Defender", "ok", "Windows Defender aktiv (MpCmdRun)"),
            ("ClamAV", "ok", "ClamAV bereit (clamd-Daemon)"),
            ("YARA", "ok", "85 lokale Regeln"),
            ("7-Zip", "ok", "Verfügbar"),
        ],
    )
    win.retranslate()
    QApplication.processEvents()

    produced: list[Path] = []
    gif_frames: list[Path] = []

    # 1. Dark mode — Dangerous file detail (malaz-ui.png)
    win._select_result_in_tree(results[0])
    win.detail_view.select_tab(0)
    p_ui = _grab_png(win, out_dir / "malaz-ui.png")
    produced.append(p_ui)

    # 2. Dark mode — Folder Overview (malaz-overview.png)
    win._show_batch_overview()
    p_ov = _grab_png(win, out_dir / "malaz-overview.png")
    produced.append(p_ov)

    # 3. Dark mode — Unchecked encrypted archive frame for GIF
    win._select_result_in_tree(results[3])
    win.detail_view.select_tab(0)
    p_unk = out_dir / "_tmp_unk.png"
    _grab_png(win, p_unk)

    # 4. Dark mode — Options & Auto-Update (malaz-options.png)
    win._toggle_options_view()
    p_opt = _grab_png(win, out_dir / "malaz-options.png")
    produced.append(p_opt)
    win._leave_options()

    # 5. Light mode — Clean PDF detail (malaz-light.png)
    apply_theme(app, "light", persist=False)
    win._select_result_in_tree(results[4])
    win.detail_view.select_tab(0)
    p_light = _grab_png(win, out_dir / "malaz-light.png")
    produced.append(p_light)

    # 6. Light mode — Technical details frame for GIF
    win._select_result_in_tree(results[0])
    win.detail_view.select_tab(1)
    p_tech = out_dir / "_tmp_tech.png"
    _grab_png(win, p_tech)

    if make_gif:
        gif_frames = [p_ov, p_ui, p_tech, p_unk, p_light, p_opt]
        imgs = [Image.open(fp).convert("RGB") for fp in gif_frames]
        # Quantize smoothly to 256-color palette for crisp small GitHub GIF
        pal_imgs = [im.quantize(colors=256, method=Image.Quantize.MEDIANCUT) for im in imgs]
        p_gif = out_dir / "malaz-demo.gif"
        pal_imgs[0].save(
            p_gif,
            save_all=True,
            append_images=pal_imgs[1:],
            duration=[2200, 2600, 2200, 2200, 2400, 2200],
            loop=0,
            optimize=True,
        )
        produced.append(p_gif)

    for tmp_p in (p_unk, p_tech):
        tmp_p.unlink(missing_ok=True)
    win.close()
    return produced


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lang", choices=("de", "en", "tr"), default="en")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "assets")
    ap.add_argument("--no-gif", action="store_true")
    args = ap.parse_args()
    files = generate_assets(args.out, lang=args.lang, make_gif=not args.no_gif)
    for f in files:
        print(f"Generated: {f} ({f.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
