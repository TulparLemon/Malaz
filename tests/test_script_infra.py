"""Regressionstests fuer die Skript-/Infrastruktur-Fixes aus Phase B (low).

Deckt die Skripte ab, die keinen eigenen Testkasten haben: EICAR-Probe,
YARA-Kompilierung, Smoke-Build, Snapshot-Generator, Doku-Behauptungen,
OLE-Fixture-Writer, die Batch-Wrapper und den UI-Renderer.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import runpy
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import check_doc_claims  # noqa: E402
import compile_yara  # noqa: E402
import eicar_probe  # noqa: E402
import make_golden_snapshot  # noqa: E402
import smoke_build  # noqa: E402

from malaz import config  # noqa: E402

# -- SEC-044: EICAR-Schreibfehler ist nur bei AV-Errno ein AV-Nachweis -------


def _probe_fd(path: Path):
    return os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)


def _fake_mkstemp(path: Path):
    def fake(*args, **kwargs):
        return _probe_fd(path), str(path)

    return fake


@pytest.mark.parametrize("code", [225, 226])
def test_eicar_probe_counts_av_errno_as_reaction(tmp_path, monkeypatch, code):
    probe = tmp_path / "probe.txt"
    monkeypatch.setattr(eicar_probe.tempfile, "mkstemp", _fake_mkstemp(probe))

    def blocked(fd, data):
        raise OSError(code, "virus")

    monkeypatch.setattr(eicar_probe.os, "write", blocked)
    assert eicar_probe.main() == 0


@pytest.mark.parametrize("code", [225, 226])
def test_eicar_probe_counts_real_windows_winerror_as_reaction(tmp_path, monkeypatch, code):
    """Python mappt WinError 225/226 auf errno 22 — `winerror` muss zaehlen."""
    probe = tmp_path / "probe.txt"
    monkeypatch.setattr(eicar_probe.tempfile, "mkstemp", _fake_mkstemp(probe))

    def blocked(fd, data):
        raise ctypes.WinError(code)

    monkeypatch.setattr(eicar_probe.os, "write", blocked)
    assert eicar_probe.main() == 0


def test_eicar_probe_access_denied_is_not_av_alive(tmp_path, monkeypatch):
    """WinError 5 (gesperrtes/geschuetztes TEMP) ist kein AV-Nachweis."""
    probe = tmp_path / "probe.txt"
    monkeypatch.setattr(eicar_probe.tempfile, "mkstemp", _fake_mkstemp(probe))

    def blocked(fd, data):
        raise ctypes.WinError(5)

    monkeypatch.setattr(eicar_probe.os, "write", blocked)
    assert eicar_probe.main() == 1


def test_eicar_probe_write_error_without_av_is_not_av_alive(tmp_path, monkeypatch):
    """Volles/gesperrtes TEMP ist kein bestandener AV-Nachweis."""
    probe = tmp_path / "probe.txt"
    monkeypatch.setattr(eicar_probe.tempfile, "mkstemp", _fake_mkstemp(probe))

    def blocked(fd, data):
        raise OSError(errno.EACCES, "gesperrt")

    monkeypatch.setattr(eicar_probe.os, "write", blocked)
    assert eicar_probe.main() == 1
    assert not probe.exists(), "Temp-Datei muss auch im Fehlerfall aufgeraeumt werden"


def test_eicar_probe_closes_fd_when_write_fails(tmp_path, monkeypatch):
    probe = tmp_path / "probe.txt"
    fd = _probe_fd(probe)
    monkeypatch.setattr(eicar_probe.tempfile, "mkstemp", lambda *a, **k: (fd, str(probe)))
    closed: list[int] = []
    real_close = os.close
    monkeypatch.setattr(
        eicar_probe.os, "close", lambda handle: (closed.append(handle), real_close(handle))
    )

    def blocked(handle, data):
        raise OSError(225, "virus")

    monkeypatch.setattr(eicar_probe.os, "write", blocked)
    assert eicar_probe.main() == 0
    assert closed == [fd]


# -- SEC-050/051: compile_yara ----------------------------------------------


def test_compile_yara_case_collision_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path)
    (tmp_path / "foo.yarc").write_bytes(b"OLD")
    (tmp_path / "Foo.yar").write_text("rule x { condition: true }", encoding="utf-8")

    if os.path.normcase("Foo") != os.path.normcase("foo"):
        pytest.skip("braucht case-insensitive Dateisemantik (Windows/NTFS)")

    assert compile_yara.main([]) == 0
    assert (tmp_path / "foo.yarc").read_bytes() == b"OLD", "bestehende .yarc darf nicht ersetzt werden"


def test_compile_yara_clean_reports_undeletable_files(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path)
    (tmp_path / "bleibt.yarc").write_bytes(b"x")
    (tmp_path / "weg.yarc").write_bytes(b"y")
    real_unlink = Path.unlink

    def failing_unlink(self, *args, **kwargs):
        if self.name == "bleibt.yarc":
            raise PermissionError(errno.EACCES, "gesperrt", str(self))
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    assert compile_yara.main(["--clean"]) == 1
    assert (tmp_path / "bleibt.yarc").exists()
    assert not (tmp_path / "weg.yarc").exists()


# -- BUG-089: smoke_build muss den CLI-Exitcode beachten --------------------


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [(0, 0), (1, 1), (2, 1), (3, 1)],
)
def test_smoke_build_honours_cli_exit_code(tmp_path, monkeypatch, returncode, expected):
    exe = tmp_path / "Malaz.exe"
    exe.write_bytes(b"stub")

    def fake_run(command, **kwargs):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="2.1\n", stderr="")
        return SimpleNamespace(
            returncode=returncode,
            stdout="PDF_OBJSTM\n",
            stderr="",
        )

    monkeypatch.setattr(smoke_build.subprocess, "run", fake_run)
    monkeypatch.setattr(smoke_build, "make_pdf", lambda path: path.write_bytes(b"%PDF-1.7\n"))
    assert smoke_build.main(["--exe", str(exe)]) == expected


def test_smoke_build_fails_on_red_even_when_structure_is_present(tmp_path, monkeypatch):
    exe = tmp_path / "Malaz.exe"
    exe.write_bytes(b"stub")

    def fake_run(command, **kwargs):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="2.1\n", stderr="")
        return SimpleNamespace(returncode=2, stdout="PDF_OBJSTM\n", stderr="")

    monkeypatch.setattr(smoke_build.subprocess, "run", fake_run)
    monkeypatch.setattr(smoke_build, "make_pdf", lambda path: path.write_bytes(b"%PDF-1.7\n"))
    assert smoke_build.main(["--exe", str(exe)]) == 1


# -- BUG-101: unbekannte Snapshot-Flags duerfen nichts ueberschreiben -------


def test_golden_snapshot_rejects_unknown_flags(tmp_path, monkeypatch):
    snapshot = tmp_path / "golden_snapshot.json"
    snapshot.write_text('{"keep": true}', encoding="utf-8")
    monkeypatch.setattr(make_golden_snapshot, "SNAPSHOT", snapshot)

    with pytest.raises(SystemExit) as exc:
        make_golden_snapshot.main(["--chek"])
    assert exc.value.code == 2, "argparse soll mit Nutzungsfehler (2) abbrechen"
    assert json.loads(snapshot.read_text(encoding="utf-8")) == {"keep": True}


# -- BUG-094: Doku-Pruefung deckt alle Dokumente und den ganzen Baum ab -----


def test_doc_claims_counts_all_listed_docs(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "check_tests_bite.py").write_text(
        "    Mutation(\n    Mutation(\n", encoding="utf-8"
    )
    (tmp_path / "CHANGELOG.md").write_text(
        "**3/3 mutations** fail", encoding="utf-8"
    )
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)

    problems = check_doc_claims.check_counts()
    assert any("CHANGELOG.md" in problem for problem in problems), problems


def test_doc_claims_counts_accepts_matching_claim(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "check_tests_bite.py").write_text(
        "    Mutation(\n    Mutation(\n", encoding="utf-8"
    )
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "INSTALLATION.md").write_text(
        "**2/2 mutations** fail", encoding="utf-8"
    )
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)
    assert check_doc_claims.check_counts() == []


def test_doc_claims_licence_scan_catches_geschlossene_distribution(tmp_path, monkeypatch):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "lizenz.md").write_text(
        "Die geschlossene " + "Distribution bleibt unberuehrt.",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)
    problems = check_doc_claims.check_licence_claims()
    assert any("lizenz.md" in problem for problem in problems), problems


def test_doc_claims_markdown_links_validate_targets_and_ignore_code(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "vorhanden.md").write_text("# OK\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Siehe [OK](docs/vorhanden.md#ok), [Extern](https://example.org), "
        "`[Code](docs/fehlt_inline.md)`,\n"
        "```markdown\n[Fence](docs/fehlt_fence.md)\n```\n"
        '<img src="docs/vorhanden.md" /> <img src="docs/fehlt_img.png" /> '
        '`<img src="docs/fehlt_code_img.png" />`\n'
        "Kaputt: [Fehlt](docs/fehlt_echt.md) und [Ausbruch](../ausserhalb.md).\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)
    problems = check_doc_claims.check_markdown_links()
    assert any("fehlt_echt.md" in p for p in problems), problems
    assert any("fehlt_img.png" in p for p in problems), problems
    assert any("escapes repository root" in p for p in problems), problems
    assert not any("fehlt_inline.md" in p for p in problems), problems
    assert not any("fehlt_code_img.png" in p for p in problems), problems
    assert not any("fehlt_fence.md" in p for p in problems), problems
    assert not any("vorhanden.md" in p for p in problems), problems


def test_doc_claims_validates_code_signing_policy_links(tmp_path, monkeypatch):
    assert "CODE_SIGNING_POLICY.md" in check_doc_claims.CURRENT_DOCS
    assert "CODE_SIGNING_POLICY.md" in check_doc_claims.LINK_CHECK_DOCS

    (tmp_path / "CODE_SIGNING_POLICY.md").write_text(
        "# Policy\n\nBroken link: [broken](docs/DOES_NOT_EXIST.md)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)
    problems = check_doc_claims.check_markdown_links()
    assert any(
        "CODE_SIGNING_POLICY.md" in p and "DOES_NOT_EXIST.md" in p for p in problems
    ), problems


def test_doc_claims_licence_scan_uses_project_root(tmp_path, monkeypatch):
    # Der Begriff wird zusammengesetzt, damit dieser Test nicht selbst von der
    # Pruefung als Widerspruch gemeldet wird (sie durchsucht auch .py-Dateien).
    (tmp_path / "notiz.md").write_text(
        "Dieses Projekt ist Closed " + "Source.", encoding="utf-8"
    )
    elsewhere = tmp_path.parent / (tmp_path.name + "-cwd")
    elsewhere.mkdir()
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)
    monkeypatch.chdir(elsewhere)
    try:
        problems = check_doc_claims.check_licence_claims()
    finally:
        # Kein Doku-Text mit dem Begriff im Baum liegen lassen.
        (tmp_path / "notiz.md").unlink(missing_ok=True)
        monkeypatch.chdir(ROOT)
    assert any("notiz.md" in problem for problem in problems), problems


def test_doc_claims_licence_scan_skips_pytest_artifacts(tmp_path, monkeypatch):
    """Testausgaben unter ``.pytest-tmp*`` sind keine Projektaussagen."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "aussage.md").write_text(
        "Dieses Projekt ist Closed " + "Source.", encoding="utf-8"
    )
    artifacts = tmp_path / ".pytest-tmp-gate"
    artifacts.mkdir()
    (artifacts / "fixture.md").write_text(
        "Dieses Projekt ist Closed " + "Source.", encoding="utf-8"
    )
    monkeypatch.setattr(check_doc_claims, "ROOT", tmp_path)

    problems = check_doc_claims.check_licence_claims()
    assert any("aussage.md" in problem for problem in problems), problems
    assert not any("fixture.md" in problem for problem in problems), problems


# -- BUG-100: dir-Stream entspricht MS-OVBA --------------------------------


def test_ole_dir_stream_uses_spec_markers_and_ansi_names():
    import ole_writer

    stream = ole_writer._dir_stream("Module1")

    # PROJECTCONSTANTS: Id 0x000C, dann SizeOfConstants=0 und Reserved 0x003C.
    constants = struct.pack("<H", 0x000C) + struct.pack("<I", 0) + struct.pack("<H", 0x003C)
    assert constants in stream
    # MODULENAME (0x0019) ist MBCS: Groesse zaehlt Bytes, Text ist ASCII/1252.
    assert struct.pack("<HI", 0x0019, len(b"Module1")) + b"Module1" in stream
    # MODULESTREAMNAME: Size-Feld zaehlt nur den ANSI-Namen, danach folgen
    # Reserved 0x0032 und der UTF-16-Name.
    streamname = (
        struct.pack("<HI", 0x001A, len(b"Module1"))
        + b"Module1"
        + struct.pack("<H", 0x0032)
        + struct.pack("<I", len("Module1".encode("utf-16-le")))
        + "Module1".encode("utf-16-le")
    )
    assert streamname in stream
    # Die frueheren Pseudo-Records 0x0048/0x0025 sind verschwunden; 0x0032
    # lebt jetzt als Reserved-Feld INNERHALB des 0x001A-Records.
    assert struct.pack("<HI", 0x0048, 4) not in stream
    assert struct.pack("<HI", 0x0025, 4) not in stream


# -- BUG-091/092/093: Batch-Skripte geben den Fehler weiter ----------------


@pytest.mark.parametrize(
    "name",
    ["update_clamav.bat", "update_signature_base.bat"],
)
def test_bat_updaters_exit_nonzero_on_failure(name):
    text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    assert "exit /b 1" in text


def test_scan_bat_propagates_cli_exit_code():
    text = (ROOT / "scan.bat").read_text(encoding="utf-8")
    assert 'set "RC=%ERRORLEVEL%"' in text
    assert "exit /b %RC%" in text


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe batch test")
def test_build_nuitka_bat_computes_appver4_under_cmd(tmp_path):
    """CI-004: Verify build_nuitka.bat computes APPVER4 cleanly under cmd.exe
    even when %ROOT% contains spaces and without relying on a host ROOT/.venv.
    """
    import shutil
    import subprocess

    work = tmp_path / "repo with spaces"
    (work / "scripts").mkdir(parents=True)
    (work / "src" / "malaz").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "build_nuitka.bat", work / "scripts" / "build_nuitka.bat")
    shutil.copy2(ROOT / "src" / "malaz" / "__init__.py", work / "src" / "malaz" / "__init__.py")
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(work / ".venv")],
        check=True,
        timeout=60,
    )
    comspec = os.environ.get("COMSPEC", "cmd.exe")

    # 1) Invalid NAME: proves APPVER4 succeeded and reached NAME validation
    bad = subprocess.run(
        [comspec, "/c", r"scripts\build_nuitka.bat", "standalone", "bad/name"],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert bad.returncode == 1
    assert "Version konnte nicht" not in bad.stdout, bad.stdout + bad.stderr
    assert "Ungueltiger NAME" in bad.stdout, bad.stdout + bad.stderr
    assert bad.stderr.strip() == "", bad.stderr

    # 2) Valid NAME: proves realpath check + Nuitka precheck also run cleanly
    good_name = subprocess.run(
        [comspec, "/c", r"scripts\build_nuitka.bat", "standalone", "Malaz-Test"],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert good_name.returncode == 1
    assert "Nuitka nicht gefunden" in good_name.stdout, good_name.stdout + good_name.stderr
    assert good_name.stderr.strip() == "", good_name.stderr


def test_vm_deepsec_propagates_test_failure_and_reports_missing_count():
    text = (ROOT / "scripts" / "vm_deepsec_test.bat").read_text(encoding="utf-8")
    assert "if errorlevel 1" in text
    assert "!fehlend!" in text
    assert "%fehlend%" not in text, "Parse-Expansion im selben Block liefert einen leeren Wert"


# -- BUG-097: Schreibfehler ist kein AV-Lebendigkeitsnachweis --------------


def test_lab_guard_does_not_treat_write_error_as_av_alive():
    text = (ROOT / "scripts" / "lab_guard.ps1").read_text(encoding="utf-8")
    assert "$state.eicar = 'error'" in text
    assert "malaz_control_probe_" in text


# -- SEC-046/047: UI-Renderer darf keine Scanner starten/Dateien loeschen ---


def test_render_ui_passes_disabled_scanners(tmp_path, monkeypatch):
    import render_ui
    from PySide6 import QtCore, QtWidgets

    from malaz.core.dispatcher import Dispatcher
    from malaz.gui import settings as real_settings

    captured: dict[str, object] = {}

    class FakeApplication:
        @classmethod
        def instance(cls):
            return cls()

        def __init__(self, *args, **kwargs):
            pass

        def processEvents(self):
            pass

    class FakePixmap:
        def save(self, path):
            Path(path).write_bytes(b"png")
            return True

    class FakeWindow:
        def __init__(self, dispatcher=None):
            captured["dispatcher"] = dispatcher

        def resize(self, *args):
            pass

        def grab(self):
            return FakePixmap()

    class FakeQSettings:
        class Format:
            IniFormat = 1

        def __init__(self, *args, **kwargs):
            pass

    monkeypatch.setattr(QtWidgets, "QApplication", FakeApplication)
    monkeypatch.setattr(QtCore, "QSettings", FakeQSettings)
    monkeypatch.setattr(render_ui, "ensure_fonts", lambda: True)
    from malaz.core import dispatcher as dispatcher_module
    from malaz.gui import main_window, theme

    class FakeDispatcher(Dispatcher):
        def __init__(self, av_scanner=None, clam_scanner=None):
            self.av_scanner = av_scanner
            self.clam_scanner = clam_scanner
            captured["dispatcher"] = self

    monkeypatch.setattr(dispatcher_module, "Dispatcher", FakeDispatcher)
    monkeypatch.setattr(main_window, "MainWindow", FakeWindow)
    monkeypatch.setattr(theme, "apply_theme", lambda app: None)

    original_settings = real_settings.app_settings
    try:
        render_ui.render(tmp_path / "ui.png", scannen=False)
    finally:
        real_settings.app_settings = original_settings

    dispatcher = captured["dispatcher"]
    assert dispatcher.av_scanner.enabled is False
    assert dispatcher.clam_scanner.enabled is False


def test_render_ui_refuses_to_delete_non_png_argument(tmp_path, monkeypatch):
    target = tmp_path / "wichtig.txt"
    target.write_text("nicht loeschen", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["render_ui.py", str(target)])

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPTS / "render_ui.py"), run_name="__main__")

    assert exc.value.code == 2
    assert target.read_text(encoding="utf-8") == "nicht loeschen"
