import zipfile

import pytest

from scripts import check_release


def test_release_gate_rejects_runtime_log_and_secret(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "malaz.log").write_text("harmless", encoding="utf-8")
    (root / "config.py").write_text(
        'TOKEN = "' + "123456789" + ":" + "a" * 40 + '"\n', encoding="utf-8"
    )
    findings = check_release.scan_directory(root)
    assert any(item.kind == "forbidden-runtime-file" for item in findings)
    assert any(item.kind == "telegram-token" for item in findings)
    assert all("123456789" not in item.detail for item in findings)


def test_release_gate_allows_clean_binary_directory(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "Malaz.exe").write_bytes(b"MZ")
    (root / "rules").mkdir()
    (root / "rules" / "default.yar").write_text("rule x { condition: false }", encoding="utf-8")
    assert check_release.scan_directory(root) == []


def test_release_gate_rejects_private_path_in_archive(tmp_path):
    archive_path = tmp_path / "public.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        win_priv = "C:\\Users\\" + "AliceDev\\secret.txt"
        archive.writestr("src/demo.py", f'path = r"{win_priv}"\n')
    findings = check_release.scan_archive(archive_path, source=True)
    assert any(item.kind == "developer-path" for item in findings)


def test_release_gate_rejects_handover_case_insensitively(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "HANDOVER.md").write_text("local report", encoding="utf-8")
    assert any(
        item.kind == "forbidden-runtime-file"
        for item in check_release.scan_directory(root, source=True)
    )

    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("HANDOVER.md", "local report")
    assert any(
        item.kind == "forbidden-runtime-file"
        for item in check_release.scan_archive(archive_path, source=True)
    )


def test_history_grep_parser_strips_ref_and_excludes_tests():
    finding = check_release._parse_history_grep_line(
        "abc123:src/app.py:7:secret", "abc123"
    )
    test_finding = check_release._parse_history_grep_line(
        "abc123:tests/test_secret.py:3:secret", "abc123"
    )
    assert finding is not None
    assert finding.path == "abc123:src/app.py:7"
    assert test_finding is None


def test_release_gate_rejects_missing_directory_target(tmp_path):
    """A gate that cannot read its target must block, not pass.

    Before the fix a typo in the build script made ``rglob`` yield nothing and
    the gate printed "Release gate passed".
    """
    findings = check_release.scan_directory(tmp_path / "fehlt")
    assert [item.kind for item in findings] == ["invalid-target"]


def test_release_gate_main_fails_on_missing_or_non_directory_target(tmp_path, capsys):
    missing = tmp_path / "fehlt"
    assert check_release.main(["--directory", str(missing)]) == 1
    assert "RELEASE BLOCKED" in capsys.readouterr().out

    not_a_dir = tmp_path / "paket.zip"
    not_a_dir.write_bytes(b"PK")
    assert check_release.main(["--directory", str(not_a_dir)]) == 1
    assert "RELEASE BLOCKED" in capsys.readouterr().out


def test_release_gate_main_fails_on_missing_archive(tmp_path):
    assert check_release.main(["--archive", str(tmp_path / "fehlt.zip")]) == 1


@pytest.mark.parametrize(
    "name", ["deploy.ps1", "module.psm1", "lokale_regel.yar", "run.cmd", "install.sh"]
)
def test_release_gate_scans_script_and_rule_content(tmp_path, name):
    """These suffixes were not in the text set, so their content escaped the
    secret/private-path scan entirely."""
    root = tmp_path / "package"
    root.mkdir()
    (root / name).write_text(
        "path = \"" + "C:\\Users\\" + "AliceDev\\secret.txt\"\n", encoding="utf-8"
    )
    findings = check_release.scan_directory(root)
    assert any(item.kind == "developer-path" for item in findings), name


def test_release_gate_detects_feed_dirs_at_any_archive_depth(tmp_path):
    """The third-party feeds must be caught below a top-level ``rules/`` too.

    A prefix test only matched entries rooted exactly at ``rules/yara/...``;
    inside a release ZIP the same directories sit under ``Malaz/rules/...``.
    """
    archive_path = tmp_path / "public.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "Malaz/rules/yara/external/feed.yar", "rule x { condition: false }"
        )
        archive.writestr(
            "Malaz/rules/yara/signature_base/bundle.yarc", b"compiled"
        )
        archive.writestr(
            "Malaz/rules/yara/eigene.yar", "rule y { condition: false }"
        )
    findings = check_release.scan_archive(archive_path)
    forbidden = {
        item.path
        for item in findings
        if item.kind == "forbidden-runtime-file"
    }
    assert forbidden == {
        "Malaz/rules/yara/external/feed.yar",
        "Malaz/rules/yara/signature_base/bundle.yarc",
    }


# -- Quality Gate und FP-Check: ein Gate muss bei null Pruefungen scheitern --


def test_quality_gate_passes_the_coverage_threshold_to_pytest():
    """BUG-087: ``min_cover_pct`` war nur Deklaration, nie durchgesetzt.

    docs/INSTALLATION.md promises "pytest incl. coverage report (70% threshold)", der
    Schritt lief aber ohne ``--cov-fail-under``: ein Lauf mit 12 % Coverage
    meldete „ALLE PRÜFUNGEN BESTANDEN".
    """
    from scripts import run_quality_checks as quality

    step = next(s for s in quality.STEPS if "pytest" in s["name"].lower())
    assert step.get("min_cover_pct") == 70
    assert "--cov-fail-under=70" in quality._step_args(step)


def test_quality_gate_fails_when_no_step_is_selected(monkeypatch):
    """BUG-088: ``--only tpyo`` uebersprang alles und meldete Erfolg.

    ``run_step`` gab fuer jeden uebersprungenen Schritt 0 zurueck; die
    ``failures``-Liste blieb leer -> Exit 0. Jetzt zaehlt das Gate die
    tatsaechlich gelaufenen Schritte.
    """
    from scripts import run_quality_checks as quality

    def darf_nicht_laufen(*_args, **_kwargs):
        raise AssertionError("kein Schritt haette laufen duerfen")

    monkeypatch.setattr(quality.subprocess, "run", darf_nicht_laufen)
    assert quality.main(["--only", "tpyo"]) == 1


def test_quality_gate_runs_the_selected_step_with_the_threshold(monkeypatch):
    from types import SimpleNamespace

    from scripts import run_quality_checks as quality

    seen: list[list[str]] = []

    def fake_run(args, **_kwargs):
        seen.append(list(args))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(quality.subprocess, "run", fake_run)
    assert quality.main(["--only", "pytest"]) == 0
    assert len(seen) == 1, seen
    assert "--cov-fail-under=70" in seen[0]


def test_fp_check_measures_files_directly_in_the_base_dir(tmp_path):
    """BUG-083: ein flaches Verzeichnis ergab 0 Messungen.

    ``messen`` iterierte nur ``basis.iterdir()``-UNTERORDNER; Dateien direkt
    unter ``basis`` wurden nie gescannt, ``main`` meldete „Keine einzige ROT."
    mit Exit 0 — ein Freispruch ohne eine einzige gepruefte Datei.
    """
    from malaz import models
    from scripts import run_fp_check

    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "direkt.txt").write_bytes(b"x")
    nested = flat / "docx"
    nested.mkdir()
    (nested / "innen.txt").write_bytes(b"y")

    gemessen = list(run_fp_check._mess_dateien(flat))
    assert [(art, datei.name) for art, datei in gemessen] == [
        ("docx", "innen.txt"),
        ("(direkt)", "direkt.txt"),
    ]
    # Und die Messung zaehlt sie (Fake-Dispatcher, keine echten Engines).
    class _Fake:
        def __init__(self, **_kwargs):
            pass

        def scan_path(self, path):
            return models.ScanResult(
                path=str(path), detected_type="text", risk_level=models.RiskLevel.GREEN
            )

    import malaz.core.dispatcher as core_dispatcher

    original = core_dispatcher.Dispatcher
    core_dispatcher.Dispatcher = _Fake  # type: ignore[assignment]
    try:
        count, red = run_fp_check.messen(flat)
    finally:
        core_dispatcher.Dispatcher = original  # type: ignore[assignment]
    assert count == 2, count
    assert red == 0


def test_fp_check_exits_nonzero_when_nothing_was_measured(tmp_path, capsys):
    from malaz import models
    from scripts import run_fp_check

    leer = tmp_path / "leer"
    leer.mkdir()

    class _Fake:
        def __init__(self, **_kwargs):
            pass

        def scan_path(self, path):
            return models.ScanResult(path=str(path), risk_level=models.RiskLevel.GREEN)

    import malaz.core.dispatcher as core_dispatcher

    original = core_dispatcher.Dispatcher
    core_dispatcher.Dispatcher = _Fake  # type: ignore[assignment]
    try:
        rc = run_fp_check.main(["--nur-messen", "--verzeichnis", str(leer)])
    finally:
        core_dispatcher.Dispatcher = original  # type: ignore[assignment]
    assert rc == 2, capsys.readouterr()


def test_release_gate_detects_generic_unix_path_and_lab_ip_but_allows_placeholders(tmp_path):
    root = tmp_path / "src_pkg"
    root.mkdir()
    unix_priv = "/home/" + "alicedev/secret.txt"
    lab_ip = "192.168." + "178.42"
    (root / "leak.md").write_text(
        f"See {unix_priv} on host {lab_ip}\n",
        encoding="utf-8",
    )
    (root / "safe.md").write_text(
        "Placeholders: C:\\Users\\<Benutzer>\\Downloads, C:\\Users\\...\\AppData, "
        "C:\\Users\\alex\\demo.pdf, /home/alex/demo.pdf, "
        "https://github.com/Users/foo/bar\n",
        encoding="utf-8",
    )
    findings = check_release.scan_directory(root, source=True)
    by_file_kind = {(f.path, f.kind) for f in findings}
    assert ("leak.md", "developer-unix-path") in by_file_kind
    assert ("leak.md", "private-lab-ip") in by_file_kind
    assert not any(f.path == "safe.md" for f in findings), findings


def test_release_gate_source_allows_only_five_yara_attribution_docs(tmp_path):
    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "Malaz-1.0.0/rules/yara/external/LICENSE-MIT-ReversingLabs.txt", "MIT"
        )
        archive.writestr(
            "Malaz-1.0.0/rules/yara/external/README-externe-regeln.txt", "README"
        )
        archive.writestr(
            "Malaz-1.0.0/rules/yara/signature_base/LICENSE-DRL-1.1.txt", "DRL"
        )
        archive.writestr(
            "Malaz-1.0.0/rules/yara/signature_base/LICENSES-EINZELREGELN.txt", "CC"
        )
        archive.writestr(
            "Malaz-1.0.0/rules/yara/signature_base/README-signature-base.txt", "README"
        )
        archive.writestr("Malaz-1.0.0/rules/yara/malaz_custom.yar", "rule a { condition: false }")

    assert check_release.scan_archive(archive_path, source=True) == []
    # In binary mode (source=False), even the attribution docs in feed folders must not ship.
    bin_findings = check_release.scan_archive(archive_path, source=False)
    assert len(bin_findings) == 5

    # Any .yar/.yarc or non-allowlisted file under external/ or signature_base/ must still block!
    dirty_zip = tmp_path / "dirty_source.zip"
    with zipfile.ZipFile(dirty_zip, "w") as archive:
        archive.writestr("Malaz-1.0.0/rules/yara/external/feed.yar", "rule x { condition: false }")
        archive.writestr("Malaz-1.0.0/rules/yara/signature_base/bundle.yarc", b"compiled")
        archive.writestr("Malaz-1.0.0/rules/yara/external/extra.txt", "unexpected")
    dirty_findings = check_release.scan_archive(dirty_zip, source=True)
    assert {f.path for f in dirty_findings} == {
        "Malaz-1.0.0/rules/yara/external/feed.yar",
        "Malaz-1.0.0/rules/yara/signature_base/bundle.yarc",
        "Malaz-1.0.0/rules/yara/external/extra.txt",
    }


def test_source_release_gate_rejects_internal_governance_and_design_files(tmp_path):
    """GOV-003: internal agent/PM/design files must never ship in source archives."""
    for rel in (
        ".agents/plugins/x/plugin.json",
        "MOC.md",
        "AGENTS.md",
        "PROJECT_BOARD.md",
        ".gitlab-ci.yml",
        "docs/designs/001-spec.md",
    ):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("internal\n", encoding="utf-8")

    findings = check_release.scan_directory(tmp_path, source=True)
    flagged = {f.path for f in findings if f.kind == "forbidden-runtime-file"}
    assert flagged == {
        ".agents/plugins/x/plugin.json",
        "MOC.md",
        "AGENTS.md",
        "PROJECT_BOARD.md",
        ".gitlab-ci.yml",
        "docs/designs/001-spec.md",
    }
def test_tree_ref_rejects_internal_and_non_ascii_paths(tmp_path):
    """T3 & T4: --tree-ref inspects Git commit trees (incl. non-ASCII via -z) fail-closed."""
    import subprocess
    import sys
    from pathlib import Path

    import pytest

    git = check_release._git_exe(tmp_path)
    subprocess.run(
        [git, "init", "-b", "main", str(tmp_path)], check=True, capture_output=True
    )
    subprocess.run([git, "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)

    (tmp_path / "README.md").write_text("# Clean\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "README.md"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "clean"], check=True, capture_output=True
    )
    assert check_release.scan_tree_ref(tmp_path, "main") == []

    (tmp_path / "AGENTS.md").write_text("internal\n", encoding="utf-8")
    (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "03_übersicht.md").write_text("de\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "dirty"], check=True, capture_output=True
    )

    findings = check_release.scan_tree_ref(tmp_path, "HEAD")
    flagged = {(f.path, f.kind) for f in findings}
    assert ("AGENTS.md", "forbidden-public-path") in flagged
    assert (".gitlab-ci.yml", "forbidden-public-path") in flagged
    assert ("docs/03_übersicht.md", "forbidden-public-path") in flagged

    bad = check_release.scan_tree_ref(tmp_path, "refs/tags/does-not-exist")
    assert len(bad) == 1 and bad[0].kind == "invalid-target"

    prefixed_zip = tmp_path / "prefixed.zip"
    with zipfile.ZipFile(prefixed_zip, "w") as zf:
        zf.writestr("Malaz-1.0.0/docs/03_risk.md", "de\n")
        zf.writestr("Malaz-1.0.0/scripts/make_public_export.bat", "@echo off\n")
    arch_findings = check_release.scan_archive(prefixed_zip, source=True)
    assert {f.path for f in arch_findings} == {
        "Malaz-1.0.0/docs/03_risk.md",
        "Malaz-1.0.0/scripts/make_public_export.bat",
    }

    with pytest.raises(SystemExit) as exc:
        check_release.main(["--tree-ref", "main", "--archive", str(prefixed_zip)])
    assert exc.value.code == 2

    proc = subprocess.run(
        [sys.executable, str(Path(check_release.__file__).resolve()), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0 and "--tree-ref" in proc.stdout
