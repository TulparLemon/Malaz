"""T2 tests for lab_guard.ps1 -SandboxGuest, sandbox_inner.ps1 & run_lab_sandbox.ps1 (Spec 017 §4)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import pyzipper

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import lab_compare  # noqa: E402
import lab_ingest  # noqa: E402

LAB_GUARD = ROOT / "scripts" / "lab_guard.ps1"
RUN_SANDBOX = ROOT / "scripts" / "run_lab_sandbox.ps1"
SANDBOX_INNER = ROOT / "scripts" / "sandbox_inner.ps1"
POWERSHELL = shutil.which("powershell.exe") or "powershell.exe"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="PowerShell sandbox scripts target Windows"
)


def _ps_env() -> dict[str, str]:
    """Strip PSModulePath for clean, isolated Windows PowerShell 5.1 subprocesses."""
    env = dict(os.environ)
    for k in list(env):
        if k.lower() == "psmodulepath":
            env.pop(k)
    return env


def _run_ps(script: Path, args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *args,
        ],
        env=_ps_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _create_staged_corpus(tmp_path: Path, *, name: str = "stage") -> tuple[Path, str]:
    bad_dir = tmp_path / f"bad_{name}"
    ben_dir = tmp_path / f"ben_{name}"
    staging = tmp_path / f"st_{name}"
    bad_dir.mkdir()
    ben_dir.mkdir()

    with pyzipper.AESZipFile(bad_dir / "s1.zip", "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("sample[1].bin", b"dummy malicious bytes 123456")
    (ben_dir / "clean.txt").write_bytes(b"dummy clean benign text")

    rc = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(staging),
            "--corpus-id",
            f"t2-{name}",
        ]
    )
    assert rc == 0
    msha = (staging / "input_ro/manifest.sha256").read_text(encoding="utf-8").split()[0]
    return staging, msha


def _write_valid_output(out_dir: Path, msha: str, *, status: str = "ok") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "guard.json").write_text(
        json.dumps({"ok": True, "source": "sandbox_simulated", "checks": []}),
        encoding="utf-8",
    )
    (out_dir / "DONE.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": status,
                "engine_profile": "static_only",
                "exit_code": 0 if status == "ok" else 3,
                "manifest_sha256": msha,
                "samples_extracted": 1,
                "hash_mismatches": 0,
                "started_utc": "2026-11-26T00:00:00Z",
                "finished_utc": "2026-11-26T00:00:01Z",
                "error": "",
            }
        ),
        encoding="utf-8",
    )
    (out_dir / "sandbox.log").write_text("ok\n", encoding="utf-8")
    if status == "ok":
        (out_dir / "results.csv").write_text(
            "Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft,Datei_ID\n",
            encoding="utf-8",
        )
        (out_dir / "eval.json").write_text('{"schema_version":1}', encoding="utf-8")


# --------------------------------------------------------------------------- #
# T2(b): lab_guard.ps1 -SandboxGuest
# --------------------------------------------------------------------------- #


def test_lab_guard_sandbox_guest_pass_and_fail_closed(tmp_path):
    staging, msha = _create_staged_corpus(tmp_path, name="guard")
    out_dir = tmp_path / "guard_out"
    out_dir.mkdir()
    state_ok = tmp_path / "state_ok.json"
    state_ok.write_text(
        json.dumps(
            {
                "adapters": [],
                "default_routes": [],
                "dns_servers": [],
                "dns_resolves": False,
                "shared_folders": [],
                "usb_storage": [],
                "username": "WDAGUtilityAccount",
            }
        ),
        encoding="utf-8",
    )

    # PASS case
    json_out = out_dir / "guard.json"
    res = _run_ps(
        LAB_GUARD,
        [
            "-SandboxGuest",
            "-SkipEicar",
            "-StatePath",
            str(state_ok),
            "-ManifestPath",
            str(staging / "input_ro/manifest.json"),
            "-ManifestSha256",
            msha,
            "-OutputDir",
            str(out_dir),
            "-JsonOut",
            str(json_out),
        ],
    )
    assert res.returncode == 0, res.stderr + res.stdout
    raw_bytes = json_out.read_bytes()
    assert not raw_bytes.startswith(b"\xef\xbb\xbf")  # UTF-8 without BOM
    parsed = json.loads(raw_bytes.decode("utf-8"))
    assert parsed["ok"] is True
    assert parsed["source"] == "sandbox_simulated"

    # FAIL cases: wrong username, active adapter, missing field
    for tag, bad_state in (
        (
            "wrong_user",
            {
                "adapters": [],
                "default_routes": [],
                "dns_servers": [],
                "dns_resolves": False,
                "shared_folders": [],
                "usb_storage": [],
                "username": "AdminUser",
            },
        ),
        (
            "active_net",
            {
                "adapters": [{"name": "Ethernet", "status": "Up"}],
                "default_routes": [],
                "dns_servers": [],
                "dns_resolves": False,
                "shared_folders": [],
                "usb_storage": [],
                "username": "WDAGUtilityAccount",
            },
        ),
        (
            "missing_dns",
            {
                "adapters": [],
                "default_routes": [],
                "shared_folders": [],
                "usb_storage": [],
                "username": "WDAGUtilityAccount",
            },
        ),
    ):
        st_f = tmp_path / f"st_{tag}.json"
        st_f.write_text(json.dumps(bad_state), encoding="utf-8")
        od = tmp_path / f"od_{tag}"
        od.mkdir()
        r = _run_ps(
            LAB_GUARD,
            [
                "-SandboxGuest",
                "-SkipEicar",
                "-StatePath",
                str(st_f),
                "-ManifestPath",
                str(staging / "input_ro/manifest.json"),
                "-ManifestSha256",
                msha,
                "-OutputDir",
                str(od),
            ],
        )
        assert r.returncode == 1, tag


# --------------------------------------------------------------------------- #
# T2(a), (c), (f): .wsb XML-DOM, Pre-Flight Exit 2, Manifest-faithful -DryRun
# --------------------------------------------------------------------------- #


def test_run_lab_sandbox_dryrun_e2e_wsb_xml_and_preflight_guards(tmp_path):
    # Include '&' in path to prove XML-DOM escaping!
    amp_base = tmp_path / "lab&test"
    amp_base.mkdir()
    staging, _msha = _create_staged_corpus(amp_base, name="dry")
    out_dir = amp_base / "out_dry"
    out_dir.mkdir()
    wsb_path = amp_base / "custom.wsb"

    # Full manifest-faithful -DryRun
    r = _run_ps(
        RUN_SANDBOX,
        [
            "-StagingDir",
            str(staging),
            "-OutputDir",
            str(out_dir),
            "-WsbPath",
            str(wsb_path),
            "-PythonExe",
            sys.executable,
            "-DryRun",
        ],
    )
    assert r.returncode == 0, r.stderr + r.stdout

    # T2(a): Validate .wsb via ElementTree
    tree = ET.parse(wsb_path)
    cfg = tree.getroot()
    assert cfg.tag == "Configuration"
    expected_flags = {
        "Networking": "Disable",
        "vGPU": "Disable",
        "AudioInput": "Disable",
        "VideoInput": "Disable",
        "ProtectedClient": "Enable",
        "PrinterRedirection": "Disable",
        "ClipboardRedirection": "Disable",
    }
    for k, v in expected_flags.items():
        assert cfg.findtext(k) == v
    assert int(cfg.findtext("MemoryInMB") or "0") >= 2048

    mounts = cfg.findall("./MappedFolders/MappedFolder")
    assert len(mounts) == 3
    assert [m.findtext("ReadOnly") for m in mounts] == ["true", "true", "false"]
    assert "&" in (mounts[0].findtext("HostFolder") or "")
    assert (
        cfg.findtext("./LogonCommand/Command")
        == (
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
            r"-File C:\Users\WDAGUtilityAccount\Desktop\lab_in\sandbox_inner.ps1"
        )
    )

    # T2(f): 0% missing_results + finally cleanup of staged host scripts & sandbox_cfg.json
    input_ro = staging / "input_ro"
    assert not (input_ro / "sandbox_cfg.json").exists()
    assert not (input_ro / "sandbox_inner.ps1").exists()
    assert not (input_ro / "lab_guard.ps1").exists()

    rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert all(f["status"] != "missing" for f in rep["files"])
    meta = json.loads((out_dir / "lab_meta.json").read_text(encoding="utf-8"))
    assert meta["dryrun"] is True
    assert meta["sandbox_status"] == "ok"
    assert (out_dir / "misses.json").is_file()

    # Chain dryrun -> lab_compare --allow-dryrun works, --public-summary blocked!
    assert (
        lab_compare.main(["--baseline", str(out_dir), "--current", str(out_dir), "--allow-dryrun"])
        == 0
    )
    assert (
        lab_compare.main(
            [
                "--baseline",
                str(out_dir),
                "--current",
                str(out_dir),
                "--allow-dryrun",
                "--public-summary",
                str(tmp_path / "forbidden_pub.md"),
            ]
        )
        == 2
    )

    # T2(c): Pre-flight Exit 2 checks
    # 1. Non-empty OutputDir
    r_nonempty = _run_ps(
        RUN_SANDBOX,
        ["-StagingDir", str(staging), "-OutputDir", str(out_dir), "-DryRun"],
    )
    assert r_nonempty.returncode == 2
    # 2. Empty password file
    empty_pw = tmp_path / "epw.txt"
    empty_pw.write_text("\n", encoding="utf-8")
    empty_out = tmp_path / "empty_out"
    empty_out.mkdir()
    r_epw = _run_ps(
        RUN_SANDBOX,
        [
            "-StagingDir",
            str(staging),
            "-OutputDir",
            str(empty_out),
            "-PasswordFile",
            str(empty_pw),
            "-DryRun",
        ],
    )
    assert r_epw.returncode == 2
    # 3. Manifest hash mismatch
    (input_ro / "manifest.sha256").write_text("0" * 64 + "  manifest.json\n", encoding="utf-8")
    r_hash = _run_ps(
        RUN_SANDBOX,
        ["-StagingDir", str(staging), "-OutputDir", str(empty_out), "-DryRun"],
    )
    assert r_hash.returncode == 2


# --------------------------------------------------------------------------- #
# T2(d): Read-only idempotent -VerifyOutputOnly (Exit 0 / 3 / 4)
# --------------------------------------------------------------------------- #


def test_verify_output_only_readonly_ads_hidden_nul_schema_and_idempotence(tmp_path):
    staging, msha = _create_staged_corpus(tmp_path, name="ver")

    # 1. Clean valid output -> Exit 0
    ok_dir = tmp_path / "ver_ok"
    _write_valid_output(ok_dir, msha)
    r_ok = _run_ps(
        RUN_SANDBOX,
        ["-StagingDir", str(staging), "-OutputDir", str(ok_dir), "-VerifyOutputOnly"],
    )
    assert r_ok.returncode == 0, r_ok.stderr + r_ok.stdout

    # 2. custody_failed -> Exit 3 AND strictly read-only (idempotent, no lab_meta.json written!)
    cf_dir = tmp_path / "ver_cf"
    _write_valid_output(cf_dir, msha, status="custody_failed")
    before_files = sorted(p.name for p in cf_dir.iterdir())
    r_cf1 = _run_ps(
        RUN_SANDBOX,
        ["-StagingDir", str(staging), "-OutputDir", str(cf_dir), "-VerifyOutputOnly"],
    )
    r_cf2 = _run_ps(
        RUN_SANDBOX,
        ["-StagingDir", str(staging), "-OutputDir", str(cf_dir), "-VerifyOutputOnly"],
    )
    assert r_cf1.returncode == 3
    assert r_cf2.returncode == 3
    assert sorted(p.name for p in cf_dir.iterdir()) == before_files
    assert not (cf_dir / "lab_meta.json").exists()

    # 3. Exit 4 tamper scenarios
    def _case(name: str, tamper) -> None:
        d = tmp_path / f"tamper_{name}"
        _write_valid_output(d, msha)
        tamper(d)
        r = _run_ps(
            RUN_SANDBOX,
            ["-StagingDir", str(staging), "-OutputDir", str(d), "-VerifyOutputOnly"],
        )
        assert r.returncode == 4, f"{name}: expected 4, got {r.returncode} ({r.stderr})"

    _case("exe_file", lambda d: (d / "drop.exe").write_bytes(b"MZ"))
    _case(
        "hidden_file",
        lambda d: (
            (d / "hide.txt").write_text("x", encoding="utf-8"),
            subprocess.run(["attrib", "+h", str(d / "hide.txt")], check=True),
        ),
    )
    _case("subfolder", lambda d: (d / "sub").mkdir())
    _case("nul_byte", lambda d: (d / "sandbox.log").write_bytes(b"ok\x00bad"))
    _case("missing_eval", lambda d: (d / "eval.json").unlink())
    _case("bad_csv_hdr", lambda d: (d / "results.csv").write_text("Wrong,Header\n", encoding="utf-8"))
    _case("guard_false", lambda d: (d / "guard.json").write_text('{"ok":false}', encoding="utf-8"))
    _case(
        "manifest_sha_mismatch",
        lambda d: (d / "DONE.json").write_text(
            (d / "DONE.json").read_text(encoding="utf-8").replace(msha, "f" * 64),
            encoding="utf-8",
        ),
    )
    # File-ADS & Directory-ADS on NTFS
    _case("file_ads", lambda d: (d / "sandbox.log:evil").write_text("ads", encoding="utf-8"))
    def _add_dir_ads(d: Path) -> None:
        with open(f"{d}:evil_dir_stream", "w", encoding="utf-8") as fh:
            fh.write("ads")

    _case("dir_ads", _add_dir_ads)


# --------------------------------------------------------------------------- #
# T2(e): sandbox_inner.ps1 with real compiled Win32 console .exe stubs
# --------------------------------------------------------------------------- #


def _compile_stub_exe(cs_source: str, out_exe: Path) -> None:
    """Compile a minimal Win32 ConsoleApplication .exe via PowerShell Add-Type."""
    cs_file = out_exe.with_suffix(".cs")
    cs_file.write_text(cs_source, encoding="utf-8")
    ps_cmd = (
        f"$src = Get-Content -LiteralPath '{cs_file}' -Raw -Encoding UTF8; "
        f"Add-Type -TypeDefinition $src -OutputAssembly '{out_exe}' -OutputType ConsoleApplication"
    )
    r = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
        env=_ps_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, f"Stub compile failed: {r.stderr}\n{r.stdout}"


def test_sandbox_inner_with_win32_stubs_custody_and_preextract_checks(tmp_path):
    staging, msha = _create_staged_corpus(tmp_path, name="inner")
    in_dir = staging / "input_ro"
    shutil.copy2(LAB_GUARD, in_dir / "lab_guard.ps1")

    # Identify expected malicious sample payload & hash
    manifest = json.loads((in_dir / "manifest.json").read_text(encoding="utf-8"))
    mal_entry = next(e for e in manifest["files"] if e["label"] == "malicious")
    mal_payload = b"dummy malicious bytes 123456"
    assert hashlib.sha256(mal_payload).hexdigest() == mal_entry["sha256"]

    # Compile mock 7z.exe (reads mode from MOCK_7Z_MODE env var) and mock Malaz.exe
    malaz_dir = tmp_path / "mock_malaz"
    malaz_dir.mkdir()
    (malaz_dir / "7z.dll").write_bytes(b"stub")

    stub_7z_cs = r'''
using System;
using System.IO;
public class Program {
    public static int Main(string[] args) {
        string mode = Environment.GetEnvironmentVariable("MOCK_7Z_MODE") ?? "ok";
        if (args.Length > 0 && args[0] == "l") {
            Console.WriteLine("Path = C:\\Windows\\header_must_be_ignored.zip");
            Console.WriteLine("Type = zip");
            Console.WriteLine("----------");
            if (mode == "reserved") {
                Console.WriteLine("Path = sub/CON.txt");
                Console.WriteLine("Folder = -");
                Console.WriteLine("Attributes = A");
            } else if (mode == "symlink") {
                Console.WriteLine("Path = link.bin");
                Console.WriteLine("Folder = -");
                Console.WriteLine("Attributes = lrwxrwxrwx");
            } else {
                Console.WriteLine("Path = subdir");
                Console.WriteLine("Folder = +");
                Console.WriteLine("Attributes = D");
                Console.WriteLine("");
                Console.WriteLine("Path = sample[1].bin");
                Console.WriteLine("Folder = -");
                Console.WriteLine("Attributes = A");
            }
            return 0;
        }
        if (args.Length > 0 && args[0] == "e") {
            string outDir = "";
            foreach (string a in args) {
                if (a.StartsWith("-o")) outDir = a.Substring(2);
            }
            Directory.CreateDirectory(Path.Combine(outDir, "empty_sub"));
            string target = Path.Combine(outDir, "sample[1].bin");
            byte[] payload = (mode == "unknown_file")
                ? System.Text.Encoding.ASCII.GetBytes("rogue_unlisted_bytes")
                : System.Text.Encoding.ASCII.GetBytes("dummy malicious bytes 123456");
            File.WriteAllBytes(target, payload);
            File.SetAttributes(target, FileAttributes.Hidden | FileAttributes.System);
            return 0;
        }
        return 1;
    }
}
'''
    stub_malaz_cs = r'''
using System;
using System.IO;
public class Program {
    public static int Main(string[] args) {
        string csv = "";
        string js = "";
        for (int i = 0; i < args.Length - 1; i++) {
            if (args[i] == "--csv") csv = args[i + 1];
            if (args[i] == "--json") js = args[i + 1];
        }
        string hdr = "Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft,Datei_ID\n";
        if (csv != "") File.WriteAllText(csv, hdr);
        if (js != "") File.WriteAllText(js, "{\"schema_version\":1}");
        return 0;
    }
}
'''
    _compile_stub_exe(stub_7z_cs, malaz_dir / "7z.exe")
    _compile_stub_exe(stub_malaz_cs, malaz_dir / "Malaz.exe")

    (in_dir / "sandbox_cfg.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engine_profile": "static_only",
                "manifest_sha256": msha,
                "zip_password": "infected",
                "auto_shutdown": False,
            }
        ),
        encoding="utf-8",
    )
    sim_state = tmp_path / "inner_state.json"
    sim_state.write_text(
        json.dumps(
            {
                "adapters": [],
                "default_routes": [],
                "dns_servers": [],
                "dns_resolves": False,
                "shared_folders": [],
                "usb_storage": [],
                "username": "WDAGUtilityAccount",
            }
        ),
        encoding="utf-8",
    )

    def _run_inner(case_name: str, mode: str) -> tuple[int, dict]:
        out_d = tmp_path / f"in_out_{case_name}"
        work_d = tmp_path / f"in_work_{case_name}"
        tmp_d = tmp_path / f"in_tmp_{case_name}"
        out_d.mkdir()
        env = _ps_env()
        env["MOCK_7Z_MODE"] = mode
        proc = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SANDBOX_INNER),
                "-InDir",
                str(in_dir),
                "-MalazDir",
                str(malaz_dir),
                "-OutDir",
                str(out_d),
                "-WorkDir",
                str(work_d),
                "-TmpDir",
                str(tmp_d),
                "-GuardStatePath",
                str(sim_state),
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        done = json.loads((out_d / "DONE.json").read_text(encoding="utf-8"))
        return proc.returncode, done

    # 1. Happy path: ignores header Path=C:\..., allows empty_sub, Hidden+System & [1] filename!
    rc_ok, done_ok = _run_inner("ok", "ok")
    assert rc_ok == 0
    assert done_ok["status"] == "ok"
    assert done_ok["samples_extracted"] == 1
    assert done_ok["hash_mismatches"] == 0

    # 2. Reserved Windows device name after '----------' (sub/CON.txt) -> custody_failed
    rc_res, done_res = _run_inner("reserved", "reserved")
    assert rc_res == 3
    assert done_res["status"] == "custody_failed"

    # 3. Symlink attribute after '----------' -> custody_failed
    rc_sym, done_sym = _run_inner("symlink", "symlink")
    assert rc_sym == 3
    assert done_sym["status"] == "custody_failed"

    # 4. Unknown extracted file hash -> custody_failed
    rc_unk, done_unk = _run_inner("unknown", "unknown_file")
    assert rc_unk == 3
    assert done_unk["status"] == "custody_failed"

    # 5. Benign custody tamper -> custody_failed
    ben_file = next((in_dir / "benign").iterdir())
    ben_file.write_bytes(b"tampered benign bytes!")
    rc_bt, done_bt = _run_inner("benign_tamper", "ok")
    assert rc_bt == 3
    assert done_bt["status"] == "custody_failed"
    assert done_bt["hash_mismatches"] >= 1
