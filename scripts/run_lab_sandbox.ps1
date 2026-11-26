#requires -Version 5.1
<#
.SYNOPSIS
  Host orchestrator for the Windows Sandbox isolated Malaz static-only Malware Lab.

.DESCRIPTION
  Implements Spec 017 §3.3:
  * Generates hardened .wsb configuration strictly via XML-DOM (7 hardening tags,
    exact 3 MappedFolder mounts, static LogonCommand).
  * Stages sandbox_cfg.json, sandbox_inner.ps1, and lab_guard.ps1 into input_ro\
    and cleans them up defensively in try/finally.
  * Waits for guaranteed exit of all WindowsSandbox* processes before ever touching
    OutputDir (fail-closed Exit 4 if any process remains alive).
  * Runs the strictly read-only, idempotent Post-Exit output filter Test-LabOutputDir
    (including Win32 FindFirstStreamW/FindNextStreamW ADS checks on OutputDir and files,
    0 subfolders/reparse points, strict allowlist, 0 NUL bytes, strict UTF-8/JSON/CSV,
    <= 50 MiB, guard.json.ok == true, DONE.json schema/hash/status).
  * Supports -VerifyOutputOnly (strictly read-only, exits 0 / 3 / 4) and manifest-faithful
    -DryRun (0% missing_results, full E2E report + triage_misses --split dev).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StagingDir,
    [string]$MalazBundleDir = "",
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [string]$WsbPath = "",
    [string]$PasswordFile = "",
    [int]$MemoryMB = 0,
    [int]$TimeoutMinutes = 30,
    [string]$PythonExe = "",
    [switch]$DryRun,
    [switch]$VerifyOutputOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $WsbPath) {
    $WsbPath = Join-Path $StagingDir 'lab.wsb'
}
if (-not $PythonExe) {
    $candPy = Join-Path $script:RepoRoot '.venv\Scripts\python.exe'
    $PythonExe = if (Test-Path -LiteralPath $candPy -PathType Leaf) { $candPy } else { 'python' }
}

# Win32 FindFirstStreamW / FindNextStreamW P/Invoke helper for fail-closed NTFS ADS checks
if (-not ('MalazAdsHelper' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class MalazAdsHelper
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindFirstStreamW(
        string lpFileName,
        int InfoLevel,
        out WIN32_FIND_STREAM_DATA lpFindStreamData,
        uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool FindNextStreamW(
        IntPtr hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const int ERROR_HANDLE_EOF = 38;

    public static string[] ListStreams(string path, out int win32Error)
    {
        win32Error = 0;
        var list = new List<string>();
        WIN32_FIND_STREAM_DATA data;
        IntPtr handle = FindFirstStreamW(path, 0, out data, 0);
        if (handle == INVALID_HANDLE_VALUE)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == ERROR_HANDLE_EOF)
            {
                return list.ToArray();
            }
            win32Error = err;
            return null;
        }
        try
        {
            list.Add(data.cStreamName);
            while (FindNextStreamW(handle, out data))
            {
                list.Add(data.cStreamName);
            }
            int endErr = Marshal.GetLastWin32Error();
            if (endErr != ERROR_HANDLE_EOF)
            {
                win32Error = endErr;
                return null;
            }
        }
        finally
        {
            FindClose(handle);
        }
        return list.ToArray();
    }
}
"@
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Test-IsReparsePointPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $cur = [System.IO.Path]::GetFullPath($Path)
    while ($cur) {
        if (Test-Path -LiteralPath $cur) {
            $item = Get-Item -LiteralPath $cur -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $true
            }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    return $false
}

function Test-PathInside {
    param([string]$Candidate, [string]$BaseDir)
    $c = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $b = [System.IO.Path]::GetFullPath($BaseDir).TrimEnd('\')
    if ($c.Equals($b, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $c.StartsWith($b + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-ExpectedShaFile {
    param([string]$ShaPath)
    if (-not (Test-Path -LiteralPath $ShaPath -PathType Leaf)) { return $null }
    $raw = (Get-Content -LiteralPath $ShaPath -Raw -Encoding UTF8).Trim()
    if ($raw -match '^([0-9a-fA-F]{64})\b') {
        return $Matches[1].ToLowerInvariant()
    }
    return $null
}

function New-SandboxWsbXml {
    param(
        [string]$HostInDir,
        [string]$HostMalazDir,
        [string]$HostOutDir,
        [int]$MemMB,
        [string]$DestWsbPath
    )
    $doc = New-Object System.Xml.XmlDocument
    $root = $doc.CreateElement('Configuration')
    [void]$doc.AppendChild($root)

    $hardening = [ordered]@{
        Networking           = 'Disable'
        vGPU                 = 'Disable'
        AudioInput           = 'Disable'
        VideoInput           = 'Disable'
        ProtectedClient      = 'Enable'
        PrinterRedirection   = 'Disable'
        ClipboardRedirection = 'Disable'
        MemoryInMB           = [string]$MemMB
    }
    foreach ($k in $hardening.Keys) {
        $el = $doc.CreateElement($k)
        $el.InnerText = $hardening[$k]
        [void]$root.AppendChild($el)
    }

    $mappedFolders = $doc.CreateElement('MappedFolders')
    [void]$root.AppendChild($mappedFolders)

    $mounts = @(
        @{ Host = $HostInDir;    Guest = 'C:\Users\WDAGUtilityAccount\Desktop\lab_in';    Ro = 'true'  },
        @{ Host = $HostMalazDir; Guest = 'C:\Users\WDAGUtilityAccount\Desktop\lab_malaz'; Ro = 'true'  },
        @{ Host = $HostOutDir;   Guest = 'C:\Users\WDAGUtilityAccount\Desktop\lab_out';   Ro = 'false' }
    )
    foreach ($m in $mounts) {
        $mf = $doc.CreateElement('MappedFolder')
        $hf = $doc.CreateElement('HostFolder'); $hf.InnerText = $m.Host; [void]$mf.AppendChild($hf)
        $sf = $doc.CreateElement('SandboxFolder'); $sf.InnerText = $m.Guest; [void]$mf.AppendChild($sf)
        $ro = $doc.CreateElement('ReadOnly'); $ro.InnerText = $m.Ro; [void]$mf.AppendChild($ro)
        [void]$mappedFolders.AppendChild($mf)
    }

    $lc = $doc.CreateElement('LogonCommand')
    $cmd = $doc.CreateElement('Command')
    $cmd.InnerText = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\lab_in\sandbox_inner.ps1'
    [void]$lc.AppendChild($cmd)
    [void]$root.AppendChild($lc)

    $parent = Split-Path -Parent $DestWsbPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = [System.Xml.XmlWriter]::Create($DestWsbPath, $settings)
    try {
        $doc.Save($writer)
    } finally {
        $writer.Dispose()
    }
}

function Test-LabOutputDir {
    <#
      Strictly READ-ONLY, idempotent post-exit output filter (Spec 017 §3.3).
      Returns [ordered]@{ Passed; ExitCode (0|3|4); Done; Guard; Reason }.
    #>
    param(
        [string]$Dir,
        [string]$ExpectedManifestSha
    )
    $maxBytes = 50 * 1024 * 1024
    $allowList = @('results.csv', 'eval.json', 'guard.json', 'DONE.json', 'sandbox.log')
    $expectedCsvHeader = 'Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft,Datei_ID'
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)

    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "OutputDir missing: $Dir" }
    }
    if (Test-IsReparsePointPath -Path $Dir) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "OutputDir is/under a reparse point" }
    }

    # 1. Fail-closed directory ADS check (0 streams allowed on directory)
    $dirErr = 0
    $dirStreams = [MalazAdsHelper]::ListStreams($Dir, [ref]$dirErr)
    if ($null -eq $dirStreams -or $dirErr -ne 0) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Directory ADS probe failed (win32=$dirErr)" }
    }
    if ($dirStreams.Length -gt 0) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Unexpected ADS on OutputDir: $($dirStreams -join ', ')" }
    }

    # 2. List ALL entries with -Force: 0 subfolders, 0 reparse points, exact allowlist, <= 50 MiB, 0 foreign ADS
    $entries = @(Get-ChildItem -LiteralPath $Dir -Force)
    $present = @{}
    foreach ($item in $entries) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Reparse point in OutputDir: $($item.Name)" }
        }
        if ($item.PSIsContainer) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Subfolder forbidden in OutputDir: $($item.Name)" }
        }
        if ($allowList -cnotcontains $item.Name) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Unexpected file in OutputDir: $($item.Name)" }
        }
        if ($item.Length -gt $maxBytes) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "File exceeds 50 MiB: $($item.Name)" }
        }
        $fErr = 0
        $fStreams = [MalazAdsHelper]::ListStreams($item.FullName, [ref]$fErr)
        if ($null -eq $fStreams -or $fErr -ne 0) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "File ADS probe failed for $($item.Name) (win32=$fErr)" }
        }
        foreach ($st in $fStreams) {
            if ($st -ne '::$DATA') {
                return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Foreign ADS '$st' on $($item.Name)" }
            }
        }
        # Raw byte validation: 0 NUL bytes & strict UTF-8
        $rawBytes = [System.IO.File]::ReadAllBytes($item.FullName)
        if ([Array]::IndexOf($rawBytes, [byte]0) -ge 0) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "NUL byte detected in $($item.Name)" }
        }
        try {
            $decoded = $strictUtf8.GetString($rawBytes)
        } catch {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Invalid UTF-8 in $($item.Name)" }
        }
        $present[$item.Name] = $decoded
    }

    # 3. Mandatory files: DONE.json & guard.json
    if (-not $present.ContainsKey('DONE.json') -or -not $present.ContainsKey('guard.json')) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Missing mandatory DONE.json or guard.json" }
    }

    function Get-JsonProp {
        param($Obj, [string]$Name)
        if ($null -eq $Obj) { return $null }
        $p = $Obj.PSObject.Properties[$Name]
        if ($null -eq $p) { return $null }
        return $p.Value
    }

    try {
        $guardObj = $present['guard.json'].TrimStart([char]0xFEFF) | ConvertFrom-Json
    } catch {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $null; Reason = "Invalid JSON in guard.json" }
    }
    $guardOk = Get-JsonProp $guardObj 'ok'
    if (($guardOk -isnot [bool]) -or (-not $guardOk)) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $guardObj; Reason = "guard.json.ok is not true" }
    }

    try {
        $doneObj = $present['DONE.json'].TrimStart([char]0xFEFF) | ConvertFrom-Json
    } catch {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $guardObj; Reason = "Invalid JSON in DONE.json" }
    }
    if ($null -eq $doneObj) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $null; Guard = $guardObj; Reason = "DONE.json is null" }
    }
    $rawDoneSha = Get-JsonProp $doneObj 'manifest_sha256'
    $doneSha = if ($null -ne $rawDoneSha) { ([string]$rawDoneSha).ToLowerInvariant() } else { '' }
    if ($doneSha -ne $ExpectedManifestSha.ToLowerInvariant()) {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "DONE.json.manifest_sha256 mismatch" }
    }
    $rawEngineProfile = Get-JsonProp $doneObj 'engine_profile'
    if ([string]$rawEngineProfile -ne 'static_only') {
        return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "DONE.json.engine_profile must be 'static_only'" }
    }

    # 4. Status check
    $rawStatus = Get-JsonProp $doneObj 'status'
    $dStatus = if ($null -ne $rawStatus) { [string]$rawStatus } else { '' }
    if ($dStatus -eq 'ok') {
        if (-not $present.ContainsKey('results.csv') -or -not $present.ContainsKey('eval.json')) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "DONE.json.status=ok but results.csv or eval.json missing" }
        }
        $csvText = $present['results.csv'].TrimStart([char]0xFEFF)
        $firstLine = ($csvText -split "`r?`n", 2)[0].Trim()
        if ($firstLine -cne $expectedCsvHeader) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "Unexpected CSV header: $firstLine" }
        }
        try {
            $evalObj = $present['eval.json'].TrimStart([char]0xFEFF) | ConvertFrom-Json
        } catch {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "Invalid JSON in eval.json" }
        }
        if ($null -eq $evalObj) {
            return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "eval.json is empty or null" }
        }
        return [ordered]@{ Passed = $true; ExitCode = 0; Done = $doneObj; Guard = $guardObj; Reason = 'ok' }
    }

    if (@('custody_failed', 'eval_failed', 'error') -contains $dStatus) {
        return [ordered]@{ Passed = $false; ExitCode = 3; Done = $doneObj; Guard = $guardObj; Reason = "Guest run failed after guard passed: status=$dStatus" }
    }

    return [ordered]@{ Passed = $false; ExitCode = 4; Done = $doneObj; Guard = $guardObj; Reason = "Unknown/invalid DONE.json.status: '$dStatus'" }
}

function Wait-SandboxProcessesExit {
    param([int]$GraceSeconds = 30, [int]$KillSeconds = 15)
    $deadline = (Get-Date).AddSeconds($GraceSeconds)
    while ((Get-Date) -lt $deadline) {
        $procs = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue)
        if ($procs.Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    $procs = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { }
    }
    $killDeadline = (Get-Date).AddSeconds($KillSeconds)
    while ((Get-Date) -lt $killDeadline) {
        $left = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return (@(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue).Count -eq 0)
}

# --------------------------------------------------------------------------- #
# Pre-flight validation (Exit 2 on any violation)
# --------------------------------------------------------------------------- #
if (-not (Test-Path -LiteralPath $StagingDir -PathType Container)) {
    [Console]::Error.WriteLine("FEHLER: StagingDir fehlt: $StagingDir")
    exit 2
}
if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    [Console]::Error.WriteLine("FEHLER: OutputDir fehlt: $OutputDir")
    exit 2
}
if ((Test-IsReparsePointPath $StagingDir) -or (Test-IsReparsePointPath $OutputDir)) {
    [Console]::Error.WriteLine("FEHLER: StagingDir/OutputDir duerfen keine Symlinks/Reparse-Points sein.")
    exit 2
}
if ((Test-PathInside $StagingDir $script:RepoRoot) -or (Test-PathInside $OutputDir $script:RepoRoot)) {
    [Console]::Error.WriteLine("FEHLER: StagingDir/OutputDir duerfen nicht im Repository liegen.")
    exit 2
}
if ((Test-PathInside $OutputDir $StagingDir) -or (Test-PathInside $StagingDir $OutputDir)) {
    [Console]::Error.WriteLine("FEHLER: StagingDir und OutputDir muessen getrennte Pfade sein.")
    exit 2
}

$inputRo = Join-Path $StagingDir 'input_ro'
$manifestPath = Join-Path $inputRo 'manifest.json'
$manifestShaPath = Join-Path $inputRo 'manifest.sha256'
$summaryPath = Join-Path $inputRo 'ingest_summary.json'
$summaryShaPath = Join-Path $inputRo 'ingest_summary.sha256'

$expectedManifestSha = Read-ExpectedShaFile $manifestShaPath
$expectedSummarySha = Read-ExpectedShaFile $summaryShaPath
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not $expectedManifestSha) {
    [Console]::Error.WriteLine("FEHLER: manifest.json oder manifest.sha256 fehlt/ungueltig.")
    exit 2
}
if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf) -or -not $expectedSummarySha) {
    [Console]::Error.WriteLine("FEHLER: ingest_summary.json oder ingest_summary.sha256 fehlt/ungueltig.")
    exit 2
}
$actualManifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualManifestSha -ne $expectedManifestSha) {
    [Console]::Error.WriteLine("FEHLER: manifest.sha256 stimmt nicht mit manifest.json ueberein.")
    exit 2
}
$actualSummarySha = (Get-FileHash -LiteralPath $summaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSummarySha -ne $expectedSummarySha) {
    [Console]::Error.WriteLine("FEHLER: ingest_summary.sha256 stimmt nicht mit ingest_summary.json ueberein.")
    exit 2
}
$ingestSummary = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (([string]$ingestSummary.manifest_sha256).ToLowerInvariant() -ne $expectedManifestSha) {
    [Console]::Error.WriteLine("FEHLER: ingest_summary.manifest_sha256 weicht von manifest.sha256 ab.")
    exit 2
}

# Read-only verification mode (-VerifyOutputOnly): zero writes, idempotent!
if ($VerifyOutputOnly) {
    $ver = Test-LabOutputDir -Dir $OutputDir -ExpectedManifestSha $expectedManifestSha
    if ($ver.ExitCode -ne 0) {
        [Console]::Error.WriteLine("VerifyOutputOnly FAIL (exit $($ver.ExitCode)): $($ver.Reason)")
    } else {
        Write-Output "VerifyOutputOnly PASS"
    }
    exit [int]$ver.ExitCode
}

# Live & DryRun additional pre-flight checks
if (@(Get-ChildItem -LiteralPath $OutputDir -Force).Count -gt 0) {
    [Console]::Error.WriteLine("FEHLER: OutputDir muss vor Laufbeginn leer sein: $OutputDir")
    exit 2
}
if ((Test-PathInside $WsbPath $script:RepoRoot) -or (Test-PathInside $WsbPath $OutputDir) -or (Test-IsReparsePointPath $WsbPath)) {
    [Console]::Error.WriteLine("FEHLER: WsbPath darf nicht im Repository, in OutputDir oder unter einem Reparse-Point liegen.")
    exit 2
}

if ($PasswordFile) {
    if (-not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) {
        [Console]::Error.WriteLine("FEHLER: PasswordFile fehlt: $PasswordFile")
        exit 2
    }
    $zipPassword = (Get-Content -LiteralPath $PasswordFile -Raw -Encoding UTF8).Trim("`r", "`n")
    if ([string]::IsNullOrEmpty($zipPassword)) {
        [Console]::Error.WriteLine("FEHLER: Passwort aus PasswordFile ist leer.")
        exit 2
    }
} else {
    $zipPassword = 'infected'
}

if (-not $DryRun) {
    if (-not [Environment]::UserInteractive) {
        [Console]::Error.WriteLine("FEHLER: Live-Windows-Sandbox erfordert eine interaktive Desktop-Session.")
        exit 2
    }
    $wsbExe = Get-Command 'WindowsSandbox.exe' -ErrorAction SilentlyContinue
    if (-not $wsbExe) {
        [Console]::Error.WriteLine("FEHLER: WindowsSandbox.exe nicht installiert.")
        exit 2
    }
    if (@(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue).Count -gt 0) {
        [Console]::Error.WriteLine("FEHLER: Es laeuft bereits eine WindowsSandbox-Instanz.")
        exit 2
    }
    if (-not $MalazBundleDir -or -not (Test-Path -LiteralPath $MalazBundleDir -PathType Container) -or (Test-IsReparsePointPath $MalazBundleDir)) {
        [Console]::Error.WriteLine("FEHLER: MalazBundleDir ungueltig: $MalazBundleDir")
        exit 2
    }
    $malazExePath = Join-Path $MalazBundleDir 'Malaz.exe'
    $sevenZExePath = Join-Path $MalazBundleDir '7z.exe'
    $sevenZDllPath = Join-Path $MalazBundleDir '7z.dll'
    $sevenZaExePath = Join-Path $MalazBundleDir '7za.exe'
    $hasMalaz = (Test-Path -LiteralPath $malazExePath -PathType Leaf) -and (-not (Test-IsReparsePointPath $malazExePath))
    $has7zPair = (Test-Path -LiteralPath $sevenZExePath -PathType Leaf) -and (-not (Test-IsReparsePointPath $sevenZExePath)) -and (Test-Path -LiteralPath $sevenZDllPath -PathType Leaf) -and (-not (Test-IsReparsePointPath $sevenZDllPath))
    $has7za = (Test-Path -LiteralPath $sevenZaExePath -PathType Leaf) -and (-not (Test-IsReparsePointPath $sevenZaExePath))
    $has7z = $has7zPair -or $has7za
    if (-not $hasMalaz -or -not $has7z) {
        [Console]::Error.WriteLine("FEHLER: MalazBundleDir muss Malaz.exe sowie 7z.exe+7z.dll oder 7za.exe enthalten.")
        exit 2
    }
} elseif (-not $MalazBundleDir) {
    $MalazBundleDir = $StagingDir
}

# Compute MemoryMB if unset (0)
$effMemoryMB = $MemoryMB
if ($effMemoryMB -le 0) {
    $totalBytes = [double]$ingestSummary.total_unpacked_bytes
    $unpackedMb = [math]::Ceiling($totalBytes / (1024.0 * 1024.0))
    $desired = [math]::Max(4096.0, (2.0 * $unpackedMb) + 2048.0)
    $hostRamMb = 16384.0
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hostRamMb = [math]::Floor([double]$cs.TotalPhysicalMemory / (1024.0 * 1024.0))
    } catch { }
    $effMemoryMB = [int][math]::Min([math]::Floor($hostRamMb * 0.5), $desired)
    if ($effMemoryMB -lt 2048) { $effMemoryMB = 2048 }
}

# Stage host helper scripts & sandbox_cfg.json cleanly with defensive try/finally cleanup
$srcInner = Join-Path $PSScriptRoot 'sandbox_inner.ps1'
$srcGuard = Join-Path $PSScriptRoot 'lab_guard.ps1'
foreach ($srcF in @($srcInner, $srcGuard)) {
    if (-not (Test-Path -LiteralPath $srcF -PathType Leaf) -or (Test-IsReparsePointPath $srcF)) {
        [Console]::Error.WriteLine("FEHLER: Host-Skript fehlt oder ist Reparse-Point: $srcF")
        exit 2
    }
}

$stagedInner = Join-Path $inputRo 'sandbox_inner.ps1'
$stagedGuard = Join-Path $inputRo 'lab_guard.ps1'
$stagedCfg = Join-Path $inputRo 'sandbox_cfg.json'
$simStateFile = ''

$finalExit = 1
try {
    do {
    Copy-Item -LiteralPath $srcInner -Destination $stagedInner -Force
    Copy-Item -LiteralPath $srcGuard -Destination $stagedGuard -Force
    $cfgObj = [ordered]@{
        schema_version  = 1
        engine_profile  = 'static_only'
        manifest_sha256 = $expectedManifestSha
        zip_password    = $zipPassword
        auto_shutdown   = (-not $DryRun)
    }
    Write-Utf8NoBom -Path $stagedCfg -Content ($cfgObj | ConvertTo-Json -Depth 4)

    New-SandboxWsbXml `
        -HostInDir ([System.IO.Path]::GetFullPath($inputRo)) `
        -HostMalazDir ([System.IO.Path]::GetFullPath($MalazBundleDir)) `
        -HostOutDir ([System.IO.Path]::GetFullPath($OutputDir)) `
        -MemMB $effMemoryMB `
        -DestWsbPath $WsbPath

    if ($DryRun) {
        # Manifest-faithful DryRun (0% missing_results, no sandbox launch, no unpacking)
        $simStateFile = Join-Path ([System.IO.Path]::GetTempPath()) ("malaz_sim_state_" + [guid]::NewGuid().ToString('N') + ".json")
        $simState = [ordered]@{
            adapters       = @()
            default_routes = @()
            dns_servers    = @()
            dns_resolves   = $false
            shared_folders = @()
            usb_storage    = @()
            username       = 'WDAGUtilityAccount'
        }
        Write-Utf8NoBom -Path $simStateFile -Content ($simState | ConvertTo-Json -Depth 4)

        $guardJsonOut = Join-Path $OutputDir 'guard.json'
        & $stagedGuard -SandboxGuest -SkipEicar -StatePath $simStateFile -ManifestPath $manifestPath -ManifestSha256 $expectedManifestSha -OutputDir $OutputDir -JsonOut $guardJsonOut | Out-Null
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("FEHLER: DryRun lab_guard -SandboxGuest fehlgeschlagen.")
            $finalExit = 4
            break
        }

        $manifestObj = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $csvLines = New-Object System.Collections.ArrayList
        [void]$csvLines.Add('Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft,Datei_ID')
        foreach ($ent in $manifestObj.files) {
            $eName = [string]$ent.name
            $eType = [string]$ent.type
            if ([string]$ent.label -eq 'malicious') {
                [void]$csvLines.Add("bad,$eName,$eType,ROT,80,DRYRUN_SYNTH,,$eName")
            } else {
                [void]$csvLines.Add("good,$eName,$eType,GRÜN,0,,,$eName")
            }
        }
        Write-Utf8NoBom -Path (Join-Path $OutputDir 'results.csv') -Content (($csvLines -join "`n") + "`n")
        Write-Utf8NoBom -Path (Join-Path $OutputDir 'eval.json') -Content '{"schema_version":1,"dryrun":true}'
        Write-Utf8NoBom -Path (Join-Path $OutputDir 'sandbox.log') -Content "dryrun completed`n"

        $nowUtc = (Get-Date).ToUniversalTime().ToString('o')
        $doneDry = [ordered]@{
            schema_version    = 1
            status            = 'ok'
            engine_profile    = 'static_only'
            exit_code         = 0
            manifest_sha256   = $expectedManifestSha
            samples_extracted = @($manifestObj.files | Where-Object { $_.label -eq 'malicious' }).Count
            hash_mismatches   = 0
            started_utc       = $nowUtc
            finished_utc      = $nowUtc
            error             = ''
        }
        Write-Utf8NoBom -Path (Join-Path $OutputDir 'DONE.json') -Content ($doneDry | ConvertTo-Json -Depth 4)
    } else {
        # Live Windows Sandbox execution
        $proc = Start-Process -FilePath 'WindowsSandbox.exe' -ArgumentList @($WsbPath) -PassThru
        $startedAt = Get-Date
        $deadline = $startedAt.AddMinutes($TimeoutMinutes)
        $doneFile = Join-Path $OutputDir 'DONE.json'
        while ((Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $doneFile -PathType Leaf) {
                break
            }
            # WindowsSandbox.exe may act as a thin launcher spawning WindowsSandboxClient.exe:
            # only exit early once NO WindowsSandbox* process remains after startup grace.
            if (
                $proc.HasExited `
                -and (((Get-Date) - $startedAt).TotalSeconds -ge 15) `
                -and (@(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue).Count -eq 0)
            ) {
                break
            }
            Start-Sleep -Seconds 2
        }
        # Guarantee ALL WindowsSandbox* processes have exited BEFORE inspecting OutputDir!
        $allExited = Wait-SandboxProcessesExit -GraceSeconds 30 -KillSeconds 15
        if (-not $allExited) {
            [Console]::Error.WriteLine("FEHLER: WindowsSandbox-Prozess laeuft noch — Fail-Closed Exit 4 (OutputDir wird nicht gelesen).")
            $finalExit = 4
            break
        }
    }

    # Strictly read-only post-exit output filter
    $ver = Test-LabOutputDir -Dir $OutputDir -ExpectedManifestSha $expectedManifestSha
    if ($ver.ExitCode -eq 4) {
        [Console]::Error.WriteLine("FEHLER: Post-Exit-Output-Filter abgelehnt (Exit 4): $($ver.Reason)")
        $finalExit = 4
        break
    }

    $runDateUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    $metaObj = [ordered]@{
        schema_version         = 1
        run_date_utc           = $runDateUtc
        engine_profile         = 'static_only'
        av_engines             = 'disabled'
        dryrun                 = [bool]$DryRun
        manifest_sha256        = $expectedManifestSha
        ingest_rejected        = [int]$ingestSummary.rejected_total
        ingest_rejected_detail = $ingestSummary.rejected
        sandbox_status         = [string]$ver.Done.status
    }
    Write-Utf8NoBom -Path (Join-Path $OutputDir 'lab_meta.json') -Content ($metaObj | ConvertTo-Json -Depth 6)

    if ($ver.ExitCode -eq 3) {
        [Console]::Error.WriteLine("FEHLER: Gastlauf fehlgeschlagen (status=$($ver.Done.status)) — kein report.json erzeugt.")
        $finalExit = 3
        break
    }

    # Host post-processing: realworld_report.py + triage_misses.py --split dev
    $reportScript = Join-Path $PSScriptRoot 'realworld_report.py'
    $triageScript = Join-Path $PSScriptRoot 'triage_misses.py'
    $resultsCsv = Join-Path $OutputDir 'results.csv'

    & $PythonExe $reportScript $manifestPath $resultsCsv --json (Join-Path $OutputDir 'report.json') --markdown (Join-Path $OutputDir 'report.md')
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("FEHLER: realworld_report.py fehlgeschlagen (rc=$LASTEXITCODE)")
        $finalExit = 3
        break
    }

    & $PythonExe $triageScript $resultsCsv --manifest $manifestPath --split dev --json (Join-Path $OutputDir 'misses.json') --markdown (Join-Path $OutputDir 'misses.md')
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("FEHLER: triage_misses.py fehlgeschlagen (rc=$LASTEXITCODE)")
        $finalExit = 3
        break
    }

    $finalExit = 0
    } while ($false)
} finally {
    foreach ($tmpF in @($stagedCfg, $stagedInner, $stagedGuard, $simStateFile)) {
        if ($tmpF -and (Test-Path -LiteralPath $tmpF)) {
            try {
                Remove-Item -LiteralPath $tmpF -Force -ErrorAction Stop
            } catch {
                [Console]::Error.WriteLine("WARNUNG: Cleanup fehlgeschlagen fuer ${tmpF}: $($_.Exception.Message)")
            }
        }
    }
}

exit $finalExit
