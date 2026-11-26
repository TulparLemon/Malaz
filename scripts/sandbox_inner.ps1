#requires -Version 5.1
<#
.SYNOPSIS
  Isolated guest runner executed inside Windows Sandbox for Malaz static-only lab scans.

.DESCRIPTION
  Implements Spec 017 §3.2:
  1. Runs lab_guard.ps1 -SandboxGuest -SkipEicar BEFORE creating any file in OutDir.
  2. Verifies SHA-256 of every staged ZIP against bad_zips_sha256.json.
  3. Performs a 7z l -slt pre-extract check strictly AFTER the '----------' separator
     (rejecting path traversal, drive/ADS colons, control chars, reserved Windows
     device names, symlinks, hardlinks, and reparse attributes).
  4. Extracts each ZIP with '7z e -y -bd -aou' (NO -snld!) into a fresh per-ZIP temp
     directory, inspects with -Force -Recurse (rejecting reparse points & nested files),
     verifies SHA-256 via -LiteralPath against manifest.json, and moves into WorkDir\bad.
  5. Verifies full chain-of-custody for all malicious AND benign manifest entries.
  6. Runs Malaz.exe --evaluate WorkDir\bad InDir\benign --static-only.
  7. Atomically writes DONE.json in finally (DONE.json.tmp -> DONE.json) and optionally
     triggers shutdown.exe /s /t 2 /f.
#>
[CmdletBinding()]
param(
    [string]$InDir          = "C:\Users\WDAGUtilityAccount\Desktop\lab_in",
    [string]$MalazDir       = "C:\Users\WDAGUtilityAccount\Desktop\lab_malaz",
    [string]$OutDir         = "C:\Users\WDAGUtilityAccount\Desktop\lab_out",
    [string]$WorkDir        = "C:\sandbox_work",
    [string]$TmpDir         = "C:\sandbox_tmp",
    [string]$GuardStatePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$startedUtc = (Get-Date).ToUniversalTime().ToString('o')
$logBuffer = New-Object System.Collections.ArrayList
$logActive = $false
$logPath = Join-Path $OutDir 'sandbox.log'

$status = 'error'
$exitCode = 1
$manifestSha = ''
$samplesExtracted = 0
$hashMismatches = 0
$errorDetail = ''
$autoShutdown = $false

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Append-Utf8NoBom {
    param([string]$Path, [string]$Line)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText($Path, $Line + "`n", $enc)
}

function Write-LabLog {
    param([string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString('o')
    $entry = "[$ts] $Message"
    if ($script:logActive) {
        try { Append-Utf8NoBom -Path $script:logPath -Line $entry } catch { }
    } else {
        [void]$script:logBuffer.Add($entry)
    }
}

function Flush-LabLog {
    $script:logActive = $true
    foreach ($line in $script:logBuffer) {
        try { Append-Utf8NoBom -Path $script:logPath -Line $line } catch { }
    }
    $script:logBuffer.Clear()
}

function Test-UnsafeArchiveMemberPath {
    param([string]$MemberPath)
    if ([string]::IsNullOrWhiteSpace($MemberPath)) { return "empty member path" }
    if ($MemberPath.StartsWith('/') -or $MemberPath.StartsWith('\')) { return "absolute member path" }
    if ($MemberPath.Contains(':')) { return "colon/ADS in member path" }
    foreach ($ch in $MemberPath.ToCharArray()) {
        $code = [int][char]$ch
        if ($code -lt 32 -or $code -eq 127) { return "control char in member path" }
    }
    $segments = $MemberPath -split '[/\\]'
    foreach ($seg in $segments) {
        if ($seg -eq '..') { return "parent traversal segment" }
        if ([string]::IsNullOrEmpty($seg)) { continue }
        $stem = ($seg -split '\.')[0]
        if ($stem -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            return "reserved Windows device name: $seg"
        }
    }
    return $null
}

function Test-SevenZipPreExtract {
    param(
        [string]$SevenZipExe,
        [string]$ZipPath,
        [string]$Password
    )
    $lines = & $SevenZipExe l -slt "-p$Password" -- $ZipPath 2>&1
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
        return "7z l -slt failed with exit code $rc"
    }

    $seenSep = $false
    $blocks = New-Object System.Collections.ArrayList
    $cur = @{}

    foreach ($rawLine in $lines) {
        $line = [string]$rawLine
        if (-not $seenSep) {
            if ($line.Trim() -eq '----------') {
                $seenSep = $true
            }
            continue
        }
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($cur.Count -gt 0) {
                [void]$blocks.Add($cur)
                $cur = @{}
            }
            continue
        }
        $eq = $line.IndexOf(' = ')
        if ($eq -gt 0) {
            $k = $line.Substring(0, $eq).Trim()
            $v = $line.Substring($eq + 3).Trim()
            $cur[$k] = $v
        }
    }
    if ($cur.Count -gt 0) {
        [void]$blocks.Add($cur)
    }
    if (-not $seenSep) {
        return "7z l -slt output missing '----------' separator"
    }
    if ($blocks.Count -eq 0) {
        return "7z l -slt reported 0 member blocks"
    }

    $fileMembers = 0
    foreach ($blk in $blocks) {
        $mPath = if ($blk.ContainsKey('Path')) { [string]$blk['Path'] } else { '' }
        $badPath = Test-UnsafeArchiveMemberPath -MemberPath $mPath
        if ($badPath) {
            return "unsafe member path '$mPath': $badPath"
        }
        if ($blk.ContainsKey('Symbolic Link') -and -not [string]::IsNullOrWhiteSpace([string]$blk['Symbolic Link'])) {
            return "symbolic link member rejected: $mPath"
        }
        if ($blk.ContainsKey('Hard Link') -and -not [string]::IsNullOrWhiteSpace([string]$blk['Hard Link'])) {
            return "hard link member rejected: $mPath"
        }
        if ($blk.ContainsKey('Attributes')) {
            $attr = [string]$blk['Attributes']
            if ($attr -match '(?i)(?:^|\s)l[rwxstST-]{9}' -or $attr -match '^[A-Z.]*L') {
                return "symlink/reparse attribute rejected ($attr): $mPath"
            }
        }
        $isFolder = ($blk.ContainsKey('Folder') -and ([string]$blk['Folder'] -eq '+'))
        if (-not $isFolder) {
            $fileMembers++
        }
    }
    if ($fileMembers -eq 0) {
        return "ZIP contains 0 regular file members"
    }
    return $null
}

try {
    # Prepare isolated temp/work directories
    foreach ($d in @($TmpDir, $WorkDir, (Join-Path $WorkDir 'bad'))) {
        if (-not (Test-Path -LiteralPath $d -PathType Container)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
    $env:TEMP = $TmpDir
    $env:TMP = $TmpDir
    $env:LOCALAPPDATA = $TmpDir

    Write-LabLog "sandbox_inner starting (InDir=$InDir, MalazDir=$MalazDir, OutDir=$OutDir)"

    # Load sandbox_cfg.json
    $cfgPath = Join-Path $InDir 'sandbox_cfg.json'
    if (-not (Test-Path -LiteralPath $cfgPath -PathType Leaf)) {
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = "sandbox_cfg.json missing: $cfgPath"
        throw $errorDetail
    }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifestSha = [string]$cfg.manifest_sha256
    $zipPassword = [string]$cfg.zip_password
    $autoShutdown = [bool]$cfg.auto_shutdown

    if ([string]::IsNullOrEmpty($zipPassword)) {
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = 'zip_password in sandbox_cfg.json is empty'
        throw $errorDetail
    }
    if ([string]$cfg.engine_profile -ne 'static_only') {
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = "unsupported engine_profile: $($cfg.engine_profile)"
        throw $errorDetail
    }

    # Step 0: Run lab_guard.ps1 BEFORE creating sandbox.log in OutDir!
    $guardScript = Join-Path $InDir 'lab_guard.ps1'
    $manifestPath = Join-Path $InDir 'manifest.json'
    $guardOut = Join-Path $OutDir 'guard.json'

    $guardArgs = @{
        SandboxGuest   = $true
        SkipEicar      = $true
        ManifestPath   = $manifestPath
        ManifestSha256 = $manifestSha
        OutputDir      = $OutDir
        JsonOut        = $guardOut
    }
    if (-not [string]::IsNullOrWhiteSpace($GuardStatePath)) {
        $guardArgs['StatePath'] = $GuardStatePath
    }

    $guardRc = 1
    try {
        & $guardScript @guardArgs | Out-Null
        $guardRc = $LASTEXITCODE
    } catch {
        $guardRc = 1
    }

    Flush-LabLog

    $guardOk = $false
    if (Test-Path -LiteralPath $guardOut -PathType Leaf) {
        try {
            $gObj = Get-Content -LiteralPath $guardOut -Raw -Encoding UTF8 | ConvertFrom-Json
            $guardOk = ($gObj.ok -eq $true)
        } catch {
            $guardOk = $false
        }
    }
    if ($guardRc -ne 0 -or -not $guardOk) {
        $status = 'guard_failed'
        $exitCode = 2
        $errorDetail = "lab_guard -SandboxGuest failed (rc=$guardRc, ok=$guardOk)"
        Write-LabLog "FAIL: $errorDetail"
        throw $errorDetail
    }
    Write-LabLog "Step 0 passed: lab_guard -SandboxGuest ok=true"

    # Resolve 7-Zip binary in MalazDir (7z.exe+7z.dll or 7za.exe)
    $sevenZipExe = ''
    $cand7z = Join-Path $MalazDir '7z.exe'
    $cand7zDll = Join-Path $MalazDir '7z.dll'
    $cand7za = Join-Path $MalazDir '7za.exe'
    if ((Test-Path -LiteralPath $cand7z -PathType Leaf) -and (Test-Path -LiteralPath $cand7zDll -PathType Leaf)) {
        $sevenZipExe = $cand7z
    } elseif (Test-Path -LiteralPath $cand7za -PathType Leaf) {
        $sevenZipExe = $cand7za
    } else {
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = "7-Zip binary (7z.exe+7z.dll or 7za.exe) missing in $MalazDir"
        throw $errorDetail
    }

    $malazExe = Join-Path $MalazDir 'Malaz.exe'
    if (-not (Test-Path -LiteralPath $malazExe -PathType Leaf)) {
        $status = 'eval_failed'
        $exitCode = 3
        $errorDetail = "Malaz.exe missing in $MalazDir"
        throw $errorDetail
    }

    # Load manifest.json & bad_zips_sha256.json
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifestByHash = @{}
    $maliciousEntries = New-Object System.Collections.ArrayList
    $benignEntries = New-Object System.Collections.ArrayList

    foreach ($entry in $manifest.files) {
        $eName = [string]$entry.name
        if ([string]::IsNullOrWhiteSpace($eName) -or $eName.Contains('/') -or $eName.Contains('\') -or $eName.Contains(':') -or $eName -eq '.' -or $eName -eq '..') {
            $status = 'custody_failed'
            $exitCode = 3
            $errorDetail = "invalid manifest entry name: $eName"
            throw $errorDetail
        }
        $eHash = ([string]$entry.sha256).ToLowerInvariant()
        if ([string]$entry.label -eq 'malicious') {
            $manifestByHash[$eHash] = $entry
            [void]$maliciousEntries.Add($entry)
        } elseif ([string]$entry.label -eq 'benign') {
            [void]$benignEntries.Add($entry)
        }
    }

    $badZipsShaPath = Join-Path $InDir 'bad_zips_sha256.json'
    if (-not (Test-Path -LiteralPath $badZipsShaPath -PathType Leaf)) {
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = 'bad_zips_sha256.json missing'
        throw $errorDetail
    }
    $badZipsExpectedObj = Get-Content -LiteralPath $badZipsShaPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $badZipsExpected = @{}
    foreach ($prop in $badZipsExpectedObj.PSObject.Properties) {
        $badZipsExpected[$prop.Name] = ([string]$prop.Value).ToLowerInvariant()
    }

    # Step 1: Verify & extract staged malicious ZIPs
    $badZipsDir = Join-Path $InDir 'bad_zips'
    $workBadDir = Join-Path $WorkDir 'bad'
    $zipFiles = @()
    if (Test-Path -LiteralPath $badZipsDir -PathType Container) {
        $zipFiles = @(Get-ChildItem -LiteralPath $badZipsDir -File -Force | Sort-Object Name)
    }

    foreach ($zf in $zipFiles) {
        if (-not $badZipsExpected.ContainsKey($zf.Name)) {
            $status = 'custody_failed'
            $exitCode = 3
            $errorDetail = "unlisted ZIP in bad_zips: $($zf.Name)"
            throw $errorDetail
        }
        $actualZipSha = (Get-FileHash -LiteralPath $zf.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualZipSha -ne $badZipsExpected[$zf.Name]) {
            $status = 'custody_failed'
            $exitCode = 3
            $errorDetail = "ZIP SHA-256 mismatch for $($zf.Name)"
            throw $errorDetail
        }

        $preErr = Test-SevenZipPreExtract -SevenZipExe $sevenZipExe -ZipPath $zf.FullName -Password $zipPassword
        if ($preErr) {
            $status = 'custody_failed'
            $exitCode = 3
            $errorDetail = "pre-extract check failed for $($zf.Name): $preErr"
            throw $errorDetail
        }

        $tmpOne = Join-Path $TmpDir ("z_" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmpOne -Force | Out-Null
        try {
            # NO -snld flag (strict default in 7-Zip 25.01+, avoids exit 7 in older versions)
            & $sevenZipExe e -y -bd -aou "-p$zipPassword" "-o$tmpOne" -- $zf.FullName | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $status = 'custody_failed'
                $exitCode = 3
                $errorDetail = "7z extract failed for $($zf.Name) (rc=$LASTEXITCODE)"
                throw $errorDetail
            }

            $extractedItems = @(Get-ChildItem -LiteralPath $tmpOne -Force -Recurse)
            foreach ($item in $extractedItems) {
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $status = 'custody_failed'
                    $exitCode = 3
                    $errorDetail = "extracted reparse point rejected: $($item.Name)"
                    throw $errorDetail
                }
                if (-not $item.PSIsContainer) {
                    $parentNorm = [System.IO.Path]::GetFullPath($item.DirectoryName).TrimEnd('\')
                    $tmpNorm = [System.IO.Path]::GetFullPath($tmpOne).TrimEnd('\')
                    if ($parentNorm -ne $tmpNorm) {
                        $status = 'custody_failed'
                        $exitCode = 3
                        $errorDetail = "unexpected file inside extracted subfolder: $($item.FullName)"
                        throw $errorDetail
                    }
                    $fHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                    if (-not $manifestByHash.ContainsKey($fHash)) {
                        $status = 'custody_failed'
                        $exitCode = 3
                        $errorDetail = "extracted file hash not in manifest: $fHash"
                        throw $errorDetail
                    }
                    $mEntry = $manifestByHash[$fHash]
                    $destFile = Join-Path $workBadDir ([string]$mEntry.name)
                    Move-Item -LiteralPath $item.FullName -Destination $destFile -Force
                    $samplesExtracted++
                }
            }
        } finally {
            if (Test-Path -LiteralPath $tmpOne) {
                Remove-Item -LiteralPath $tmpOne -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Verify every expected ZIP was present
    foreach ($expZipName in $badZipsExpected.Keys) {
        $p = Join-Path $badZipsDir $expZipName
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            $status = 'custody_failed'
            $exitCode = 3
            $errorDetail = "expected ZIP missing from bad_zips: $expZipName"
            throw $errorDetail
        }
    }

    # Chain-of-custody verification across ALL malicious & benign manifest entries
    $actualBadFiles = @(Get-ChildItem -LiteralPath $workBadDir -File -Force)
    if ($actualBadFiles.Count -ne $maliciousEntries.Count) {
        $hashMismatches++
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = "malicious file count mismatch: actual=$($actualBadFiles.Count), expected=$($maliciousEntries.Count)"
        throw $errorDetail
    }
    foreach ($entry in $maliciousEntries) {
        $fp = Join-Path $workBadDir ([string]$entry.name)
        if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) {
            $hashMismatches++
            continue
        }
        $h = (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($h -ne ([string]$entry.sha256).ToLowerInvariant()) {
            $hashMismatches++
        }
    }
    $benignInDir = Join-Path $InDir 'benign'
    foreach ($entry in $benignEntries) {
        $fp = Join-Path $benignInDir ([string]$entry.name)
        if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) {
            $hashMismatches++
            continue
        }
        $h = (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($h -ne ([string]$entry.sha256).ToLowerInvariant()) {
            $hashMismatches++
        }
    }
    if ($hashMismatches -gt 0) {
        $status = 'custody_failed'
        $exitCode = 3
        $errorDetail = "chain-of-custody hash/existence mismatches: $hashMismatches"
        throw $errorDetail
    }
    Write-LabLog "Step 1 passed: custody verified (malicious=$($maliciousEntries.Count), benign=$($benignEntries.Count))"

    # Step 2: Run Malaz evaluation (--static-only)
    $csvOut = Join-Path $OutDir 'results.csv'
    $jsonOut = Join-Path $OutDir 'eval.json'
    & $malazExe --evaluate $workBadDir $benignInDir --static-only --csv $csvOut --json $jsonOut
    $evalRc = $LASTEXITCODE
    if ($evalRc -ne 0) {
        $status = 'eval_failed'
        $exitCode = 3
        $errorDetail = "Malaz.exe --evaluate exited with code $evalRc"
        throw $errorDetail
    }
    Write-LabLog "Step 2 passed: Malaz.exe --evaluate succeeded"

    $status = 'ok'
    $exitCode = 0
} catch {
    if (-not $logActive) {
        Flush-LabLog
    }
    if (-not $errorDetail) {
        $errorDetail = $_.Exception.Message
    }
    Write-LabLog "ABORT ($status): $errorDetail"
} finally {
    if (-not $logActive) {
        Flush-LabLog
    }
    $finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $doneObj = [ordered]@{
        schema_version    = 1
        status            = $status
        engine_profile    = 'static_only'
        exit_code         = $exitCode
        manifest_sha256   = $manifestSha
        samples_extracted = $samplesExtracted
        hash_mismatches   = $hashMismatches
        started_utc       = $startedUtc
        finished_utc      = $finishedUtc
        error             = $errorDetail
    }
    $doneJson = $doneObj | ConvertTo-Json -Depth 6
    $doneTmp = Join-Path $OutDir 'DONE.json.tmp'
    $doneFinal = Join-Path $OutDir 'DONE.json'
    try {
        Write-Utf8NoBom -Path $doneTmp -Content $doneJson
        Move-Item -LiteralPath $doneTmp -Destination $doneFinal -Force
    } catch {
        Write-LabLog "Failed writing DONE.json: $($_.Exception.Message)"
    }
    if ($autoShutdown) {
        try { & shutdown.exe /s /t 2 /f | Out-Null } catch { }
    }
}

exit $exitCode
