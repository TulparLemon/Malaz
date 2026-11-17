#requires -Version 5.1
<#
.SYNOPSIS
  Orchestriert den isolierten Realwelt-Lauf (Hyper-V) oder seinen Trockenlauf.

.DESCRIPTION
  -DryRun  erzeugt ausschliesslich synthetische Fixtures, scannt sie mit
           abgeschalteten AV-Engines und wertet sie aus. Kein Hyper-V, keine
           echte Probe, kein Netzwerk. Der Guard laeuft mit simuliertem,
           sauberem Zustand und muss PASSIEREN.

  Ohne -DryRun wird eine vorhandene Hyper-V-VM aus einem kalten Checkpoint
  gestartet, eine read-only ISO eingebunden, Malaz per PowerShell Direct
  ausgefuehrt und das Ergebnis zurueckgeholt. Jeder Vorbedingungsfehler bricht
  VOR der ersten Aenderung ab (fail-closed).

  Die volle Hyper-V-Strecke ist auf diesem Entwicklungsrechner nicht
  ausfuehrbar (keine Hyper-V-Rolle). Verifiziert ist der -DryRun-Pfad; die
  Hyper-V-Schritte sind defensiv und mit expliziten Vorbedingungen geschrieben.

.PARAMETER VmName
  Hyper-V-VM (Analyzer). Im DryRun nur ein Name fuer den simulierten Guard.

.PARAMETER CheckpointName
  Kalter Checkpoint, auf den zurueckgerollt wird.

.PARAMETER IsoPath
  Read-only ISO mit Malaz + Fixturen. Wird als DVD eingebunden.

.PARAMETER ResultPath
  Ziel-CSV (oder Verzeichnis). Report-JSON/Markdown entstehen daneben.

.PARAMETER MalazExe
  Pfad zu Malaz.exe INNERHALB der VM (Default C:\lab\Malaz.exe).

.PARAMETER ManifestPath / ManifestSha256
  Manifest und dessen erwarteter Datei-Hash. Ohne beides kein Lauf.

.PARAMETER ResultVhdPath
  Optional: bereits formatierte VHDX fuer die Ergebnisablage. Die Datei muss
  existieren; sie wird NICHT erzeugt oder formatiert (kein Datenverlust).

.PARAMETER Force
  Entfernt ein vorhandenes DVD-Laufwerk der VM, bevor die ISO eingebunden wird.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_lab.ps1 -DryRun

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_lab.ps1 `
    -VmName Malaz-Analyzer -CheckpointName clean -IsoPath D:\lab\malaz-lab.iso `
    -ManifestPath D:\lab\manifest.json -ManifestSha256 ABCD...
#>
[CmdletBinding()]
param(
    [string]$VmName = "Malaz-Analyzer",
    [string]$CheckpointName = "clean",
    [string]$IsoPath = "",
    [string]$ResultPath = "",
    [string]$MalazExe = "C:\lab\Malaz.exe",
    [switch]$DryRun,
    [string]$ManifestPath = "",
    [string]$ManifestSha256 = "",
    [string]$WorkDir = "",
    [string]$ResultVhdPath = "",
    [string]$GuestResultDir = "",
    [string]$GuestKnownBadDir = "C:\lab\in",
    [string]$GuestKnownGoodDir = "C:\lab\good",
    [System.Management.Automation.PSCredential]$Credential = $null,
    [int]$TimeoutMinutes = 120,
    [switch]$KeepRunning,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Jeder Abbruch laeuft durch diesen Trap. Wichtig fuer die Sicherheit: ein
# Fehler NACH dem VM-Start muss die finally-Bloecke (Stopp + Rollback) noch
# ausfuehren. Ein direktes 'exit' wuerde sie ueberspringen.
trap {
    [Console]::Error.WriteLine("run_lab: " + $_.Exception.Message)
    exit 1
}

$Repo = Split-Path -Parent $PSScriptRoot

function Fail {
    param([string]$Message)
    throw $Message
}

function Resolve-Python {
    if ($env:MALAZ_PYTHON) {
        if (Test-Path -LiteralPath $env:MALAZ_PYTHON -PathType Leaf) {
            return $env:MALAZ_PYTHON
        }
        Fail "MALAZ_PYTHON zeigt auf keine Datei: $env:MALAZ_PYTHON"
    }
    $venv = Join-Path $Repo ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) { return $venv }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    Fail "Kein Python gefunden (MALAZ_PYTHON setzen oder .venv anlegen)."
}

function Resolve-ResultCsv {
    param([string]$Path, [string]$DefaultDir)
    if (-not $Path) {
        return (Join-Path $DefaultDir "results.csv")
    }
    if (Test-Path -LiteralPath $Path -PathType Container) {
        return (Join-Path $Path "results.csv")
    }
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    return $Path
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Hash {
    param([string]$Path, [string]$Expected)
    if (-not $Expected) { Fail "ManifestSha256 fehlt (Chain of Custody)." }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "Manifest fehlt: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual.ToLowerInvariant() -ne $Expected.ToLowerInvariant()) {
        Fail "Manifest-Hash weicht ab (ist $actual) -- Abbruch vor jeder Aktion."
    }
}

# --------------------------------------------------------------------------- #
# Dry run: synthetische Fixtures, simulierter Guard, echte Auswertung.
# --------------------------------------------------------------------------- #
if ($DryRun) {
    $python = Resolve-Python
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not $WorkDir) {
        $WorkDir = Join-Path $env:TEMP ("malaz_lab_dryrun_" + $stamp)
    }
    $WorkDir = [IO.Path]::GetFullPath($WorkDir)
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $runDir = Join-Path $WorkDir "run"
    $outDir = Join-Path $WorkDir "out"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    if (@(Get-ChildItem -LiteralPath $outDir -Force).Count -gt 0) {
        Fail "Ausgabeordner ist nicht leer: $outDir"
    }

    $resultCsv = Resolve-ResultCsv $ResultPath $outDir
    if (Test-Path -LiteralPath $resultCsv -PathType Leaf) {
        Fail "Ergebnis existiert bereits (kein stilles Ueberschreiben): $resultCsv"
    }
    $reportJson = [IO.Path]::ChangeExtension($resultCsv, ".report.json")
    $reportMd = [IO.Path]::ChangeExtension($resultCsv, ".report.md")
    $summaryPath = [IO.Path]::ChangeExtension($resultCsv, ".summary.json")

    & $python (Join-Path $Repo "scripts\lab_dryrun.py") --work-dir $runDir --overwrite
    if ($LASTEXITCODE -ne 0) { Fail "lab_dryrun.py fehlgeschlagen (Exit $LASTEXITCODE)." }

    $manifest = Join-Path $runDir "dryrun_manifest.json"
    $manifestHash = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash

    # Simulierter, sauberer Analyzer-Zustand. Der Guard muss trotzdem alle
    # Felder pruefen -- kein Kurzschluss, kein "DryRun = skip".
    $statePath = Join-Path $WorkDir "dryrun_guard_state.json"
    $state = [ordered]@{
        adapters          = @()
        default_routes    = @()
        dns_servers       = @()
        dns_resolves      = $false
        shared_folders    = @()
        clipboard_text    = ""
        drag_and_drop     = $false
        enhanced_session  = $false
        drive_redirection = $false
        usb_storage       = @()
        is_admin          = $false
        vm_name           = $VmName
        vm_state          = "Off"
        checkpoint        = $CheckpointName
        eicar             = "detected"
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding ASCII

    $guardJson = Join-Path $WorkDir "guard.json"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $Repo "scripts\lab_guard.ps1") `
        -StatePath $statePath -ManifestPath $manifest -ManifestSha256 $manifestHash `
        -OutputDir $outDir -VmName $VmName -CheckpointName $CheckpointName `
        -JsonOut $guardJson | Out-Null
    $guardCode = $LASTEXITCODE
    if (-not (Test-Path -LiteralPath $guardJson -PathType Leaf)) {
        Fail "Guard hat kein JSON geschrieben (Exit $guardCode)."
    }
    $guard = Get-Content -LiteralPath $guardJson -Raw | ConvertFrom-Json
    if ($guardCode -ne 0 -or -not $guard.ok) {
        Fail "Guard fehlgeschlagen (Exit $guardCode) -- kein Scan."
    }

    & $python (Join-Path $Repo "scripts\realworld_report.py") `
        $manifest (Join-Path $runDir "dryrun_results.csv") `
        --json $reportJson --markdown $reportMd
    if ($LASTEXITCODE -ne 0) { Fail "realworld_report.py fehlgeschlagen (Exit $LASTEXITCODE)." }

    if ([IO.Path]::GetFullPath($resultCsv) -ne [IO.Path]::GetFullPath((Join-Path $runDir "dryrun_results.csv"))) {
        Copy-Item -LiteralPath (Join-Path $runDir "dryrun_results.csv") -Destination $resultCsv -Force
    }

    $summary = [ordered]@{
        mode              = "dry-run"
        ok                = $true
        vm_name           = $VmName
        checkpoint        = $CheckpointName
        work_dir          = $WorkDir
        manifest          = $manifest
        manifest_sha256   = $manifestHash
        results_csv       = $resultCsv
        report_json       = $reportJson
        report_markdown   = $reportMd
        guard_ok          = $guard.ok
        synthetic_only    = $true
        hyperv_touched    = $false
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding ASCII
    Write-Output ($summary | ConvertTo-Json -Depth 6)
    Write-Output "OK: Trockenlauf abgeschlossen (keine echte Probe, keine VM)."
    exit 0
}

# --------------------------------------------------------------------------- #
# Real run: Hyper-V. Every precondition is checked before a single change.
# --------------------------------------------------------------------------- #
if (-not (Test-IsAdmin)) {
    Fail "Hyper-V-Orchestrierung braucht Adminrechte (Guard im Gast prueft getrennt)."
}
if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    Fail "Hyper-V-Modul nicht verfuegbar -- diese Maschine kann den Lauf nicht orchestrieren."
}
if (-not $IsoPath -or -not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
    Fail "IsoPath fehlt oder existiert nicht: '$IsoPath'"
}
if (-not $ManifestPath) { Fail "ManifestPath fehlt." }
Assert-Hash -Path $ManifestPath -Expected $ManifestSha256
if ($ResultVhdPath -and $KeepRunning) {
    Fail "-KeepRunning und -ResultVhdPath schliessen sich aus (VHD muss nach dem Stopp gelesen werden)."
}
if ($ResultVhdPath -and -not (Test-Path -LiteralPath $ResultVhdPath -PathType Leaf)) {
    Fail "ResultVhdPath existiert nicht. Die VHD wird bewusst NICHT erzeugt/formatiert: $ResultVhdPath"
}
if ($ResultVhdPath -and -not $GuestResultDir) {
    Fail "ResultVhdPath braucht -GuestResultDir (Laufwerkswurzel der VHD im Gast, z.B. E:\)."
}
if ($ResultVhdPath -and $GuestResultDir -notmatch '^[A-Za-z]:\\?$') {
    Fail "-GuestResultDir muss bei -ResultVhdPath eine Laufwerkswurzel sein (z.B. E:\), damit der Host <Laufwerk>:\\results.csv findet."
}

$vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if (-not $vm) { Fail "VM nicht gefunden: $VmName" }
$snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
if (-not $snapshot) { Fail "Checkpoint nicht gefunden: $VmName / $CheckpointName" }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $WorkDir) {
    $WorkDir = Join-Path $env:TEMP ("malaz_lab_run_" + $stamp)
}
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$resultCsv = Resolve-ResultCsv $ResultPath $WorkDir
if (Test-Path -LiteralPath $resultCsv -PathType Leaf) {
    Fail "Ergebnis existiert bereits (kein stilles Ueberschreiben): $resultCsv"
}
$reportJson = [IO.Path]::ChangeExtension($resultCsv, ".report.json")
$reportMd = [IO.Path]::ChangeExtension($resultCsv, ".report.md")
$summaryPath = [IO.Path]::ChangeExtension($resultCsv, ".summary.json")

$vdhAttached = $false
$vhdDrive = $null
$session = $null
$vhdMounted = $false
try {
    Write-Output "1/6 Kalter Checkpoint wird zurueckgerollt ..."
    Restore-VMSnapshot -VMName $VmName -Name $CheckpointName -Confirm:$false

    $dvd = @(Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue)
    if ($dvd.Count -gt 0) {
        if (-not $Force) {
            Fail "VM hat bereits ein DVD-Laufwerk. -Force entfernt es (bewusste Bestaetigung noetig)."
        }
        foreach ($drive in $dvd) {
            Remove-VMDvdDrive -VMName $VmName `
                -ControllerNumber $drive.ControllerNumber `
                -ControllerLocation $drive.ControllerLocation -Confirm:$false
        }
    }
    Add-VMDvdDrive -VMName $VmName -Path $IsoPath | Out-Null
    Write-Output "2/6 Read-only ISO eingebunden: $IsoPath"

    if ($ResultVhdPath) {
        $vhdDrive = Add-VMHardDiskDrive -VMName $VmName -Path $ResultVhdPath -Passthru
        $vdhAttached = $true
    }

    Start-VM -Name $VmName
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        Start-Sleep -Seconds 2
        $vm = Get-VM -Name $VmName
        $heartbeat = [string]$vm.Heartbeat
    } while (
        $heartbeat -notin @('OkApplicationsHealthy', 'OkApplicationsUnknown') -and
        (Get-Date) -lt $deadline
    )
    if ($heartbeat -notin @('OkApplicationsHealthy', 'OkApplicationsUnknown')) {
        Fail "VM-Heartbeat nach $TimeoutMinutes Minuten nicht bereit: $heartbeat"
    }
    Write-Output "3/6 VM laeuft (Heartbeat $heartbeat)."

    $sessionArgs = @{ VMName = $VmName }
    if ($Credential) { $sessionArgs.Credential = $Credential }
    $session = New-PSSession @sessionArgs

    $guestOut = if ($GuestResultDir) { $GuestResultDir } else { "C:\lab\out" }
    Invoke-Command -Session $session -ScriptBlock {
        param($exe, $bad, $good, $out)
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        & $exe --evaluate $bad $good `
            --csv (Join-Path $out "results.csv") `
            --report (Join-Path $out "results.html")
        if ($LASTEXITCODE -ne 0) {
            throw "Malaz --evaluate Exit $LASTEXITCODE"
        }
    } -ArgumentList $MalazExe, $GuestKnownBadDir, $GuestKnownGoodDir, $guestOut
    Write-Output "4/6 Malaz --evaluate im Gast beendet."

    if (-not $ResultVhdPath) {
        Copy-Item -FromSession $session `
            -Path (Join-Path $guestOut "results.csv") -Destination $resultCsv -Force
    }
}
finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if (-not $KeepRunning) {
        # Ein Rollback, der nicht nachweisbar war, darf NICHT als Erfolg
        # gemeldet werden: sonst ist die Isolationszusage still verletzt.
        $rollbackProblems = @()

        $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
        if ($vm -and $vm.State -ne 'Off') {
            try {
                Stop-VM -Name $VmName -Force -Confirm:$false -ErrorAction Stop
            } catch {
                $rollbackProblems += "Stop-VM: $($_.Exception.Message)"
            }
            # Stop-VM -Force ist asynchron; ein Restore gegen eine noch
            # laufende VM wuerde nur scheitern (oder schlimmer: nicht greifen).
            $offDeadline = (Get-Date).AddSeconds(60)
            do {
                Start-Sleep -Seconds 1
                $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
            } while ($vm -and $vm.State -ne 'Off' -and (Get-Date) -lt $offDeadline)
        }
        $stateText = if ($vm) { [string]$vm.State } else { 'unbekannt' }
        if (-not $vm -or $stateText -ne 'Off') {
            $rollbackProblems += "VM nicht Off (Zustand: $stateText)"
        }

        if ($vdhAttached -and $vhdDrive) {
            try {
                Remove-VMHardDiskDrive -VMName $VmName `
                    -ControllerType $vhdDrive.ControllerType `
                    -ControllerNumber $vhdDrive.ControllerNumber `
                    -ControllerLocation $vhdDrive.ControllerLocation `
                    -ErrorAction Stop
            } catch {
                $rollbackProblems += "Remove-VMHardDiskDrive: $($_.Exception.Message)"
            }
        }

        if ($stateText -eq 'Off') {
            try {
                Restore-VMSnapshot -VMName $VmName -Name $CheckpointName `
                    -Confirm:$false -ErrorAction Stop
            } catch {
                $rollbackProblems += "Restore-VMSnapshot: $($_.Exception.Message)"
            }
        }

        if ($rollbackProblems.Count -gt 0) {
            [Console]::Error.WriteLine(
                "run_lab: ROLLBACK FEHLGESCHLAGEN: " + ($rollbackProblems -join " | ")
            )
            [Console]::Error.WriteLine(
                "run_lab: VM NICHT als sauber freigeben -- manuell pruefen und zuruecksetzen."
            )
            exit 1
        }
        Write-Output "5/6 VM gestoppt und Checkpoint zurueckgerollt."
    }
}

if ($ResultVhdPath) {
    # Read-only mount: the result volume is never modified on the host.
    $disk = Mount-VHD -Path $ResultVhdPath -ReadOnly -Passthru
    try {
        $volume = Get-Disk -Number $disk.Number |
            Get-Partition | Get-Volume |
            Where-Object { $_.DriveLetter } |
            Select-Object -First 1
        if (-not $volume) { Fail "Keine Partition mit Laufwerksbuchstaben in $ResultVhdPath." }
        Copy-Item -LiteralPath ("{0}:\results.csv" -f $volume.DriveLetter) `
            -Destination $resultCsv -Force
    } finally {
        Dismount-VHD -Path $ResultVhdPath
    }
}
if (-not (Test-Path -LiteralPath $resultCsv -PathType Leaf)) {
    Fail "Kein Ergebnis zurueckgeholt: $resultCsv"
}

$python = Resolve-Python
& $python (Join-Path $Repo "scripts\realworld_report.py") `
    $ManifestPath $resultCsv --json $reportJson --markdown $reportMd
if ($LASTEXITCODE -ne 0) { Fail "realworld_report.py fehlgeschlagen (Exit $LASTEXITCODE)." }

$summary = [ordered]@{
    mode            = "hyperv"
    ok              = $true
    vm_name         = $VmName
    checkpoint      = $CheckpointName
    iso             = $IsoPath
    manifest        = $ManifestPath
    manifest_sha256 = $ManifestSha256
    results_csv     = $resultCsv
    report_json     = $reportJson
    report_markdown = $reportMd
    result_vhd      = $ResultVhdPath
    synthetic_only  = $false
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding ASCII
Write-Output "6/6 Auswertung geschrieben: $reportMd"
Write-Output ($summary | ConvertTo-Json -Depth 6)
exit 0
