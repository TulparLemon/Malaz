#requires -Version 5.1
<#
.SYNOPSIS
  Fail-closed guard for the isolated Realwelt-Labor.

.DESCRIPTION
  Checks the ANALYZER environment before a sample run. Every check that cannot
  be determined counts as a FAILURE (fail-closed): a missing probe is not a
  passed probe. The result is JSON on stdout; exit code 1 if any check failed.

  Two modes:
    * live   - probes this machine (network, shares, clipboard, USB, Hyper-V).
    * state  - reads a simulated state JSON via -StatePath. This is how the
               logic is tested without Hyper-V and how a dry run demonstrates
               the gate. The state file is untrusted input: unknown fields are
               ignored, missing fields fail.

  No sample is opened. The optional EICAR probe writes the industry-standard
  harmless test string and observes whether Defender removes it.

.PARAMETER StatePath
  Simulated state JSON instead of live probes. Its fields:
  adapters, default_routes, dns_servers, dns_resolves, shared_folders,
  clipboard_text, drag_and_drop, enhanced_session, drive_redirection,
  usb_storage, is_admin, vm_name, vm_state, checkpoint, eicar.

.PARAMETER ManifestPath
  Path to the hash manifest. Combined with -ManifestSha256 this pins the
  corpus description before the run.

.PARAMETER ManifestSha256
  Expected SHA-256 of the manifest FILE (not of a sample).

.PARAMETER OutputDir
  Result directory. It must already exist and be empty.

.PARAMETER VmName / CheckpointName
  Expected Hyper-V VM and cold checkpoint names.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/lab_guard.ps1 `
    -StatePath state.json -ManifestPath m.json -ManifestSha256 ABCD... `
    -OutputDir C:\lab\out -VmName Malaz-Analyzer -CheckpointName clean
#>
[CmdletBinding()]
param(
    [string]$StatePath = "",
    [string]$ManifestPath = "",
    [string]$ManifestSha256 = "",
    [string]$OutputDir = "",
    [string]$VmName = "",
    [string]$CheckpointName = "",
    [switch]$SkipEicar,
    [string]$JsonOut = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Checks = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [string]$Id,
        [bool]$Passed,
        [string]$Detail
    )
    $status = if ($Passed) { 'pass' } else { 'fail' }
    [void]$script:Checks.Add([ordered]@{
        id     = $Id
        status = $status
        detail = $Detail
    })
}

function Get-StateValue {
    param($State, [string]$Name)
    if ($null -eq $State) { return $null }
    $property = $State.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $value = $property.Value
    # PowerShell unrolls arrays on return: an EMPTY JSON array would become
    # $null and look like "not determinable" (fail-closed would then reject a
    # perfectly clean state). The unary comma keeps arrays intact.
    if ($value -is [System.Array]) { return ,$value }
    return $value
}

function Test-EmptyArray {
    param($Value)
    if ($null -eq $Value) { return $false }   # not determinable -> caller fails
    if ($Value -is [System.Array]) { return ($Value.Count -eq 0) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return (@($Value).Count -eq 0)
    }
    return $false
}

function Format-Items {
    param($Value)
    if ($null -eq $Value) { return '' }
    $items = @($Value)
    if ($items.Count -eq 0) { return '' }
    return (($items | ForEach-Object { [string]$_ }) -join ', ')
}

function Get-LiveState {
    $state = [ordered]@{}

    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop |
            Where-Object {
                $_.Status -eq 'Up' -and
                $_.InterfaceDescription -notmatch 'Loopback'
            } |
            ForEach-Object {
                [ordered]@{ name = $_.Name; status = $_.Status }
            })
        $state.adapters = $adapters
    } catch { }

    try {
        $routes = @()
        foreach ($prefix in @('0.0.0.0/0', '::/0')) {
            $routes += @(Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
                ForEach-Object { "$($_.DestinationPrefix) via $($_.InterfaceAlias)" })
        }
        $state.default_routes = $routes
    } catch { }

    try {
        $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
            Where-Object { @($_.ServerAddresses).Count -gt 0 } |
            ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ',')" })
        $state.dns_servers = $dns
    } catch { }

    try {
        [void][System.Net.Dns]::GetHostEntry('example.com')
        $state.dns_resolves = $true
    } catch {
        $state.dns_resolves = $false
    }

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop |
            Where-Object { $_.Name -notin @('C$', 'ADMIN$', 'IPC$') } |
            ForEach-Object { $_.Name })
        $state.shared_folders = $shares
    } catch { }

    try {
        $clipboard = Get-Clipboard -Raw -ErrorAction Stop
        $state.clipboard_text = [string]$clipboard
    } catch { }

    try {
        $hostInfo = Get-VMHost -ErrorAction Stop
        $state.enhanced_session = [bool]$hostInfo.EnableEnhancedSessionMode
    } catch { }

    try {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        $state.vm_name = [string]$vm.Name
        $state.vm_state = [string]$vm.State
        $guest = @(Get-VMIntegrationService -VMName $VmName -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Guest Service Interface' })
        $state.drive_redirection = ($guest.Count -gt 0 -and $guest[0].Enabled)
        $state.drag_and_drop = ($state.enhanced_session -eq $true) -or ($state.drive_redirection -eq $true)
    } catch { }

    try {
        $snapshots = @(Get-VMSnapshot -VMName $VmName -ErrorAction Stop |
            Where-Object { $_.Name -eq $CheckpointName })
        if ($snapshots.Count -gt 0) { $state.checkpoint = $CheckpointName }
    } catch { }

    try {
        $usb = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
            Where-Object { $_.InterfaceType -eq 'USB' } |
            ForEach-Object { [string]$_.Model })
        $state.usb_storage = $usb
    } catch { }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $state.is_admin = $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    } catch { }

    if (-not $SkipEicar) {
        $eicar = -join (88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53,
            52, 40, 80, 94, 41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45,
            83, 84, 65, 78, 68, 65, 82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85, 83,
            45, 84, 69, 83, 84, 45, 70, 73, 76, 69, 33, 36, 72, 43, 72, 42)
        $probe = Join-Path $env:TEMP ('malaz_eicar_probe_' + [guid]::NewGuid().ToString('N') + '.com')
        try {
            [IO.File]::WriteAllText($probe, $eicar)
            Start-Sleep -Seconds 2
            if (Test-Path -LiteralPath $probe) {
                $state.eicar = 'none'
                Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            } else {
                $state.eicar = 'quarantined'
            }
        } catch {
            # Ein Schreibfehler allein sagt NICHTS ueber AV: volles TEMP,
            # fehlende Rechte und Laufwerksfehler landen im selben catch.
            # Gegenprobe mit harmlosem Inhalt in DERSELBEN Endung: geht die
            # durch, hat nur der EICAR-Inhalt gestoert (= AV). Geht auch sie
            # nicht, ist der Ordner/die Endung schreibunfaehig -> 'error',
            # KEIN AV-Nachweis.
            $control = Join-Path $env:TEMP ('malaz_control_probe_' + [guid]::NewGuid().ToString('N') + '.com')
            try {
                [IO.File]::WriteAllText($control, 'malaz control')
                Remove-Item -LiteralPath $control -Force -ErrorAction SilentlyContinue
                $state.eicar = 'blocked'
            } catch {
                $state.eicar = 'error'
            }
        }
    } else {
        $state.eicar = 'skip'
    }

    return [pscustomobject]$state
}

$source = if ($StatePath) { 'simulated' } else { 'live' }
if ($StatePath) {
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        Add-Check 'state' $false "State-Datei fehlt: $StatePath"
        $state = $null
    } else {
        try {
            $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
            Add-Check 'state' $true "simulierter Zustand: $StatePath"
        } catch {
            Add-Check 'state' $false "State-Datei nicht lesbar: $($_.Exception.Message)"
            $state = $null
        }
    }
} else {
    try {
        $state = Get-LiveState
        Add-Check 'state' $true 'Live-Abfrage abgeschlossen'
    } catch {
        Add-Check 'state' $false "Live-Abfrage fehlgeschlagen: $($_.Exception.Message)"
        $state = $null
    }
}

# -- Network ------------------------------------------------------------------
$adapters = Get-StateValue $state 'adapters'
if ($null -eq $adapters) {
    Add-Check 'network_offline' $false 'Netzwerkadapter nicht ermittelbar'
} else {
    $up = @($adapters | Where-Object {
        ($_.PSObject.Properties['status'] -and $_.status -eq 'Up') -or
        ($_.PSObject.Properties['Status'] -and $_.Status -eq 'Up')
    })
    Add-Check 'network_offline' ($up.Count -eq 0) `
        "aktive Adapter: $(Format-Items ($up | ForEach-Object { $_.name }))"
}

$routes = Get-StateValue $state 'default_routes'
if ($null -eq $routes) {
    Add-Check 'no_default_route' $false 'Standardrouten nicht ermittelbar'
} else {
    Add-Check 'no_default_route' (Test-EmptyArray $routes) `
        "Standardrouten: $(Format-Items $routes)"
}

$dnsServers = Get-StateValue $state 'dns_servers'
$dnsResolves = Get-StateValue $state 'dns_resolves'
if ($null -eq $dnsServers -or $null -eq $dnsResolves) {
    Add-Check 'dns_offline' $false 'DNS-Zustand nicht ermittelbar'
} else {
    $dnsOk = (Test-EmptyArray $dnsServers) -and ($dnsResolves -eq $false)
    Add-Check 'dns_offline' $dnsOk `
        "DNS-Server: $(Format-Items $dnsServers); Namensaufloesung: $dnsResolves"
}

# -- Host integration ---------------------------------------------------------
$shares = Get-StateValue $state 'shared_folders'
if ($null -eq $shares) {
    Add-Check 'no_shared_folders' $false 'Freigaben nicht ermittelbar'
} else {
    Add-Check 'no_shared_folders' (Test-EmptyArray $shares) `
        "Freigaben: $(Format-Items $shares)"
}

$clipboard = Get-StateValue $state 'clipboard_text'
if ($null -eq $clipboard) {
    Add-Check 'clipboard_clear' $false 'Zwischenablage nicht ermittelbar'
} else {
    $clear = ([string]$clipboard).Trim().Length -eq 0
    Add-Check 'clipboard_clear' $clear `
        $(if ($clear) { 'leer' } else { "Inhalt vorhanden ($(([string]$clipboard).Length) Zeichen)" })
}

$dragDrop = Get-StateValue $state 'drag_and_drop'
$enhanced = Get-StateValue $state 'enhanced_session'
$driveRedir = Get-StateValue $state 'drive_redirection'
if ($null -eq $dragDrop) {
    Add-Check 'no_drag_and_drop' $false 'Drag-and-Drop-Zustand nicht ermittelbar'
} else {
    $integrationOk = ($dragDrop -eq $false) -and
        ($null -ne $enhanced) -and ($enhanced -eq $false) -and
        ($null -ne $driveRedir) -and ($driveRedir -eq $false)
    Add-Check 'no_drag_and_drop' $integrationOk `
        "drag_and_drop=$dragDrop enhanced_session=$enhanced drive_redirection=$driveRedir"
}

$usb = Get-StateValue $state 'usb_storage'
if ($null -eq $usb) {
    Add-Check 'no_usb_storage' $false 'USB-Geraete nicht ermittelbar'
} else {
    Add-Check 'no_usb_storage' (Test-EmptyArray $usb) `
        "USB-Massenspeicher: $(Format-Items $usb)"
}

$isAdmin = Get-StateValue $state 'is_admin'
if ($null -eq $isAdmin) {
    Add-Check 'not_admin' $false 'Rechte nicht ermittelbar'
} else {
    Add-Check 'not_admin' ($isAdmin -eq $false) "is_admin=$isAdmin"
}

# -- VM identity --------------------------------------------------------------
$stateVm = Get-StateValue $state 'vm_name'
$stateCheckpoint = Get-StateValue $state 'checkpoint'
$stateVmState = Get-StateValue $state 'vm_state'
$expectedVm = if ($VmName) { $VmName } else { $null }
$expectedCheckpoint = if ($CheckpointName) { $CheckpointName } else { $null }
$identityOk = $false
$identityDetail = 'VM-/Snapshot-Name nicht ermittelbar'
if ($null -ne $stateVm) {
    $identityOk = ($expectedVm -ne $null) -and
        ($expectedCheckpoint -ne $null) -and
        ($stateVm -eq $expectedVm) -and
        ($stateCheckpoint -eq $expectedCheckpoint)
    $identityDetail = "vm='$stateVm' (erwartet '$expectedVm'), checkpoint='$stateCheckpoint' (erwartet '$expectedCheckpoint')"
    if ($null -ne $stateVmState) {
        $off = @('Off', 'Saved') -contains [string]$stateVmState
        $identityOk = $identityOk -and $off
        $identityDetail += ", state='$stateVmState' (erwartet Off/Saved)"
    } else {
        $identityOk = $false
        $identityDetail += ', VM-Zustand nicht ermittelbar'
    }
}
Add-Check 'vm_identity' $identityOk $identityDetail

# -- Manifest and output ------------------------------------------------------
if (-not $ManifestPath -or -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    Add-Check 'manifest_present' $false "Manifest fehlt: '$ManifestPath'"
} else {
    Add-Check 'manifest_present' $true $ManifestPath
}

if (-not $ManifestSha256) {
    Add-Check 'manifest_hash' $false 'Erwarteter Manifest-Hash fehlt (-ManifestSha256)'
} elseif (-not $ManifestPath -or -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    Add-Check 'manifest_hash' $false 'Manifest-Hash nicht pruefbar (Datei fehlt)'
} else {
    $actualHash = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
    $hashOk = $actualHash.ToLowerInvariant() -eq $ManifestSha256.ToLowerInvariant()
    Add-Check 'manifest_hash' $hashOk `
        $(if ($hashOk) { 'Hash stimmt' } else { "Hash weicht ab (ist $actualHash)" })
}

if (-not $OutputDir) {
    Add-Check 'output_dir_empty' $false 'Ausgabeordner fehlt (-OutputDir)'
} elseif (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    Add-Check 'output_dir_empty' $false "Ausgabeordner existiert nicht: $OutputDir"
} else {
    $content = @(Get-ChildItem -LiteralPath $OutputDir -Force)
    Add-Check 'output_dir_empty' ($content.Count -eq 0) `
        "Eintraege im Ausgabeordner: $($content.Count)"
}

# -- Optional AV liveness -----------------------------------------------------
$eicar = Get-StateValue $state 'eicar'
if ($SkipEicar) {
    Add-Check 'eicar_av_alive' $true 'uebersprungen (-SkipEicar): AV-Status unbekannt'
} elseif ($null -eq $eicar) {
    Add-Check 'eicar_av_alive' $false 'EICAR-Status nicht ermittelbar'
} elseif ([string]$eicar -eq 'error') {
    Add-Check 'eicar_av_alive' $false 'Schreibversuch fehlgeschlagen (auch Kontrollschreibversuch) - kein AV-Nachweis'
} else {
    $alive = @('blocked', 'detected', 'quarantined') -contains [string]$eicar
    Add-Check 'eicar_av_alive' $alive "Reaktion: $eicar"
}

$failed = @($script:Checks | Where-Object { $_.status -eq 'fail' })
$result = [ordered]@{
    ok           = ($failed.Count -eq 0)
    source       = $source
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    vm_name      = $VmName
    checkpoint   = $CheckpointName
    checks       = @($script:Checks)
}

$json = $result | ConvertTo-Json -Depth 8
if ($JsonOut) {
    $parent = Split-Path -Parent $JsonOut
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Set-Content -LiteralPath $JsonOut -Value $json -Encoding UTF8
}
Write-Output $json

if ($failed.Count -gt 0) {
    [Console]::Error.WriteLine(
        "lab_guard: {0} Pruefung(en) fehlgeschlagen (fail-closed)." -f $failed.Count
    )
    exit 1
}
exit 0
