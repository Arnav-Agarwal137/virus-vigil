# Virus Vigil - which apps used the camera and microphone, and when. READ-ONLY, no admin.
# Windows keeps this per app under CapabilityAccessManager\ConsentStore (HKCU): LastUsedTimeStart /
# LastUsedTimeStop are FILETIMEs; Start set with Stop = 0 means the app is using it RIGHT NOW.
# Desktop programs sit under "NonPackaged" with their path written using # instead of \.
# NOT every user is logged: a program recording the mic directly (ffmpeg dshow, 24 Sep) left no entry.
# Test mode: $env:VV_CAMERA_CASES = a JSON file {masters:{webcam,microphone}, webcam:[..], microphone:[..]},
# each case {key, packaged, start, stop, value} with raw FILETIMEs, judged INSTEAD of the registry.
# Output: one JSON line. ASCII only.
$ErrorActionPreference = 'Stop'
$base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
$out = [ordered]@{ ok = $true; devices = @(); error = $null }

function ConvertFrom-FileTimeSafe($v) {
    if ($null -eq $v) { return $null }
    try { $n = [int64]$v } catch { return $null }
    if ($n -le 0) { return $null }
    try { return [DateTime]::FromFileTimeUtc($n).ToString('o') } catch { return $null }
}

# One app's record. $keyName = the registry key name (for desktop programs: the path with # for \).
function Get-Use([string]$keyName, [bool]$packaged, $startRaw, $stopRaw, $value) {
    $start = ConvertFrom-FileTimeSafe $startRaw
    if (-not $start) { return $null }   # allowed but never used: nothing to report
    $stop = ConvertFrom-FileTimeSafe $stopRaw
    $name = $keyName
    $path = $null
    if (-not $packaged) { $path = $keyName -replace '#', '\'; $name = [IO.Path]::GetFileName($path) }
    $exists = $null; $signed = $null
    if ($path) {
        $exists = [bool](Test-Path -LiteralPath $path)
        if ($exists) { try { $signed = (Get-AuthenticodeSignature -LiteralPath $path).Status.ToString() } catch { $signed = $null } }
    }
    [ordered]@{
        name = $name; path = $path; packaged = $packaged
        lastStart = $start; lastStop = $stop
        inUse = ($null -eq $stop) -or ([int64]$stopRaw -lt [int64]$startRaw)
        allowed = [string]$value; signature = $signed; exists = $exists
    }
}

function Add-Device([string]$dev, [bool]$read, $master, $apps) {
    $out.devices += [ordered]@{ device = $dev; read = $read; allowedForApps = if ($read) { [string]$master } else { $null }; apps = @($apps | Sort-Object { $_.lastStart } -Descending) }
}

try {
    if ($env:VV_CAMERA_CASES) {
        # Assigned first: PowerShell 5.1 passes a JSON array down the pipe as ONE object.
        $cases = Get-Content -Raw -LiteralPath $env:VV_CAMERA_CASES | ConvertFrom-Json
        foreach ($dev in 'webcam', 'microphone') {
            $apps = @()
            foreach ($c in @($cases.$dev)) { if ($c) { $r = Get-Use ([string]$c.key) ([bool]$c.packaged) $c.start $c.stop $c.value; if ($r) { $apps += $r } } }
            Add-Device $dev $true $cases.masters.$dev $apps
        }
    } else {
        foreach ($dev in 'webcam', 'microphone') {
            $root = Join-Path $base $dev
            if (-not (Test-Path -LiteralPath $root)) { Add-Device $dev $false $null @(); continue }
            $apps = @()
            $master = (Get-ItemProperty -LiteralPath $root -ErrorAction SilentlyContinue).Value
            $keys = @()
            foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                if ($k.PSChildName -eq 'NonPackaged') {
                    foreach ($n in @(Get-ChildItem -LiteralPath $k.PSPath -ErrorAction SilentlyContinue)) { $keys += , @($n, $false) }
                } else { $keys += , @($k, $true) }
            }
            foreach ($pair in $keys) {
                $p = Get-ItemProperty -LiteralPath $pair[0].PSPath -ErrorAction SilentlyContinue
                if (-not $p) { continue }
                $r = Get-Use $pair[0].PSChildName $pair[1] $p.LastUsedTimeStart $p.LastUsedTimeStop $p.Value
                if ($r) { $apps += $r }
            }
            Add-Device $dev $true $master $apps
        }
    }
} catch {
    $out.ok = $false; $out.error = $_.Exception.Message
}
$out | ConvertTo-Json -Depth 6 -Compress
