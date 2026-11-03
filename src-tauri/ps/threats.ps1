# Virus Vigil - read-only: every threat Windows Defender has recorded on this PC.
# ASCII only. Prints ONE JSON object.
$ErrorActionPreference = 'SilentlyContinue'

$names = @{}
foreach ($t in @(Get-MpThreat)) {
    $names[[string]$t.ThreatID] = [ordered]@{
        name = [string]$t.ThreatName
        severity = [int]$t.SeverityID
        category = [int]$t.CategoryID
        active = [bool]$t.IsActive
    }
}

$actionText = @{ 0 = 'Unknown'; 1 = 'Cleaned'; 2 = 'Quarantined'; 3 = 'Removed'; 4 = 'Allowed'; 5 = 'User defined'; 6 = 'No action'; 8 = 'Blocked'; 9 = 'Blocked'; 10 = 'Blocked' }

# 31 Oct 2026: a failed read used to print ok=$true with no items, which the page recorded as
# "found nothing". Now a failure says so (ok=$false). "No MSFT_... objects found" means an empty
# history, not a failure.
$ok = $true; $err = $null
try { $det = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending) }
catch {
    $det = @()
    if ([string]$_.Exception.Message -notmatch 'No MSFT_') { $ok = $false; $err = [string]$_.Exception.Message }
}
if ($env:VV_TEST_THREATS_FAIL -eq '1') { $ok = $false; $err = 'test: forced failure'; $det = @() }

$items = @()
foreach ($d in $det) {
    $id = [string]$d.ThreatID
    $info = $names[$id]
    $items += [ordered]@{
        id = $id
        name = if ($info) { $info.name } else { $null }
        severity = if ($info) { $info.severity } else { $null }
        active = if ($info) { $info.active } else { $false }
        found = if ($d.InitialDetectionTime) { $d.InitialDetectionTime.ToString('o') } else { $null }
        lastSeen = if ($d.LastThreatStatusChangeTime) { $d.LastThreatStatusChangeTime.ToString('o') } else { $null }
        action = $actionText[[int]$d.CleaningActionID]
        resources = @($d.Resources | ForEach-Object { [string]$_ })
        process = [string]$d.ProcessName
        success = [bool]$d.ActionSuccess
    }
}

[ordered]@{ ok = $ok; error = $err; items = $items } | ConvertTo-Json -Depth 5 -Compress
