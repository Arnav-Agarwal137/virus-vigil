# Virus Vigil - read-only: Defender's own record of its last scans and the engine it used.
# Shown under "What I checked" after a scan, and read while the full sweep runs.
# Defender records NO count of files scanned (event 1001 holds only the scan type and time),
# so none is printed - never invent one. ASCII only. Prints ONE JSON object.
$ErrorActionPreference = 'SilentlyContinue'
$s = Get-MpComputerStatus
$iso = { param($d) if ($d) { $d.ToString('o') } else { $null } }
$out = [ordered]@{
    read = [bool]$s
    quickStart = & $iso $s.QuickScanStartTime
    quickEnd = & $iso $s.QuickScanEndTime
    quickSigs = [string]$s.QuickScanSignatureVersion
    fullStart = & $iso $s.FullScanStartTime
    fullEnd = & $iso $s.FullScanEndTime
    fullSigs = [string]$s.FullScanSignatureVersion
    sigs = [string]$s.AntivirusSignatureVersion
    sigsUpdated = & $iso $s.AntivirusSignatureLastUpdated
    engine = [string]$s.AMEngineVersion
    realTime = [bool]$s.RealTimeProtectionEnabled
    # No "is a scan running" field: MpCmdRun also runs for definition updates, so a running one
    # proves nothing. Vigil follows its own scan by the process id it started.
    time = (Get-Date).ToString('o')
}
$out | ConvertTo-Json -Compress
