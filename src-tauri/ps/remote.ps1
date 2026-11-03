# Virus Vigil - screen-sharing / remote-control programs running RIGHT NOW (B7, the check before
# a big payment). Read-only. The commonest UPI/bank scam in India: a "support" caller has the
# person install AnyDesk or TeamViewer, then watches the screen while they pay.
# A program in this list can let someone else SEE and CONTROL the screen. Running does not prove
# anyone is connected (TeamViewer and AnyDesk keep a background service), so the page says
# "running", never "someone is watching".
# Test mode: $env:VV_REMOTE_CASES = a JSON file [{name, path}], judged INSTEAD of Get-Process.
# Output: one JSON line. ASCII only.
$ErrorActionPreference = 'Stop'
$out = [ordered]@{ ok = $true; running = @(); checked = 0; error = $null }

# process name (lower case, no .exe) -> the program's name as people know it
$TOOLS = @{
    'anydesk' = 'AnyDesk'
    'teamviewer' = 'TeamViewer'; 'teamviewer_service' = 'TeamViewer'; 'tv_w32' = 'TeamViewer'; 'tv_x64' = 'TeamViewer'
    'rustdesk' = 'RustDesk'
    'ultraviewer_desktop' = 'UltraViewer'; 'ultraviewer_service' = 'UltraViewer'
    'aa_v3' = 'Ammyy Admin'
    'supremo' = 'Supremo'; 'supremoservice' = 'Supremo'
    'screenconnect.clientservice' = 'ScreenConnect'; 'screenconnect.windowsclient' = 'ScreenConnect'
    'quickassist' = 'Quick Assist'
    'msra' = 'Windows Remote Assistance'
    'remoting_host' = 'Chrome Remote Desktop'
    'airdroid' = 'AirDroid'
}

function Test-Proc([string]$name, [string]$path) {
    $key = $name.ToLower() -replace '\.exe$', ''
    if ($TOOLS.ContainsKey($key)) { return [ordered]@{ tool = $TOOLS[$key]; process = $key; path = $path } }
    return $null
}

try {
    $procs = @()
    if ($env:VV_REMOTE_CASES) {
        # Assigned first: PowerShell 5.1 passes a JSON array down the pipe as ONE object.
        $cases = Get-Content -Raw -LiteralPath $env:VV_REMOTE_CASES | ConvertFrom-Json
        foreach ($c in @($cases)) { if ($c) { $procs += [pscustomobject]@{ Name = [string]$c.name; Path = [string]$c.path } } }
    } else {
        foreach ($p in Get-Process) {
            $path = $null
            try { $path = $p.Path } catch { }
            $procs += [pscustomobject]@{ Name = $p.ProcessName; Path = $path }
        }
    }
    $out.checked = $procs.Count
    $seen = @{}
    foreach ($p in $procs) {
        $r = Test-Proc $p.Name $p.Path
        if ($r -and -not $seen.ContainsKey($r.process)) { $seen[$r.process] = $true; $out.running += $r }
    }
} catch {
    $out.ok = $false
    $out.error = [string]$_.Exception.Message
}
if ($out.checked -eq 0 -and $out.ok) { $out.ok = $false; $out.error = 'no programs could be listed' }
$out | ConvertTo-Json -Depth 5 -Compress
