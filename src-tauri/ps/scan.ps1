# Virus Vigil - read-only system check. Prints ONE JSON object. Changes nothing.
# ASCII only (Windows PowerShell 5.1 reads BOM-less files as ANSI).
$ErrorActionPreference = 'SilentlyContinue'

function Get-RegValue($path, $name) {
    $v = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $v) { return $null }
    return $v.$name
}

function Get-PolicyValue($subKey, $name) {
    # Machine policy wins over user policy, as in the browsers themselves.
    $m = Get-RegValue ("HKLM:\SOFTWARE\Policies\" + $subKey) $name
    if ($null -ne $m) { return @{ value = $m; scope = 'machine' } }
    $u = Get-RegValue ("HKCU:\SOFTWARE\Policies\" + $subKey) $name
    if ($null -ne $u) { return @{ value = $u; scope = 'user' } }
    return @{ value = $null; scope = $null }
}

function Find-FirstPath($paths) {
    foreach ($p in $paths) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
    return $null
}

$pf = $env:ProgramFiles
$pf86 = ${env:ProgramFiles(x86)}
$lad = $env:LOCALAPPDATA

$out = [ordered]@{ ok = $true; time = (Get-Date).ToString('o') }

# --- Defender ---
$s = Get-MpComputerStatus
if ($s) {
    $out.defender = [ordered]@{
        available = $true
        realTime = [bool]$s.RealTimeProtectionEnabled
        tamper = [bool]$s.IsTamperProtected
        mode = [string]$s.AMRunningMode
        signatureAgeDays = [int]$s.AntivirusSignatureAge
        lastQuickScan = if ($s.QuickScanEndTime) { $s.QuickScanEndTime.ToString('o') } else { $null }
        lastFullScan = if ($s.FullScanEndTime) { $s.FullScanEndTime.ToString('o') } else { $null }
    }
} else {
    $out.defender = [ordered]@{ available = $false }
}
$pref = Get-MpPreference
if ($pref) {
    $out.defender.puaBlock = ($pref.PUAProtection -eq 1)
    $out.defender.networkProtection = [int]$pref.EnableNetworkProtection
    $out.defender.asrRules = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ }).Count
}

# --- Firewall ---
$fw = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } })
$out.firewall = $fw

# --- SmartScreen (apps and files) ---
$ssPolicy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
$ssLevel = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
$ssUser = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
$out.smartscreen = [ordered]@{ policy = $ssPolicy; level = $ssLevel; setting = $ssUser }

# --- UAC ---
$out.uac = [ordered]@{
    enabled = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    adminPrompt = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
}

# --- Windows Update: newest installed update ---
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$out.lastUpdate = if ($hf) { $hf.InstalledOn.ToString('o') } else { $null }

# --- Browsers ---
$browsers = @()

$chrome = Find-FirstPath @("$pf\Google\Chrome\Application\chrome.exe", "$pf86\Google\Chrome\Application\chrome.exe", "$lad\Google\Chrome\Application\chrome.exe")
$browsers += [ordered]@{
    id = 'chrome'; name = 'Google Chrome'; installed = [bool]$chrome; path = $chrome; kind = 'chromium'
    safeBrowsing = Get-PolicyValue 'Google\Chrome' 'SafeBrowsingProtectionLevel'
    downloads = Get-PolicyValue 'Google\Chrome' 'DownloadRestrictions'
    passwords = Get-PolicyValue 'Google\Chrome' 'PasswordManagerEnabled'
    doh = Get-PolicyValue 'Google\Chrome' 'DnsOverHttpsMode'
}

$edge = Find-FirstPath @("$pf86\Microsoft\Edge\Application\msedge.exe", "$pf\Microsoft\Edge\Application\msedge.exe")
$browsers += [ordered]@{
    id = 'edge'; name = 'Microsoft Edge'; installed = [bool]$edge; path = $edge; kind = 'edge'
    safeBrowsing = Get-PolicyValue 'Microsoft\Edge' 'SmartScreenEnabled'
    safeBrowsingPua = Get-PolicyValue 'Microsoft\Edge' 'SmartScreenPuaEnabled'
    downloads = Get-PolicyValue 'Microsoft\Edge' 'DownloadRestrictions'
    passwords = Get-PolicyValue 'Microsoft\Edge' 'PasswordManagerEnabled'
    doh = Get-PolicyValue 'Microsoft\Edge' 'DnsOverHttpsMode'
}

$brave = Find-FirstPath @("$pf\BraveSoftware\Brave-Browser\Application\brave.exe", "$pf86\BraveSoftware\Brave-Browser\Application\brave.exe", "$lad\BraveSoftware\Brave-Browser\Application\brave.exe")
$browsers += [ordered]@{
    id = 'brave'; name = 'Brave'; installed = [bool]$brave; path = $brave; kind = 'chromium'
    safeBrowsing = Get-PolicyValue 'BraveSoftware\Brave' 'SafeBrowsingProtectionLevel'
    downloads = Get-PolicyValue 'BraveSoftware\Brave' 'DownloadRestrictions'
    passwords = Get-PolicyValue 'BraveSoftware\Brave' 'PasswordManagerEnabled'
    doh = Get-PolicyValue 'BraveSoftware\Brave' 'DnsOverHttpsMode'
}

$ffDir = $null
$ff = Find-FirstPath @("$pf\Mozilla Firefox\firefox.exe", "$pf86\Mozilla Firefox\firefox.exe")
$ffPolicy = $null
if ($ff) {
    $ffDir = Split-Path $ff
    $pj = Join-Path $ffDir 'distribution\policies.json'
    if (Test-Path -LiteralPath $pj) {
        try { $ffPolicy = (Get-Content -LiteralPath $pj -Raw | ConvertFrom-Json).policies } catch { $ffPolicy = $null }
    }
}
$browsers += [ordered]@{
    id = 'firefox'; name = 'Firefox'; installed = [bool]$ff; path = $ff; kind = 'firefox'
    doh = if ($ffPolicy -and $ffPolicy.DNSOverHTTPS) { [bool]$ffPolicy.DNSOverHTTPS.Enabled } else { $null }
    passwords = if ($ffPolicy -and ($null -ne $ffPolicy.PasswordManagerEnabled)) { [bool]$ffPolicy.PasswordManagerEnabled } else { $null }
    hasPolicyFile = [bool]$ffPolicy
}

$opera = Find-FirstPath @("$lad\Programs\Opera\opera.exe", "$lad\Programs\Opera GX\opera.exe", "$pf\Opera\opera.exe")
$browsers += [ordered]@{ id = 'opera'; name = 'Opera'; installed = [bool]$opera; path = $opera; kind = 'guide' }

$out.browsers = $browsers

# --- Past threats (count only here; details come from threats.ps1) ---
# A failed read is $null ("not read"), never 0 ("caught nothing") - 31 Oct 2026.
try { $out.threatCount = @(Get-MpThreatDetection -ErrorAction Stop).Count }
catch { $out.threatCount = if ([string]$_.Exception.Message -match 'No MSFT_') { 0 } else { $null } }

$out | ConvertTo-Json -Depth 6 -Compress
