# --- Deeper checks (24 Sep 2026). Read-only, no admin. Sources: ideas/research/22-windows-checks.md ---
# Each value is raw; the page decides good/bad. $null = could not be read (the page then shows nothing,
# never "needs care", so an unreadable setting is not reported as a problem).

$extra = [ordered]@{}

# Other antivirus products Windows knows about. productState bit 0x1000 = real-time on,
# bit 0x10 = signatures out of date (community-decoded, see 22-windows-checks.md).
$av = @()
foreach ($p in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct)) {
    if ($p.displayName -match '^(Windows Defender|Microsoft Defender)') { continue }
    $st = [int]$p.productState
    $av += [ordered]@{ name = [string]$p.displayName; state = ('0x{0:X6}' -f $st); on = [bool]($st -band 0x1000); outOfDate = [bool]($st -band 0x10) }
}
$extra.otherAv = $av

# Accounts. PasswordRequired=False means Windows lets the account have NO password.
$guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
$extra.guestEnabled = if ($guest) { [bool]$guest.Enabled } else { $null }
$users = @(Get-LocalUser -ErrorAction SilentlyContinue)
$extra.accountsRead = $users.Count -gt 0
$extra.noPasswordAccounts = @($users | Where-Object { $_.Enabled -and -not $_.PasswordRequired -and $_.Name -ne 'Guest' } | ForEach-Object { [string]$_.Name })

# Old file-sharing protocol (WannaCry). Get-SmbServerConfiguration needs no admin.
$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$extra.smb1 = if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null }

# Remote control of this PC.
$extra.rdpDeny = Get-RegValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$extra.remoteAssist = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'

# File name endings hidden (invoice.pdf.exe trick). Windows default = 1 (hidden).
$hide = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt'
$extra.hideExt = if ($null -eq $hide) { 1 } else { [int]$hide }

# Hosts file: any line that is not a comment and not localhost.
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$extra.hostsRead = Test-Path -LiteralPath $hostsPath
$extra.hostsEntries = @()
if ($extra.hostsRead) {
    foreach ($line in Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        $parts = $l -split '\s+'
        $names = @($parts | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^(localhost|localhost\.localdomain|ip6-localhost|ip6-loopback)$' })
        if ($names.Count -gt 0) { $extra.hostsEntries += [ordered]@{ ip = $parts[0]; names = $names } }
    }
}

# System proxy (a sign of adware / traffic hijack when nobody set it on purpose).
$is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$extra.proxy = [ordered]@{ enabled = Get-RegValue $is 'ProxyEnable'; server = Get-RegValue $is 'ProxyServer'; pac = Get-RegValue $is 'AutoConfigURL' }

# Windows Update paused, restart waiting.
$ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$pause = @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime') | ForEach-Object { Get-RegValue $ux $_ } | Where-Object { $_ }
$extra.updatesPausedUntil = $null
foreach ($d in $pause) {
    $t = [datetime]::MinValue
    if ([datetime]::TryParse([string]$d, [ref]$t) -and $t -gt (Get-Date)) { $extra.updatesPausedUntil = $t.ToString('o') }
}
$extra.rebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')

# Defender cloud look-ups and sample sharing.
$mp = Get-MpPreference -ErrorAction SilentlyContinue
$extra.cloud = if ($mp) { [ordered]@{ maps = [int]$mp.MAPSReporting; samples = [int]$mp.SubmitSamplesConsent } } else { $null }
# Ransomware-safe folders (Controlled folder access). Not graded on the card: it blocks honest
# programs too, so the page explains it and leaves the choice to the person (B5).
$extra.cfa = if ($mp) { [int]$mp.EnableControlledFolderAccess } else { $null }

# Backups (B6, report only). OneDrive folder backup = Desktop / Documents / Pictures sit inside a
# SIGNED-IN OneDrive account's folder. Inside a OneDrive folder with no account signed in, they are
# copied nowhere - found on the owner's laptop 24 Sep (account unlinked, folders still redirected).
$usf = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
$folders = [ordered]@{}
foreach ($n in @('Desktop', 'Personal', 'My Pictures')) {
    $v = Get-RegValue $usf $n
    if ($v) { $folders[$n] = [Environment]::ExpandEnvironmentVariables([string]$v) }
}
$odAccounts = @()
Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue | ForEach-Object {
    $uf = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).UserFolder
    if ($uf) { $odAccounts += [ordered]@{ name = [string]$_.PSChildName; folder = [string]$uf } }
}
$extra.backup = [ordered]@{
    folders = $folders
    oneDriveAccounts = $odAccounts
    oneDriveRoots = @(@($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ } | Select-Object -Unique)
    oneDriveRunning = [bool](Get-Process -Name OneDrive -ErrorAction SilentlyContinue)
    # File History keeps its setup here once it is switched on. Community-known location, NOT in
    # Microsoft's docs (checked 24 Sep), so the page never says "no backup" on its absence alone.
    fileHistory = [bool](Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\Windows\FileHistory\Configuration" -Filter 'Config*.xml' -ErrorAction SilentlyContinue)
}

# Hardware-backed protections (read without admin).
$dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$extra.memoryIntegrity = if ($dg) { @($dg.SecurityServicesRunning) -contains 2 } else { $null }
$extra.lsaPpl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$extra.driverBlocklist = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
$extra.secureBoot = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'

# Defender's attack-blocking (ASR) rules, id -> action (0 off, 1 block, 2 watch only, 6 warn).
# Readable without admin. The benchmark (24 Sep): rule 01443614 "block rare/new/unsigned programs"
# is the one setting that would have stopped the 12 Sep fake-game installer on the owner's laptop.
$extra.asr = $null
if ($mp) {
    $asr = [ordered]@{}
    $ids = @($mp.AttackSurfaceReductionRules_Ids); $acts = @($mp.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $asr[([string]$ids[$i]).ToLower()] = [int]$acts[$i] } }
    $extra.asr = $asr
}
# Smart App Control: 0 off, 1 on, 2 evaluation. Where apps may come from: Anywhere / PreferStore / StoreOnly / Recommendations.
$extra.sac = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
$extra.appSource = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'AicEnabled'

# WMI hooks that RUN something when an event fires - a way malware survives restarts without a file
# in any start-up list. Windows' own "SCM Event Log Consumer" only writes to the event log. null = unreadable.
$extra.wmiHooks = $null
try {
    $extra.wmiHooks = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop |
        Where-Object { $_.CimClass.CimClassName -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer') } |
        ForEach-Object {
            $what = if ($_.CommandLineTemplate) { [string]$_.CommandLineTemplate } elseif ($_.ScriptFileName) { [string]$_.ScriptFileName } else { 'a script' }
            [ordered]@{ name = [string]$_.Name; kind = [string]$_.CimClass.CimClassName; runs = $what.Substring(0, [Math]::Min(200, $what.Length)) }
        })
} catch { }

# Services whose program sits in a folder ordinary programs can write to (user folders, AppData,
# Temp, ProgramData) AND has no valid signature. Signed ones there are normal (Defender, NVIDIA).
$extra.oddServices = $null
try {
    $extra.oddServices = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName -match '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\' } | ForEach-Object {
        $pn = [string]$_.PathName
        $exe = if ($pn -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($pn -match '^\s*(\S+\.exe)') { $Matches[1] } else { $pn }
        # A folder ordinary programs cannot even READ is not one they can write to: 'Unreadable' is
        # never reported. (Test-Path says False on "access denied" - it was mistaken for Missing, 24 Sep.)
        $sig = try { $null = Get-Item -LiteralPath $exe -ErrorAction Stop; [string](Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop).Status }
               catch [System.UnauthorizedAccessException] { 'Unreadable' }
               catch [System.Management.Automation.ItemNotFoundException] { 'Missing' }
               catch { 'Unreadable' }
        if ($sig -notin @('Valid', 'Unreadable')) { [ordered]@{ name = [string]$_.Name; display = [string]$_.DisplayName; path = $exe; state = [string]$_.State; signature = [string]$sig } }
    })
} catch { }

$out.extra = $extra
