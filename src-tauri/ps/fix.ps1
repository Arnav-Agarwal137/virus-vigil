# Virus Vigil - apply browser protections, or undo them. Runs ELEVATED (the app asks Windows first).
# ASCII only. Reads its plan from -Plan (a JSON file), writes the read-back result to -Out.
# Applying only ADDS or RAISES protection; it never deletes an existing policy. Every write first
# records what was there before (value + type, or "nothing"), so it can be put back exactly.
# Undo (plan.undo) restores those records - but ONLY for the keys and names this script itself
# writes, so an edited plan cannot be used to set anything else with admin rights.
# Defender attack-blocking (ASR) rules: only the four ids in $asrAllowed, only raised to Block, and a
# rule already at Block is not touched (so undo can never lower it). Set with Add-MpPreference, the
# local way Microsoft documents - NOT the policy registry, which could make Defender ignore local rules.
# -AsrStore (tests only) is a JSON file standing in for Defender, so the tests need no admin.
# -Root / -FirefoxDir exist for the test suite (a scratch HKCU key and folder, no admin needed);
# the app never passes them.
# Every file read names UTF-8: PowerShell 5.1 reads a BOM-less file as the ANSI code page, which
# turned an accented character in Firefox's policies.json into two (found by the undo test, 24 Sep).
param(
    [Parameter(Mandatory = $true)][string]$Plan,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Root = 'HKLM:\SOFTWARE\Policies',
    [string]$FirefoxDir = '',
    [string]$AsrStore = '',
    [string]$SysRoot = '',
    [string]$SysStore = ''
)
# Windows settings (plan.system, 7 Oct 2026 - "Do it all for me"): only the fix ids in $sysReg /
# $sysOther, each a fixed list of named values. A value already at a safe setting is not touched,
# so undo can never lower it. -SysRoot (tests) moves every HKLM / HKEY_USERS path under a scratch
# HKCU key; -SysStore (tests) is a JSON file standing in for Defender, the firewall, the Guest account
# and SMB1. Per-user values go to HKEY_USERS\<plan.userSid> - the person who pressed the button -
# because an elevated process's own HKCU can belong to a different (admin) account.
$ErrorActionPreference = 'Stop'

$result = [ordered]@{ ok = $true; mode = 'apply'; changes = @(); errors = @(); firefoxBefore = $null }

$allowed = @{
    'Google\Chrome'       = @('SafeBrowsingProtectionLevel', 'DownloadRestrictions', 'DnsOverHttpsMode', 'PasswordManagerEnabled', 'AutofillCreditCardEnabled')
    'BraveSoftware\Brave' = @('SafeBrowsingProtectionLevel', 'DownloadRestrictions', 'DnsOverHttpsMode', 'PasswordManagerEnabled', 'AutofillCreditCardEnabled')
    'Microsoft\Edge'      = @('SmartScreenEnabled', 'SmartScreenPuaEnabled', 'DownloadRestrictions', 'DnsOverHttpsMode', 'PasswordManagerEnabled', 'AutofillCreditCardEnabled')
}

$asrAllowed = @('01443614-cd74-433a-b99e-2ecdc07bfc25', '56a863a9-875e-4185-98a7-b882c64b5ce5', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'e6db77e5-3df2-4cf1-b95a-636979351e5b')
$asrNames = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }

function Get-AsrTable {
    $t = @{}
    if ($AsrStore) {
        if (Test-Path -LiteralPath $AsrStore) { (Get-Content -LiteralPath $AsrStore -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $t[$_.Name.ToLower()] = [int]$_.Value } }
        return $t
    }
    $mp = Get-MpPreference
    $ids = @($mp.AttackSurfaceReductionRules_Ids); $acts = @($mp.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $t[([string]$ids[$i]).ToLower()] = [int]$acts[$i] } }
    return $t
}
function Set-AsrRule($id, $action) {
    if ($AsrStore) { $t = Get-AsrTable; if ($null -eq $action) { $t.Remove($id) } else { $t[$id] = [int]$action }; [System.IO.File]::WriteAllText($AsrStore, ($t | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false))); return }
    if ($null -eq $action) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id }
    else { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $asrNames[[int]$action] }
}
function Get-AsrBefore($id) {
    $t = Get-AsrTable
    if ($t.ContainsKey($id)) { return [ordered]@{ existed = $true; value = $t[$id]; type = $null } }
    return [ordered]@{ existed = $false; value = $null; type = $null }
}

# What is there now: @{ existed; value; type } (type as New-ItemProperty spells it).
function Get-Before($path, $name) {
    if (-not (Test-Path -LiteralPath $path)) { return [ordered]@{ existed = $false; value = $null; type = $null } }
    $k = Get-Item -LiteralPath $path
    if ($k.GetValueNames() -notcontains $name) { return [ordered]@{ existed = $false; value = $null; type = $null } }
    $kind = $k.GetValueKind($name).ToString()
    $type = @{ DWord = 'DWord'; QWord = 'QWord'; String = 'String'; ExpandString = 'ExpandString'; MultiString = 'MultiString'; Binary = 'Binary' }[$kind]
    return [ordered]@{ existed = $true; value = $k.GetValue($name, $null, 'DoNotExpandEnvironmentNames'); type = $type }
}

function Set-Policy($subKey, $name, $value, $type) {
    $path = Join-Path $Root $subKey
    try {
        $before = Get-Before $path $name
        if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
        New-ItemProperty -LiteralPath $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
        $back = (Get-ItemProperty -LiteralPath $path -Name $name).$name
        $script:result.changes += [ordered]@{ where = $subKey; name = $name; wanted = $value; readBack = $back; ok = ([string]$back -eq [string]$value); before = $before }
    } catch {
        $script:result.errors += ("{0}\{1}: {2}" -f $subKey, $name, $_.Exception.Message)
    }
}

# Each item: path, value name, safe value ($null = remove the value), type, and a test saying the
# CURRENT state is already safe (then it is left alone). Paths use HKLM:\ or HKU:\ (resolved below).
$sysReg = [ordered]@{
    smartscreen = @(
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System', 'EnableSmartScreen', 1, 'DWord', { param($b) $b.existed -and [int]$b.value -eq 1 }),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System', 'ShellSmartScreenLevel', 'Warn', 'String', { param($b) $b.existed -and @('Warn', 'Block') -contains [string]$b.value }))
    uac = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA', 1, 'DWord', { param($b) $b.existed -and [int]$b.value -eq 1 }),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'ConsentPromptBehaviorAdmin', 5, 'DWord', { param($b) -not $b.existed -or [int]$b.value -ne 0 }))
    rdp = @(, @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections', 1, 'DWord', { param($b) $b.existed -and [int]$b.value -eq 1 }))
    assist = @(, @('HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance', 'fAllowToGetHelp', 0, 'DWord', { param($b) -not $b.existed -or [int]$b.value -ne 1 }))
    lsa = @(, @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 1, 'DWord', { param($b) $b.existed -and [int]$b.value -ge 1 }))
    drivers = @(, @('HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config', 'VulnerableDriverBlocklistEnable', 1, 'DWord', { param($b) -not $b.existed -or [int]$b.value -ne 0 }))
    pause = @('PauseUpdatesExpiryTime', 'PauseUpdatesStartTime', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime' |
        ForEach-Object { , @('HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings', $_, $null, $null, { param($b) -not $b.existed }) })
    ext = @(, @('HKU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'HideFileExt', 0, 'DWord', { param($b) $b.existed -and [int]$b.value -eq 0 }))
}
# Items that are not plain registry values: name, safe value, already-safe test.
$sysOther = [ordered]@{
    realtime = @(, @('mp:DisableRealtimeMonitoring', $false, { param($v) $v -eq $false }))
    cloud = @(, @('mp:MAPSReporting', 2, { param($v) [int]$v -ge 1 }))
    fw = @('Domain', 'Private', 'Public' | ForEach-Object { , @("fw:$_", $true, { param($v) $v -eq $true }) })
    guest = @(, @('guest:Enabled', $false, { param($v) $v -ne $true }))
    smb1 = @(, @('smb1:EnableSMB1Protocol', $false, { param($v) $v -ne $true }))
}
$userSid = ''

function Resolve-SysPath($p) {
    if ($p.StartsWith('HKU:\')) {
        if ($userSid -notmatch '^S-1-5-21(-\d+){4}$') { throw 'no valid user SID for a per-user setting' }
        $p = 'Registry::HKEY_USERS\' + $userSid + '\' + $p.Substring(5)
        if ($SysRoot) { return $SysRoot + '\HKU\' + $p.Substring(('Registry::HKEY_USERS\' + $userSid + '\').Length) }
        return $p
    }
    if ($SysRoot) { return $SysRoot + '\HKLM\' + $p.Substring(6) }
    return $p
}

function Get-SysStore { if (Test-Path -LiteralPath $SysStore) { return (Get-Content -LiteralPath $SysStore -Raw -Encoding UTF8 | ConvertFrom-Json) } return [pscustomobject]@{} }
function Get-SysVal($item) {
    if ($SysStore) { $s = Get-SysStore; return $s.$item }
    switch -Wildcard ($item) {
        'mp:*' { return (Get-MpPreference).($item.Substring(3)) }
        'fw:*' { return ([string](Get-NetFirewallProfile -Name $item.Substring(3)).Enabled -eq 'True') }
        'guest:Enabled' { $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; if ($g) { return [bool]$g.Enabled } return $null }
        'smb1:EnableSMB1Protocol' { return [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }
    }
    throw "unknown item $item"
}
function Set-SysVal($item, $value) {
    if ($SysStore) {
        $s = Get-SysStore; $s | Add-Member -NotePropertyName $item -NotePropertyValue $value -Force
        [System.IO.File]::WriteAllText($SysStore, ($s | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false))); return
    }
    switch -Wildcard ($item) {
        'mp:DisableRealtimeMonitoring' { Set-MpPreference -DisableRealtimeMonitoring ([bool]$value); return }
        'mp:MAPSReporting' { Set-MpPreference -MAPSReporting ([int]$value); return }
        'fw:*' { Set-NetFirewallProfile -Name $item.Substring(3) -Enabled $(if ($value) { 'True' } else { 'False' }); return }
        'guest:Enabled' { if ($value) { Enable-LocalUser -Name 'Guest' } else { Disable-LocalUser -Name 'Guest' }; return }
        'smb1:EnableSMB1Protocol' { Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$value) -Force -Confirm:$false; return }
    }
    throw "unknown item $item"
}

# Write one registry item (or remove it when $value is $null), recording what was there.
function Set-SysReg($fix, $it) {
    $path = Resolve-SysPath $it[0]; $name = $it[1]; $value = $it[2]; $type = $it[3]
    $before = Get-Before $path $name
    if (& $it[4] $before) { return }   # already safe: nothing to raise, nothing to undo
    if ($null -eq $value) {
        Remove-ItemProperty -LiteralPath $path -Name $name
        $now = Get-Before $path $name
        $script:result.changes += [ordered]@{ where = 'System'; name = "$fix|$name"; wanted = 'removed'; readBack = $now.value; ok = (-not $now.existed); before = $before }
        return
    }
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -LiteralPath $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
    $back = (Get-ItemProperty -LiteralPath $path -Name $name).$name
    $script:result.changes += [ordered]@{ where = 'System'; name = "$fix|$name"; wanted = $value; readBack = $back; ok = ([string]$back -eq [string]$value); before = $before }
}

function Set-SysOther($fix, $it) {
    $item = $it[0]; $value = $it[1]
    $was = Get-SysVal $item
    if ($null -eq $was -or (& $it[2] $was)) { return }   # absent (no Guest account) or already safe
    Set-SysVal $item $value
    $back = Get-SysVal $item
    $script:result.changes += [ordered]@{ where = 'System'; name = "$fix|$item"; wanted = $value; readBack = $back; ok = ([string]$back -eq [string]$value); before = [ordered]@{ existed = $true; value = $was; type = $null } }
}

function Invoke-SysFix($fix) {
    if ($fix -eq 'sigs') {
        # A fresh virus list: nothing to undo, so no "before".
        if ($SysStore) { Set-SysVal 'sigs:updated' $true; $ok = $true } else { Update-MpSignature; $ok = ((Get-MpComputerStatus).AntivirusSignatureAge -le 1) }
        $script:result.changes += [ordered]@{ where = 'System'; name = 'sigs|Update-MpSignature'; wanted = 'fresh'; readBack = $ok; ok = $ok }
        return
    }
    if ($sysReg.Contains($fix)) { foreach ($it in $sysReg[$fix]) { try { Set-SysReg $fix $it } catch { $script:result.errors += ("{0} {1}: {2}" -f $fix, $it[1], $_.Exception.Message) } }; return }
    if ($sysOther.Contains($fix)) { foreach ($it in $sysOther[$fix]) { try { Set-SysOther $fix $it } catch { $script:result.errors += ("{0} {1}: {2}" -f $fix, $it[0], $_.Exception.Message) } }; return }
    $script:result.errors += ("refused {0}: not a setting Virus Vigil changes" -f $fix)
}

# Put one System record back. Only items this script itself writes; anything else is refused.
function Undo-Sys($u) {
    $fix, $item = ([string]$u.name) -split '\|', 2
    if ($sysReg.Contains($fix)) {
        $it = $sysReg[$fix] | Where-Object { $_[1] -eq $item } | Select-Object -First 1
        if (-not $it) { throw "refused $($u.name): not a setting Virus Vigil writes" }
        $path = Resolve-SysPath $it[0]
        if ($u.before.existed) {
            if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
            New-ItemProperty -LiteralPath $path -Name $item -Value $u.before.value -PropertyType ([string]$u.before.type) -Force | Out-Null
        } elseif ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).GetValueNames() -contains $item)) {
            Remove-ItemProperty -LiteralPath $path -Name $item
        }
        $now = Get-Before $path $item
        return (($now.existed -eq [bool]$u.before.existed) -and ([string]$now.value -eq [string]$u.before.value))
    }
    if ($sysOther.Contains($fix) -and ($sysOther[$fix] | Where-Object { $_[0] -eq $item })) {
        Set-SysVal $item $u.before.value
        return ([string](Get-SysVal $item) -eq [string]$u.before.value)
    }
    throw "refused $($u.name): not a setting Virus Vigil writes"
}

function Get-FirefoxFile {
    $ff = if ($FirefoxDir) { $FirefoxDir } else {
        @("$env:ProgramFiles\Mozilla Firefox", "${env:ProgramFiles(x86)}\Mozilla Firefox") | Where-Object { Test-Path (Join-Path $_ 'firefox.exe') } | Select-Object -First 1
    }
    if (-not $ff) { throw 'Firefox folder not found' }
    return (Join-Path (Join-Path $ff 'distribution') 'policies.json')
}

function Invoke-Undo($undo) {
    $script:result.mode = 'undo'
    foreach ($u in @($undo.registry)) {
        if (-not $u) { continue }
        $subKey = [string]$u.where; $name = [string]$u.name
        if ($subKey -eq 'System') {
            try { $ok = Undo-Sys $u; $script:result.changes += [ordered]@{ where = $subKey; name = $name; wanted = $u.before; readBack = $ok; ok = $ok } }
            catch { $script:result.errors += $(if ($_.Exception.Message -like 'refused*') { $_.Exception.Message } else { ('{0}: {1}' -f $name, $_.Exception.Message) }) }
            continue
        }
        if ($subKey -eq 'Defender ASR') {
            $id = $name.ToLower()
            if ($asrAllowed -notcontains $id) { $script:result.errors += ("refused ASR {0}: not a rule Virus Vigil sets" -f $name); continue }
            try {
                Set-AsrRule $id $(if ($u.before.existed) { [int]$u.before.value } else { $null })
                $now = Get-AsrBefore $id
                $same = ($now.existed -eq [bool]$u.before.existed) -and ([string]$now.value -eq [string]$u.before.value)
                $script:result.changes += [ordered]@{ where = $subKey; name = $id; wanted = $u.before; readBack = $now; ok = $same }
            } catch { $script:result.errors += ("ASR {0}: {1}" -f $id, $_.Exception.Message) }
            continue
        }
        if (-not $allowed.ContainsKey($subKey) -or $allowed[$subKey] -notcontains $name) {
            $script:result.errors += ("refused {0}\{1}: not a setting Virus Vigil writes" -f $subKey, $name); continue
        }
        $path = Join-Path $Root $subKey
        try {
            if ($u.before.existed) {
                if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                New-ItemProperty -LiteralPath $path -Name $name -Value $u.before.value -PropertyType ([string]$u.before.type) -Force | Out-Null
            } elseif ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).GetValueNames() -contains $name)) {
                Remove-ItemProperty -LiteralPath $path -Name $name
            }
            $now = Get-Before $path $name
            $same = ($now.existed -eq [bool]$u.before.existed) -and ([string]$now.value -eq [string]$u.before.value)
            $script:result.changes += [ordered]@{ where = $subKey; name = $name; wanted = $u.before; readBack = $now; ok = $same }
        } catch {
            $script:result.errors += ("{0}\{1}: {2}" -f $subKey, $name, $_.Exception.Message)
        }
    }
    if ($undo.firefox) {
        try {
            $pj = Get-FirefoxFile
            if ([string]$undo.firefox.path -ne $pj) { throw "refused: $($undo.firefox.path) is not Firefox's policies file" }
            if ($undo.firefox.existed) {
                [System.IO.File]::WriteAllText($pj, [string]$undo.firefox.text, (New-Object System.Text.UTF8Encoding($false)))
                $ok = ([System.IO.File]::ReadAllText($pj, [System.Text.Encoding]::UTF8) -eq [string]$undo.firefox.text)
            } else {
                if (Test-Path -LiteralPath $pj) { Remove-Item -LiteralPath $pj -Force }
                $ok = -not (Test-Path -LiteralPath $pj)
            }
            $script:result.changes += [ordered]@{ where = 'Firefox policies.json'; name = 'whole file'; wanted = if ($undo.firefox.existed) { 'as before' } else { 'removed' }; readBack = $ok; ok = $ok }
        } catch {
            $script:result.errors += ('Firefox: ' + $_.Exception.Message)
        }
    }
}

try {
    $p = Get-Content -LiteralPath $Plan -Raw -Encoding UTF8 | ConvertFrom-Json
    $userSid = [string]$p.userSid
    if ($p.undo) { Invoke-Undo $p.undo; $p = $null }
    $blockPasswords = [bool]$p.blockPasswords
    $blockCards = [bool]$p.blockCards   # AutofillCreditCardEnabled: verified in Edge + Firefox docs, Chrome's own policy page, 24 Sep 2026

    foreach ($f in @($p.system)) { if ($f) { Invoke-SysFix ([string]$f) } }

    foreach ($a in @($p.asr)) {
        if (-not $a) { continue }
        $id = ([string]$a).ToLower()
        if ($asrAllowed -notcontains $id) { $result.errors += ("refused ASR {0}: not a rule Virus Vigil sets" -f $a); continue }
        try {
            $before = Get-AsrBefore $id
            if ($before.existed -and $before.value -eq 1) { continue }  # already blocking: nothing to raise, nothing to undo
            Set-AsrRule $id 1
            $back = (Get-AsrBefore $id).value
            $result.changes += [ordered]@{ where = 'Defender ASR'; name = $id; wanted = 1; readBack = $back; ok = ($back -eq 1); before = $before }
        } catch { $result.errors += ("ASR {0}: {1}" -f $id, $_.Exception.Message) }
    }

    foreach ($b in @($p.browsers)) {
        switch ($b) {
            'chrome' {
                Set-Policy 'Google\Chrome' 'SafeBrowsingProtectionLevel' 2 'DWord'
                Set-Policy 'Google\Chrome' 'DownloadRestrictions' 1 'DWord'
                Set-Policy 'Google\Chrome' 'DnsOverHttpsMode' 'automatic' 'String'
                if ($blockPasswords) { Set-Policy 'Google\Chrome' 'PasswordManagerEnabled' 0 'DWord' }
                if ($blockCards) { Set-Policy 'Google\Chrome' 'AutofillCreditCardEnabled' 0 'DWord' }
            }
            'brave' {
                Set-Policy 'BraveSoftware\Brave' 'SafeBrowsingProtectionLevel' 2 'DWord'
                Set-Policy 'BraveSoftware\Brave' 'DownloadRestrictions' 1 'DWord'
                Set-Policy 'BraveSoftware\Brave' 'DnsOverHttpsMode' 'automatic' 'String'
                if ($blockPasswords) { Set-Policy 'BraveSoftware\Brave' 'PasswordManagerEnabled' 0 'DWord' }
                if ($blockCards) { Set-Policy 'BraveSoftware\Brave' 'AutofillCreditCardEnabled' 0 'DWord' }
            }
            'edge' {
                Set-Policy 'Microsoft\Edge' 'SmartScreenEnabled' 1 'DWord'
                Set-Policy 'Microsoft\Edge' 'SmartScreenPuaEnabled' 1 'DWord'
                Set-Policy 'Microsoft\Edge' 'DownloadRestrictions' 1 'DWord'
                Set-Policy 'Microsoft\Edge' 'DnsOverHttpsMode' 'automatic' 'String'
                if ($blockPasswords) { Set-Policy 'Microsoft\Edge' 'PasswordManagerEnabled' 0 'DWord' }
                if ($blockCards) { Set-Policy 'Microsoft\Edge' 'AutofillCreditCardEnabled' 0 'DWord' }
            }
            'firefox' {
                try {
                    $pj = Get-FirefoxFile
                    $dist = Split-Path -Parent $pj
                    $had = Test-Path -LiteralPath $pj
                    $result.firefoxBefore = [ordered]@{ path = $pj; existed = $had; text = if ($had) { [System.IO.File]::ReadAllText($pj, [System.Text.Encoding]::UTF8) } else { $null } }
                    if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }
                    $doc = if ($had) { Get-Content -LiteralPath $pj -Raw -Encoding UTF8 | ConvertFrom-Json } else { [pscustomobject]@{ policies = [pscustomobject]@{} } }
                    if (-not $doc.policies) { $doc | Add-Member -NotePropertyName policies -NotePropertyValue ([pscustomobject]@{}) -Force }
                    $doc.policies | Add-Member -NotePropertyName DNSOverHTTPS -NotePropertyValue ([pscustomobject]@{ Enabled = $true; Fallback = $true }) -Force
                    if ($blockPasswords) { $doc.policies | Add-Member -NotePropertyName PasswordManagerEnabled -NotePropertyValue $false -Force }
                    if ($blockCards) { $doc.policies | Add-Member -NotePropertyName AutofillCreditCardEnabled -NotePropertyValue $false -Force }
                    $json = $doc | ConvertTo-Json -Depth 10
                    [System.IO.File]::WriteAllText($pj, $json, (New-Object System.Text.UTF8Encoding($false)))
                    $back = (Get-Content -LiteralPath $pj -Raw -Encoding UTF8 | ConvertFrom-Json).policies
                    $script:result.changes += [ordered]@{ where = 'Firefox policies.json'; name = 'DNSOverHTTPS'; wanted = $true; readBack = [bool]$back.DNSOverHTTPS.Enabled; ok = [bool]$back.DNSOverHTTPS.Enabled }
                    if ($blockCards) {
                        $cardsBack = $back.AutofillCreditCardEnabled
                        $script:result.changes += [ordered]@{ where = 'Firefox policies.json'; name = 'AutofillCreditCardEnabled'; wanted = $false; readBack = $cardsBack; ok = ($cardsBack -eq $false) }
                    }
                } catch {
                    $script:result.errors += ('Firefox: ' + $_.Exception.Message)
                }
            }
        }
    }
} catch {
    $result.errors += ('plan: ' + $_.Exception.Message)
}

if ($result.errors.Count -gt 0) { $result.ok = $false }
$json = $result | ConvertTo-Json -Depth 8 -Compress
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))
