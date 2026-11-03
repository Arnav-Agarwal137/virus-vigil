# Virus Vigil - browser add-ons (extensions). Prints ONE JSON object. Changes nothing on the PC.
# ASCII only (Windows PowerShell 5.1 reads BOM-less files as ANSI).
# Reads Chrome / Edge / Brave / Opera profile folders. The ONLY network use: it may download
# the public list of known-malicious extension IDs (chrome-mal-ids, The Privacy Commons
# Institute, CC BY 4.0). Nothing about this PC is sent - the match happens here.
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Web.Extensions
$json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$json.MaxJsonLength = [int]::MaxValue

function Read-Json($path) {
    # JavaScriptSerializer, not ConvertFrom-Json: browser prefs can hold keys that differ only by case.
    try { return $json.DeserializeObject([IO.File]::ReadAllText($path)) } catch { return $null }
}
function Get-Key($d, $k) { if ($d -is [System.Collections.IDictionary] -and $d.ContainsKey($k)) { return $d[$k] } return $null }

# ---------- the known-bad list (cached one day) ----------
$LIST_URL = 'https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list.txt'
$cacheDir = Join-Path $env:LOCALAPPDATA 'VirusVigil\lists'
$cache = Join-Path $cacheDir 'chrome-mal-ids.txt'
$list = [ordered]@{ source = 'chrome-mal-ids (The Privacy Commons Institute, CC BY 4.0)'; fetched = $false; error = $null; generated = $null; count = 0; ageHours = $null }

# Returns the ID set, or $null when the text is not a whole, valid list (count must equal its own "Total:").
function Read-List([string]$text) {
    $ids = New-Object 'System.Collections.Generic.HashSet[string]'
    $total = $null
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^#\s*Total:\s*(\d+)') { $total = [int]$Matches[1]; continue }
        if ($line -match '^#\s*Generated:\s*(.+)$') { $script:gen = $Matches[1].Trim(); continue }
        if ($line.StartsWith('#')) { continue }
        $id = ($line.Trim() -split '[\s,]+')[0]
        if ($id -match '^[a-p]{32}$') { [void]$ids.Add($id) }
    }
    if ($null -eq $total -or $ids.Count -ne $total -or $ids.Count -lt 1000) { return $null }
    return $ids
}

$bad = $null
$fresh = (Test-Path -LiteralPath $cache) -and ((Get-Date) - (Get-Item -LiteralPath $cache).LastWriteTime).TotalHours -lt 24
if (-not $fresh -and -not $env:VV_NO_NETWORK) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($try = 1; $try -le 3 -and -not $list.fetched; $try++) {
        try {
            $r = Invoke-WebRequest -Uri $LIST_URL -UseBasicParsing -TimeoutSec 30
            $text = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())
            $script:gen = $null
            $ids = Read-List $text
            if ($ids) {
                New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
                [IO.File]::WriteAllText($cache, $text)
                $bad = $ids; $list.fetched = $true; $list.error = $null
            } else { $list.error = 'downloaded list was incomplete' }
        } catch { $list.error = [string]$_.Exception.Message; Start-Sleep -Seconds (2 * $try) }
    }
}
if (-not $bad -and (Test-Path -LiteralPath $cache)) {
    $script:gen = $null
    $bad = Read-List ([IO.File]::ReadAllText($cache))
    if (-not $bad) { $list.error = 'saved list is damaged' }
}
if ($bad) {
    $list.count = $bad.Count
    $list.generated = $script:gen
    $list.ageHours = [math]::Round(((Get-Date) - (Get-Item -LiteralPath $cache).LastWriteTime).TotalHours, 1)
}

# ---------- installed extensions ----------
$lad = $env:LOCALAPPDATA
$browsers = @(
    @{ id = 'chrome'; name = 'Google Chrome'; root = "$lad\Google\Chrome\User Data" },
    @{ id = 'edge'; name = 'Microsoft Edge'; root = "$lad\Microsoft\Edge\User Data" },
    @{ id = 'brave'; name = 'Brave'; root = "$lad\BraveSoftware\Brave-Browser\User Data" },
    @{ id = 'opera'; name = 'Opera'; root = "$env:APPDATA\Opera Software"; opera = $true }
)

function Resolve-Name($raw, $dir, $manifest) {
    if (-not $raw -or $raw -notmatch '^__MSG_(.+)__$') { return $raw }
    $key = $Matches[1]
    $locs = @((Get-Key $manifest 'default_locale'), 'en', 'en_US', 'en_GB') | Where-Object { $_ }
    foreach ($l in $locs) {
        $m = Read-Json (Join-Path $dir "_locales\$l\messages.json")
        if (-not $m) { continue }
        foreach ($k in $m.Keys) { if ($k -ieq $key) { return (Get-Key $m[$k] 'message') } }
    }
    return $raw
}

$exts = New-Object System.Collections.ArrayList
$profilesRead = 0
foreach ($b in $browsers) {
    if (-not (Test-Path -LiteralPath $b.root)) { continue }
    # Profile display names live in "Local State" (profile.info_cache), not in each profile.
    $cacheNames = Get-Key (Get-Key (Read-Json (Join-Path $b.root 'Local State')) 'profile') 'info_cache'
    $profiles = if ($b.opera) { @(Get-ChildItem -LiteralPath $b.root -Directory | Where-Object { $_.Name -like 'Opera*' }) }
                else { @(Get-ChildItem -LiteralPath $b.root -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) }
    foreach ($p in $profiles) {
        $prefsFile = @('Secure Preferences', 'Preferences') | ForEach-Object { Join-Path $p.FullName $_ }
        $settings = @{}
        $profileName = $p.Name
        foreach ($f in $prefsFile) {
            $pr = Read-Json $f
            if (-not $pr) { continue }
            $s = Get-Key (Get-Key $pr 'extensions') 'settings'
            if ($s) { foreach ($k in $s.Keys) { if (-not $settings.ContainsKey($k)) { $settings[$k] = $s[$k] } } }
        }
        $cn = Get-Key (Get-Key $cacheNames $p.Name) 'name'
        if ($cn) { $profileName = [string]$cn }
        $extDir = Join-Path $p.FullName 'Extensions'
        $seen = @{}
        $dirs = @()
        if (Test-Path -LiteralPath $extDir) {
            foreach ($d in Get-ChildItem -LiteralPath $extDir -Directory) {
                $v = Get-ChildItem -LiteralPath $d.FullName -Directory | Sort-Object { try { [version]($_.Name -replace '_\d+$', '') } catch { [version]'0.0' } } -Descending | Select-Object -First 1
                if ($v) { $dirs += @{ id = $d.Name; dir = $v.FullName } }
            }
        }
        # Unpacked (developer mode) add-ons live wherever their folder is.
        foreach ($k in $settings.Keys) {
            $st = $settings[$k]
            if ((Get-Key $st 'location') -eq 4 -and (Get-Key $st 'path')) { $dirs += @{ id = $k; dir = [string](Get-Key $st 'path') } }
        }
        $profilesRead++
        foreach ($e in $dirs) {
            if ($seen.ContainsKey($e.id)) { continue }
            $seen[$e.id] = $true
            $m = Read-Json (Join-Path $e.dir 'manifest.json')
            if (-not $m) { continue }
            $st = $settings[$e.id]
            $loc = Get-Key $st 'location'
            if ($loc -eq 5 -or $loc -eq 10) { continue }   # built into the browser itself
            $dr = Get-Key $st 'disable_reasons'
            $state = Get-Key $st 'state'
            # Newer browsers write disable_reasons only when an add-on is OFF; older ones write state 0/1.
            # No settings entry at all = unknown (null), never assumed on or off.
            $enabled = $null
            if ($st) {
                $off = ($null -ne $state -and [int]$state -eq 0)
                if ($null -ne $dr) { $off = $off -or ($(if ($dr -is [array]) { $dr.Count -gt 0 } else { [int]$dr -ne 0 })) }
                $enabled = -not $off
            }
            $hosts = @()
            $hosts += @(Get-Key $m 'host_permissions')
            foreach ($cs in @(Get-Key $m 'content_scripts')) { $hosts += @(Get-Key $cs 'matches') }
            $perms = @()
            foreach ($x in @(Get-Key $m 'permissions')) { if ($x -match '://|^<all_urls>$|^\*') { $hosts += $x } else { $perms += $x } }
            [void]$exts.Add([ordered]@{
                browser = $b.id; browserName = $b.name; profile = [string]$profileName
                id = $e.id; name = [string](Resolve-Name (Get-Key $m 'name') $e.dir $m); version = [string](Get-Key $m 'version')
                mv = Get-Key $m 'manifest_version'
                permissions = @($perms | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
                hosts = @($hosts | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
                enabled = $enabled; location = $loc; fromStore = Get-Key $st 'from_webstore'
                updateUrl = [string](Get-Key $m 'update_url')
                known = [bool]($bad -and $bad.Contains($e.id))
            })
        }
    }
}

# ---------- Firefox (B9) ----------
# Each profile keeps its add-ons in extensions.json (Mozilla source, XPIDatabase.sys.mjs, read 24 Sep 2026):
# { schemaVersion, addons: [ { id, type, location, active, userDisabled, appDisabled, version,
#   defaultLocale.name, signedState, userPermissions {permissions, origins}, foreignInstall, sourceURI } ] }.
# Temporary (about:debugging) add-ons are never written there. signedState (AddonManager.sys.mjs):
# -2 broken, -1 unknown, 0 unsigned, 1 preliminary, 2 reviewed, 3 system, 4 Mozilla-privileged.
# chrome-mal-ids lists Chrome-store ids only, so Firefox add-ons are never "known" - the page says so.
$ffRoot = Join-Path $env:APPDATA 'Mozilla\Firefox'
$ffBuiltIn = @('app-builtin', 'app-builtin-addons', 'app-system-addons', 'app-system-defaults', 'app-system-profile')
$ffProfiles = @()
$ini = Join-Path $ffRoot 'profiles.ini'
if (Test-Path -LiteralPath $ini) {
    $sec = $null
    foreach ($line in [IO.File]::ReadAllLines($ini)) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $sec = if ($Matches[1] -like 'Profile*') { @{ name = $null; path = $null; rel = $true } } else { $null }; if ($sec) { $ffProfiles += $sec }; continue }
        if (-not $sec -or $line -notmatch '^\s*([^=]+?)\s*=\s*(.*?)\s*$') { continue }
        switch ($Matches[1]) { 'Name' { $sec.name = $Matches[2] } 'Path' { $sec.path = $Matches[2] } 'IsRelative' { $sec.rel = ($Matches[2] -eq '1') } }
    }
}
if (-not @($ffProfiles | Where-Object { $_.path }).Count -and (Test-Path -LiteralPath (Join-Path $ffRoot 'Profiles'))) {
    $ffProfiles = @(Get-ChildItem -LiteralPath (Join-Path $ffRoot 'Profiles') -Directory | ForEach-Object { @{ name = $_.Name; path = $_.FullName; rel = $false } })
}
foreach ($fp in $ffProfiles) {
    if (-not $fp.path) { continue }
    $dir = if ($fp.rel) { Join-Path $ffRoot ($fp.path -replace '/', '\') } else { $fp.path -replace '/', '\' }
    $db = Read-Json (Join-Path $dir 'extensions.json')
    if (-not $db) { continue }
    $profilesRead++
    foreach ($a in @(Get-Key $db 'addons')) {
        if ((Get-Key $a 'type') -ne 'extension') { continue }   # themes, dictionaries, language packs
        $loc = [string](Get-Key $a 'location')
        $signed = Get-Key $a 'signedState'
        if ($ffBuiltIn -contains $loc -or $signed -eq 3 -or $signed -eq 4) { continue }   # part of Firefox itself
        $up = Get-Key $a 'userPermissions'
        $src = [string](Get-Key $a 'sourceURI')
        [void]$exts.Add([ordered]@{
            browser = 'firefox'; browserName = 'Firefox'; profile = [string]$(if ($fp.name) { $fp.name } else { Split-Path $dir -Leaf })
            id = [string](Get-Key $a 'id'); name = [string]$(if (Get-Key (Get-Key $a 'defaultLocale') 'name') { Get-Key (Get-Key $a 'defaultLocale') 'name' } else { Get-Key $a 'id' })
            version = [string](Get-Key $a 'version'); mv = Get-Key $a 'manifestVersion'
            permissions = @(@(Get-Key $up 'permissions') | Where-Object { $_ } | ForEach-Object { [string]$_ })
            hosts = @(@(Get-Key $up 'origins') | Where-Object { $_ } | ForEach-Object { [string]$_ })
            enabled = [bool](Get-Key $a 'active')
            location = $loc
            # Signed-and-reviewed add-ons can also come from outside the store, so "store" is only
            # claimed when Firefox recorded the download address as addons.mozilla.org.
            fromStore = $(if ($src -match '^https://addons\.mozilla\.org/') { $true } else { $null })
            foreign = [bool](Get-Key $a 'foreignInstall') -or ($loc -ne 'app-profile')
            signedState = $signed
            updateUrl = ''
            known = $false; listCovers = $false
        })
    }
}

[ordered]@{ ok = $true; time = (Get-Date).ToString('o'); list = $list; profilesRead = $profilesRead; extensions = $exts } | ConvertTo-Json -Depth 6 -Compress
