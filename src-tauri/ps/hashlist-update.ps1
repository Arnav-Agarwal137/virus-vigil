# Virus Vigil - refresh MalwareBazaar's public list of known malware fingerprints (SHA-256).
# Prints ONE JSON object. ASCII only. Source: abuse.ch MalwareBazaar exports, free under its
# fair-use terms (checked 25 Sep 2026: the txt exports need no sign-in).
#   full   = every sample ever shared (~1.14 million, 43 MB zip)  - once a WEEK, or sooner when
#            the recent list no longer reaches back to it (see the end)
#   recent = samples of the last 48 hours (small text)             - at most once a DAY
# Downloads PUBLIC lists; sends nothing about this PC. A download replaces the old copy only
# after it passes the checks below, so a bad download never wipes a good list.
$ErrorActionPreference = 'SilentlyContinue'
# PowerShell 5.1 redraws a progress bar per chunk, which slows a 44 MB download so much that the
# keyed abuse.ch server closes the connection (measured 1 Nov 2026: fails after 156 s with it,
# 18 s without).
$ProgressPreference = 'SilentlyContinue'
# Since Oct 2026 abuse.ch serves these lists only with an Auth-Key (the keyless addresses answer
# 410 Gone). The key is each user's own (free at auth.abuse.ch), read from the user environment
# variable ABUSE_CH_AUTH_KEY - never stored in the app. It is never printed: errors are scrubbed.
$mbKey = [string]$env:ABUSE_CH_AUTH_KEY
if ($mbKey -notmatch '^[A-Za-z0-9]{20,100}$') { $mbKey = '' }
$mbBase = if ($mbKey) { "https://mb-api.abuse.ch/v2/files/exports/$mbKey/" } else { '' }
$fullUrl = if ($env:VV_MB_FULL_URL) { $env:VV_MB_FULL_URL } elseif ($mbKey) { $mbBase + 'sha256_full.txt.zip' } else { 'https://bazaar.abuse.ch/export/txt/sha256/full/' }
$recentUrl = if ($env:VV_MB_RECENT_URL) { $env:VV_MB_RECENT_URL } elseif ($mbKey) { $mbBase + 'sha256_recent.txt' } else { 'https://bazaar.abuse.ch/export/txt/sha256/recent/' }
$noKeyNote = 'abuse.ch now needs a free Auth-Key for this list (auth.abuse.ch); set it as ABUSE_CH_AUTH_KEY'
$dir = if ($env:VV_LISTS_DIR) { $env:VV_LISTS_DIR } else { Join-Path $env:LOCALAPPDATA 'VirusVigil\lists' }
$fullMin = if ($env:VV_MB_FULL_MIN) { [int]$env:VV_MB_FULL_MIN } else { 1000000 }
$recentMin = if ($env:VV_MB_RECENT_MIN) { [int]$env:VV_MB_RECENT_MIN } else { 50 }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Counts hash lines and how many are valid; comments and blank lines are skipped.
function Measure-HashFile([string]$path) {
    $n = 0; $good = 0
    foreach ($line in [IO.File]::ReadLines($path)) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        $n++
        if ($l -match '^[0-9a-fA-F]{64}$') { $good++ }
    }
    return @($n, $good)
}

function Update-HashList([string]$url, [string]$dest, [double]$maxHours, [int]$min, [bool]$zipped) {
    $r = [ordered]@{ updated = $false; skipped = $false; lines = $null; error = $null }
    if ((Test-Path -LiteralPath $dest) -and ((Get-Date) - (Get-Item -LiteralPath $dest).LastWriteTime).TotalHours -lt $maxHours) {
        $r.skipped = $true; return $r
    }
    # Expand-Archive refuses any name not ending in .zip (measured 25 Sep), so the zip gets one.
    $tmp = if ($zipped) { "$dest.download.zip" } else { "$dest.download" }; $unz = "$dest.unzip"
    for ($try = 1; $try -le 3 -and -not $r.updated; $try++) {
        try {
            Remove-Item -LiteralPath $tmp, $unz -Recurse -Force -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
            $txt = $tmp
            if ($zipped) {
                Expand-Archive -LiteralPath $tmp -DestinationPath $unz -Force -ErrorAction Stop
                $inner = @(Get-ChildItem -LiteralPath $unz -File)
                if ($inner.Count -ne 1) { throw "the zip held $($inner.Count) files, expected 1" }
                $txt = $inner[0].FullName
            }
            $m = Measure-HashFile $txt
            if ($m[0] -ge $min -and $m[1] -ge 0.99 * $m[0]) {
                Move-Item -LiteralPath $txt -Destination $dest -Force -ErrorAction Stop
                # A file out of a zip keeps the zip's own date, which can be OLDER than the sorted
                # list hashlist.rs built from the last download - and then it would never be rebuilt.
                # Stamp it with its arrival time (measured 25 Sep: 08:45 export, arrived 15:27).
                (Get-Item -LiteralPath $dest).LastWriteTime = Get-Date
                $r.updated = $true; $r.lines = $m[0]; $r.error = $null
            } else {
                $r.error = "downloaded list failed its checks ($($m[1]) of $($m[0]) lines valid, need $min)"
            }
        } catch {
            $msg = [string]$_.Exception.Message
            if ($mbKey) { $msg = $msg.Replace($mbKey, '<key>') } elseif ($msg -match '410|Gone') { $msg = "$msg - $noKeyNote" }
            $r.error = $msg; Start-Sleep -Seconds (3 * $try)
        }
    }
    Remove-Item -LiteralPath $tmp, $unz -Recurse -Force -ErrorAction SilentlyContinue
    return $r
}

# The recent list first: whether the full one is due depends on how far back it now reaches.
# Same rule as hashlist.rs full_due (29 Sep 2026): weekly, OR sooner when the full list is more than
# 40 hours older than the recent one - otherwise samples shared in between are in NEITHER list.
$fullPath = Join-Path $dir 'malwarebazaar-full.txt'; $recentPath = Join-Path $dir 'malwarebazaar-recent.txt'
$recent = Update-HashList $recentUrl $recentPath 20 $recentMin $false
$fullMax = 24 * 7
if ((Test-Path -LiteralPath $fullPath) -and (Test-Path -LiteralPath $recentPath)) {
    $gapHours = ((Get-Item -LiteralPath $recentPath).LastWriteTime - (Get-Item -LiteralPath $fullPath).LastWriteTime).TotalHours
    if ($gapHours -gt 40) { $fullMax = 0 }
}
$full = Update-HashList $fullUrl $fullPath $fullMax $fullMin $true
$res = [ordered]@{ ok = $true; full = $full; recent = $recent }
$res | ConvertTo-Json -Compress
