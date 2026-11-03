# Virus Vigil - refresh the public phishing-domain lists. Prints ONE JSON object.
# ASCII only. Two lists (2 Nov 2026):
#   Phishing.Database (MIT), phishing-domains-ACTIVE.txt, ~11 MB, at most daily. Its fields stay at the TOP.
#   CERT Polska Warning List, hole.cert.pl/domains/v2/domains.txt, ~2.5 MB, at most every 6 hours,
#   answer under "certpl". Data policy: "may be used by any user for any purpose, including commercial purposes".
# Downloads PUBLIC lists; sends nothing about this PC. A list is replaced only by a download that passes
# the checks below, so a bad download never wipes it.
$ErrorActionPreference = 'SilentlyContinue'
# No progress bar: PowerShell 5.1 redraws it per chunk and big downloads crawl (see hashlist-update.ps1).
$ProgressPreference = 'SilentlyContinue'
$dir = Join-Path $env:LOCALAPPDATA 'VirusVigil\lists'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Unix seconds from "2026-10-02T15:30:28Z", or $null.
function ConvertFrom-IsoUtc([string]$s) {
    try {
        return [DateTimeOffset]::ParseExact($s, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).ToUnixTimeSeconds()
    } catch { return $null }
}

# $since: a scriptblock given the download response, returning the makers' last change (unix seconds) or $null.
function Update-PhishList([string]$url, [string]$file, [int]$minLines, [int]$hours, [scriptblock]$since) {
    $res = [ordered]@{ ok = $true; updated = $false; skipped = $false; error = $null; lines = $null }
    $dest = Join-Path $dir $file
    if ((Test-Path -LiteralPath $dest) -and ((Get-Date) - (Get-Item -LiteralPath $dest).LastWriteTime).TotalHours -lt $hours) {
        $res.skipped = $true
        return $res
    }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $tmp = "$dest.download"
    for ($try = 1; $try -le 3 -and -not $res.updated; $try++) {
        try {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            $resp = Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -TimeoutSec 120 -PassThru
            # Whole and sane: enough lines, and nearly all of them look like host names.
            $n = 0; $good = 0
            foreach ($line in [IO.File]::ReadLines($tmp)) {
                if ($line.StartsWith('#') -or -not $line) { continue }
                $n++
                if ($line -match '^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$') { $good++ }
            }
            if ($n -ge $minLines -and $good -ge 0.99 * $n) {
                Move-Item -LiteralPath $tmp -Destination $dest -Force
                $res.updated = $true; $res.lines = $n; $res.error = $null
                # When the list's MAKERS last changed it (31 Oct 2026: Phishing.Database stopped on 2 Oct
                # while our download time said "today"). Unix seconds beside the list; if it can't be read
                # the old note is removed, so it never describes a newer list.
                $sp = [IO.Path]::ChangeExtension($dest, 'since')
                $t = $null
                try { $t = & $since $resp } catch { $t = $null }
                if ($t) { [IO.File]::WriteAllText($sp, [string]$t); $res.sourceTime = $t }
                else { Remove-Item -LiteralPath $sp -Force -ErrorAction SilentlyContinue }
            } else {
                $res.error = "downloaded list failed its checks ($good of $n lines valid, need $minLines)"
            }
        } catch { $res.error = [string]$_.Exception.Message; Start-Sleep -Seconds (3 * $try) }
    }
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    return $res
}

$pdbUrl = if ($env:VV_PHISH_URL) { $env:VV_PHISH_URL } else { 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt' }
$pdbMin = if ($env:VV_PHISH_MIN) { [int]$env:VV_PHISH_MIN } else { 100000 }
$res = Update-PhishList $pdbUrl 'phishing-domains.txt' $pdbMin 24 {
    param($r)
    # GitHub's public commit record for that file.
    $api = if ($env:VV_PHISH_API) { $env:VV_PHISH_API } else { 'https://api.github.com/repos/Phishing-Database/Phishing.Database/commits?path=phishing-domains-ACTIVE.txt&per_page=1' }
    $raw = (Invoke-WebRequest -Uri $api -UseBasicParsing -TimeoutSec 30 -Headers @{ 'User-Agent' = 'VirusVigil'; 'Accept' = 'application/vnd.github+json' } -ErrorAction Stop).Content
    $m = [regex]::Match($raw, '"date"\s*:\s*"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"')
    if ($m.Success) { ConvertFrom-IsoUtc $m.Groups[1].Value } else { $null }
}

$certUrl = if ($env:VV_CERTPL_URL) { $env:VV_CERTPL_URL } else { 'https://hole.cert.pl/domains/v2/domains.txt' }
$certMin = if ($env:VV_CERTPL_MIN) { [int]$env:VV_CERTPL_MIN } else { 10000 }
$res.certpl = Update-PhishList $certUrl 'phishing-certpl.txt' $certMin 6 {
    param($r)
    # The list is rebuilt every few minutes, so the server's own Last-Modified is the makers' date.
    $lm = $r.Headers['Last-Modified']
    if (-not $lm) { return $null }
    [DateTimeOffset]::Parse([string]$lm, [Globalization.CultureInfo]::InvariantCulture).ToUnixTimeSeconds()
}
$res | ConvertTo-Json -Compress -Depth 4
