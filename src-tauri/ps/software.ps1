# Virus Vigil - installed programs whose OLD versions were used in real attacks. READ-ONLY, no admin.
# Cut-offs verified 24 Sep 2026 against NVD + the CISA Known Exploited Vulnerabilities list:
#   WinRAR  < 7.13  (CVE-2025-8088, fixed 7.13; also CVE-2023-38831 fixed 6.23, CVE-2025-6218 fixed 7.12) - ransomware use "Known"
#   7-Zip   < 24.09 (CVE-2025-0411, Mark-of-the-Web bypass) - the only 7-Zip entry in KEV
#   Java 8  - not a version rule: most people no longer need it at all (info only)
# Only installed copies are seen (uninstall keys); a portable copy in a folder is not. Output: one JSON line. ASCII only.
# Test mode: $env:VV_SOFTWARE_CASES = a JSON file of [{name, version}] judged INSTEAD of the registry.
$ErrorActionPreference = 'Stop'
$out = [ordered]@{ ok = $true; items = @(); read = 0; error = $null }

function ConvertTo-Ver([string]$s) {
    if (-not $s) { return $null }
    $m = [regex]::Match($s, '\d+(\.\d+){0,3}')
    if (-not $m.Success) { return $null }
    $t = $m.Value; if ($t -notmatch '\.') { $t += '.0' }
    try { return [version]$t } catch { return $null }
}

$rules = @(
    @{ id = 'winrar'; match = '^WinRAR(\s|$)'; min = [version]'7.13'; minText = '7.13'; cve = 'CVE-2025-8088, CVE-2023-38831'; url = 'https://www.win-rar.com/download.html' },
    @{ id = '7zip'; match = '^7-Zip(\s|$)'; min = [version]'24.9'; minText = '24.09'; cve = 'CVE-2025-0411'; url = 'https://www.7-zip.org/download.html' },
    @{ id = 'java'; match = '^Java(\(TM\))?\s+\d+\s+Update\s+\d+'; min = $null; cve = $null; url = 'https://www.java.com/en/download/uninstalltool.jsp' }
)
$seen = @{}

function Add-Entry([string]$name, [string]$version, [string]$scope) {
    $out.read++
    foreach ($r in $rules) {
        if ($name -notmatch $r.match) { continue }
        $key = $r.id + '|' + $name + '|' + $version
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        # 7-Zip writes "24.09" (= 24.9 as a version); compare minor numerically, not as text.
        $v = ConvertTo-Ver $version
        # From the NAME only a dotted number after the program's own name: "7-Zip" is not
        # version 7, and "WinRAR (64-bit)" is not version 64. Unreadable stays $null (said, not graded).
        if (-not $v) {
            $m = [regex]::Match(($name -replace $r.match, ''), '\d+\.\d+(\.\d+){0,2}')
            if ($m.Success) { $v = ConvertTo-Ver $m.Value }
        }
        $old = if ($r.min -and $v) { $v -lt $r.min } else { $null }
        $out.items += [ordered]@{
            id = $r.id; name = $name; version = $version
            parsed = if ($v) { $v.ToString() } else { $null }; minSafe = $r.minText
            old = $old; cve = $r.cve; url = $r.url; scope = $scope
        }
    }
}

try {
    if ($env:VV_SOFTWARE_CASES) {
        # Assigned first: PowerShell 5.1 passes a JSON array down the pipe as ONE object.
        $cases = Get-Content -Raw -LiteralPath $env:VV_SOFTWARE_CASES | ConvertFrom-Json
        foreach ($c in $cases) {
            Add-Entry ([string]$c.name) ([string]$c.version) 'test'
        }
    } else {
        $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        foreach ($k in $keys) {
            if (-not (Test-Path -LiteralPath $k)) { continue }
            foreach ($e in @(Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) {
                $p = Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction SilentlyContinue
                if (-not $p -or -not $p.DisplayName) { continue }
                Add-Entry ([string]$p.DisplayName) ([string]$p.DisplayVersion) $(if ($k -like 'HKCU*') { 'user' } else { 'machine' })
            }
        }
    }
} catch {
    $out.ok = $false; $out.error = $_.Exception.Message
}
$out | ConvertTo-Json -Depth 5 -Compress
