# Virus Vigil - Have I Been Pwned "range" look-up. Prints ONE JSON object.
# ASCII only. Receives ONLY the first 5 characters of a SHA-1 hash ($env:VV_PREFIX, checked by
# Rust to be exactly 5 hex characters). The password itself never reaches this script.
# The API returns every leaked hash starting with those 5 characters; the page compares.
# "Add-Padding" makes every answer a similar size, so even the reply's length reveals nothing.
$ErrorActionPreference = 'SilentlyContinue'
$prefix = [string]$env:VV_PREFIX
if ($prefix -notmatch '^[0-9A-F]{5}$') { '{"ok":false,"error":"bad prefix"}'; return }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$res = [ordered]@{ ok = $false; error = $null; body = $null }
for ($try = 1; $try -le 3 -and -not $res.ok; $try++) {
    try {
        $r = Invoke-WebRequest -Uri "https://api.pwnedpasswords.com/range/$prefix" -UseBasicParsing -TimeoutSec 20 `
            -Headers @{ 'Add-Padding' = 'true' } -UserAgent 'VirusVigil (personal security helper)'
        $res.body = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())
        $res.ok = $true; $res.error = $null
    } catch { $res.error = [string]$_.Exception.Message; Start-Sleep -Seconds (2 * $try) }
}
$res | ConvertTo-Json -Compress
