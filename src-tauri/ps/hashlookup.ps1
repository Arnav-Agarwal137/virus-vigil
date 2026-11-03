# Virus Vigil - online fingerprint look-up (CIRCL hashlookup). Prints ONE JSON array.
# ASCII only. Receives ONLY SHA-256 fingerprints ($env:VV_HASHES, comma-separated, each checked by
# Rust AND here to be 64 lowercase hex characters). No file, name or path ever reaches this script.
# Asks 8 at a time; if a whole first batch gets no answer at all, the rest are not tried.
# Every fingerprint gets a row: {sha, status, body}; status 0 = no answer, body = the reason.
$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http
$shas = @([string]$env:VV_HASHES -split ',' | Where-Object { $_ -cmatch '^[0-9a-f]{64}$' })
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromSeconds(15)
$client.DefaultRequestHeaders.UserAgent.ParseAdd('VirusVigil/0.1')
$rows = New-Object System.Collections.ArrayList
$dead = $false
for ($i = 0; $i -lt $shas.Count; $i += 8) {
    $batch = @($shas[$i..([Math]::Min($i + 7, $shas.Count - 1))])
    if ($dead) {
        foreach ($s in $batch) { [void]$rows.Add([ordered]@{ sha = $s; status = 0; body = 'not tried: the checker could not be reached' }) }
        continue
    }
    $tasks = @($batch | ForEach-Object { $client.GetAsync("https://hashlookup.circl.lu/lookup/sha256/$_") })
    try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks) } catch { }
    $answered = 0
    for ($k = 0; $k -lt $batch.Count; $k++) {
        $t = $tasks[$k]
        if ($t.Status -eq 'RanToCompletion') {
            $answered++
            $body = $t.Result.Content.ReadAsStringAsync().Result
            [void]$rows.Add([ordered]@{ sha = $batch[$k]; status = [int]$t.Result.StatusCode; body = [string]$body })
        } else {
            $why = 'no connection'
            if ($t.Exception) { $why = [string]$t.Exception.GetBaseException().Message }
            [void]$rows.Add([ordered]@{ sha = $batch[$k]; status = 0; body = $why })
        }
    }
    if ($i -eq 0 -and $answered -eq 0) { $dead = $true }
}
$client.Dispose()
if ($rows.Count -eq 0) { '[]'; return }
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
