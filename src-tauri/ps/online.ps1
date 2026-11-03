# Virus Vigil - post ONE question to the online AI (Groq). Prints ONE JSON object {status, body, error}.
# ASCII only. Rust already stripped personal details and built the whole request body ($env:VV_BODY);
# this script only posts it to the one fixed address below. Key: $env:VV_KEY, else the user's
# GROQ_API_KEY (read from the user scope too, so a Vigil started before the key was set still finds it).
$ErrorActionPreference = 'Stop'
$res = [ordered]@{ status = 0; body = ''; error = $null }
$key = [string]$env:VV_KEY
if (-not $key) { $key = [string][Environment]::GetEnvironmentVariable('GROQ_API_KEY', 'User') }
if (-not $key) { $res.error = 'no-key'; $res | ConvertTo-Json -Compress; return }
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$env:VV_BODY)
    $r = Invoke-WebRequest -Uri 'https://api.groq.com/openai/v1/chat/completions' -Method Post -Body $bytes `
        -ContentType 'application/json; charset=utf-8' -Headers @{ Authorization = "Bearer $key" } `
        -UseBasicParsing -TimeoutSec 45
    $res.status = [int]$r.StatusCode
    # Content is decoded by the response's charset; read the raw bytes as UTF-8 to be sure.
    $res.body = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())
} catch {
    $resp = $_.Exception.Response
    if ($resp) {
        $res.status = [int]$resp.StatusCode
        try { $res.body = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch {}
    } else { $res.error = [string]$_.Exception.Message }
}
# Print ASCII only: PowerShell 5.1 writes stdout in the console code page, which would garble
# any non-English character (a rupee sign, a curly quote). JSON \uXXXX escapes survive any code page.
[regex]::Replace(($res | ConvertTo-Json -Compress), '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
