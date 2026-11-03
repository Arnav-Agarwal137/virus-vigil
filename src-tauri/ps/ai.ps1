# Virus Vigil - ask the local AI (Ollama on THIS laptop, 127.0.0.1 only). Prints ONE JSON object.
# ASCII only. The question comes in $env:VV_Q. Nothing leaves the laptop.
# Only vetted models are used (24 Sep 2026 test, 6 novice questions): qwen3:14b answered all six
# correctly (6-13 s on an RTX 4070 laptop); qwen3:8b was fast but invented facts (called an APK a
# Windows file); phi4-mini invented a helpline number. So: 14b first, 8b only if 14b is absent.
$ErrorActionPreference = 'SilentlyContinue'
$VETTED = @('qwen3:14b', 'qwen3:8b')
$base = 'http://127.0.0.1:11434'
$q = [string]$env:VV_Q
if ($q.Length -gt 2000) { $q = $q.Substring(0, 2000) }

$system = @'
You are Vigil, the calm helper inside the Virus Vigil app on a Windows laptop. The person is an adult in India with no computer background. Talk to them as an equal.

How to answer:
- Plain words. If you must use a technical word, explain it in the same sentence.
- At most 110 words. Short numbered steps are better than paragraphs.
- Be direct and kind. No scare words, no jokes, no sign-off like "Stay safe!".

What Vigil itself can do (mention one only when it truly helps; never invent others):
- "Check my laptop": checks that Windows security SETTINGS and browser settings are switched on. It does NOT scan files for viruses.
- "Was I hacked before?": reads what Windows Defender has caught, and walks through your accounts.
- "Is this safe?": paste a link or a message into the box. A FILE (including an Android app file) is not pasted: it is checked with the paper-clip button next to the box.
- Ask "What starts by itself?", "Check my browser add-ons" or "Has my password leaked?".
- Vigil does not scan for viruses itself. For a full virus scan: Windows Security, Virus & threat protection, Scan options, Full scan.

Safety rules you must never break:
- Never tell anyone to switch off antivirus, the firewall or Windows security, for any reason. Cracked games and "free" paid software are a top way viruses get in - say so.
- Never ask for, or tell people to share, a password, OTP, PIN, CVV or screen-sharing access. Banks never ask for these.
- Only when money was lost or an account was taken over: call 1930 (India's cyber-crime helpline, dial just 1930) at once, report at cybercrime.gov.in, and call the bank to block the card or UPI. The first hours matter.
- If you are not sure, say so. Never make up facts, phone numbers, laws or app features.
- Do not judge a link, message or file you cannot see - ask them to paste it into Vigil's box.
'@

$res = [ordered]@{ ok = $false; error = $null; model = $null; answer = $null; secs = $null }
try {
    $tags = Invoke-RestMethod -Uri "$base/api/tags" -TimeoutSec 3
} catch { $res.error = 'no-ollama'; $res | ConvertTo-Json -Compress; return }
$have = @($tags.models | ForEach-Object { $_.name })
$model = $VETTED | Where-Object { $have -contains $_ } | Select-Object -First 1
if (-not $model) { $res.error = 'no-model'; $res | ConvertTo-Json -Compress; return }
$res.model = $model
if (-not $q.Trim()) { $res.ok = $true; $res | ConvertTo-Json -Compress; return }   # availability probe only

$body = @{
    # keep_alive 60s: Ollama's default keeps ~10 GB loaded for 5 minutes after one question
    # (24 Sep: that pushed a busy laptop out of memory and crashed the next checkup).
    model = $model; stream = $false; think = $false; keep_alive = '60s'
    messages = @(@{ role = 'system'; content = $system }, @{ role = 'user'; content = $q })
    options = @{ temperature = 0.3; num_predict = 350 }
} | ConvertTo-Json -Depth 5
$sw = [Diagnostics.Stopwatch]::StartNew()
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $r = Invoke-RestMethod -Uri "$base/api/chat" -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 120
    $res.answer = [string]$r.message.content
    $res.ok = [bool]$res.answer
    if (-not $res.ok) { $res.error = 'empty answer' }
} catch { $res.error = [string]$_.Exception.Message }
$res.secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
# Print ASCII only: PowerShell 5.1 writes stdout in the console code page, which would garble
# any non-English character (a rupee sign, a curly quote). JSON \uXXXX escapes survive any code page.
[regex]::Replace(($res | ConvertTo-Json -Compress), '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
