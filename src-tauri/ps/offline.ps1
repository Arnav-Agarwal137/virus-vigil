# Virus Vigil - start Microsoft Defender Offline scan. Runs ELEVATED (the app asks Windows first).
# THE PC RESTARTS about a minute after this; the scan runs before Windows starts (~15 minutes),
# then Windows starts normally. Results appear in Windows Security > Protection history.
# The page asks the person first and tells them to save their work. ASCII only.
param([string]$Plan = '', [Parameter(Mandatory = $true)][string]$Out)
$r = [ordered]@{ ok = $true; errors = @() }
try { Start-MpWDOScan -ErrorAction Stop } catch { $r.ok = $false; $r.errors += $_.Exception.Message }
[System.IO.File]::WriteAllText($Out, ($r | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
