# Virus Vigil - what starts by itself. Read-only, no admin. Prints ONE JSON object.
# ASCII only (Windows PowerShell 5.1 reads BOM-less files as ANSI).
# Sources: Run/RunOnce keys (HKLM, HKLM WOW6432Node, HKCU), both Startup folders,
# and enabled scheduled tasks outside \Microsoft\. Signature via Get-AuthenticodeSignature.
$ErrorActionPreference = 'SilentlyContinue'

# Task Manager's on/off switch. First byte even (02, 06) = enabled, odd (03, 07) = disabled.
function Get-Approved($hive, $sub, $name) {
    $k = "$hive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub"
    $v = (Get-ItemProperty -Path $k -Name $name -ErrorAction SilentlyContinue).$name
    if ($null -eq $v -or $v.Length -lt 1) { return $true }
    return (($v[0] -band 1) -eq 0)
}

# Pull the program path out of a command line: "C:\a b\x.exe" -arg, C:\x.exe -arg, or C:\a b\x.exe -arg.
function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|vbs|js|ps1|dll|scr|lnk))(\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# Programs that only launch something else; the real target is in the arguments.
$hosts = @('rundll32.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'conhost.exe')

$items = New-Object System.Collections.ArrayList

function Resolve-Program([string]$p) {
    if (-not $p -or [IO.Path]::IsPathRooted($p)) { return $p }
    $g = Get-Command -Name $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($g) { return $g.Source }
    return $p
}

# For a launcher: the script file it runs (-File x, or the first argument that names a script).
function Get-LaunchTarget([string]$cmd, [string]$prog) {
    $c = [Environment]::ExpandEnvironmentVariables($cmd)
    $m = [regex]::Match($c, '-File\s+(?:"([^"]+)"|''([^'']+)''|(\S+))', 'IgnoreCase')
    if ($m.Success) { return ($m.Groups[1].Value + $m.Groups[2].Value + $m.Groups[3].Value) }
    $at = if ($prog) { $c.IndexOf($prog, [StringComparison]::OrdinalIgnoreCase) } else { -1 }
    $rest = $c
    if ($at -ge 0) {
        $rest = $c.Substring([Math]::Min($c.Length, $at + $prog.Length))
        # Only the quote that CLOSES a quoted program path is dropped, never an argument's opening quote.
        if ($at -gt 0 -and $c[$at - 1] -eq '"' -and $rest.StartsWith('"')) { $rest = $rest.Substring(1) }
    }
    $ext = '(?:ps1|vbs|vbe|js|jse|bat|cmd|py|pyw|hta|dll|wsf)'
    $m = [regex]::Match($rest, "(?:""([^""]+\.$ext)""|'([^']+\.$ext)'|([^\s""']+\.$ext))(?![\w.])", 'IgnoreCase')
    # A web address is not a file on this laptop (Get-Flags reports it as "web" instead),
    # and must never read as a missing file - that would file a live launcher under "leftovers".
    if ($m.Success -and ($m.Value.Trim('"', "'") -notmatch '^[a-z][a-z0-9+.-]*://')) {
        return ($m.Groups[1].Value + $m.Groups[2].Value + $m.Groups[3].Value)
    }
    return $null
}

function Add-Item($name, $source, $cmd, $enabled) {
    $path = Resolve-Program (Get-ExePath $cmd)
    $exists = [bool]($path -and (Test-Path -LiteralPath $path))
    $sig = $null; $pub = $null
    if ($exists) {
        $s = Get-AuthenticodeSignature -LiteralPath $path
        $sig = [string]$s.Status
        if ($s.SignerCertificate) { $pub = ($s.SignerCertificate.Subject -replace '^CN="?([^",]+)"?.*$', '$1') }
    }
    $leaf = if ($path) { Split-Path -Leaf $path } else { '' }
    $launcher = ($hosts -contains $leaf.ToLower()) -or ($hosts -contains ($leaf.ToLower() + '.exe'))
    $target = $null; $targetExists = $null
    if ($launcher) {
        $target = Get-LaunchTarget ([string]$cmd) (Get-ExePath $cmd)
        if ($target) { $targetExists = [bool](Test-Path -LiteralPath $target) }
    }
    $f = Get-Flags ([string]$cmd) $path $target
    [void]$items.Add([ordered]@{
        name = [string]$name; source = $source; command = [string]$cmd; path = $path
        exists = $exists; signature = $sig; publisher = $pub; enabled = [bool]$enabled
        launcher = $launcher; target = $target; targetExists = $targetExists
        encoded = $f.encoded; web = $f.web; tempPlace = $f.tempPlace
    })
}

# Raw red-flag facts; the page decides what they mean.
function Get-Flags([string]$cmd, $path, $target) {
    $x = [Environment]::ExpandEnvironmentVariables($cmd)
    $where = (@($path, $target) -join ' ')
    return @{
        encoded = [bool]($x -match '\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}')
        # A plain link is not a flag (a reminder's text may hold one); fetching code is.
        web = [bool]($x -match 'DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Net\.WebClient|bitsadmin|Start-BitsTransfer|(mshta|regsvr32)(\.exe)?\W.*https?://|curl.*\|\s*(iex|sh)')
        tempPlace = [bool]($where -match '\\(Temp|Downloads)\\|\\Users\\Public\\|\\ProgramData\\[^\\]+\.(exe|dll|ps1|vbs|js)$')
    }
}

# Test mode: parse the command lines in $env:VV_PARSE_CASES (a JSON file) and print what was read.
if ($env:VV_PARSE_CASES) {
    $cases = Get-Content -Raw -LiteralPath $env:VV_PARSE_CASES | ConvertFrom-Json
    $res = foreach ($c in $cases) {
        $prog = Get-ExePath $c
        $leaf = if ($prog) { (Split-Path -Leaf $prog).ToLower() } else { '' }
        $isHost = ($hosts -contains $leaf) -or ($hosts -contains ($leaf + '.exe'))
        $t = if ($isHost) { Get-LaunchTarget $c $prog } else { $null }
        $f = Get-Flags $c $prog $t
        [ordered]@{ program = $prog; target = $t; encoded = $f.encoded; web = $f.web; tempPlace = $f.tempPlace }
    }
    ConvertTo-Json -InputObject @($res) -Depth 3 -Compress
    return
}

$runKeys = @(
    @{ key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; hive = 'HKLM:'; sub = 'Run'; src = 'all users' },
    @{ key = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; hive = 'HKLM:'; sub = 'Run32'; src = 'all users' },
    @{ key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; hive = 'HKCU:'; sub = 'Run'; src = 'you' },
    @{ key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; hive = $null; sub = $null; src = 'all users, once' },
    @{ key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; hive = $null; sub = $null; src = 'you, once' }
)
foreach ($r in $runKeys) {
    $p = Get-ItemProperty -Path $r.key -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    foreach ($prop in $p.PSObject.Properties) {
        if ($prop.Name -like 'PS*') { continue }
        $en = if ($r.hive) { Get-Approved $r.hive $r.sub $prop.Name } else { $true }
        Add-Item $prop.Name $r.src ([string]$prop.Value) $en
    }
}

$shell = New-Object -ComObject WScript.Shell
$folders = @(
    @{ dir = [Environment]::GetFolderPath('Startup'); hive = 'HKCU:'; src = 'your Startup folder' },
    @{ dir = [Environment]::GetFolderPath('CommonStartup'); hive = 'HKLM:'; src = 'everyone''s Startup folder' }
)
foreach ($f in $folders) {
    if (-not $f.dir -or -not (Test-Path -LiteralPath $f.dir)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $f.dir -File) {
        if ($file.Name -eq 'desktop.ini') { continue }
        $cmd = $file.FullName
        if ($file.Extension -eq '.lnk') {
            $lnk = $shell.CreateShortcut($file.FullName)
            if ($lnk.TargetPath) { $cmd = '"' + $lnk.TargetPath + '" ' + $lnk.Arguments }
        }
        Add-Item $file.BaseName $f.src $cmd (Get-Approved $f.hive 'StartupFolder' $file.Name)
    }
}

$taskCount = 0
foreach ($t in Get-ScheduledTask) {
    if ($t.TaskPath -like '\Microsoft\*') { continue }
    if ($t.State -eq 'Disabled') { continue }
    foreach ($a in @($t.Actions)) {
        if (-not $a.Execute) { continue }
        $taskCount++
        $exe = [string]$a.Execute
        $cmd = if ($exe.Contains(' ') -and -not $exe.StartsWith('"')) { '"' + $exe + '" ' + $a.Arguments } else { $exe + ' ' + $a.Arguments }
        Add-Item ($t.TaskPath.TrimEnd('\') + '\' + $t.TaskName).TrimStart('\') 'scheduled task' $cmd.Trim() $true
    }
}

[ordered]@{ ok = $true; time = (Get-Date).ToString('o'); items = $items; taskActions = $taskCount } | ConvertTo-Json -Depth 5 -Compress
