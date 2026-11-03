# Virus Vigil - the deep check. Runs ELEVATED (the app asks Windows first) and is READ-ONLY:
# it changes nothing. ASCII only. Writes its JSON to -Out.
# What it reads, all things an ordinary account is refused (measured 24 Sep on the owner's laptop):
#  1. Defender's exclusion list - malware adds its own folder here so Defender never looks.
#  2. Hidden scheduled tasks - a task whose "SD" (security descriptor) value was deleted from the
#     TaskCache\Tree key vanishes from Task Scheduler and schtasks but still runs ("Tarrask").
#  3. Prefetch - Windows' own record of programs that ran. Programs run from Downloads, Temp or
#     straight out of a zip/rar are how the 12 Sep fake-game installer got in.
# -PrefetchDir / -TreeRoot / -ExclusionsFile exist for the test suite (fixtures, no admin); the app never passes them.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Plan = '',
    [string]$PrefetchDir = "$env:SystemRoot\Prefetch",
    [string]$TreeRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree',
    [string]$ExclusionsFile = ''
)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ ok = $true; exclusions = $null; hiddenTasks = $null; prefetch = $null; errors = @() }

# 1. Exclusions. Without admin Defender answers with this sentence instead of the list.
try {
    $mp = if ($ExclusionsFile) { Get-Content -LiteralPath $ExclusionsFile -Raw -Encoding UTF8 | ConvertFrom-Json } else { Get-MpPreference }
    $list = [ordered]@{}
    foreach ($k in @('ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress')) {
        $v = @($mp.$k | Where-Object { $_ })
        if ($v | Where-Object { [string]$_ -like 'N/A*' }) { throw 'Defender would not show its exclusions (not running as administrator)' }
        $list[$k] = @($v | ForEach-Object { [string]$_ })
    }
    $result.exclusions = $list
} catch { $result.errors += ('exclusions: ' + $_.Exception.Message) }

# 2. Hidden tasks: every key under Tree that has an Id (a real task, not a folder) but no SD.
try {
    $root = Get-Item -LiteralPath $TreeRoot
    $hidden = @()
    $count = 0
    foreach ($k in @(Get-ChildItem -LiteralPath $TreeRoot -Recurse)) {
        $names = $k.GetValueNames()
        if ($names -notcontains 'Id') { continue }
        $count++
        if ($names -notcontains 'SD') {
            $rel = $k.Name.Substring($root.Name.Length)
            $hidden += [ordered]@{ path = $rel; id = [string]$k.GetValue('Id'); index = $k.GetValue('Index') }
        }
    }
    $result.hiddenTasks = $hidden
    $result.tasksRead = $count
} catch { $result.errors += ('tasks: ' + $_.Exception.Message) }

# 3. Prefetch. Windows 10/11 files start "MAM\x04" + uncompressed size, then Xpress-Huffman data;
#    ntdll decompresses it. Rather than trust version-specific offsets, the decompressed file is
#    searched for the paths it records (\VOLUME{...}\... or \DEVICE\HARDDISKVOLUMEn\...), and the
#    one ending in the program's own name is its full path.
try {
    if (-not ('VV.Mam' -as [type])) {
        Add-Type -Namespace VV -Name Mam -MemberDefinition @'
[DllImport("ntdll.dll")] public static extern uint RtlGetCompressionWorkSpaceSize(ushort fmt, out uint bufWs, out uint fragWs);
[DllImport("ntdll.dll")] public static extern uint RtlDecompressBufferEx(ushort fmt, byte[] dst, int dstSize, byte[] src, int srcSize, out int finalSize, byte[] ws);
'@
    }
    # Run straight from Downloads, or out of an archive (Explorer's Temp1_x.zip, WinRAR's Rar$EX, 7-Zip's 7zO...).
    # Plain Temp is NOT flagged: every normal installer unpacks itself there.
    $risky = '\\DOWNLOADS\\|\\RAR\$EX|\\7Z[A-Z0-9]{4,}\\|\\TEMP1_|\.ZIP\\|\.RAR\\|\.7Z\\'
    $runs = @()
    $read = 0; $unread = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $PrefetchDir -Filter '*.pf' -File)) {
        try {
            $b = [System.IO.File]::ReadAllBytes($f.FullName)
            if ($b.Length -gt 8 -and $b[0] -eq 0x4D -and $b[1] -eq 0x41 -and $b[2] -eq 0x4D) {
                $size = [BitConverter]::ToInt32($b, 4)
                $bw = [uint32]0; $fw = [uint32]0
                [void][VV.Mam]::RtlGetCompressionWorkSpaceSize(4, [ref]$bw, [ref]$fw)
                $ws = New-Object byte[] ([int]$fw); $dst = New-Object byte[] $size; $got = 0
                $src = New-Object byte[] ($b.Length - 8); [Array]::Copy($b, 8, $src, 0, $src.Length)
                $st = [VV.Mam]::RtlDecompressBufferEx(4, $dst, $size, $src, $src.Length, [ref]$got, $ws)
                if ($st -ne 0) { throw ('decompress status 0x{0:X8}' -f $st) }
                $b = $dst
            }
            if ([Text.Encoding]::ASCII.GetString($b, 4, 4) -ne 'SCCA') { throw 'not a prefetch file' }
            $exe = ([Text.Encoding]::Unicode.GetString($b, 16, 60) -split "`0")[0]
            # Both byte alignments: the strings block is normally even, but nothing here should depend on it.
            $paths = @(foreach ($o in 0, 1) { [regex]::Matches([Text.Encoding]::Unicode.GetString($b, $o, $b.Length - $o), '\\(?:VOLUME\{[^}]+\}|DEVICE\\HARDDISKVOLUME\d+)\\[^\x00]+') | ForEach-Object { $_.Value } })
            $own = $paths | Where-Object { $_.ToUpper().EndsWith('\' + $exe.ToUpper()) } | Select-Object -First 1
            $read++
            if ($own -and $own.ToUpper() -match $risky) {
                $rest = $own -replace '^\\(VOLUME\{[^}]+\}|DEVICE\\HARDDISKVOLUME\d+)', ''
                # Still on C:? Then say whether its maker signed it. (Other drives: not guessed.)
                $sig = $null
                if (Test-Path -LiteralPath ('C:' + $rest)) { $sig = [string](Get-AuthenticodeSignature -LiteralPath ('C:' + $rest)).Status }
                $runs += [ordered]@{ exe = $exe; path = $rest; lastRun = $f.LastWriteTime.ToString('o'); pf = $f.Name; stillThere = ($null -ne $sig); signature = $sig }
            }
        } catch { $unread++ }
    }
    $result.prefetch = [ordered]@{ read = $read; unread = $unread; risky = @($runs | Sort-Object { $_.lastRun } -Descending) }
} catch { $result.errors += ('prefetch: ' + $_.Exception.Message) }

if ($result.errors.Count -gt 0) { $result.ok = $false }
[System.IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 6 -Compress), (New-Object System.Text.UTF8Encoding($false)))
