rule SCRIPT_Dropper_Unknown_ForgeAuto_8266e867
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_ps1, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "8266e8673e14155e0932de16e425809f0fece414733f7d4dbb7f02656fc32d27"
        yarahub_uuid = "5fd5c405-995e-4057-8ef7-bd3b73eba4c4"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_ps1"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "374f2d7cb5cfdf1f9e78d6da68f35d9f"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "New-Item -ItemType Directory -Force -Path $Dest | Out-Null" ascii
        $s1 = "Thin process helpers for Smart Build / packaging." ascii
        $s2 = "let pip/npm/vite show their own progress when possible." ascii
        $s3 = "Dot-source from build.ps1 / start-menu.ps1." ascii
        $s4 = "function Write-LongStepHint {" ascii
        $s5 = "Write-Host \"    $Message\"" ascii
        $s6 = "function Format-ProcessArgumentList {" ascii
        $s7 = "if ($null -eq $a) { continue }" ascii
        $s8 = "function Invoke-NativeWithHeartbeat {" ascii
        $s9 = "Run a native exe on the real console so pip/npm keep their own progress UI." ascii
        $s10 = "Returns only the exit code (stdout must not enter the PowerShell pipeline)." ascii
        $s11 = "[int]$HeartbeatSeconds = 12" ascii
        $s12 = "Write-LongStepHint $Activity" ascii
        $s13 = "$argString = Format-ProcessArgumentList -Args $ArgumentList" ascii
        $s14 = "$p = Start-Process -FilePath $FilePath `" ascii
        $s15 = "-ArgumentList $argString `" ascii
        $s16 = "-NoNewWindow -Wait -PassThru" ascii
        $s17 = "if ($null -eq $p) { return 1 }" ascii
        $s18 = "function Invoke-ProcessWithHeartbeat {" ascii
        $s19 = "Same as Invoke-NativeWithHeartbeat (name kept for build.ps1 callers)." ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
