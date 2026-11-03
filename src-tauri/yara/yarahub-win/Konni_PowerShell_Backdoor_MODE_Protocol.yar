rule Konni_PowerShell_Backdoor_MODE_Protocol
{
    meta:
        description = "PowerShell backdoor that logs in to a PHP C2 with a MODE header (LI, GC, RP, UF, DF), polls for cmd, powershell, download and upload tasks, and solves a free-hosting aes.js anti-bot page for its __test cookie (final stage of a Konni-tagged shortcut, September 2026)"
        author = "Daydream"
        date = "2026-10-11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "19b116bc-1314-45ba-8d5b-82eddb506e58"
        yarahub_reference_md5 = "9eb39bfa5c5ba5493aa9ee3cfd63048d"
    strings:
        $m1 = "-Mode \"LI\"" ascii wide
        $m2 = "-Mode \"GC\"" ascii wide
        $m3 = "-Mode \"RP\"" ascii wide
        $m4 = "\"MODE\" = $Mode" ascii wide
        $f1 = "Get-ServerCommands" ascii wide
        $f2 = "Invoke-FireAndForgetTask" ascii wide
        $f3 = "Invoke-EnvironmentCheck" ascii wide
        $f4 = "Process-TaskCommands" ascii wide
        $f5 = "Get-UniqueDeviceId" ascii wide
        $v1 = "gServerURL" ascii wide
        $v2 = "sMutexUID" ascii wide
        $v3 = "chunk_base64" ascii wide
        $v4 = "placeholder_" ascii wide
    condition:
        filesize < 5MB and
        2 of ($m*) and 3 of ($f*) and 2 of ($v*)
}
