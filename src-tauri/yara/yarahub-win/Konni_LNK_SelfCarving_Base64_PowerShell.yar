rule Konni_LNK_SelfCarving_Base64_PowerShell
{
    meta:
        description = "Windows shortcut that runs a base64 PowerShell script from its own arguments, which reads a decoy and an encrypted payload out of the .lnk file by offset and registers a scheduled task (Konni-tagged SANC_Nine_KBW_Seoul_Invitation.pdf.lnk, September 2026)"
        author = "Daydream"
        date = "2026-10-11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "0c550c2a-4993-477a-ad09-e4fa8e2427be"
        yarahub_reference_md5 = "d42d636edb1ea873f266c3c192f332a1"
    strings:
        $wrap1 = "FromBase64String($" wide
        $wrap2 = "[ScriptBlock]::Create($" wide
        $ps    = "powershell" wide nocase
        // inside the base64 script (the arguments are UTF-16 text)
        $b1 = "::OpenRead($" base64wide
        $b2 = ".Seek(0x" base64wide
        $b3 = "WriteAllBytes(" base64wide
        $b4 = "Register-ScheduledTask" base64wide
        $b5 = "Get-ChildItem $env:TEMP -Recurse" base64wide
        $b6 = "IsEnvironmentSuspicious" base64wide
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 20KB and filesize < 20MB and
        $ps and all of ($wrap*) and 4 of ($b*)
}
