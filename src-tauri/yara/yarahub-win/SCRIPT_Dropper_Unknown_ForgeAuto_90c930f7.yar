rule SCRIPT_Dropper_Unknown_ForgeAuto_90c930f7
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617"
        yarahub_uuid = "7dc54ed9-832f-44c8-8f35-f6c8d10d8222"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5cced002f900545719e0a86fa7d8c9bb"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "$(basename" ascii
        $s1 = "SRV=\"http://176.65.139.206\"" ascii
        $s2 = "detect_arch() {" ascii
        $s3 = "arch=$(uname -m | tr '[:upper:]' '[:lower:]')" ascii
        $s4 = "BIN_NAME=\"kworkerd-rcu\"" ascii
        $s5 = "x86_64|amd64|x64|x86-64)            BIN_NAME=\"kworkerd\" ;;" ascii
        $s6 = "i386|i586|i686|i786|x86|ia32)        BIN_NAME=\"kworkerd-events\" ;;" ascii
        $s7 = "armv4*|armv4l*)                       BIN_NAME=\"kworkerd-irq\" ;;" ascii
        $s8 = "armv5*|armv5l*|armv5te*)              BIN_NAME=\"kworkerd-irq-bal\" ;;" ascii
        $s9 = "armv6*|armv6l*)                       BIN_NAME=\"kworkerd-softirq\" ;;" ascii
        $s10 = "armv7*|armv7l*|armv8l*|armv8-compat)  BIN_NAME=\"kworkerd-blkcg\" ;;" ascii
        $s11 = "aarch64|arm64|armv8|armv8a|armv9*)    BIN_NAME=\"kworkerd-blkcg\" ;;" ascii
        $s12 = "mipsel|mips32el|mips64el|mips64r2el)  BIN_NAME=\"kworkerd-rcu\" ;;" ascii
        $s13 = "if is_le; then BIN_NAME=\"kworkerd-rcu\"; else BIN_NAME=\"kworkerd-netns-rt\"; fi ;;" ascii
        $s14 = "if is_le; then BIN_NAME=\"kworkerd-rcu\"; else BIN_NAME=\"kworkerd-netns\"; fi ;;" ascii
        $s15 = "ppc|powerpc|ppc32|ppc64|ppc64le)      BIN_NAME=\"kworkerd-writeback\" ;;" ascii
        $s16 = "sh4|sh4a|sh)                          BIN_NAME=\"kworkerd-crypto\" ;;" ascii
        $s17 = "sparc|sparc32|sparc64)                BIN_NAME=\"kworkerd-mm\" ;;" ascii
        $s18 = "find_writable_dir() {" ascii
        $s19 = "for dir in /dev/shm /tmp /var/system /mnt /var/tmp /run /dev; do" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s1)
}
