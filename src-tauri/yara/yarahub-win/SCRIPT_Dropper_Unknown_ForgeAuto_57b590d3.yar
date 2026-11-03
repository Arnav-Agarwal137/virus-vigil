rule SCRIPT_Dropper_Unknown_ForgeAuto_57b590d3
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "57b590d336b79a0df8be3712bc9f205a8d41a87620d4bc6fc1df2a4a8cf3a9c9"
        yarahub_uuid = "45dda646-c46b-41a1-8418-6c214737193c"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "094425d49c87f8358546603e63468f05"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "while [[ $# -gt 0 ]]; do" ascii
        $s1 = "if command -v curl >/dev/null 2>&1; then" ascii
        $s2 = "if command -v wget >/dev/null 2>&1; then" ascii
        $s3 = "export POC_ALLOW_VM=\"${POC_ALLOW_VM:-1}\"" ascii
        $s4 = "${POC_ALLOW_VM:-1}" ascii
        $s5 = "aarch64|arm64)" ascii
        $s6 = "BASE=\"${BOT_FETCH_BASE:-http://217.60.195.161}\"" ascii
        $s7 = "probe BASE/<arch>" ascii
        $s8 = "Default: nohup/setsid background (survives telnet/SSH hangup), like field deploy.sh." ascii
        $s9 = "Use --fg for foreground exec (lab debug)." ascii
        $s10 = "BOT_FETCH_BASE / baked BASE   CNC http root" ascii
        $s11 = "BOT_OUT=./bot                 output path (relative to workdir unless absolute)" ascii
        $s12 = "BOT_WORKDIR=/tmp              force workdir (else first writable of the fallback list)" ascii
        $s13 = "BOT_BG=0 / --fg               foreground exec (default is background)" ascii
        $s14 = "BOT_RM=1                      after successful bg start, unlink the binary" ascii
        $s15 = "POC_ALLOW_VM=1                default on (VPS/KVM labs)" ascii
        $s16 = "if [[ \"${1:-}\" == http://* || \"${1:-}\" == https://* ]]; then" ascii
        $s17 = "BASE=\"http://$1\"" ascii
        $s18 = "if [[ -z \"${BASE:-}\" ]]; then" ascii
        $s19 = "many IoT/VPS shells land somewhere read-only." ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s6)
}
