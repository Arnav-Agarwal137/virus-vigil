rule SCRIPT_Dropper_Unknown_ForgeAuto_5318a8c0
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "5318a8c0007e57e4cabf87ad02375cbf4df5e1b3ef9c2e631a41dc0bfc191db7"
        yarahub_uuid = "065a83ca-f6d9-4fd2-b864-063f2d876975"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "45567941e4184b04ab49482c58d15e04"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "[ -d \"$d\" ] || continue" ascii
        $s1 = "cd \"$d\" 2>/dev/null || continue" ascii
        $s2 = "if command -v setsid >/dev/null 2>&1; then" ascii
        $s3 = "$B/bins/1e" ascii
        $s4 = "$(basename" ascii
        $s5 = "Land dropper served as $LAND/i (see gitea_v4 land_fetch_sh)." ascii
        $s6 = "$1 = land base (http://host:port). $2 = source tag." ascii
        $s7 = "Idempotent: mutex OR recent stamp => do nothing (stops download storms)." ascii
        $s8 = "Never kill persist copies (.ext4* / .kworker* / $HOME/.cache/...)." ascii
        $s9 = "Deploy: cp gitea_stage2.sh" ascii
        $s10 = "scanner /var/cache/.mirror/i and CNC httpdrop/i" ascii
        $s11 = "export PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin" ascii
        $s12 = "B=\"${1:-http://80.87.206.86:18081}\"" ascii
        $s13 = "T=\"${2:-app-gitea}\"" ascii
        $s14 = "Prefer a writable stamp dir owned by this uid." ascii
        $s15 = "${HOME:+$HOME/.cache} \\" ascii
        $s16 = "/data/gitea/.cache /var/lib/gitea/.cache /home/git/.cache \\" ascii
        $s17 = "[ -n \"$d\" ] || continue" ascii
        $s18 = "mkdir -p \"$d\" 2>/dev/null || continue" ascii
        $s19 = "touch \"$d/.boat_wtest\" 2>/dev/null || continue" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s12)
}
