rule VShell_Implant_VSHCFG_Markers
{
    meta:
        author = "Daydream"
        description = "VShell implant, newer generation (seen as Go 1.26 Linux ELF): VSHCFG config markers, stage marker, key-derivation label and config field tags"
        date = "2026-10-10"
        yarahub_uuid = "54c6e5fb-c740-458f-941e-756dfc981d01"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "40cc6050f3daac09f962eda58cd63848"
    strings:
        $cfg2  = "VSHCFG02"
        $cfg1  = "VSHCFG01"
        $stage = "VSHSTAGE01"
        $mon   = "VSHMON_DIR"
        $kdf   = "vshell2|"
        $tag_addr   = "json:\"server_addr\""
        $tag_verify = "json:\"verify_key\""
    condition:
        filesize > 1MB and filesize < 40MB and
        $cfg2 and $cfg1 and 2 of ($stage, $mon, $kdf) and all of ($tag_*)
}
