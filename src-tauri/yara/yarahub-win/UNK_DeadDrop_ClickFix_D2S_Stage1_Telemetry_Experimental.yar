rule UNK_DeadDrop_ClickFix_D2S_Stage1_Telemetry_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Historical D2S build marker in a ClickFix stage-one file"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "1ba1d7e4a845bdb213f56418972d584f"
        yarahub_uuid = "4be6545a-4fcb-4efc-a2bd-321cb1ee3171"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "historical file-content identification only; hostname string is time-bound"
    strings:
        $host = "d2saitrade.ink" ascii nocase
        $event1 = "/guard-launcher-result" ascii
        $event2 = "/guard-install-log" ascii
        $api = "api.fallbaav.ink" ascii nocase
        $family = "deepfake_guard" ascii
    condition:
        filesize < 1MB and $host and 1 of ($event*) and ($api or $family)
}
