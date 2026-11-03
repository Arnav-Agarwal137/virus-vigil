rule UNK_DeadDrop_ClickFix_Stage1_Dropper_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "ClickFix first-stage dropper with recovered installer telemetry and launcher guards"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "f51e586f10d9be31d411e90f588032f6"
        yarahub_uuid = "88d4e81c-94da-4e81-9490-00d34ed9be35"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "small Windows or Unix first-stage files; names and lure brands are not required"
    strings:
        $telemetry = "guard-launcher-result" ascii wide
        $platform = "X-Guard-Platform" ascii wide
        $guard = "deepfake_guard" ascii wide
        $detached = "NVDG_DETACHED" ascii wide
        $hidden = "NVDG_HIDDEN" ascii wide
    condition:
        filesize < 1MB and $telemetry and 1 of ($detached, $hidden) and
        1 of ($platform, $guard)
}
