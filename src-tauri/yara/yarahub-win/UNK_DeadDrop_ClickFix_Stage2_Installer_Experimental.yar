rule UNK_DeadDrop_ClickFix_Stage2_Installer_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "ClickFix second-stage installer or a first-stage file carrying its encoded body"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "0f56c4169bb633b6fe18e11256cd99ed"
        yarahub_uuid = "848e16e6-0535-4415-a466-549eeae5997d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext installer or a small wrapper embedding the known base64 anchors"
    strings:
        $work = "deepfake_guard_work" ascii wide
        $fallback = "GUARD_STORE_FALLBACK" ascii wide
        $runner = "deepfake_guard_run.sh" ascii wide
        $log = "guard-install-log" ascii wide
        $encoded_guard = "ZGVlcGZha2VfZ3VhcmQ" ascii
        $encoded_fallback = "R1VBUkRfU1RPUkVfRkFMTEJBQ0s" ascii
    condition:
        filesize < 2MB and (2 of ($work, $fallback, $runner, $log) or
                            all of ($encoded_guard, $encoded_fallback))
}
