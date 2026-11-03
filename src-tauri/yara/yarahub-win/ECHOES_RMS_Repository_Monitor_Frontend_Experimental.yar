rule ECHOES_RMS_Repository_Monitor_Frontend_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recovered rms-platform repository-availability monitoring component"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/08-administration-platform/"
        yarahub_reference_md5 = "b6459a0ea5ca93618a7f50339117d2b5"
        yarahub_uuid = "009de5bf-ea30-41eb-9118-b417aa1b9b82"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "frontend source component identification; not proof of backend activity"
    strings:
        $endpoint = "github-jobs-check" ascii nocase
        $clone_url = "clone_url" ascii
        $status = "httpStatus" ascii
        $warming = "warming_up" ascii
        $not_found = "httpStatus === 404" ascii
        $refresh = "refresh" ascii nocase
    condition:
        filesize < 512KB and $endpoint and $clone_url and $status and
        $warming and $not_found and $refresh
}
