rule UNK_DeadDrop_GitLab_Resolver_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Overlord-based campaign component naming the mutable GitLab server-list resolver"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/06-gitlab-dead-drop-infrastructure/"
        yarahub_reference_md5 = "15e2f4004a4c896636e1ee8948cc63e8"
        yarahub_uuid = "242e74e9-bb3d-4a8d-8f9a-a21ebac61cae"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "source or unpacked binary; historical resolver path, not a live domain blocklist"
    strings:
        $project = "gitlab.com/drop-indexing/tasks" ascii wide nocase
        $path = "/-/raw/main/config.json" ascii wide
        $setting = "OVERLORD_SERVER_RAW" ascii wide
    condition:
        filesize < 64MB and all of them
}
