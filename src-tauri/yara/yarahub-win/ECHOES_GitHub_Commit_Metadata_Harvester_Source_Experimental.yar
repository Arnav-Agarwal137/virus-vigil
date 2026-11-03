rule ECHOES_GitHub_Commit_Metadata_Harvester_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Python source for harvesting GitHub repository commit-author and committer email metadata"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/07-developer-target-harvesting/"
        yarahub_reference_md5 = "d7e9c66051029ce95a5db3ff8e86c5bf"
        yarahub_uuid = "bf810c3e-4d00-453a-8ef8-5ad796186c1f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "static collector-source identification; no addresses, credentials or database contents are included"
    strings:
        $api = "https://api.github.com" ascii
        $stars = "stars:" ascii
        $branches = "MAX_BRANCHES_PER_REPO = 20" ascii
        $search = "MAX_SEARCH_RESULTS = 1000" ascii
        $author = "author_email" ascii
        $committer = "committer_email" ascii
        $sqlite = "sqlite3" ascii
    condition:
        filesize < 256KB and all of ($api, $stars, $branches, $search, $author, $committer, $sqlite)
}
