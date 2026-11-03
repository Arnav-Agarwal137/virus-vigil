rule ECHOES_Target_Pool_Merge_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Python source that partitions harvested addresses into named mailing pools"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/07-developer-target-harvesting/"
        yarahub_reference_md5 = "6227eb6d7b594bf1f99010583678cdef"
        yarahub_uuid = "b96e31e4-16fb-4ab4-936c-ce43967d5173"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "static source identification; no database contents or addresses are included"
    strings:
        $splitter = "ANTISPAM_DOMAINS" ascii
        $predicate = "def is_antispam(email: str)" ascii
        $antispam_db = "results_antispam.db" ascii
        $safe_db = "results_safe.db" ascii
        $table = "CREATE TABLE IF NOT EXISTS emails" ascii
        $insert = "INSERT OR IGNORE INTO emails" ascii
    condition:
        filesize < 64KB and all of them
}
