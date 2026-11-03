rule UNK_DeadDrop_Phase3_Home_Credential_Sweep_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "JavaScript stage-three source with bounded whole-home credential filename search"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        yarahub_reference_md5 = "61f3b3b608a24e4aee5571a85afd7451"
        yarahub_uuid = "addcbd9c-3809-4dd9-81b1-d834b327b90a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or decoded JavaScript; source markers do not establish collection or upload"
    strings:
        $regex = "CREDENTIAL_NAME_RE" ascii
        $phase3 = "phase3" ascii
        $budget1 = "DEFAULT_PHASE3_MAX_MS" ascii
        $budget2 = "DEFAULT_PHASE3_ROOT_MAX_MS" ascii
        $budget3 = "DEFAULT_WALK_MAX_DIRS" ascii
        $tcc = "macTccReadableCache" ascii
        $cloud = "CloudStorage" ascii
        $upload = "GUS_UPLOAD_CHUNK_SIZE" ascii
        $placeholder = "%%GUS_EMBED" ascii
        // Retained implementation syntax, not just markers quoted in research.
        $impl_match = /function matchesCredentialNamedSecretFile\(name\) *\{/ ascii
        $impl_budget = /function createPhase3Budget\(opts\) *\{/ ascii
        $impl_collect = /function collectPhase3DevHarvest(Async)?\(opts\) *\{/ ascii
    condition:
        all of ($impl_*) and
        filesize < 8MB and $regex and $phase3 and 2 of ($budget*) and
        2 of ($tcc, $cloud, $upload, $placeholder)
}
