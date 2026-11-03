rule UNK_DeadDrop_Stage3_Collector_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Plaintext stage-three JavaScript collection and Windows agent staging markers"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        yarahub_reference_md5 = "61f3b3b608a24e4aee5571a85afd7451"
        yarahub_uuid = "876162a3-0fd5-4205-a0e3-8ccda1c1587f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext source; obfuscation or encryption can evade"
    strings:
        $task = "GoogleUpdateSupporterNode" ascii
        $stage1 = "GUS_UPLOAD_CHUNK_SIZE" ascii
        $stage2 = "DEFAULT_PHASE3_MAX_MS" ascii
        $stage3 = "OVERLORD_KEEP_AGENT_STATE" ascii
        $stage4 = "WIN_NODE_AGENT_BUNDLE_B64" ascii
        $stage5 = "DEFAULT_WALK_MAX_DIRS" ascii
    condition:
        filesize < 8MB and $task and 3 of ($stage*)
}
