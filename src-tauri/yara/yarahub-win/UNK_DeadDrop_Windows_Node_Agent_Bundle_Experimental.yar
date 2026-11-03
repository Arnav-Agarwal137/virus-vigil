rule UNK_DeadDrop_Windows_Node_Agent_Bundle_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Embedded Windows Node agent archive or its unpacked runtime markers"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/05-screen-capture-analysis/"
        yarahub_reference_md5 = "e5415f46ccfd2dbe462c86910ed8ec9f"
        yarahub_uuid = "c7a24ba2-2da4-4db9-8ea9-c4e66c617867"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "ZIP member names or unpacked JavaScript; not a detector for the full VSIX archive"
    strings:
        $zip1 = "run-update-agent.vbs" ascii
        $zip2 = "update-agent.js" ascii
        $zip3 = "lib/agent-update.js" ascii
        $agent_dir = "OVERLORD_NODE_AGENT_DIR" ascii
        $websocket = "WebSocket" ascii
    condition:
        filesize < 64MB and
        ((uint32(0) == 0x04034b50 and 2 of ($zip*)) or
         ($agent_dir and $websocket))
}
