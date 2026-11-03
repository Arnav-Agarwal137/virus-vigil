rule UNK_DeadDrop_Electron_Node_Bootstrap_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recovered source pairing Electron Node mode with the campaign wallet-client header"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        yarahub_reference_md5 = "5d2bbf703e1f1f68bb8e0515818c3eb4"
        yarahub_uuid = "e60e74a7-3943-483d-a591-2be8e249d905"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "static JavaScript source identification; does not establish task execution"
    strings:
        $electron = "ELECTRON_RUN_AS_NODE" ascii
        $client = "X-Company-Wallet-Client-Id" ascii
    condition:
        filesize > 32KB and filesize < 512KB and all of them
}
