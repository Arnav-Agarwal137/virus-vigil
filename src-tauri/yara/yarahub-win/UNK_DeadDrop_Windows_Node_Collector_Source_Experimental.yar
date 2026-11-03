rule UNK_DeadDrop_Windows_Node_Collector_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Windows JavaScript collector with the recovered phase-one and elevated phase-two modes"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        yarahub_reference_md5 = "51ca5bba64d605c4718b5683c6bbec07"
        yarahub_uuid = "6b4fc9c3-cd85-497b-95cd-6ea8195b952c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or decoded JavaScript source; does not establish collection"
    strings:
        $phase1 = "--company-wallet-phase1-local" ascii
        $phase2 = "--company-wallet-job" ascii
        $login_data = "Login Data" ascii
        $local_extension_data = "Local Extension Settings" ascii
        $phase1_archive = "_phase1.zip" ascii
        $phase2_archive = "_pass.zip" ascii
        // Retained implementation syntax, not just markers quoted in research.
        $impl_phase1 = /function buildPhase1Zip\(sourceHome\) *\{/ ascii
        $impl_phase2 = /function buildPhase2PassZip\(epFilePath, *agentLogPath\) *\{/ ascii
    condition:
        all of ($impl_*) and
        filesize < 1MB and $phase1 and $phase2 and
        1 of ($login_data, $local_extension_data) and
        1 of ($phase1_archive, $phase2_archive)
}
