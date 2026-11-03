rule UNK_DeadDrop_VSIX_Manifest_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Extracted Google Update Support VSIX manifest and company-wallet configuration"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        yarahub_reference_md5 = "2f6cb61c8e2e9f7abba018af681f96ef"
        yarahub_uuid = "658c4c6c-2431-4ba2-b06c-5841355a98f4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "small extracted VSIX manifest members; does not decompress archives"
    strings:
        $identity1 = "google-update-support" ascii
        $identity2 = "google-dev-tools" ascii
        $identity3 = "onStartupFinished" ascii
        $config1 = "googleUpdateSupport.companyWalletServerUrl" ascii
        $config2 = "googleUpdateSupport.companyWalletClientId" ascii
        $config3 = "googleUpdateSupport.companyWalletAgentToken" ascii
        $config4 = "googleUpdateSupport.windowsActivationMode" ascii
    condition:
        filesize < 4KB and all of ($identity*) and 2 of ($config*)
}
