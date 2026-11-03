rule ECHOES_RMS_Wallet_Admin_Frontend_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recovered rms-platform wallet-administration component with multi-chain import and claim controls"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/08-administration-platform/"
        yarahub_reference_md5 = "4494e3ecbcb74a7571a7250ddca72d2b"
        yarahub_uuid = "02bed6d1-2369-4985-96e2-29218c7afa9d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "frontend source component identification; does not prove backend use or wallet transactions"
    strings:
        $claim_call = "adminBase.post(\"admin/wallets/claim-all/\")" ascii
        $coldkey = "ColdKey" ascii
        $mnemonic = "mnemonic" ascii nocase
        $aptos = "Aptos" ascii
        $evm = "EVM" ascii
        $solana = "Solana wallet.json" ascii
    condition:
        filesize < 512KB and $claim_call and $coldkey and $mnemonic and
        2 of ($aptos, $evm, $solana)
}
