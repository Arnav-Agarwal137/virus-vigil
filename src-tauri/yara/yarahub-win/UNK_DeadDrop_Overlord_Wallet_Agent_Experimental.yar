rule UNK_DeadDrop_Overlord_Wallet_Agent_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "ELF Overlord wallet-agent marker conjunction; static hunting only"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/12-framework-and-collection-boundary/"
        yarahub_reference_md5 = "15e2f4004a4c896636e1ee8948cc63e8"
        yarahub_uuid = "35406cbe-a252-4335-9570-7581c60b1993"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "marker conjunction; not campaign attribution"
    strings:
        $elf = { 7F 45 4C 46 }
        $framework = "overlord-client/cmd/agent" ascii wide
        $env = "OVERLORD_SERVER_RAW" ascii wide
        $wallet1 = "OVERLORD_COMPANY_WALLET_EP" ascii wide
        $wallet2 = "X-Company-Wallet-Client-Id" ascii wide
        $wallet3 = "/api/company-wallet/upload" ascii wide
    condition:
        filesize < 64MB and $elf at 0 and $framework and $env and 2 of ($wallet*)
}
