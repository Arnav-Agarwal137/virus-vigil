rule UNK_DeadDrop_Chromium_App_Bound_Bypass_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Python or JavaScript source implementing Chromium App-Bound key recovery through IElevator"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        yarahub_reference_md5 = "61f3b3b608a24e4aee5571a85afd7451"
        yarahub_uuid = "dd721387-6eb8-4055-8bcf-8c0bb52df64c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or decoded source; does not establish successful browser credential decryption"
    strings:
        $key = "app_bound_encrypted_key" ascii nocase
        $elevator = "IElevator" ascii nocase
        $decrypt = "DecryptData" ascii
        $chrome = "708860E0-F641-4611-8895-7D867DD3675B" ascii nocase
        $edge = "1FCBE96C-1697-43AF-9140-2897C7C69767" ascii nocase
        $brave = "576B31AF-6369-4B6B-8560-E4B203A97A8B" ascii nocase
        $moniker = "Elevation:Administrator!new:" ascii
        $legacy1 = "CryptUnprotectData" ascii
        $legacy2 = "v20" ascii
        $filename = "detect_malware.py" ascii
        // Retained implementation syntax, not just markers quoted in research.
        $impl_decrypt = /def decrypt_app_bound_key\(cipher_after_appb[,:]/ ascii
        $impl_load = /def load_master_key\(data[,:]/ ascii
    condition:
        all of ($impl_*) and
        filesize < 2MB and $key and $elevator and $decrypt and
        1 of ($chrome, $edge, $brave, $moniker) and
        1 of ($legacy1, $legacy2, $filename)
}
