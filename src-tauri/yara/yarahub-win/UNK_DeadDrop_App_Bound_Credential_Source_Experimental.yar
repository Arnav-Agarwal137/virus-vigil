rule UNK_DeadDrop_App_Bound_Credential_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Retained Python credential-recovery implementation, standalone or embedded in JavaScript"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        yarahub_reference_md5 = "5d2bbf703e1f1f68bb8e0515818c3eb4"
        yarahub_uuid = "c8f22d36-fc24-4992-9989-758dab810580"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or decoded source; does not establish successful credential recovery"
    strings:
        $login_data = "Login Data" ascii
        $local_state = "Local State" ascii
        $app_bound_key = "app_bound_encrypted_key" ascii
        $recovery_dpapi = "DPAPI" ascii nocase
        $recovery_app_bound = "App-Bound Encryption" ascii nocase
        $recovery_elevation = "Elevation Service" ascii nocase
        $recovery_aes_gcm = "AES-GCM" ascii nocase
        // Retained implementation syntax, not just markers quoted in research.
        $impl_decrypt = /def decrypt_app_bound_key\(cipher_after_appb[,:]/ ascii
        $impl_load = /def load_master_key\(data[,:]/ ascii
        $impl_export = "def export_logins(" ascii
    condition:
        all of ($impl_*) and
        filesize < 1MB and $login_data and $local_state and $app_bound_key and
        2 of ($recovery_*)
}
