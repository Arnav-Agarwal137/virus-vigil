rule UNK_DeadDrop_Encrypted_Stage3_Loader_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Obfuscated JavaScript loader using AES-GCM to recover later-stage source"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        yarahub_reference_md5 = "ffe4b6346441815753de7d664d98fc02"
        yarahub_uuid = "506f1b6e-2609-4474-8aa6-f30f11d6cf82"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext JavaScript loader; exact case examples are up to 1.6 MiB; does not include the embedded decryption key"
    strings:
        $entry = "const _0x1=require" ascii
        $crypto = "(\"crypto\")" ascii
        $cipher = "aes-256-gcm" ascii
        $decrypt = "createDecipheriv" ascii
        $auth = "setAuthTag" ascii
        $compile = "_compile" ascii
    condition:
        filesize < 2MB and all of them
}
