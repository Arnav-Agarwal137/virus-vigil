rule MAL_BACKDOOR_WIN_X64_Silentium_Implant_Oct26
{
    meta:
        description = "Detects the Silentium Go implant (MalwareBazaar tag UmbraRAT) by its own key-derivation and format labels, in an unpacked DLL or in process memory"
        author = "IAmForeverAloneToo"
        date = "2026-10-29"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "505bef109cfe0579291f22cad6b82354e43fbf99fc8b462f200ed60c8e23e45d"
        yarahub_reference_md5 = "daaddd3cd5f00d59770f531aaae2688c"
        yarahub_uuid = "99beec51-3e75-4345-9382-3075851ab248"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- memory scan or unpacked DLL"
        note = "The silentium-* labels name the config AAD, the ECDH salt, the agent key, the task HMAC, the Solana framing MAC and the migrate stash. They are compressed in the delivered loader and become plaintext once the implant is mapped. The rule needs no MZ header so it can fire on a memory region."

    strings:
        $x1 = "silentium-baked-config-v1" ascii
        $x2 = "silentium-solana-framing-mac-v1" ascii
        $x3 = "silentium-ecdh-salt-v1" ascii
        $x4 = "silentium-task-hmac" ascii
        $x5 = "silentium-agent-key" ascii
        $x6 = "silentium-migrate-stash-v1" ascii
        $s1 = "solana transport does not support file upload" ascii
        $s2 = "ntappip-" ascii

    condition:
        3 of ($x*) or (1 of ($x*) and all of ($s*))
}
