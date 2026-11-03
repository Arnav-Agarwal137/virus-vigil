rule AELCMS_XOR_Python_Explorer_Injector
{
    meta:
        description = "Detects the AELCMS Python XOR decoder and explorer.exe remote-thread injector"
        author = "ShadowOpCode"
        date = "2026-10-28"
        category = "malware"
        sample_sha256 = "5cd5224af5d882043e5189466e92237e01403fa6f81ceaf0efc5305541e700fe"
        yarahub_reference_md5 = "9fc68d89d96755f34c6e71a04aede179"
        yarahub_uuid = "b13cdd3f-e1b7-41b4-b456-1aa502cf113e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $a = "CreateToolhelp32Snapshot" ascii
        $b = "VirtualAllocEx" ascii
        $c = "VirtualProtectEx" ascii
        $d = "NtCreateThreadEx" ascii
        $e = "key[i % len(key)]" ascii
        $f = "explorer.exe" ascii nocase

    condition:
        filesize < 60000 and all of them
}
