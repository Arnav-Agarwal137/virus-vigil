rule MAL_Win_LoldUpdateClient_Config
{
    meta:
        description = "Lold Update Client embedded config block (LOLD_CFG_V1 + C2 URL + k_ key); also matches memory dumps"
        date = "2026-10-17"
        author = "anonymous"
        yarahub_uuid = "20bb5fa3-69eb-473d-873a-9e2be6ffec9b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "31b0b958e8aef8dc4a694faaacb6a963"

    strings:
        $cfg = { 4C 4F 4C 44 5F 43 46 47 5F 56 31 00 [0-16] 68 74 74 70 ( 3A | 73 3A ) 2F 2F }   // "LOLD_CFG_V1\0" ... "http(s)://"
        $key = /k_[0-9a-f]{48}\x00/

    condition:
        $cfg and $key
}
