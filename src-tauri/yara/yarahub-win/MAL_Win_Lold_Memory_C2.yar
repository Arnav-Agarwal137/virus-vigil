rule MAL_Win_Lold_Memory_C2
{
    meta:
        description = "Lold Update Client C2 artefacts in process memory or dumps: :8093 base URL with payload chunk path or k_ session key"
        date = "2026-10-19"
        author = "anonymous"
        yarahub_uuid = "5d67fefb-36a7-42ff-968c-685646a927f8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a9e07b2b8ac6fea86549d9f96eb70d4f"

    strings:
        $chunk = /https?:\/\/[0-9.]{7,15}:8093\/chunks\/p_[0-9a-f]{8,}\/(v[0-9]+\/)?[0-9]+\.bin/ ascii wide
        $base  = /https?:\/\/[0-9.]{7,15}:8093/ ascii wide
        $key   = /k_[0-9a-f]{48}/ ascii wide
        $hb    = /\/files\/hb\/[0-9A-F]{16}\.json/ ascii wide

    condition:
        $chunk or ($base and ($key or $hb))
}
