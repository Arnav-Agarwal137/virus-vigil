rule MULTI_Sample_Unique_a717038f
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "a717038f47623c8b05367c3c578c997644a68a5f831b0a6e682f0782af3c0ed6"
        yarahub_uuid = "f516fc41-591e-4f25-82d5-db7b4fb80320"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c82ddcb0a302f17ef41683f6f2c7caf8"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "discord.gg/hitsonly and https://discord.gg/6gTd5XXyqQ) are subject to the following terms:" ascii
        $s1 = "1. **Exclusive Access:**" ascii
        $s2 = "as a benefit of their support." ascii
        $s3 = "2. **No Public Redistribution:**" ascii
        $s4 = "Recipients may not redistribute, share, or re-upload Rewards outside official channels designated or authorized by the" ascii
        $s5 = "server administration." ascii
        $s6 = "3. **Personal Use:**" ascii
        $s7 = "Boosters are granted permission to use, modify, and enjoy Rewards for personal, non-commercial purposes." ascii
        $s8 = "4. **No Commercial Use:**" ascii
        $s9 = "Selling, licensing, or otherwise commercially exploiting Rewards is strictly prohibited." ascii
        $s10 = "Please give credit to the server \"HitsOnly\" and the booster rewards program when sharing content or media featuring these Rewards." ascii
        $s11 = "6. **Revocation:**" ascii
        $s12 = "Access to Rewards and permission to use them may be revoked by the server administration at any time, especially in case of abuse or violation of these terms." ascii
        $s13 = "7. **Liability Disclaimer:**" ascii
        $s14 = "All Rewards are provided \"as is\", without warranty of any kind. Use at your own risk." ascii
        $s15 = "server administration at discord.gg/hitsonly or https://discord.gg/6gTd5XXyqQ." ascii
        $s16 = "Booster Rewards License" ascii
        $s17 = "All content, mods, resources, and other materials (\"Rewards\") distributed as part of Booster Rewards for the Discord servers" ascii
        $s18 = "Rewards are exclusively for members who boost the Discord server(s)" ascii
        $s19 = "5. **Attribution:**" ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s16, $s17, $s18, $s19) and 1 of ($s0, $s15)
}
