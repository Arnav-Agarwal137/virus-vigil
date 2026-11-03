rule MULTI_Sample_Unique_ce2aaca2
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "ce2aaca254fc094fcc4b3a16d14a9b8780f011de111d5cb6741160db79f55b2d"
        yarahub_uuid = "ebe64463-7718-4554-a909-a55a7736c553"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3cb2b76a9b68d8fd86b40309898fb722"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "\"generatedAt\": 1783175360," ascii
        $s1 = "\"site\": \"https://www.donut.build\"," ascii
        $s2 = "\"listingUrl\": \"https://www.donut.build/schematics\"," ascii
        $s3 = "\"schematicCount\": 471," ascii
        $s4 = "\"familyCount\": 436," ascii
        $s5 = "\"familyHash\": \"006722941261c9b3689952c6224589bd59ba036d\"," ascii
        $s6 = "\"primarySlug\": \"lox-v54-kelp-farm\"," ascii
        $s7 = "\"author\": \"RTPQu3ue\"," ascii
        $s8 = "\"aliasCount\": 1," ascii
        $s9 = "\"slug\": \"lox-v54-kelp-farm\"," ascii
        $s10 = "\"outlineMinY\": 0," ascii
        $s11 = "\"outlineMaxY\": 19," ascii
        $s12 = "\"baseMinY\": 1," ascii
        $s13 = "\"baseMaxY\": 18," ascii
        $s14 = "\"totalBlocks\": 17579," ascii
        $s15 = "\"baseBlockCount\": 5060," ascii
        $s16 = "\"familyHash\": \"00d149af3d5d566c393addfb31146a9cee2ec002\"," ascii
        $s17 = "\"primarySlug\": \"fastest-bonemeal-farm\"," ascii
        $s18 = "\"author\": \"BigBobby68\"," ascii
        $s19 = "\"slug\": \"fastest-bonemeal-farm\"," ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s1, $s2)
}
