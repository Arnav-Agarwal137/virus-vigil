rule Social_Engineering_Twitter_Bot_Dialogue {
    meta:
        description = "Detects X (Twitter) bot scripts, automation tools, or binaries containing specific social engineering or engagement dialogue strings."
        author = "Serhii Kocherhan"
        date = "2026-10-15"
        yarahub_twitter = "@skocherhan"
        yarahub_uuid = "30fd36ea-93bb-4a91-a5f1-97827b2d5356"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "00000000000000000000000000000000"

    strings:
        // Core bot dialogue phrases (split or ASCII-safed to prevent non-ASCII file compilation errors)
        $s1 = "So you are really going through with that" ascii wide nocase
        $s2 = "Was that too much for you?" ascii wide nocase

    condition:
        filesize < 20MB and (
            $s1 and $s2
        )
}