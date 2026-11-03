rule MULTI_Sample_XWorm_d82a5ada
{
    meta:
        author = "Marjoriefort"
        description = "Detects XWorm (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "d82a5ada925fd980afb04e7902b9bfb8e23824736eb51256894b3da3a485d942"
        yarahub_uuid = "82267c93-4d3a-4b83-a2cd-574bcc13eb90"
        famille = "XWorm"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "067f1364a82fc8c115e6e9d1f5c6b9f8"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "var topiaries = \"http://johnsonsvalves.cam/HF1W1Z5K\";" wide ascii
        $s1 = "enteradenology.open(\"GET\", topiaries, false);" wide ascii
        $s2 = "enteradenology.send();" wide ascii
        $s3 = "var uncommunicable = enteradenology.responseText;" wide ascii
        $s4 = "eval(uncommunicable);" wide ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4) and 1 of ($s0)
}
