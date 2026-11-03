rule MULTI_Sample_Unique_748dd824
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "748dd824e0dc716e94e68434d0fb4b3811208349521513c8ad0c5eb46b369694"
        yarahub_uuid = "c17c8a43-e7be-42dc-9402-d975223a8fed"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0395aa402e5a40c548384c61f89afada"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "var endemiology = \"http://johnsonsvalves.cam/luFiVL08\";" wide ascii
        $s1 = "sulfite.open(\"GET\", endemiology, false);" wide ascii
        $s2 = "sulfite.send();" wide ascii
        $s3 = "var eurafrican = sulfite.responseText;" wide ascii
        $s4 = "eval(eurafrican);" wide ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4) and 1 of ($s0)
}
