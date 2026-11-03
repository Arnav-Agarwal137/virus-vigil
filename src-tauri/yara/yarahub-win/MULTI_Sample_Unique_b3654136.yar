rule MULTI_Sample_Unique_b3654136
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "b36541365298a91a78f7dca53e69524744233962b02ef87f7297019804baa28c"
        yarahub_uuid = "7224d126-c4b4-4dee-91eb-5de1cdd63ec2"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "26918a4b1354affb823799f369af6e7b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "url : https://carolcolecatholicartist.com/wp-includes/js/jquery/articles/" ascii
        $s1 = "hta name : Mzfmj.hta" ascii
        $s2 = "schedule name : Adobe\\Microsoft\\Windows\\Snun\\Qds ,Intel Pro\\Windows\\Fvmi\\Ebn" ascii
        $s3 = "vbs name : Microsoft\\Erx\\pgpis.vbs" ascii
        $s4 = "js name : Adobe\\Zcw\\lwgtv.js" ascii
        $s5 = "depth : 7" ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4, $s5) and 1 of ($s0)
}
