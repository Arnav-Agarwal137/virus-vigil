rule MULTI_Sample_Unique_75f29b1e
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "75f29b1e556d22f0e235bd6e4308b2bcda8111f2306e6a4c86255bae43986345"
        yarahub_uuid = "a2ab2b27-efab-4a25-a66e-fbc4244a14c2"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "746b1f943d16ab515817b2796d10509b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "If Application.RecentFiles.Count > 5 Then" ascii
        $s1 = "Shell(\"mshta https://carolcolecatholicartist.com/wp-includes/js/jquery/articles/Mzfmj0.hta\")" ascii
        $s2 = "mshta https://carolcolecatholicartist.com/wp-includes/js/jquery/articles/Mzfmj0.hta" ascii
    condition:
        true and filesize < 50MB and 3 of them
}
