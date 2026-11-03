rule MULTI_Sample_Unique_528a6d5e
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "528a6d5e211ea6ab27a86813221e7b1874f517fb04768fc876e81911bdfd60f0"
        yarahub_uuid = "e13dcaab-1b31-4ff7-a570-e13e9cd4e498"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "33ac5135bf6e289104626ac946fbc5c4"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "\"Read more about it at https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies\"," ascii
        $s1 = "\"content-hash\": \"0e00879fc6a2cb05c2e71e99a365abe7\"," ascii
        $s2 = "\"packages-dev\": []," ascii
        $s3 = "\"minimum-stability\": \"dev\"," ascii
        $s4 = "\"stability-flags\": []," ascii
        $s5 = "\"prefer-stable\": false," ascii
        $s6 = "\"prefer-lowest\": false," ascii
        $s7 = "\"platform-dev\": []," ascii
        $s8 = "\"plugin-api-version\": \"2.0.0\"" ascii
        $s9 = "\"_readme\": [" ascii
        $s10 = "\"This file locks the dependencies of your project to a known state\"," ascii
        $s11 = "\"This file is @generated automatically\"" ascii
        $s12 = "\"packages\": []," ascii
        $s13 = "\"platform\": []," ascii
        $s14 = "\"aliases\": []," ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14) and 1 of ($s0)
}
