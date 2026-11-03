rule MULTI_Sample_Unique_b10c4841_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat extrait)"
        date = "2026-10-02"
        reference_sha256 = "b10c4841a0aec65c50a6fe07532b2c8f10c4fda90e4a6223e9b16d1f17eb0b54"
        yarahub_uuid = "aa71e843-c8e3-4258-b995-55e53c63ceee"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1dc726613ddbd67de5951dfc74ff4592"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "Honesty Snapshot for Windows 7, 8, 10, and 11" ascii
        $s1 = "1. Unzip this folder." ascii
        $s2 = "2. Double-click Honesty-Snapshot.exe." ascii
        $s3 = "3. Sign in with your Honesty Software account." ascii
        $s4 = "4. Click Capture screen, write on the picture, then Save to my dashboard." ascii
        $s5 = "The picture shows up on your dashboard at https://honestysoftware.com/dashboard" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s2, $s3, $s4) and 1 of ($s5)
}
