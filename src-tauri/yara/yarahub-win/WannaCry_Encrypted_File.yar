rule WannaCry_Encrypted_File {
    meta:
        description = "Detects files encrypted by WannaCry (victim files)"
        author = "Bristol Agri-Tech Solutions SOC"
        date = "2026-10-01"
        severity = "High"
        yarahub_reference_md5 = "84c82835a5d21bbcf75a61706d8ab549"
        yarahub_uuid = "6117dc8b-ada6-416e-a31b-8764eb864f8d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // WannaCry encrypted file header marker
        $header = "WANACRY!" ascii
        $header2 = { 57 41 4E 41 43 52 59 21 }

    condition:
        $header at 0 or $header2 at 0
}
