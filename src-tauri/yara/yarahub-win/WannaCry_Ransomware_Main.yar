rule WannaCry_Ransomware_Main {
    meta:
        description = "Detects WannaCry ransomware main executable"
        author = "Bristol Agri-Tech Solutions SOC"
        date = "2026-10-01"
        severity = "Critical"
        yarahub_reference_link = "https://attack.mitre.org/software/S0366/"
        yarahub_reference_md5 = "84c82835a5d21bbcf75a61706d8ab549"
        yarahub_uuid = "d759131f-02f8-41b6-b6b3-1f136ec4502e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // WannaCry file extension markers
        $ext1 = ".WNCRY" ascii wide
        $ext2 = ".WNCRYT" ascii wide

        // Ransom note identifiers
        $ransom1 = "@WanaDecryptor@" ascii wide
        $ransom2 = "WanaCrypt0r" ascii wide
        $ransom3 = "WANACRY" ascii wide nocase

        // Kill switch domain (unique fingerprint)
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii

        // Bitcoin wallet addresses
        $btc1 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $btc2 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
        $btc3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii

        // Service name for persistence
        $service = "mssecsvc2.0" ascii wide

        // Commands used during execution
        $cmd1 = "icacls . /grant Everyone:F /T /C /Q" ascii
        $cmd2 = "attrib +h" ascii
        $cmd3 = "taskdl.exe" ascii wide
        $cmd4 = "tasksche.exe" ascii wide

        // Dropped component filenames
        $drop1 = "c.wnry" ascii
        $drop2 = "t.wnry" ascii
        $drop3 = "r.wnry" ascii
        $drop4 = "s.wnry" ascii
        $drop5 = "u.wnry" ascii

        // Encryption-related
        $crypt1 = "CryptGenKey" ascii
        $crypt2 = "CryptEncrypt" ascii
        $crypt3 = "CryptImportKey" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            // High confidence: kill switch domain present
            ($killswitch) or
            // High confidence: multiple WannaCry-specific strings
            (3 of ($ext1, $ext2, $ransom1, $ransom2, $ransom3)) or
            // Medium confidence: Bitcoin + ransom indicators
            (any of ($btc*) and any of ($ransom*)) or
            // Medium confidence: persistence + commands
            ($service and any of ($cmd*)) or
            // Medium confidence: multiple dropped components
            (3 of ($drop*) and any of ($crypt*))
        )
}
