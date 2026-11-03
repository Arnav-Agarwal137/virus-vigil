rule MULTI_Sample_Unique_48a59ece_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat extrait)"
        date = "2026-10-01"
        reference_sha256 = "48a59ece169b2ea9098c8aaa71456fb18c58726da08e28514f90fb5786f66ff2"
        yarahub_uuid = "cd118ea6-1bc1-41bd-868c-3d2588202e1e"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "59120326b4f4397490214acb0504d32b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "OVERHAU#L.exe (Beta Version)" ascii
        $s1 = "This malware was made by soheil shahrab and gifted to malware testers who don't have VM." ascii
        $s2 = "I don't have VM and can't make MBR, so I don't make destructive yet. The beta version," ascii
        $s3 = "yes, you know, it was shown for people who cant wait to see OVERHAU#L malware." ascii
        $s4 = "0.2: made in 9/4/2023 3:57 PM" ascii
        $s5 = "0.5: made in 9/6/2023 4:50 PM" ascii
        $s6 = "0.2 Feautures:" ascii
        $s7 = "Has 3 warnings, 3 payloads, 1 bytebeat, harmless" ascii
        $s8 = "the second one is bitblt payload, contains blur-like screen, the payload lasts about 60 seconds" ascii
        $s9 = "0.5 Features:" ascii
        $s10 = "Has the same warnings as 0.2 version, 6 payloads, 3 bytebeats, still harmless" ascii
        $s11 = "the third one is bitblt payload, contains blur-like screen, the payload lasts about 60 seconds" ascii
        $s12 = "1.0: SOON" ascii
        $s13 = "--------------------------------------------------------------------------------------------------------------------------" ascii
        $s14 = "the first one is elipse payload, contains moving circles, the payload lasts about 30 seconds" ascii
        $s15 = "the third one is another bitblt payload, contains instant inverted screen, the payload lasts about 30 seconds" ascii
        $s16 = "the second one is elipse payload, has patblt rectangles with transperent, contains bouncing circle, lasts about 30 seconds" ascii
        $s17 = "the fourth one is another bitblt payload, contains instant inverted screen, the payload lasts about 30 seconds" ascii
        $s18 = "the fifth one is first shader payload, contains shaders with a inverted black rectangles, the payload lasts about 30 seconds" ascii
        $s19 = "the sixith one is second shader payload, contains another shaders with a inverted white rectangles, the payload lasts about 30 seconds" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
