rule SCRIPT_Dropper_Unknown_ForgeAuto_621463eb
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "621463eb73a9dd7e891c77e6523b93e044be1fca12044dc15ededcd91dbd086f"
        yarahub_uuid = "9ffb1568-581f-421f-baf9-d513c4b45580"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9ead00a62355184da38652c4d4ac888c"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "MobiX Unlock localization. Named tokens are resolved by the app's t() helper. */" ascii
        $s1 = "['result.completed', 'OPERATION COMPLETE', '" ascii
        $s2 = "['result.tabs', 'Report sections', '" ascii
        $s3 = "['result.summary', 'Result summary', '" ascii
        $s4 = "['result.details', 'Device details', '" ascii
        $s5 = "['result.profileStatus', 'Profile status', '" ascii
        $s6 = "['result.verification', 'Session verification', '" ascii
        $s7 = "['result.passed', 'Passed', '" ascii
        $s8 = "['result.operation', 'Operation', '" ascii
        $s9 = "['result.elapsed', 'Execution time', '" ascii
        $s10 = "['result.session', 'Session ID', '" ascii
        $s11 = "['result.step1', 'Profile processed', '" ascii
        $s12 = "['result.step2', 'Session checks passed', '" ascii
        $s13 = "['result.step3', 'Report saved to history', '" ascii
        $s14 = "['result.network.title', 'Unlock successful', '" ascii
        $s15 = "['result.network.description', 'The selected network profile is now unlocked.', '" ascii
        $s16 = "['result.network.state', 'Unlocked', '" ascii
        $s17 = "['result.screen.title', 'Screen profile cleared', '" ascii
        $s18 = "['result.screen.description', 'The selected screen lock profile has been cleared.', '" ascii
        $s19 = "['result.screen.state', 'Cleared', '" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
