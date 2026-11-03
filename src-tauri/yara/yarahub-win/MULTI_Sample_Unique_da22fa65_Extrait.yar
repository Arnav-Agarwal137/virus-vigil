rule MULTI_Sample_Unique_da22fa65_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat extrait)"
        date = "2026-10-02"
        reference_sha256 = "da22fa6584627568bbee2501b5b58d2d53f766a2dcf7fc75abb5fdb8beee68bd"
        yarahub_uuid = "dad2ccf5-69d3-4b44-8dc6-ac4fae33dd35"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "09e812d59a9d2f2254451f6c6cf522a3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "if not defined UHGFHZRUSWI cd /d \"%~dp0\"" ascii
        $s1 = "set \"DKANHB=ell\\v1.0\\po\"" ascii
        $s2 = "set \"GXDCGO=ell.\"" ascii
        $s3 = "set \"QGNYW=\\sysnative\\Win\"" ascii
        $s4 = "set \"WUNNYSFQLCS=%~f0\"" ascii
        $s5 = "set \"GOHW=&($executioncontext.InvokeCommand.\"" ascii
        $s6 = "set \"FNOUWZCQW=/b\"" ascii
        $s7 = "set \"XFIBFEZBN=%~f0\"" ascii
        $s8 = "set \"CUNC=\\Mic\"" ascii
        $s9 = "set \"VTJM=ft\\W\"" ascii
        $s10 = "set \"HGLH=ws\\C\"" ascii
        $s11 = "set \"NMHC=s\\nl\"" ascii
        $s12 = "set \"MFRZ=s_ca\"" ascii
        $s13 = "set \"ZKIN=\\nls\"" ascii
        $s14 = "set \"IAQH=_cac\"" ascii
        $s15 = "set \"VJGE=he.c\"" ascii
        $s16 = "BMWSUHLQTWBOOT|1|5009|114a1f45205df30bb1d04fb3c844b96670ff7e4966924d8e3fe576bafa4048c4|0" ascii
        $s17 = "BMWSUHLQTWHCS|1|213246|d175381e35877d53d5f00a3157a7e6c1c23f48c34fb662758948ced4aa91d348|1|102" ascii
        $s18 = "BMWSUHLQTWHBT|1|7168|ec0b69bedd94ff7cece67271bd720b1dde5b7c62fbb50fc90f746df4c7fe9c7c|0" ascii
        $s19 = "BMWSUHLQTWRSC|1|132704|713172542b35fa10f72645ff3f779863acbbc3cd36a2bc3d70807c9f66c74f18|0" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
