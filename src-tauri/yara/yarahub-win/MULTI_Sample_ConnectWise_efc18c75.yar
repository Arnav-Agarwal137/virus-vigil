rule MULTI_Sample_ConnectWise_efc18c75
{
    meta:
        author = "Marjoriefort"
        description = "Detects ConnectWise (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "efc18c75af9688a5d471d80954fa64dea70b04a2c872a0d6e34cc4a9137073cb"
        yarahub_uuid = "83c3efed-054a-46ae-a164-01b85f8919de"
        famille = "ConnectWise"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "26c6adda723ab763f546a0be26972cf2"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "eC^hO U2V0IGlhc1ogPSBDcmVhdGVPYmplY3QoIlNoZWxsLkFwcGxpY2F0aW9uIikNCmlhc1ouU2hlbGxFeGV>>\"%TEMP%\\AIrC.b64\"" ascii
        $s1 = "E^c^ho jdXRlICJtc2lleGVjLmV4ZSIsICIvaSBodHRwczovL3B1Yi1jNGVmMGNkYTIzZTU0MDE1IiAmICI4Nj>>\"%TEMP%\\AIrC.b64\"" ascii
        $s2 = "ec^H^O gxYzExMDI5MTI1MmM1LnIyLmRldi9TY3JlZW5Db25uZWN0LkNsaWVudFNldHVwLm1zaSAvcXVpZXQgL>>\"%TEMP%\\AIrC.b64\"" ascii
        $s3 = "E^cHO 25vcmVzdGFydCIsICIiLCAicnVuYXMiLCAwDQpTZXQgeEFTVyA9IENyZWF0ZU9iamVjdCgiU2NyaXB0>>\"%TEMP%\\AIrC.b64\"" ascii
        $s4 = "e^C^H^O aW5nLkZpbGVTeXN0ZW1PYmplY3QiKQ0KeEFTVy5EZWxldGVGaWxlIFdTY3JpcHQuU2NyaXB0RnVsbE5>>\"%TEMP%\\AIrC.b64\"" ascii
        $s5 = "e^c^hO hbWUsIFRydWU=>>\"%TEMP%\\AIrC.b64\"" ascii
        $s6 = "C^e^rtUtil -decode \"%TEMP%\\AIrC.b64\" \"%TEMP%\\PuKc.vbs\" >nul 2>&1" ascii
        $s7 = "DEL \"%TEMP%\\AIrC.b64\" >nul 2>&1" ascii
        $s8 = "s^Tar^t \"\" /min wscript.exe //nologo \"%TEMP%\\PuKc.vbs\"" ascii
        $s9 = "%TEMP%\\AIrC.b64" ascii
        $s10 = "%TEMP%\\PuKc.vbs" ascii
        $s11 = "/min wscript.exe //nologo" ascii
        $s12 = "RE^m DSLZGrhyZVUgXOpji" ascii
        $s13 = "S^Et aaay=%gTZc%" ascii
        $s14 = "REm oPHMTwHPpxmswKtQPfKCIjQb" ascii
        $s15 = "SET cNXe=%IPgn%" ascii
        $s16 = "r^e^m lUmmPguiMbcwMKFJaRqmfR" ascii
        $s17 = "if 0==1 sET JNv=rkpnQ" ascii
        $s18 = "rEm LcvymEpOQvk" ascii
        $s19 = "aqxmuyuzxqhUVotJu" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
