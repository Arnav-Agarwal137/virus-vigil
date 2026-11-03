rule MULTI_Sample_EtherRAT_9da8a219_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects EtherRAT (inconnu, etat extrait)"
        date = "2026-10-01"
        reference_sha256 = "9da8a2195dcb57f1b326760e307fddb5981cdeb510c0147fb8c77fc558f3784e"
        yarahub_uuid = "973b83f0-6ffb-4a50-9038-d02d655bc839"
        famille = "EtherRAT"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "90f388ff6f3721620f96f6aa44a1133c"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "function _a(){const _b=['zgf0yq','zxjYB3i','Bwv0Ag8','CMvZDwW','mhHJmMy','DhrSzwq','yMXVy2S','zdOG','oI8VBwe','u3rHCNq','qxnZzw0','z2LMEq','uMvJzwK','Bg9VCca','lNb1yMW','rxjYB3i','FsKOkq','odKXzty','B" ascii
        $s1 = "start \"\" /min \"%~f0\" h" ascii
        $s2 = "set \"_zgp=DzbsUntJmxADcurlmHKltarIcnodefeNTtimeoutZQJlANwhereZMXsJEdelKfrenFuXjrmy.exeqfHi.zipUIAzTM-sLonJhIDQ-xfzIxj/nobreakYKKRDGhttps://nodejs.orgUaU/dist/v18.20.5/FOwanode-v18.20.5-win-x64WFJcmdnj" ascii
        $s3 = "rem 949T4xFpdI8WK2" ascii
        $s4 = "_zgp:~46,5% %_zgp:~25,4% >\"!s5o!\\7APqpkrz\" 2>nul" ascii
        $s5 = "_zgp:~57,3% \"!s5o!\\7APqpkrz\" >nul 2>&1" ascii
        $s6 = "rem o8GBSLz3HnQI" ascii
        $s7 = "set \"ags=%_zgp:~121,18%%_zgp:~142,15%%_zgp:~161,21%%_zgp:~80,4%\"" ascii
        $s8 = "_zgp:~12,4% %_zgp:~90,4% \"%TEMP%\\!zb4!\" \"!ags!\"" ascii
        $s9 = "if not exist \"%TEMP%\\!zb4!\" exit /b" ascii
        $s10 = "_zgp:~20,3% %_zgp:~100,3% \"%TEMP%\\!zb4!\" -C \"!s5o!\"" ascii
        $s11 = "_zgp:~57,3% /q \"%TEMP%\\!zb4!\" >nul 2>&1" ascii
        $s12 = "_zgp:~62,3% \"!s5o!\\node-v18.20.5-win-x64\" hXnMzo >nul 2>&1" ascii
        $s13 = "if exist \"!s5o!\\hXnMzo\\%_zgp:~25,4%%_zgp:~72,4%\" (" ascii
        $s14 = "set \"dn7=!s5o!\\hXnMzo\\%_zgp:~25,4%%_zgp:~72,4%\"" ascii
        $s15 = "rem oZCY8DnxIF4A" ascii
        $s16 = "if not exist \"!s5o!\\n9sJanS9hDpT.ini\" goto :T1Xmb" ascii
        $s17 = "rem EmJsay28LE4S5GnVeYn7" ascii
        $s18 = "_zgp:~230,7% //B //nologo \"!s5o!\\HCd8Ycyg7y.js\" \"!dn7!\" \"!s5o!\\n9sJanS9hDpT.ini\"" ascii
        $s19 = "var s=new ActiveXObject('Shell.Application');s.ShellExecute(WScript.Arguments(0),'\"'+WScript.Arguments(1)+'\"','','open',0);" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s2)
}
