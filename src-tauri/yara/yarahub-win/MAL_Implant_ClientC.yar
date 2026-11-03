rule MAL_Implant_ClientC
{
    meta:
        description    = "clientc RAT - stage 3 implant"
        author         = "Tek"
        date           = "2026-09-15"
        tlp            = "CLEAR"
        yarahub_uuid   = "ac3ad1cd-f139-47ae-8b4c-a3395bf4cbfa"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "2916bf775e1f5f2464cd522417bdf14a"

    strings:
        // --- C2 protocol framing (ASCII) ---
        $p1 = "$Online||" ascii
        $p2 = "$Heartbeat||" ascii
        $p3 = "$ExecuteCommand||" ascii
        $p4 = "$ModuleDataIsOnMemory||" ascii
        $p5 = "$GlobalHeartbeatTime||" ascii
        $p6 = "||IsEnd" ascii

        // --- C2 transport, stored UTF-16 ---
        $c1 = "/v1/chat/completions" wide
        $c2 = "CodePage: %u" wide

        // --- module family ---
        $m1 = "NetLoader-Pillager" ascii
        $m2 = "NetLoader-GodPotato" ascii
        $m3 = "NetLoader-SweetPotato" ascii
        $m4 = "NetLoader-PrintNotifyPotatoCreateThread" ascii

        // --- distinctive host-side artefacts ---
        $a1 = "@HasPassword@" ascii
        $a2 = "WindowsUpdateTask" ascii
        $a3 = "CLSID\\{B4E15CD0-F916-4C8E-830A-15E3E9D01A1B}\\InprocServer32" ascii
        $a4 = "/calldll C:\\Users\\Public\\Update:2.dll DllRegisterServer" ascii
        $a5 = "ToDesk Info - ID: %s, Password: %s" ascii
        $a6 = "XDShellExtHelper64" ascii

        // --- build artefact ---
        $pdb = "D:\\VisualStudio\\clientc\\Release\\clientc.pdb" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 4MB
        and (
            $pdb
            or ( 3 of ($p*) and 1 of ($c*) )
            or ( 2 of ($m*) and 2 of ($a*) )
            or ( 3 of ($p*) and 2 of ($a*) )
            or 4 of ($a*)
        )
}
