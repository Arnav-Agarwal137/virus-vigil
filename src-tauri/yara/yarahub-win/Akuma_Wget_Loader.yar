rule Akuma_Wget_Loader
{
    meta:
        description = "akuma kit loader script (wget.sh) that picks and runs an akuma_<arch> bot from /bins/telnet/"
        author = "KSI Digital"
        date = "2026-10-11"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/akuma-loader"
        tlp = "clear"
        yarahub_uuid = "ec8c9e51-bb28-45af-948e-988fc577daac"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "83be4620ebcf494f47811ce81f4a0d52"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/akuma-loader"
        // Matches both captured loader versions (81a7cdbb from 143.20.154.42, c87eecde from 85.137.53.167); no hits on
        // ~92,000 other honeypot captures, 142 recent MalwareBazaar Mirai/Gafgyt/Mozi ELFs or Ubuntu 24.04 system binaries.
    strings:
        $fail = "wget.sh: failed to download/run bot" ascii
        $p1   = "pick_bot" ascii
        $p2   = "run_bot" ascii
        $b1   = "akuma_x64" ascii
        $b2   = "akuma_riscv64" ascii
        $b3   = "akuma_mpsl" ascii
        $path = "/bins/telnet/" ascii
    condition:
        uint32(0) != 0x464c457f and filesize < 64KB and
        ($fail or ($path and 2 of ($b*) and 1 of ($p*)))
}
