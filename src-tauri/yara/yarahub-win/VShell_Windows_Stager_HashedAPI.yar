rule VShell_Windows_Stager_HashedAPI
{
    meta:
        author = "Daydream"
        description = "VShell Windows stager (x86/x64, tcp and ws variants): resolves APIs by ROR-13 hash, checks %TEMP%\\log_de.log, downloads a stage and XOR 0x99 decodes it in memory"
        date = "2026-10-10"
        yarahub_uuid = "17feb2aa-e2b6-4f40-9c73-93b7467d6657"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "dfe0826ecc3baeb9e74e361adbcd34bd"
    strings:
        // ROR-13 API hashes loaded as immediates (module hash + function hash)
        $h_loadlibrarya  = { 4C 77 26 07 }
        $h_wsastartup    = { 29 80 6B 00 }
        $h_wsasocketa    = { EA 0F DF E0 }
        $h_connect       = { 99 A5 74 61 }
        $h_recv          = { 02 D9 C8 5F }
        $h_virtualalloc  = { 58 A4 53 E5 }
        $h_access        = { 31 FA F2 70 }
        $h_gettemppatha  = { 30 F3 49 E4 }
        // stack-string fragments of the marker file name "log_de.log"
        $s_log = "log_"
        $s_de  = { 64 65 2E 00 }
        // VirtualAlloc size 30,000,000 and the XOR 0x99 decode of the received stage
        $c_bufsize = { 80 C3 C9 01 }
        $x_decode32 = { 80 3? 99 4? }
        $x_decode64 = { 80 34 ?? 99 }
    condition:
        uint16(0) == 0x5A4D and filesize < 16KB and
        6 of ($h_*) and $s_log and $s_de and $c_bufsize and 1 of ($x_decode*)
}
