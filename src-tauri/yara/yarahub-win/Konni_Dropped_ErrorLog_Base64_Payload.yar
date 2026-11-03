rule Konni_Dropped_ErrorLog_Base64_Payload
{
    meta:
        description = "Encrypted PowerShell payload disguised as an error log: every line is 'Error: ' followed by base64 (dropped as C:\\ProgramData\\Diagnosis\\DiagnosisUTC_Storage_Error.err by a Konni-tagged shortcut, September 2026)"
        author = "Daydream"
        date = "2026-10-11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "527c94e5-48a6-4c04-a0b3-4af11418a4fb"
        yarahub_reference_md5 = "a51144e1c15afeb0956cf94eb222b1eb"
    strings:
        $line = /Error: [A-Za-z0-9+\/]{64,76}\r?\n/
        $text = /Error: [^\r\n]{0,60}[ \.,:;\(\)'"\-_\\][^\r\n]{0,60}\r?\n/
    condition:
        uint32be(0) == 0x4572726F and uint32be(3) == 0x6F723A20 and
        filesize > 4KB and filesize < 5MB and
        #line > 50 and not $text
}
