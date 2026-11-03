rule VShell_Windows_Implant_4x_DLL
{
    meta:
        author = "Daydream"
        description = "VShell 4.x Windows implant DLL (Go, scrambled symbols) as unpacked from its stage: marker file names and config structure fields"
        date = "2026-10-10"
        yarahub_uuid = "60052629-0138-481f-a650-4e250be67cea"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c1f042939d03f1dc3cf8e6a0d5319b0e"
    strings:
        $log1 = "log_de.log"
        $log2 = "log_de-0.log"
        $tag_vkey   = "json:\"vkey\""
        $tag_salt   = "json:\"salt\""
        $tag_server = "json:\"server\""
        $f_salt  = "EncryptSalt"
        $f_hb    = "HeartBeatTime"
        $f_disc  = "DisconnectTime"
        $f_limit = "UploadLimitSpeed"
    condition:
        uint16(0) == 0x5A4D and filesize > 2MB and filesize < 30MB and
        all of ($log*) and all of ($tag_*) and 3 of ($f_*)
}
