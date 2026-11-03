rule Linux_Telegram_Agent_Installer
{
    meta:
        description = "agent_i.sh shell installer that stages the Go Telegram agent"
        author = "KSI Digital"
        date = "2026-10-06"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/telegram-go-agent"
        tlp = "clear"
        yarahub_uuid = "7d639ae9-2221-4c74-ab90-cdb15da2a3e7"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e84b6e4b4b1283486267009fbddd5c7c"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/telegram-go-agent"
    strings:
        $hdr = "hang-proof installer for telnet-reached hosts" ascii
        $m1 = "SELFTEST_OK" ascii
        $m2 = "STAGE_OK STAGED" ascii
        $m3 = "STAGE_FAIL" ascii
        $m4 = "/tmp/.g_" ascii
        $m5 = "--selftest" ascii
        $m6 = "PROOF=" ascii
    condition:
        uint16(0) != 0x457f and filesize < 64KB and
        ($hdr or 4 of ($m*))
}
