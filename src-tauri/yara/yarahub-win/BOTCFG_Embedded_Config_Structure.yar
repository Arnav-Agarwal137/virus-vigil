import "pe"

rule BOTCFG_Embedded_Config_Structure
{
    meta:
        author = "ShadowOpCode"
        description = "Detects the embedded BOTCFG configuration structure independently of C2 addresses, port, campaign tag and process name"
        date = "2026-09-20"

        sample_sha256 = "a5926522d7ce3a0073da79c5082da6644c742d6a34440bba3f5d878f03712938"

        yarahub_reference_md5 = "6234dcab24dc1f15e61d851b716af60a"
        yarahub_uuid = "6139626f-9fbb-4771-989b-fa8a5d0f2901"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $cfg_start    = "BOTCFG|host=" ascii
        $cfg_fallback = "|fallback=" ascii
        $cfg_port     = "|port=" ascii
        $cfg_tag      = "|tag=" ascii
        $cfg_name     = "|name=" ascii
        $cfg_persist  = "|persist=" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.machine == pe.MACHINE_AMD64 and

        all of ($cfg_*) and

        @cfg_start <
        @cfg_fallback and
        @cfg_fallback <
        @cfg_port and
        @cfg_port <
        @cfg_tag and
        @cfg_tag <
        @cfg_name and
        @cfg_name <
        @cfg_persist and

        (@cfg_persist - @cfg_start) < 512
}