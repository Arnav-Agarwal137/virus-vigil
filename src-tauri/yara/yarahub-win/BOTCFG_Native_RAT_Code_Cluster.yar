import "pe"

rule BOTCFG_Native_RAT_Code_Cluster
{
    meta:
        author = "ShadowOpCode"
        description = "Detects a native x64 RAT code cluster associated with the BOTCFG configuration format; descriptive detection, no family attribution"
        date = "2026-09-20"

        sample_sha256 = "a5926522d7ce3a0073da79c5082da6644c742d6a34440bba3f5d878f03712938"

        yarahub_reference_md5 = "6234dcab24dc1f15e61d851b716af60a"
        yarahub_uuid = "83b29f0b-b72b-4979-9783-2840a9cdcf6b"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $marker = "BOTCFG|" ascii

        $mutex = "Local\\BotC2Stub.SingleInstance" wide

        $c1 = "CLIPPER_CONFIG" ascii fullword
        $c2 = "CRYPTO_FOUND" ascii fullword
        $c3 = "SCREENCAST_START" ascii fullword
        $c4 = "TERMINAL_INPUT" ascii fullword
        $c5 = "PERSISTENCE_INSTALL" ascii fullword
        $c6 = "hollowed pid " ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.machine == pe.MACHINE_AMD64 and
        filesize < 5MB and
        $marker and
        $mutex and
        4 of ($c*)
}