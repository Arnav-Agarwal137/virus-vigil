rule Lold_Loader_Implant_CFG_V1
{
    meta:
        description = "Lold/1.0 (Lold.UpdateClient) x64 C++ loader/implant and verbatim outer PE wrappers: matches the .loldcfg (LOLD_CFG_V1) configuration section, Lold/1.0 User-Agent, Local\\Lold_ mutex, --lold-container CLI flag, and rs42 Reed-Solomon RS(4,2) chunk assembly strings"
        author = "Daydream"
        date = "2026-10-31"
        reference = "https://bazaar.abuse.ch/sample/269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300/"
        reference_sample = "fa647a4d12cc887bd96cb2eb126f161cbcf47e84312094bb0dcc2429e7c8e296 (also matches outer wrapper 578cc6d26bf7c5536d2c0ea0df5a788155e15d09e49054303915b535f4012791)"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3cd789e114e93b06e5162f8d7b462fe3"
        yarahub_uuid = "6d29f4c1-83a2-47e9-b105-9f81c3e24710"
    strings:
        $magic = "LOLD_CFG_V1" ascii
        $sect1 = ".loldcfg" ascii
        $sect2 = ".fptable" ascii
        $ua = "Lold/1.0" ascii wide
        $mutex = "Local\\Lold_" ascii wide
        $cli = "--lold-container" ascii wide
        $hdr = "X-Chunk-Key" ascii wide
        $rs1 = "rs: need at least 2 slots" ascii
        $rs2 = "endpoint or chunk id was not found" ascii
        $xml = "name=\"Lold.UpdateClient\"" ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            ($magic and $sect1 and 2 of ($ua, $mutex, $cli, $hdr, $rs1, $rs2, $xml)) or
            (all of ($ua, $mutex, $cli) and 2 of ($sect1, $sect2, $hdr, $rs1, $rs2, $xml))
        )
}
