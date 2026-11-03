import "pe"

rule MAL_Win_LoldUpdateClient
{
    meta:
        description = "Lold Update Client (lold-container) payload delivered via ClickFix: WinHTTP C2 on :8093 (/files, /files/hb, /files/inbox), embedded LOLD_CFG_V1 config"
        date = "2026-10-17"
        author = "anonymous"
        hash1 = "022bee19ebf5e3c9a5cfee7fcec97f2aec630d7ffc4bb1ee90c6420d3031b39b"
        hash2 = "127826140ece090e71a75aa9a847708d3484d734fee591981cb1ea0b3e5b5f9a"
        yarahub_uuid = "cdda50ae-0442-4934-b5f8-d76f82b5e23c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "31b0b958e8aef8dc4a694faaacb6a963"

    strings:
        $cfg   = "LOLD_CFG_V1" ascii
        $id1   = "Lold.UpdateClient" ascii
        $id2   = "LOLD_COM_CLSID_PLACEHOLDER" ascii
        $id3   = "Lold Update Client" ascii
        $w1    = "--lold-container" wide
        $w2    = "Lold/1.0" wide
        $w3    = "CLIENT_SELF_SPAWN_TARGET" wide
        $w4    = "Container placeholder exited without normal loader workflow" wide
        $w5    = "PayloadKeepAlive exit:" wide
        $w6    = "Local\\Lold_" wide
        $p1    = "/files/hb/" ascii
        $p2    = "/files/inbox/" ascii
        $p3    = "/files?prefix=inbox/" ascii
        $p4    = "Microsoft\\SyncServices\\manifest.json" ascii wide
        $p5    = "Microsoft\\Terminal Server Client\\state.bin" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (
            for any s in pe.sections : ( s.name == ".loldcfg" ) or
            $cfg or
            2 of ($id*, $w1, $w2, $w3, $w4, $w5, $w6) or
            (1 of ($id*, $w*) and 2 of ($p*))
        )
}
