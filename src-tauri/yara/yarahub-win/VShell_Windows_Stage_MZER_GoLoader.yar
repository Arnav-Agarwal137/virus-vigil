rule VShell_Windows_Stage_MZER_GoLoader
{
    meta:
        author = "Daydream"
        description = "VShell 4.x Windows stage after XOR 0x99 decoding: Go loader with an MZER self-loading header that carries the implant DLL as a gzip asset"
        date = "2026-10-10"
        yarahub_uuid = "2edf2aeb-d710-4fc9-907a-12b8861c12f4"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "2bd3df895000037833bec52611819495"
    strings:
        // self-loading stub inside the DOS header: call $+5; pop; adjust; add loader offset; call
        $stub32 = { 4D 5A 45 52 E8 00 00 00 00 58 83 E8 09 50 05 ?? ?? ?? ?? FF D0 C3 }
        $stub64 = { 4D 5A 45 52 E8 00 00 00 00 59 48 83 E9 09 48 8B C1 48 05 ?? ?? ?? ?? FF }
        $asset1 = "Asset %s not found"
        $asset2 = "Asset %s can't read by error: %v"
        $cgo    = "_cgo_dummy_export"
        $gzip   = { 1F 8B 08 00 }
    condition:
        ($stub32 at 0 or $stub64 at 0) and filesize > 1MB and filesize < 20MB and
        all of ($asset*) and $cgo and $gzip
}
