rule DvnX_Loader_v2_Base32Dot_Scatter_SplitMix64
{
    meta:
        description = "DvnX Loader v1/v2 and Unpacked Warden Stealer (YapStealer): 32-symbol Base32-Dot + custom SplitMix64 stream XOR + LZSS codec or legacy 88-symbol exclusion mask"
        author = "Daydream"
        date = "2026-11-01"
        reference_sample = "1047c65e1f0eaecde16193c896cfc4f154c58486304dd910c34cca2bacef450e (also matches unpacked stealer e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b)"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "cd1e014c59d9c42b1b8f8bcde7f36f4b"
        yarahub_uuid = "a84e239b-7f41-4c9d-9e32-5f18d402c91a"

    strings:
        // DvnX v1 88-symbol printable ASCII exclusion bitmask (0x4400000008002201)
        $legacy_mask = { 01 22 00 08 00 00 00 44 }

        // DvnX v2 36-char Fisher-Yates alphabet shuffle PRNG constants (0x18000388c / 0x180011cf1)
        $mix_seed_xor = { DB 28 B4 A0 D1 7E 03 E7 }
        $mix_mul1     = { B9 E5 E4 1C 6D 47 58 BF }
        $mix_mul2     = { FE 6D 7B 6C 02 30 E7 0A }

        // DvnX v2 custom 64-bit stream generator recurrence constants (0x180004f15 / 0x180029bf0)
        $stream_step  = { 03 33 09 4C BB 07 26 B0 }
        $stream_mul   = { 4B 39 A3 0B 46 BF C3 64 }
        $stream_zero  = { 4F EE 10 72 6B 0B 59 B9 }
        $aux_constant = { 4C E9 EA C9 77 01 0E 22 }

        // JLI side-loading export stubs and OLLVM/MBA custom section headers
        $jli_1 = "JLI_CmdToArgs" ascii fullword
        $jli_2 = "JLI_GetStdArgc" ascii fullword
        $jli_3 = "JLI_GetStdArgs" ascii fullword
        $jli_4 = "JLI_InitArgProcessing" ascii fullword
        $jli_5 = "JLI_Launch" ascii fullword
        $jli_6 = "JLI_MemAlloc" ascii fullword
        $jli_7 = "JLI_MemFree" ascii fullword
        $sec_fptable = ".fptable" ascii
        $sec_rdata   = "_RDATA" ascii

    condition:
        uint16(0) == 0x5A4D and
        (4 of ($jli_*) or ($sec_fptable and $sec_rdata)) and
        (
            ($stream_step and $stream_mul and 2 of ($mix_*, $stream_zero, $aux_constant)) or
            $legacy_mask
        )
}
