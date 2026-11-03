/*
    ChainDrop/54dc7ea5 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: ChainDrop/54dc7ea5/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_WORM_JS_ChainDropStage2_Aug26
{
    meta:
        description = "Detects the ChainDrop stage-2 Bun-compiled worm bundle by its obfuscated function and class identifiers"
        author = "IAmForeverAloneToo"
        date = "2026-08-08"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"
        yarahub_reference_md5 = "7bcf8d9f6834c44450eac145a967d2f2"
        yarahub_uuid = "5165e0a1-6b56-4503-9e38-6899a07d430c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert"
        note = "Stage 2 was byte-identical across all 442 surveyed packages. The obfuscated identifiers are specific to this build and appear in cleartext throughout the 727,680-byte bundle. Occurrence counts verified by grep on the raw file."

    strings:
        $a1 = "// @bun" ascii

        $x1 = "n7gIxM" ascii
        $x2 = "lkjWus" ascii
        $x3 = "C8CPvDk" ascii
        $x4 = "z0Mqdi" ascii
        $x5 = "FEj38A" ascii

        $s1 = "jsTXVr" ascii
        $s2 = "MYqou1" ascii

    condition:
        $a1 and
        filesize > 100KB and filesize < 2MB and
        3 of ($x*) and
        1 of ($s*)
}
