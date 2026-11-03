/*
    ChainDrop/54dc7ea5 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: ChainDrop/54dc7ea5/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_WORM_JS_ChainDropEmbeddedLoader_Aug26
{
    meta:
        description = "Detects the ChainDrop jCZTWoC embedded loader written to worm-republished npm packages as setup.mjs"
        author = "IAmForeverAloneToo"
        date = "2026-08-08"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"
        yarahub_reference_md5 = "4140f7e17e6f97f83aa3472473e01add"
        yarahub_uuid = "fe1078d3-ec07-4b96-8003-0cddd69e9b4b"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert"
        note = "This is the 11,017-byte Node ESM loader carried as an AES-256-GCM-encrypted payload inside stage 2 and written to victim packages during worm republication. It is distinct from the 29,918-byte operator-seeded loader. Obfuscation uses _0x-prefixed variable names (javascript-obfuscator style). Occurrence counts verified by grep on the decrypted payload."

    strings:
        $x1 = "_0x488df8" ascii
        $x2 = "math_init" ascii

    condition:
        filesize > 5KB and filesize < 50KB and
        #x1 >= 5 and
        $x2
}
