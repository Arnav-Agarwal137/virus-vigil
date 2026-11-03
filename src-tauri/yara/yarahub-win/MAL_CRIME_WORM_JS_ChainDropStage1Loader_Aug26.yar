/*
    ChainDrop/54dc7ea5 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: ChainDrop/54dc7ea5/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_WORM_JS_ChainDropStage1Loader_Aug26
{
    meta:
        description = "Detects the ChainDrop operator-seeded npm preinstall loader (setup.mjs) by its cleartext API pattern"
        author = "IAmForeverAloneToo"
        date = "2026-08-08"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        yarahub_reference_md5 = "f92ee93a0af971a3966bfa8efa9c2625"
        yarahub_uuid = "dbf0fa0d-8755-45b7-95d0-4a4e5e2f73df"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "medium"
        deploy = "alert with caveats -- the matched strings are legitimate Node.js APIs, not threat-unique identifiers; the rule relies on their unusual co-occurrence and count in a small file. May false-positive on heavily obfuscated npm packages that call execFileSync 5+ times and use fileURLToPath. Consider combining with npm package metadata (preinstall hook, companion Math_Symbol.js file) for triage."
        note = "All non-API strings in this loader are behind an RC4+base64 string table with 39 nested decode wrappers. The 7 execFileSync and 2 fileURLToPath occurrences are the only cleartext strings with threat significance, verified by grep on the raw file. This rule covers only the 11 operator-seeded packages, not the 431 worm-republished ones (those use jCZTWoC, matched by the EmbeddedLoader rule)."

    strings:
        $x1 = "execFileSync" ascii
        $x2 = "fileURLToPath" ascii

    condition:
        filesize > 10KB and filesize < 100KB and
        #x1 >= 5 and
        $x2
}
