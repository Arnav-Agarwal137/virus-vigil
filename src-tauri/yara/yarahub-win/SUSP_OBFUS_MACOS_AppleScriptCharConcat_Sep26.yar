/*
    EssentialStealer/18a029fc -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: EssentialStealer/18a029fc/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule SUSP_OBFUS_MACOS_AppleScriptCharConcat_Sep26
{
    meta:
        description = "Detects AppleScript built by the per-character concatenation obfuscator used across the EssentialStealer chain, including its per-download stealer modules"
        author = "IAmForeverAloneToo"
        date = "2026-09-01"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "8c407a9e06c900db0aa4cae2b0d2ee402f4fe0056af27e0ead81d81e359d34a6"
        yarahub_reference_md5 = "537fe4d33c456930fca762e94d9050df"
        yarahub_uuid = "ad5fe913-8ef5-47fd-b914-fed974397a06"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "medium"
        deploy = "HUNTING ONLY -- do not alert. Identifies the technique, not the actor."
        note = "The stealer modules are rebuilt per download: variable names, decoy padding, staging path and hash all change, so no stable content-based anchor exists for them. This rule keys on the obfuscation shape and requires a high occurrence count to separate it from incidental use. Benign obfuscated AppleScript will match."

    strings:
        $o1 = "(ASCII character " ascii
        $o2 = "(character id " ascii
        $s1 = "do shell script" ascii

    condition:
        filesize < 5MB and $s1 and (#o1 + #o2) > 400
}
