/*
    EssentialStealer/18a029fc -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: EssentialStealer/18a029fc/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_BACKDOOR_MACOS_EssentialStealerAgent_Sep26
{
    meta:
        description = "Detects the EssentialStealer tasking agent (bmodule) by the stable obfuscated identifiers of its template and its phishing-dialog construction"
        author = "IAmForeverAloneToo"
        date = "2026-09-01"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "8c407a9e06c900db0aa4cae2b0d2ee402f4fe0056af27e0ead81d81e359d34a6"
        yarahub_reference_md5 = "537fe4d33c456930fca762e94d9050df"
        yarahub_uuid = "be050b10-2059-4018-ab44-b4429058953b"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- memory scan, captured traffic, or a saved copy"
        note = "The agent is a static template: two affiliates' builds differ by exactly one line (the campaign id), so these obfuscated variable names are stable. Confirmed present in both. It is piped directly into osascript and does not normally exist as a file on the victim."

    strings:
        $x1 = "_avcEyVQxd" ascii
        $x2 = "_GaGYmP8" ascii
        $x3 = "__FYFD4cj" ascii
        $x4 = "_ZryFg3G" ascii
        $s1 = "default answer" ascii
        $s2 = "do shell script" ascii

    condition:
        filesize < 2MB and 3 of ($x*) and all of ($s*)
}
