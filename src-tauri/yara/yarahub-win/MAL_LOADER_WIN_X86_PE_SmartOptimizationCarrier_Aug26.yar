/*
    AgentTesla/79e3baf2 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: AgentTesla/79e3baf2/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_LOADER_WIN_X86_PE_SmartOptimizationCarrier_Aug26
{
    meta:
        description = "Detects the SmartAssembly-obfuscated stage-2 carrier in this AgentTesla chain, by its Microsoft-impersonating assembly metadata"
        author = "IAmForeverAloneToo"
        date = "2026-08-06"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "79e3baf24631aeea1b35c96dc7a9a761ea6350a29c1c51eef2f17f7763b681b9"
        yarahub_reference_md5 = "660c82e5362a9eac830ade229cf4790a"
        yarahub_uuid = "92a9ccd4-70c1-4b6f-b1ec-8936bdc62381"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- but only matches the extracted stage-2 DLL or process memory, never the delivered file (embedded as steganographic pixel data, not contiguous bytes)"
        note = "The assembly GUID is a strong secondary marker but is stored little-endian binary in the metadata heap and is not matched here as a text string; the description string alone is sufficiently unique."
    strings:
        $x1 = "Adaptive machine learning system tuning service" ascii wide
        $s1 = "Microsoft Smart Optimization" ascii wide
        $s2 = "SmartAssembly.HouseOfCards.MemberRefsProxy" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $x1 and
        1 of ($s*)
}
