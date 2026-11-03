/*
    AgentTesla/79e3baf2 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: AgentTesla/79e3baf2/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_LOADER_WIN_X86_PE_TideWhistleStego_Aug26
{
    meta:
        description = "Detects the TideWhistle stego loader that opens this AgentTesla chain, by its decoy project identity and reflective-load evasion strings"
        author = "IAmForeverAloneToo"
        date = "2026-08-06"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "79e3baf24631aeea1b35c96dc7a9a761ea6350a29c1c51eef2f17f7763b681b9"
        yarahub_reference_md5 = "eb48718f8ee70303224d77724b05fa5e"
        yarahub_uuid = "56696552-e822-4704-8a52-44edfeb6d389"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert"
        note = "$s3 (\"jfgx\", the assembly's InternalName) is 4 bytes, under the 6-byte floor for a standalone string -- it is never sufficient alone: the condition requires it alongside $x1 and one more 7+ byte string via 2 of ($s*)."
    strings:
        $x1 = "TideWhistle" ascii wide
        $s1 = "Cave Helmholtz Resonator Simulation" ascii wide
        $s2 = "#8###8#" ascii wide
        $s3 = "jfgx" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $x1 and
        2 of ($s*)
}
