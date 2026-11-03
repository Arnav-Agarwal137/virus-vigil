/*
    AgentTesla/79e3baf2 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: AgentTesla/79e3baf2/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_STEALER_WIN_X86_PE_AgentTeslaExfilTemplate_Aug26
{
    meta:
        description = "Detects AgentTesla's exfiltration report template, recovered from the decrypted stage-4 payload of this chain but generic to the family"
        author = "IAmForeverAloneToo"
        date = "2026-08-06"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "79e3baf24631aeea1b35c96dc7a9a761ea6350a29c1c51eef2f17f7763b681b9"
        yarahub_reference_md5 = "231d935c6b5eaf67ec44ff7ae71b094c"
        yarahub_uuid = "74527302-caa9-441d-9c7d-d24e0c720706"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- decrypted payload or process memory only, never the delivered file or the packed crypter"
        note = "This is a family-generic signature, not specific to this build or campaign. Expect it to fire on other AgentTesla samples independent of loader chain."
    strings:
        $x1 = "OSFullName: " ascii wide
        $x2 = " Recovered!" ascii wide
        $s1 = "User Name: " ascii wide
        $s2 = "Computer Name: " ascii wide
        $s3 = "IP Address: " ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        all of ($x*) and
        2 of ($s*)
}
