/*
    FROSTHORN/c98e3614 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: FROSTHORN/c98e3614/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_BACKDOOR_WIN_X64_PE_FROSTHORN_Pivot_Oct26
{
    meta:
        description = "Detects FROSTHORN builds from July 2026 onward by their plaintext pivot-module names and error string"
        author = "IAmForeverAloneToo"
        date = "2026-10-29"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "41a8b5b57ef7382194e580799ef6fbb1f12e295aad3a34680df424d0287b5f68"
        yarahub_reference_md5 = "cb3165b99dd5b930eb09648e4180dd46"
        yarahub_uuid = "d10d6947-dfe1-470f-8c75-63c708ab2e2e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan or memory"
        note = "Fires on the 47 builds compiled from 3 July 2026 onward; the May-June builds have no pivot command and are covered by the ModuleABI rule. tcp_pivot and smb_pivot are generic red-team words and appear in other frameworks, so they are required together with the exact FROSTHORN error string."

    strings:
        $x1 = "no pivot module loaded" ascii
        $s1 = "tcp_pivot" ascii
        $s2 = "smb_pivot" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and $x1 and all of ($s*)
}
