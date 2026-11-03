/*
    FROSTHORN/c98e3614 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: FROSTHORN/c98e3614/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_BACKDOOR_WIN_X64_PE_FROSTHORN_HttpC2Module_Oct26
{
    meta:
        description = "Detects the FROSTHORN http_c2.dll runtime module, a standalone HTTPS transport behind the FROSTHORN module ABI"
        author = "IAmForeverAloneToo"
        date = "2026-10-29"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "8b23d4d52760c722e3d693674ef1c273bc9af36a691658a85ec50f0b20ecd7f5"
        yarahub_reference_md5 = "48c7594ac6fe2b395c1f347650dd141a"
        yarahub_uuid = "61afc245-5ce2-4117-8acd-934570da0379"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan or memory"
        note = "Also fires on the core build 98cf3b10, which carries the module byte-identical in .rdata. 'http_c2.dll' is the module's export-directory name and 'not configured' its own error string; its URI paths, header names and reply marker are not plaintext."

    strings:
        $s1 = "module_init" ascii
        $s2 = "module_handle" ascii
        $s3 = "module_free_result" ascii
        $s4 = "module_cleanup" ascii
        $x1 = "not configured" ascii
        $x2 = "http_c2.dll" ascii
        $x3 = "Microsoft Unified Security Protocol Provider" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and all of ($s*) and all of ($x*)
}
