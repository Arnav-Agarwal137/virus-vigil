/*
    FROSTHORN/c98e3614 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: FROSTHORN/c98e3614/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_BACKDOOR_WIN_X64_PE_FROSTHORN_ModuleABI_Oct26
{
    meta:
        description = "Detects FROSTHORN core builds and FROSTHORN runtime modules by the four module-ABI export names"
        author = "IAmForeverAloneToo"
        date = "2026-10-29"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "c98e3614ead6f644a140a650cb9b1a036eca24425daae64ae5e80ec085296505"
        yarahub_reference_md5 = "726c45afc15e244c8634f0a2f421266e"
        yarahub_uuid = "7afeb092-fd66-4277-843b-db5634293a22"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan or memory"
        note = "The core resolves module_init, module_handle, module_free_result and module_cleanup from every runtime module it loads, and the http_c2 module exports them, so the names are plaintext in both. Present in all 86 builds from 16 May to 18 October 2026, GNU and MSVC targets alike. A VirusTotal content search for all four names returned only FROSTHORN cores and the two http_c2 images."

    strings:
        $s1 = "module_init" ascii
        $s2 = "module_handle" ascii
        $s3 = "module_free_result" ascii
        $s4 = "module_cleanup" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and all of ($s*)
}
