/*
    qilin-agenda/83e446a7 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: qilin-agenda/83e446a7/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_RANSOM_WIN_X86_PE_Qilin_LogVocabulary_Aug26
{
    meta:
        description = "Detects Qilin/Agenda builds by the [LEVEL|COMPONENT] logging scheme compiled into the shipped binary"
        author = "IAmForeverAloneToo"
        date = "2026-08-05"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "83e446a739a0321c1397f05463bbfa9b38419e26e0d3479ab1183728f2d067f5"
        yarahub_reference_md5 = "a4988673165920d97941725317a5da64"
        yarahub_uuid = "c14b93fc-c7e5-44bf-b2a2-ae0b4f563e51"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malware_family = "Qilin"
        confidence = "high"
        deploy = "safe to alert"
        note = "This build ships with debug logging compiled in: 426 tagged literals across 46 components. The component tags chosen here name capabilities rather than generic activity, so they do not collide with ordinary application logging."
    strings:
        $x1 = "[INFO|PSEXEC] Successfully spread to " ascii
        $x2 = "[FATAL] Auto mode should not be passed directly during encryption!" ascii
        $x3 = "[ERROR|STORAGE] is_system_volume is not implemented" ascii
        $x4 = "[CRITICAL|LOGS] Error collecting logs for SID '" ascii
        $s1 = "[INFO|CLI] Verifying CLI arguments and flags..." ascii
        $s2 = "[FATAL|PANIC] Unexpected crash occurred: " ascii
        $s3 = "Impersonating wrapped function via " ascii
        $s4 = "AESNI support detected! Using AES-CTR mode" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (any of ($x*) or 3 of ($s*))
}
