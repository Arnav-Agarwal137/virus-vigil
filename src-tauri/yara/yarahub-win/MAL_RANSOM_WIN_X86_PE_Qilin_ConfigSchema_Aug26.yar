/*
    qilin-agenda/83e446a7 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: qilin-agenda/83e446a7/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_RANSOM_WIN_X86_PE_Qilin_ConfigSchema_Aug26
{
    meta:
        description = "Detects a Qilin/Agenda build by its embedded JSON configuration field names"
        author = "IAmForeverAloneToo"
        date = "2026-08-05"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "83e446a739a0321c1397f05463bbfa9b38419e26e0d3479ab1183728f2d067f5"
        yarahub_reference_md5 = "a4988673165920d97941725317a5da64"
        yarahub_uuid = "d3045842-2310-4190-ac14-478e343de2d0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malware_family = "Qilin"
        confidence = "medium"
        deploy = "safe to alert"
        note = "The field names are the operator's schema, not the operator's data, so this survives a re-generated configuration. MZ-gated on purpose: in this family the configuration ships embedded in the encryptor, and without the header the rule fires on any document that quotes the schema -- an analysis report, an IOC feed, a rule file. That trade-off means a configuration blob dropped on its own will NOT match; use the field names as a hunting string if you need to cover that case."
    strings:
        $x1 = "encrypt_mounted_shares" ascii
        $x2 = "white_symlink_subdirs" ascii
        $x3 = "white_symlink_dirs" ascii
        $x4 = "enable_extension_filter" ascii
        $x5 = "enable_cluster_killer" ascii
        $x6 = "enable_sandbox_detection" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        4 of ($x*)
}
