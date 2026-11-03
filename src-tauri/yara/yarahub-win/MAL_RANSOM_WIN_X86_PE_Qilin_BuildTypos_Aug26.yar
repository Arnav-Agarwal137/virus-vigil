/*
    qilin-agenda/83e446a7 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: qilin-agenda/83e446a7/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_RANSOM_WIN_X86_PE_Qilin_BuildTypos_Aug26
{
    meta:
        description = "Detects Qilin/Agenda builds by spelling and duplicated-word errors in the operator's own source"
        author = "IAmForeverAloneToo"
        date = "2026-08-05"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "83e446a739a0321c1397f05463bbfa9b38419e26e0d3479ab1183728f2d067f5"
        yarahub_reference_md5 = "a4988673165920d97941725317a5da64"
        yarahub_uuid = "2964d552-88c8-494b-a594-b0c4d30e6382"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malware_family = "Qilin"
        confidence = "high"
        deploy = "safe to alert"
        note = "These survive rebuilds until the author fixes them, and they carry no library-collision risk: no legitimate project ships 'can't fet file meta'. Any single one is sufficient; two are required here only to keep the rule robust against a partial file."
    strings:
        $x1 = "can't fet file meta" ascii
        $x2 = "public ket is not provided" ascii
        $x3 = "Couldnt spread to  possible offline hosts" ascii
        $x4 = "Failed to convert to impersonation token token" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        2 of ($x*)
}
