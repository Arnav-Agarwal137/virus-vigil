/*
    qilin-agenda/83e446a7 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: qilin-agenda/83e446a7/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_RANSOM_WIN_X86_PE_Qilin_EsxiStage_Aug26
{
    meta:
        description = "Detects the Qilin/Agenda vCenter/ESXi PowerShell stage, embedded in the encryptor or dropped to disk"
        author = "IAmForeverAloneToo"
        date = "2026-08-05"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "83e446a739a0321c1397f05463bbfa9b38419e26e0d3479ab1183728f2d067f5"
        yarahub_reference_md5 = "a4988673165920d97941725317a5da64"
        yarahub_uuid = "f9f949ce-7c9f-4ca5-a853-edfd1d8108de"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malware_family = "Qilin"
        confidence = "high"
        deploy = "safe to alert"
        note = "Deliberately not anchored on an MZ header: the stage is plain PowerShell inside the encryptor and would be a standalone .ps1 if written out. An earlier version of this rule fired on a purpose-built legitimate maintenance runbook that happened to define functions named Disable-ClusterServices, Enable-ESXiSSH and Change-ESXiPassword -- those are natural names for administrative tooling and are NOT discriminating on their own. The rule now requires one of the malware's own markers ($x*) before any of them counts."
    strings:
        // malware-unique anchors: its own variable, its own log tag, and two
        // literals it matches against the Linux payload's stdout
        $x1 = "fallbackESXiList" ascii
        $x2 = "[DEBUG|POWERSHELL] Script execution started." ascii
        $x3 = "Fixing ESXi VMFS filesystem bug." ascii
        $x4 = "Process gone into background" ascii
        // hypervisor operations: real, but administrators do these too
        $s1 = "/User/execInstalledOnly" ascii
        $s2 = "Disable-ClusterServices" ascii
        $s3 = "Change-ESXiPassword" ascii
        $s4 = "Enable-ESXiSSH" ascii
        // analysis artefacts that quote the strings above
        $fp1 = "condition:" ascii
        $fp2 = "reference_sample" ascii
    condition:
        filesize < 20MB and
        any of ($x*) and
        any of ($s*) and
        not any of ($fp*)
}
