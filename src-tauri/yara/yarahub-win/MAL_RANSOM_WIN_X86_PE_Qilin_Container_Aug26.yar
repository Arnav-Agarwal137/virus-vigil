/*
    qilin-agenda/83e446a7 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: qilin-agenda/83e446a7/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_RANSOM_WIN_X86_PE_Qilin_Container_Aug26
{
    meta:
        description = "Detects a Qilin/Agenda encryptor by the encrypted-file container vocabulary it carries"
        author = "IAmForeverAloneToo"
        date = "2026-08-05"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "83e446a739a0321c1397f05463bbfa9b38419e26e0d3479ab1183728f2d067f5"
        yarahub_reference_md5 = "a4988673165920d97941725317a5da64"
        yarahub_uuid = "9172aba9-a870-42e6-90b5-95f3879f1b19"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malware_family = "Qilin"
        confidence = "medium"
        deploy = "safe to alert"
        note = "Matches the ENCRYPTOR, not its output: these are the error-enum arms and the delimiter literal, which live in the binary. The delimiter alone is family-generic and is deliberately not sufficient on its own here."
    strings:
        $x1 = "cannot find begin ciphertext block" ascii
        $x2 = "cannot find end ciphertext block" ascii
        $x3 = "cannot write initial checkpoint" ascii
        $x4 = "trying to decrypt invalid file" ascii
        $s1 = "-----END CIPHERTEXT BLOCK-----" ascii
        $s2 = "startblock doesn't match" ascii
        $s3 = "can't resize file to original size" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (2 of ($x*) or (any of ($x*) and 2 of ($s*)))
}
