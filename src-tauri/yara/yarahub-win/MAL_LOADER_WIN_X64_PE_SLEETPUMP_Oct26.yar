/*
    FROSTHORN/c98e3614 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: FROSTHORN/c98e3614/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_LOADER_WIN_X64_PE_SLEETPUMP_Oct26
{
    meta:
        description = "Detects the SLEETPUMP in-memory loader for FROSTHORN by the bounded NUL-scan helper every build carries"
        author = "IAmForeverAloneToo"
        date = "2026-10-29"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "0b9d8893adb751aaa0786b57b128b44330276c2b26b235303c52c0207f32b8c9"
        yarahub_reference_md5 = "508f254a729c86b2948342b464bad485"
        yarahub_uuid = "525ae876-a110-4cf0-948d-a466495acdb8"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan"
        note = "The 34-byte pattern is the start of a 42-byte helper that scans for a NUL within 513 bytes (cmp rdx, 0x201). It is present exactly once in all 26 known loaders, C/C++ and Rust builds alike, and a VirusTotal content search for it returned those 26 files and no other. It does not depend on the payload encoding, which varies by build."

    strings:
        $x1 = { 48 85 C9 74 1D 48 89 C8 31 D2 80 3C 10 00 74 11 48 FF C2 48 81 FA 01 02 00 00 75 EE BA 01 02 00 00 C3 }

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and $x1
}
