rule MAL_LOADER_WIN_X64_PE_SilentiumLZSSStub_Oct26
{
    meta:
        description = "Detects the MinGW loader stub that carries the Silentium Go implant (MalwareBazaar tag UmbraRAT) LZSS-compressed in a .payload section"
        author = "IAmForeverAloneToo"
        date = "2026-10-29"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "0c86b4073439409ff3667b17abc53096e2a026daa1b88980f264753e061fc98e"
        yarahub_reference_md5 = "f8fffc10b54087e720509114e7c4fba2"
        yarahub_uuid = "fbd7b020-3063-4f2e-ac6c-3883d8e14cdf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan"
        note = "The 41-byte block decodes an LZSS back-reference (12-bit offset, 4-bit length plus 3) in the stub's loader function. It also fires on the two other UmbraRAT-tagged files on MalwareBazaar (3395fc45, 21bfd3d2). The stub may be reused for other payloads; a hit identifies the loader, and the payload must be recovered to name what it carries."

    strings:
        $x1 = { 0F B6 4C 31 04 44 89 C2 41 83 C0 02 0F B6 54 32 04 41 89 CA 83 E1 0F 41 C1 E2 04 44 8D 59 03 41 81 E2 00 0F 00 00 41 09 D2 }
        $s1 = ".payload" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and $s1 in (0..0x400) and $x1
}
