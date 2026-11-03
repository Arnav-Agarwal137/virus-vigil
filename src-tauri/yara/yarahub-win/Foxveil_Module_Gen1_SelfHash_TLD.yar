rule Foxveil_Module_Gen1_SelfHash_TLD
{
    meta:
        yarahub_uuid = "7f383f9c-6a3c-4724-a5dd-783efa2e8716"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3106cffb9da7380fcc0237e8fde0efa0"
        description = "Foxveil second-stage macOS modules, first generation (2026-08, dropped as AccountsHelper / mdworker_shared): ad-hoc-signed fat x86_64+arm64 C++ Mach-O linking only libSystem and libc++, hashing its own __TEXT,__text through getsectiondata(_dyld_get_image_header(0)) to key its string decryption, and carrying the contiguous TLD list it appends to resolver names. Predates the LCG-obfuscated, empty-segment generation covered by Foxveil_Module_LCGString_Runtime"
        actor = "Foxveil"
        family = "Foxveil module runtime (gen 1)"
        reference_sha256 = "6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620"
        date = "2026-10-02"
        tlp = "CLEAR"
        confidence = "medium-high"

    strings:
        $macho_fat = { CA FE BA BE 00 00 00 02 01 00 00 07 }
        $dylib1 = "/usr/lib/libSystem.B.dylib\x00"
        $dylib2 = "/usr/lib/libc++.1.dylib\x00"
        // __cstring, once per slice: TLD list, contiguous and in this order
        $tld = ".com\x00.net\x00.org\x00.xyz\x00.site\x00.app\x00"
        // __cstring, once per slice: getsectiondata() arguments for the self-hash
        $sect = "__TEXT\x00__text\x00"
        $imp1 = "_getsectiondata\x00"
        $imp2 = "__dyld_get_image_header\x00"
        $imp3 = "_popen\x00"
        $imp4 = "_dlsym\x00"
        $other1 = "/System/Library/Frameworks/"
        $other2 = "/usr/lib/libobjc"

    condition:
        $macho_fat at 0 and filesize > 131072 and filesize < 4194304 and
        $dylib1 and $dylib2 and not any of ($other*) and
        #tld >= 2 and #sect >= 2 and all of ($imp*)
}
