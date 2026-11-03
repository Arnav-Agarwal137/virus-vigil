rule Foxveil_Loader_TaskInfo_NoFw_Variant
{
    meta:
        yarahub_uuid = "85e5fd36-3fce-4745-bc1f-6ba84ebfd384"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "94422c1aa780b891d34e7591d9e62b98"
        description = "Foxveil macOS loader (ClickFix -> AMOS), quill/stratos generation, framework-agnostic: fat x86_64+arm64 linking libSystem+libc++ with any number of system frameworks (zero since 2026-10-30) and no framework, CF, objc or swift import, the task_info/mach_task_self_/pthread_once resolver core in both slices, and a 128 KB-1 MB __DATA_CONST,__const payload section in both slices"
        actor = "Foxveil"
        family = "AMOS loader"
        reference_sha256 = "79b6ec3e1c1f70f234f3785827ba666f74e5470830efc84843e4888357fb2b45"
        reference_sha256_frame97 = "21b49dee39292ce7f66ebc10f58f8624f05408cf7aa389307f1ab38b108810a5"
        reference_sha256_chant = "1cfa88d98876f84f071d86ea667a1d5e75bb87773625a33e13a4c48e5b4dbdb9"
        date = "2026-10-31"
        tlp = "CLEAR"

    strings:
        $macho_fat = { CA FE BA BE 00 00 00 02 01 00 00 07 }
        $dylib1 = { 2F 75 73 72 2F 6C 69 62 2F 6C 69 62 53 79 73 74 65 6D 2E 42 2E 64 79 6C 69 62 00 }
        $dylib2 = { 2F 75 73 72 2F 6C 69 62 2F 6C 69 62 63 2B 2B 2E 31 2E 64 79 6C 69 62 00 }
        $i_ti  = "\x00_task_info\x00"
        $i_mts = "\x00_mach_task_self_\x00"
        $i_po  = "\x00_pthread_once\x00"
        // section_64 "__const" in "__DATA_CONST", addr 0x1_xxxx_xxxx, size 0x20000..0xFFFFF:
        // the base64-wrapped encrypted item array (400-505 KB on the 2026-10-30 builds).
        $payload_sect = { 5F 5F 63 6F 6E 73 74 00 00 00 00 00 00 00 00 00
                          5F 5F 44 41 54 41 5F 43 4F 4E 53 54 00 00 00 00
                          ?? ?? ?? ?? 01 00 00 00
                          ?? ?? (02|03|04|05|06|07|08|09|0A|0B|0C|0D|0E|0F) 00 00 00 00 00 }
        $cf_imp   = "\x00_CF"
        $sec_imp  = "\x00_Sec"
        $objc_imp = "\x00_objc_"
        $swift    = "\x00_swift_"

    // WHY THIS RULE EXISTS (2026-10-31, haven-post 79b6ec3e / md5 94422c1a, frame97 21b49dee,
    // chantcompass9 1cfa88d9): the loader stopped linking ANY framework (only libSystem + libc++),
    // so Foxveil_Loader_TaskInfo_Variant ($fw1 CoreFoundation) and Foxveil_Loader_TaskInfo_FwRot_Variant
    // (#fw_any >= 2) both miss. The framework list was decoy all along and can go to zero, so this
    // rule does not count frameworks; the payload section size takes over the specificity that the
    // framework path gave. Three-letter negatives (_CG, _LS, _AE) are left out on purpose: 4-byte
    // anchors hit by chance in code bytes (6 older builds lost to a stray 00 5F 43 47 in __text).
    // The import core and the empty framework import side are unchanged.

    condition:
        $macho_fat at 0 and filesize > 204800 and filesize < 4194304 and
        $dylib1 and $dylib2 and #payload_sect >= 2 and
        #i_ti >= 2 and #i_mts >= 2 and #i_po >= 2 and
        not $cf_imp and not $sec_imp and
        not $objc_imp and not $swift
}
