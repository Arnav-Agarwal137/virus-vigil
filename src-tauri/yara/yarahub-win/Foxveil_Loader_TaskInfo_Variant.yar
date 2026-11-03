rule Foxveil_Loader_TaskInfo_Variant
{
    meta:
        yarahub_uuid = "d061268d-d8a5-4216-95b2-02c6a51f1ee6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "94b83bf6c9a161c508a72c7323eff877"
        description = "Foxveil macOS loader (ClickFix -> AMOS), quill generation with run-time settings back inside the payload script (no constructor settings file): fat x86_64+arm64 linking CoreFoundation+libSystem+libc++ but importing nothing from CoreFoundation or objc, with the task_info/mach_task_self_ resolver core in both slices inside a per-build random libc decoy import set"
        actor = "Foxveil"
        family = "AMOS loader"
        reference_sha256 = "9083c41421642ee650b9e2cf19ac7cbc462af49aa6856ae4255030e83fbdd6dd"
        date = "2026-09-29"
        modified = "2026-10-15"
        version = "2"
        tlp = "CLEAR"

    strings:
        $macho_fat = { CA FE BA BE 00 00 00 02 01 00 00 07 }
        $fw1 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation\x00"
        // Same bytes as "/usr/lib/libSystem.B.dylib\x00" / "/usr/lib/libc++.1.dylib\x00", written as hex on purpose
        // (v2, 2026-10-15): YARA-X 1.20 shares a text pattern that is byte-identical across rules, and when
        // Foxveil_Loader_MachO / _Hunt (same text strings, filesize < 2MB) are compiled alongside, it reports
        // no match for that pattern to this rule on files over 2 MB. YARA 4.x is unaffected. Missed willow 25
        // aa2a4e66 (2,184,528 B), willow 3045f398 and chant 22 40fa4235 (2,284,176 B) in the repack tripwire.
        $dylib1 = { 2F 75 73 72 2F 6C 69 62 2F 6C 69 62 53 79 73 74 65 6D 2E 42 2E 64 79 6C 69 62 00 }
        $dylib2 = { 2F 75 73 72 2F 6C 69 62 2F 6C 69 62 63 2B 2B 2E 31 2E 64 79 6C 69 62 00 }
        $i_ti  = "\x00_task_info\x00"
        $i_mts = "\x00_mach_task_self_\x00"
        $i_po  = "\x00_pthread_once\x00"
        $cf_imp   = "\x00_CF"
        $objc_imp = "\x00_objc_"
        $swift    = "\x00_swift_"

    // WHY THIS RULE EXISTS (2026-09-29, quill build 73 9083c414 / md5 94b83bf6): the constructor no
    // longer writes a settings file, so _open/_write/_unlink/_unsetenv left the import table and
    // Foxveil_Loader_CtorCfg_Variant (which needs them) stopped matching; no loader rule hit.
    // What stays: the fat CF+libSystem+libc++ link set with no CF/objc import (CF is resolved at run
    // time) and the task_info(mach_task_self()) + pthread_once core in both slices.

    condition:
        $macho_fat at 0 and filesize > 204800 and filesize < 4194304 and
        $fw1 and $dylib1 and $dylib2 and
        #i_ti >= 2 and #i_mts >= 2 and #i_po >= 2 and
        not $cf_imp and not $objc_imp and not $swift
}
