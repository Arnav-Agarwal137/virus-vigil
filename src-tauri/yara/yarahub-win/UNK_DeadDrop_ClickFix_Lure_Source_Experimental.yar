rule UNK_DeadDrop_ClickFix_Lure_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recruitment verification page with clipboard substitution telemetry"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "c19b54da53a78c9ff1ac233b83aaa743"
        yarahub_uuid = "2755d212-e665-4936-8fbd-598dd9ae4d2d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or decoded web source; does not establish user execution"
    strings:
        $telemetry = "cmdline_copied" ascii
        $mime = "text/plain" ascii
        $verify = "VERIFY-" ascii
        $clipboard_set = "setData" ascii
        $clipboard_write = "writeText" ascii
        // Retained implementation syntax, not just markers quoted in research.
        $impl_copy = /\.clipboardData\?\.setData\([`"]text\/plain[`"],[^;\r\n]{1,160}cmdline_copied[`"],\{os:[A-Za-z_$][A-Za-z0-9_$]*,step:[`"](verify|check)[`"]/ ascii
    condition:
        $impl_copy and
        filesize > 16KB and filesize < 2MB and all of ($telemetry, $mime, $verify) and
        1 of ($clipboard_*)
}
