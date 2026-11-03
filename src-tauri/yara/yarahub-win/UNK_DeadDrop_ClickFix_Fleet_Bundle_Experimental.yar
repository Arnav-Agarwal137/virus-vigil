rule UNK_DeadDrop_ClickFix_Fleet_Bundle_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recovered recruitment bundle that writes a shell download command to the browser clipboard"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "c19b54da53a78c9ff1ac233b83aaa743"
        yarahub_uuid = "9b14a0d6-0098-4e5c-ac47-6c50538260cc"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "recovered minified web bundles; detects source markers, not visitor execution"
    strings:
        $clipboard_api = "navigator.clipboard.writeText" ascii
        $mime = "text/plain" ascii
        $telemetry = "cmdline_copied" ascii
        $download = "curl -ks" ascii
        $verify = "VERIFY-" ascii
        $unix_detach = "perl -MPOSIX -e" ascii
        $windows_hidden = "start -WindowStyle Hidden cmd" ascii
    condition:
        filesize < 4MB and $clipboard_api and $mime and $telemetry and
        $download and $verify and ($unix_detach or $windows_hidden)
}
