rule UNK_DeadDrop_ClickFix_Copy_Hijack_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recruitment-lure JavaScript that writes a shell download command to the clipboard"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "c19b54da53a78c9ff1ac233b83aaa743"
        yarahub_uuid = "1f0c5e3c-bc8d-4441-a4c3-e9481195ca70"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or gzip-decoded JavaScript; detects content, not visitor execution"
    strings:
        $daemon = "perl -MPOSIX" ascii
        $setsid = "POSIX::setsid" ascii
        $winhide = "start -WindowStyle Hidden cmd" ascii
        $curl = "curl -ks" ascii
        $setdata = ".setData(" ascii
        $write = "clipboard.writeText" ascii
        $clipboard = "clipboard" ascii
    condition:
        filesize > 16KB and filesize < 4MB and
        ($setdata or $write) and $clipboard and
        (($daemon and $setsid) or $winhide or $curl)
}
