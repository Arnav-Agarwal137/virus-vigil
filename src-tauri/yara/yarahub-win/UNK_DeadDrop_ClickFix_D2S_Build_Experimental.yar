rule UNK_DeadDrop_ClickFix_D2S_Build_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Identifies the observed D2S ClickFix bundle variant by its challenge and walkthrough features"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "730d5970361240847040621296deb393"
        yarahub_uuid = "68c3a3bc-48d5-4c6d-b168-4764a3523313"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "variant identification for plaintext or gzip-decoded lure bundles"
    strings:
        $daemon = "perl -MPOSIX" ascii
        $setsid = "setsid" ascii
        $winhide = "start -WindowStyle Hidden cmd" ascii
        $new1 = "design-challenge" ascii
        $new2 = "/guide.mp4" ascii
        $new3 = "design_challenge_render" ascii
        $new4 = "design_challenge_antibot_required" ascii
        $new5 = "check_3d_m" ascii
        $new6 = "check_bot_m" ascii
        $kit1 = "track-activity" ascii
        $kit2 = "environment-setup" ascii
        $kit3 = "anti-bot-check" ascii
        // Retained implementation syntax, not just markers quoted in research.
        $impl_copy = /\.clipboardData\?\.setData\([`"]text\/plain[`"],[^;\r\n]{1,160}cmdline_copied[`"],\{os:[A-Za-z_$][A-Za-z0-9_$]*,step:[`"]design_challenge_render[`"]/ ascii
    condition:
        $impl_copy and
        filesize < 2MB and ($winhide or ($daemon and $setsid)) and
        2 of ($new*) and 1 of ($kit*)
}
