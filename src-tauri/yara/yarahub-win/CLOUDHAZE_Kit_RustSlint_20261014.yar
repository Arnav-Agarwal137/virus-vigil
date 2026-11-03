/*
   CLOUDHAZE / UNC7072 kit (rebrandable trojanized app suite:
   Paperline/QuartzLine document viewers, CAIRA AI-tool lure)
   Cluster: win.cloudeye on ThreatFox (likely mislabel), aliases CLOUDHAZE/UNC7072/PinkHugeSearch
   Samples: 7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3 (quartzline.exe)
   Author: Blackfish Security LLC / Hermia, 2026-10-14
*/
rule CLOUDHAZE_Kit_RustSlint_20261014
{
    meta:
        description = "CLOUDHAZE/UNC7072 rebrandable Rust+Slint trojanized-app kit (Paperline/QuartzLine/CAIRA)"
        author = "Blackfish Security LLC"
        date = "2026-10-14"
        reference = "https://x.com/vxunderground/status/2110222399241126337"
        sample = "7f1db334fd3302cf98dd4afddf6f90e98e2a496fe7e86bf1832b89d02f3d73c3"
        yarahub_uuid = "e026b907-c90e-40d1-8acf-a4b562f54af9"
        yarahub_reference_md5 = "d62d4b7811e37ce789b40ff9343e3458"
        yarahub_license = "CC0 1.0"
        yarahub_author_twitter = "@Darkfibr3"
        yarahub_reference_link = "https://x.com/vxunderground/status/2110222399241126337"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // deliberate single-letter obfuscated source tree (unique kit fingerprint)
        $src1 = "C:\\r\\src\\g\\register.rs" ascii
        $src2 = "C:\\r\\src\\e\\config.rs" ascii
        $src3 = "C:\\r\\src\\e\\commands.rs" ascii
        $src4 = "C:\\r\\src\\e\\a\\mod.rn" ascii
        $src5 = "C:\\r\\src\\d\\c\\profile.rs" ascii

        // C2 protocol vocabulary (concatenated run in .rdata)
        $proto = "indexcomsuccessecdurst1" ascii

        // updater methods
        $upd = "register_setupupdate_pre_downloadupdate_post_download" ascii

        // command execution template
        $cmd = "cmd.exe /e:ON /v:O" ascii wide

        // brand markers (any one build carries at least one)
        $brand1 = "Summit Works" wide
        $brand2 = "QuartzLine" wide
        $brand3 = "Paperline Document Viewer" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and (2 of ($src*) or ($proto and $upd))
        and (1 of ($brand*) or $cmd)
}
