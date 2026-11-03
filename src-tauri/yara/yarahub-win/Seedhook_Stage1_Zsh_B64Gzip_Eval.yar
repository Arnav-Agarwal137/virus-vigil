rule Seedhook_Stage1_Zsh_B64Gzip_Eval
{
    meta:
        yarahub_uuid = "e99e5f5c-57bd-44c2-867b-7243420f7fb8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b13641e5d100b2f67404aa2685f7db9b"
        description = "Seedhook/MacSync ClickFix stage-1 zsh: gzip+base64 heredoc with randomised PAYLOAD_m delimiter decoded into a $d<digits> variable and eval'd"
        actor = "Seedhook (MacSync Stealer cluster)"
        reference_sha256 = "92f9d5ac6813ca77e92a511f584bbc2017dd8b92cebb60bfc20a83df33f2631e"
        date = "2026-09-30"
        tlp = "CLEAR"

    strings:
        $shebang = "#!/bin/zsh"
        $hd = /=\$\(base64 -D <<'PAYLOAD_m[0-9]{8,20}' \| gunzip\n/
        $gz = "\nH4sI"
        $ev = /\neval "\$d[0-9]{3,8}"/

    condition:
        filesize < 20KB and $shebang at 0 and $hd and $gz and $ev
}
