rule Foxveil_Stage1_Zsh_OuterKey_AesCtr
{
    meta:
        yarahub_uuid = "9c08e737-425c-459f-ab10-6e9e31a4f344"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "2bb444692c62607f5cc602c6aec04305"
        description = "Foxveil ClickFix stage-1 zsh dropper, outer-keyed variant: each hex blob decrypted separately with md5(_kb + blob index + a variable set by the pasted ClickFix command) -> openssl AES-128-CTR IV 0, concatenated, gunzip, eval"
        actor = "Foxveil"
        family = "AMOS ClickFix dropper"
        reference_sha256 = "3957725c425fbfe89cbe2e6bed37f0938609ac0af14ad1e111a078e154975b20"
        date = "2026-10-22"
        tlp = "CLEAR"

    strings:
        $shebang = "#!/bin/zsh"
        $loop    = /do _[a-z]{1,8}=\$\(\(_[a-z]{1,8}\+1\)\); printf '%s' "\$_[a-z]{1,8}" \| \$\{[a-z0-9]{2,8}\} -r -p \| /
        $key     = /enc -d -aes-128-ctr -K "\$\(printf '%s' "\$\{_kb\}\$\{_[a-z]{1,8}\}\$\{_[a-z0-9_]{2,20}\}" \| \$\{[a-z0-9]{2,8}\}\)" -iv 00000000000000000000000000000000; done \| \$\{/
        $kb      = /\n_kb=\$\(\( \( /
        $arr     = /\n_[a-z]{2,16}=\( "\$_[a-z_]+" "\$_[a-z_]+" "\$_[a-z_]+"/
        $hexvar  = /\n_[a-z_]{4,20}="[0-9a-f]{90,}"\n/

    condition:
        filesize < 32KB and $shebang at 0 and $key and $loop and $kb and $arr and #hexvar >= 3
}
