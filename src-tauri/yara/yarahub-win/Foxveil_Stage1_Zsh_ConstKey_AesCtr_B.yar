rule Foxveil_Stage1_Zsh_ConstKey_AesCtr_B
{
    meta:
        yarahub_uuid = "30a693a4-030a-4e1a-9f14-10202071ed72"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0c8c1d6d7a9fb091ffb392a8ba385912"
        description = "Foxveil ClickFix stage-1 zsh dropper, 2026-10-21 generator: any blob-array name and a _kb expression starting on a plain variable; hex blobs -> md5(constant _kb) -> openssl AES-128-CTR IV 0 -> gunzip, run via eval"
        actor = "Foxveil"
        family = "AMOS ClickFix dropper"
        reference_sha256 = "7311a535954158323045282fef16e143a4f323a8b2916518854874957eba1d45"
        date = "2026-10-21"
        tlp = "CLEAR"

    strings:
        $shebang = "#!/bin/zsh"
        $k       = "_k=$(printf '%s' \"$_kb\" | ${"
        $dec     = "enc -d -aes-128-ctr -K \"$_k\" -iv 00000000000000000000000000000000 | ${"
        $unhex   = "} -r -p | ${"
        $kb      = /\n_kb=\$\(\( \( \$/
        $arr     = /\n_[a-z]{2,16}=\( "\$_[a-z_]+" "\$_[a-z_]+" "\$_[a-z_]+"/
        $hexvar  = /\n_[a-z_]{4,20}="[0-9a-f]{90,}"\n/

    condition:
        filesize < 32KB and $shebang at 0 and $dec and $k and $unhex and $kb and $arr and #hexvar >= 3
}
