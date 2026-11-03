rule UNK_DeadDrop_ClickFix_Device_Check_Prop_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "ClickFix lure bundle that pairs browser ML dependencies with shell-download markers"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        yarahub_reference_md5 = "9095b757f643e03360b9b2c3bc0f9344"
        yarahub_uuid = "f822d237-d989-4bb2-aa9a-edcbd0301329"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or gzip-decoded web bundle; subtype indicator, not a general ML detector"
    strings:
        $ml1 = "tensorflow" nocase ascii
        $ml2 = "@tensorflow" nocase ascii
        $three = "three" nocase ascii
        $device = "device-check" ascii
        $curl = "curl -ks" ascii
        $daemon = "perl -MPOSIX" ascii
    condition:
        filesize > 300KB and filesize < 2MB and
        ($ml1 or $ml2) and $three and $device and ($curl or $daemon)
}
