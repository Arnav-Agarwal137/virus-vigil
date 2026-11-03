rule WardenStealer_DvnX_Alphabet_Decoder
{
    meta:
        description = "Warden Stealer (YapStealer) Oct 2026 DvnX loader and unpacked stealer: 88-symbol printable ASCII alphabet generator with exclusion bitmask 0x4400000008002201"
        author = "Daydream"
        date = "2026-10-16"
        reference_sample = "463f56104d5b9459918a39fd23d28937c1c7a1f88d8c3b6e48d6755fc0bbb7c7 (also matches e5b790c3a237edc2 and unpacked stealers cefd574917e8625d, 8351041a32a2c892)"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c185824056badcb489660d643e1f1952"
        yarahub_uuid = "e391b04f-82c1-4e7a-a519-07d3c812f94b"
    strings:
        $dvnx_mask = { 49 ( B8 | B9 | BA | BB ) 01 22 00 08 00 00 00 44 }
        $ascii_bt1 = { ( B0 21 | 40 B6 21 ) [0-24] 83 ( C0 | C1 | C2 ) DE [0-12] ( 49 | 4D ) 0F A3 }
        $ascii_bt2 = { 49 ( B8 | B9 | BA | BB ) 01 22 00 08 00 00 00 44 [0-16] 83 ( C0 | C1 | C2 ) DE [0-12] ( 49 | 4D ) 0F A3 }
    condition:
        $dvnx_mask and 1 of ($ascii_bt*)
}
