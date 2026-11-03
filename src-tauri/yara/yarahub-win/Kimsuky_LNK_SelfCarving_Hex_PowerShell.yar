rule Kimsuky_LNK_SelfCarving_Hex_PowerShell
{
    meta:
        description = "Windows shortcut that runs a hex-encoded PowerShell script from its own arguments, which finds its own .lnk in the current folder or under TEMP and reads a decoy and a single-byte-XOR PowerShell stage out of it by offset (14 Kimsuky-tagged lures, June 2026)"
        author = "Daydream"
        date = "2026-10-11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "8160bf0d-45c3-4388-8bfd-eb5eec3168ee"
        yarahub_reference_md5 = "a7da58d034366bcfb291e3fc4d869756"
    strings:
        $w1 = "$hex = '" wide
        $w2 = "[Convert]::ToByte($hex.Substring(" wide
        // upper-case hex of script tokens, as UTF-16 text
        $h1 = "4F70656E52656164" wide                 // OpenRead
        $h2 = "2E5365656B28" wide                     // .Seek(
        $h3 = "2D62786F72" wide                       // -bxor
        $h4 = "4765742D4C6F636174696F6E" wide         // Get-Location
        $h5 = "4765742D4368696C644974656D" wide       // Get-ChildItem
        $h6 = "2E6C6E6B2729" wide                     // .lnk')
        $h7 = "2D456E636F64696E672042797465" wide     // -Encoding Byte
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 12KB and filesize < 20MB and
        all of ($w*) and 5 of ($h*)
}
