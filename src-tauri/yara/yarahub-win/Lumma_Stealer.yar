import "pe"

rule Lumma_Stealer
{
    meta:
        description = "Detects Lumma Stealer malware"
        author = "blade391off"
        date = "2024-06-01"
        
        
        yarahub_uuid = "39271a1a-5648-44f3-bf30-94172df1eb83"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fea50d3bb695f6ccc5ca13834cdfe298"

    strings:
        $s1 = "offenms.cyou" ascii nocase
        $s2 = "memory-scanner.cc" ascii nocase 
        $s3 = "C:\\Users\\Public\\Documents\\Lumma" wide ascii
        $s4 = { 4D 5A 90 00 03 00 00 00 }
        $s5 = { 50 45 00 00 4C 01 03 00 }

    condition:
        uint16(0) == 0x5A4D and 
        2 of ($s*) and
        pe.imports("winhttp.dll", "WinHttpOpen") and
        pe.imports("winhttp.dll", "WinHttpConnect") 
}