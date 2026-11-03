rule SCRIPT_Sample_Unique_7e87155d
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "7e87155da96e3218cf26ff3d3f816c0735b4d833bd32fa39799e0cc6b510fbd7"
        yarahub_uuid = "1a98738f-f768-4241-a8c1-323c38bf7a61"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "761c30662bfb51257387c6b58231c435"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "tmp/xb mikrotrick-container >/tmp/xb.out 2>/tmp/xb.err &" ascii
        $s1 = "cat /tmp/xb.out 2>/dev/null" ascii
        $s2 = "cat /tmp/xb.err 2>/dev/null" ascii
    condition:
        true and filesize < 50MB and 3 of them
}
