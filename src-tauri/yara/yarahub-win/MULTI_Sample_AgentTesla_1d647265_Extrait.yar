rule MULTI_Sample_AgentTesla_1d647265_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects AgentTesla (archive, etat extrait)"
        date = "2026-10-01"
        reference_sha256 = "1d6472657471d066810f516306ef9f770e852d27b3b1ecec5064f9f77871e4c3"
        yarahub_uuid = "23978eb6-bbc3-480e-bb7e-accb52b27613"
        famille = "AgentTesla"
        famille_source = "reputation"
        classe = "archive"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9090d4d5aafb3c75cb50d5fa372a8822"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "i1bo4ZMapGkIHSju1hi0st826aLonhdHgPZX2GZ6pZlRI32hUjNlN6PTyRKBlXqVUWaK23h5ffcHSRBEztv6N3h9MzUGqJSjX9KD0Fv5iMzrfwJ2ww13m38bg1T6vKeUF4RFp6NdPQWDqmbdlfJeULtMKIxivqZJ14aQPvDE7csLtICZpsTwQF7xiba8j9NjFvQofycS" ascii
        $s1 = "olE10NaTive" wide ascii
    condition:
        true and filesize < 50MB and 2 of them
}
