rule MULTI_Sample_Unique_3d9978d3
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "3d9978d34937bd7828fcdb5825e7368de1d0eddc4da8847f3505c6c3ad27b374"
        yarahub_uuid = "9820f3c3-c01b-4714-aab8-85b4371e4839"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "47f9e6b4fbaacb2b54913f5564032781"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "li><a href=\"https://www.curseforge.com/minecraft/mc-mods/simple-voice-chat\">Simple Voice Chat (by henkelmax)</a></li>" ascii
        $s1 = "li><a href=\"https://www.curseforge.com/minecraft/mc-mods/xaeros-minimap\">Xaero's Minimap (by xaero96)</a></li>" ascii
        $s2 = "li><a href=\"https://www.curseforge.com/minecraft/mc-mods/mouse-tweaks\">Mouse Tweaks (by YaLTeR)</a></li>" ascii
        $s3 = "li><a href=\"https://www.curseforge.com/minecraft/mc-mods/geckolib\">GeckoLib (by Gecko)</a></li>" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3)
}
