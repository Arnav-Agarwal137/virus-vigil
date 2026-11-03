rule MULTI_Sample_Unique_d6b0ccb8
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "d6b0ccb83a60d386f0764cd14e8befb3c1999e95050215abd6cc27f501c230fe"
        yarahub_uuid = "fdb3077e-5d5f-4d1e-b0a3-d4d8976c7e81"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "bd1e32f470b49af703662bd7078c3447"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "name = \"anime-face-detector\"" ascii
        $s1 = "version = \"0.1.0\"" ascii
        $s2 = "description = \"Anime Face Detector using YOLOv8 and HRNetV2 (pure PyTorch)\"" ascii
        $s3 = "readme = \"README.md\"" ascii
        $s4 = "requires-python = \">=3.10\"" ascii
        $s5 = "\"numpy>=1.21.3\"," ascii
        $s6 = "\"opencv-python-headless>=4.5.4.58\"," ascii
        $s7 = "\"torch==2.9.1\"," ascii
        $s8 = "\"torchvision==0.24.1\"," ascii
        $s9 = "\"huggingface-hub>=0.20.0\"," ascii
        $s10 = "\"ultralytics>=8.0.0\"," ascii
        $s11 = "project.urls]" ascii
        $s12 = "Homepage = \"https://github.com/hysts/anime-face-detector\"" ascii
        $s13 = "project.optional-dependencies]" ascii
        $s14 = "demo = [\"gradio>=5.0.0\"]" ascii
        $s15 = "\"pre-commit>=3.0.0\"," ascii
        $s16 = "\"mmengine==0.10.7\"," ascii
        $s17 = "dependency-groups]" ascii
        $s18 = "demo = [\"anime-face-detector[demo]\"]" ascii
        $s19 = "dev = [\"anime-face-detector[dev]\"]" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s2, $s3, $s4, $s5, $s7, $s8, $s9, $s10, $s11, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s6, $s12)
}
