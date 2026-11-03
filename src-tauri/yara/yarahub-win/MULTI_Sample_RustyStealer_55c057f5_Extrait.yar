rule MULTI_Sample_RustyStealer_55c057f5_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects RustyStealer (inconnu, etat extrait)"
        date = "2026-10-01"
        reference_sha256 = "55c057f52baa94b22c7d8c41b664f7bcf9217739e3fe0fc005f621755de5aa67"
        yarahub_uuid = "00b6b5c3-a8a4-49c3-aeb2-942eee98991d"
        famille = "RustyStealer"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a68828b8db87ca1e6d21f85e5597a5b3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "Societext para Windows v1.13.0" ascii
        $s1 = "Aplicacion oficial construida con Tauri 2 y WebView2." ascii
        $s2 = "Abre https://societext-app.pages.dev/ y conserva la sesion dentro de la ventana nativa." ascii
        $s3 = "Requisitos: Windows 10/11 con WebView2 Runtime." ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s3) and 1 of ($s2)
}
