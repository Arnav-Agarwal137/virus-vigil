rule MULTI_Sample_Unique_b45fa506
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "b45fa506195cfcdef406ba9f0c77b36ddc1a7c224040926ec70abc2fdea7b93a"
        yarahub_uuid = "6c857a8f-386f-4e3c-b80a-e3f6d01d9504"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3b4fcfcf393eca4d264dca4a4663bc37"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "svg xmlns=\"http://www.w3.org/2000/svg\">" ascii
        $s1 = "<symbol id=\"bluesky-icon\" viewBox=\"0 0 16 17\">" ascii
        $s2 = "<g clip-path=\"url(#bluesky-clip)\"><path fill=\"#08060d\" d=\"M7.75 7.735c-.693-1.348-2.58-3.86-4.334-5.097-1.68-1.187-2.32-.981-2.74-.79C.188 2.065.1 2.812.1 3.251s.241 3.602.398 4.13c.52 1.744 2.367" ascii
        $s3 = "<defs><clipPath id=\"bluesky-clip\"><path fill=\"#fff\" d=\"M.1.85h15.3v15.3H.1z\"/></clipPath></defs>" ascii
        $s4 = "<symbol id=\"discord-icon\" viewBox=\"0 0 20 19\">" ascii
        $s5 = "<path fill=\"#08060d\" d=\"M16.224 3.768a14.5 14.5 0 0 0-3.67-1.153c-.158.286-.343.67-.47.976a13.5 13.5 0 0 0-4.067 0c-.128-.306-.317-.69-.476-.976A14.4 14.4 0 0 0 3.868 3.77C1.546 7.28.916 10.703 1." ascii
        $s6 = "<symbol id=\"documentation-icon\" viewBox=\"0 0 21 20\">" ascii
        $s7 = "<path fill=\"none\" stroke=\"#aa3bff\" stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.35\" d=\"m15.5 13.333 1.533 1.322c.645.555.967.833.967 1.178s-.322.623-.967 1.179L15.5 18.333m-3.333" ascii
        $s8 = "<path fill=\"none\" stroke=\"#aa3bff\" stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.35\" d=\"M17.167 10.836v-4.32c0-1.41 0-2.117-.224-2.68-.359-.906-1.118-1.621-2.08-1.96-.599-.21-1.34" ascii
        $s9 = "<path fill=\"none\" stroke=\"#aa3bff\" stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.35\" d=\"M3 10a2.78 2.78 0 0 1 2.778-2.778c.555 0 1.209.097 1.748-.047.48-.129.854-.503.982-.982.145" ascii
        $s10 = "<symbol id=\"github-icon\" viewBox=\"0 0 19 19\">" ascii
        $s11 = "<path fill=\"#08060d\" fill-rule=\"evenodd\" d=\"M9.356 1.85C5.05 1.85 1.57 5.356 1.57 9.694a7.84 7.84 0 0 0 5.324 7.44c.387.079.528-.168.528-.376 0-.182-.013-.805-.013-1.454-2.165.467-2.616-.935-2.616" ascii
        $s12 = "<symbol id=\"social-icon\" viewBox=\"0 0 20 20\">" ascii
        $s13 = "<path fill=\"none\" stroke=\"#aa3bff\" stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.35\" d=\"M12.5 6.667a4.167 4.167 0 1 0-8.334 0 4.167 4.167 0 0 0 8.334 0\"/>" ascii
        $s14 = "<path fill=\"none\" stroke=\"#aa3bff\" stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.35\" d=\"M2.5 16.667a5.833 5.833 0 0 1 8.75-5.053m3.837.474.513 1.035c.07.144.257.282.414.309l.93.15" ascii
        $s15 = "<symbol id=\"x-icon\" viewBox=\"0 0 19 19\">" ascii
        $s16 = "<path fill=\"#08060d\" fill-rule=\"evenodd\" d=\"M1.893 1.98c.052.072 1.245 1.769 2.653 3.77l2.892 4.114c.183.261.333.48.333.486s-.068.089-.152.183l-.522.593-.765.867-3.597 4.087c-.375.426-.734.834-.79" ascii
        $s17 = "</symbol>" ascii
    condition:
        true and filesize < 50MB and 3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s8, $s9, $s10, $s11, $s12, $s13, $s15, $s17) and 1 of ($s0, $s7, $s14, $s16)
}
