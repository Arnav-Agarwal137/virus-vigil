rule Web_Phishing_Evitree_Google_Docs_Captcha {
    meta:
        description = "Detects phishing pages associated with the Evitree / Paperless Post phishing campaign"
        author = "Serhii Kocherhan"
        date = "2026-10-04"
        yarahub_twitter = "@skocherhan"
        yarahub_uuid = "8f80134b-ff9f-4976-ae8d-6dcaf0797c83"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5bff5065b3768b57fded05eefcbec827"
        reference = "https://github.com/dendritelab/intelreporting/blob/main/evitreephishingdeepdive.md"

    strings:
        // Specific reCAPTCHA site key utilized in the Evitree / Google Docs phishing infrastructure
        $s_sitekey = "data-sitekey=\"6LfTPlUUAAAAAGSUt1_LqpJXQpatx7_BzTDcU9On\"" ascii wide nocase
        
        // Alternative field-split match in case of formatting variations
        $s_key_only = "6LfTPlUUAAAAAGSUt1_LqpJXQpatx7_BzTDcU9On" ascii wide

    condition:
        filesize < 500KB and (
            $s_sitekey or
            $s_key_only
        )
}