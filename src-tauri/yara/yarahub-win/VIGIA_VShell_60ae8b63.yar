rule VIGIA_VShell_60ae8b63 {
    meta:
        date = "2026-10-28"
        yarahub_uuid = "62ff5411-d052-4de2-87a6-4e9da793aabf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "2c0298637545878ea93be495da06b120"
        contact = "javigp@usal.es"
        vigia_rule_id = "60ae8b63-76f8-4263-9605-1c9f6388a86a"
        family = "VShell"

    
        /*
        * DISCLAIMER
        * The strings in this rule are code that the VIG-IA platform mined from a family's samples obtained
        * from MalwareBazaar (https://bazaar.abuse.ch), kept only when no goodware and no file of
        * another family contains them.
        *
        * The resulting rule has undergone refinement via AI-assisted processing and validation against
        * curated goodware and malware corpora. However, this pipeline cannot guarantee high generalization
        * across all malware variants and environments. False positives and blind spots may occur.
        *
        * === Rule Evaluation Summary ===
        * False Positive Rate: 0.00% (on validated goodware corpus)
        * Family files matched: 25 of the VShell files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 8b004963413cf30f7f0424468b9c08880000004585db74d1488b042448c1e81066443bf0 }
        $c1 = { 75f18d04133bc5740e41ffc3453b5a1872d5e95dffffff418b4224438d0c1b4903c10f }
        $c2 = { 04914903c1eb0233c0488b5c2420488b6c2428488b742430488b7c2438 }
        $c3 = { e74f8d1419458bde418b7a204903f945397218768d8b37418bde4903 }
        $c4 = { 488970184889782041564883ec1065488b0425600000008be9 }
        $c5 = { 4c2408440fb7d00fbe01c1ca0d8039617c0383c2e003d048ff }
        $c6 = { 0f84b70000004d8b4830418bd6410f10 }
    condition:
        any of them
}
