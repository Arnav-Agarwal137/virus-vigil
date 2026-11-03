rule VIGIA_PEASS_NG_d7288d76 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "b2ac21fd-e243-489b-a305-4240c5227ed5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6ffe4dc13ef84ff63f65946d74e4c47a"
        contact = "javigp@usal.es"
        vigia_rule_id = "d7288d76-291d-471d-81b5-35fd715741de"
        family = "PEASS-NG"
        description = "PEASS-NG: code shared by its builds (snapshot malware_snapshot_001.json); held-out 13/25, 0 benign or other-family hits"
        author = "VIG-IA - Cognitive Threat Intelligence System for Smart Territories and Tourism Sector"

    
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
        * Family files matched: 26 of the PEASS-NG files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 20736564202d247b457d2022732c2e2a2c247b5345445f5245447d }
        $c1 = { 5b20222428636f6d6d616e64202d7620 }
        $c2 = { 20736564202d247b457d2022732c2e2a }
        $c3 = { 692f656e2f6c696e75782d6861726465 }
    condition:
        any of them
}
