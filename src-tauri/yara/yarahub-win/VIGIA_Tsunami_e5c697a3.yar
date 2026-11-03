rule VIGIA_Tsunami_e5c697a3 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "481fe805-f5d0-4d9a-b2ee-2275b363fea0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "895a8e146f5e855018cb3ce5f85f0e45"
        contact = "javigp@usal.es"
        vigia_rule_id = "e5c697a3-2334-4115-8669-063313cf9188"
        family = "Tsunami"
        description = "Tsunami: code shared by its builds (snapshot malware_snapshot_001.json); held-out 7/7, 0 benign or other-family hits"
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
        * Family files matched: 12 of the Tsunami files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 0a007368697474657275206b6f746f206461 }
        $c1 = { 6b84357f6886e2a039539cb7370750aa }
        $c2 = { c7cee2a1527fcd4f015e1150fa8306a7 }
    condition:
        any of them
}
