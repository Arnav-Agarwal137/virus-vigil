rule VIGIA_AmosStealer_d9839fe3 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "4f670fa4-bd17-43a0-b974-6dbc099111a6"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "bf0cdddd435409bda71ee8272a7dfac6"
        contact = "javigp@usal.es"
        vigia_rule_id = "d9839fe3-47da-4f81-bb86-82016912fc8b"
        family = "AmosStealer"
        description = "AmosStealer: code shared by its builds (snapshot malware_snapshot_001.json); held-out 7/10, 0 benign or other-family hits"
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
        * Family files matched: 14 of the AmosStealer files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 313030455053395f005f5f5a4e5374335f5f3132385f5f657863657074696f6e5f67756172645f657863657074696f6e73494e535f32395f416c }
        $c1 = { 7445504e535f31306572726f725f636f64654500900073b00211405f5f5a4e5374335f5f31345f5f6673313066696c6573797374656d323872 }
        $c2 = { 6572726f725f636f64654500900073b00211405f5f5a4e5374335f5f31345f5f6673313066696c6573797374656d323872 }
        $c3 = { 7265616d4545443242386e653230303130304576005f5f5a4e5374335f5f313470616972494b4e535f3132626173 }
        $c4 = { 636861725f74726169747349634545454500808002c0022090405f5f5a54494e5374335f5f313135 }
    condition:
        any of them
}
