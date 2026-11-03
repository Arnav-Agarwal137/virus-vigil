rule VIGIA_CryptOne_d1e812f3 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "64b5cd9b-c2fb-4b10-afbf-479153693bd3"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7239babec4ed4f88af101430b8916684"
        contact = "javigp@usal.es"
        vigia_rule_id = "d1e812f3-338d-4fe7-aa31-288b49d58ddb"
        family = "CryptOne"
        description = "CryptOne: code shared by its builds (snapshot malware_snapshot_001.json); held-out 6/7, 0 benign or other-family hits"
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
        * Family files matched: 11 of the CryptOne files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 6e7456657273696f6e5c5c52756e000000558bec81c440ffffff53565733c9898d44ff }
    condition:
        any of them
}
