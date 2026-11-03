rule VIGIA_WARDENStealer_8f4ac3a9 {
    meta:
        date = "2026-10-28"
        yarahub_uuid = "10120432-e6e9-4629-90d9-542f9c941f19"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "954dc225ca5838f353772671aec1710d"
        contact = "javigp@usal.es"
        vigia_rule_id = "8f4ac3a9-a5d8-4755-975a-f36e05ec2569"
        family = "WARDENStealer"

    
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
        * Family files matched: 44 of the WARDENStealer files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 00488b59104c8b7918418d6e0166ffcd7414 }
        $c1 = { 48893c064c893e4883c4205b5f5e415e }
        $c2 = { 0000004889b0900000008d4f02668988 }
        $c3 = { c64404267b488b44242648894424300f }
    condition:
        any of them
}
