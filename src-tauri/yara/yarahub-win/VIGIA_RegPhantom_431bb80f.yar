rule VIGIA_RegPhantom_431bb80f {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "6017adbc-1f4f-4384-8741-4542aa2bfabd"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ea0f589e4bc2737119a1730477f8929b"
        contact = "javigp@usal.es"
        vigia_rule_id = "431bb80f-7713-4758-aa34-f95c94e88ec3"
        family = "RegPhantom"
        description = "RegPhantom: code shared by its builds (snapshot malware_snapshot_001.json); held-out 9/9, 0 benign or other-family hits"
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
        * Family files matched: 19 of the RegPhantom files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 4829c4488b45984989e04c8945204c8b45c84d89104c8b45d04d8908488911488b11488910488b09488b004863403c4801c1488b45d8488908488b45d848 }
        $c1 = { c2010f45c18945c0e955070000488b45d0488b08488b45e8488b008b004801c1488b45f8488908488b45e8488b0848 }
        $c2 = { 00488b08488b45f8488b00488b5508486312486bd2284801d08b400c4801c1488b4510488908488b4510488b0848 }
        $c3 = { 488b45b0488908488b45b848c70000000000488b45c0c70000000000488b45c8c7000000 }
        $c4 = { 25ff0f00006689c1488b4520668908488b45180fb70083f80a0f94c0240188452d }
        $c5 = { 0f45c18945c0e937030000488b45e8488b08488b45e8488b008b40044801c148 }
        $c6 = { d0488b08488b45e8488b008b004801c1488b45f8488908488b45e8488b0848 }
        $c7 = { e982000000488b45c8488b10488b45f8488b00488b4d200fb7094801c848 }
        $c8 = { 83e10183f9000f94c180e101884db683f80a0f9cc024018845b7c745 }
        $c9 = { c0e9d9050000488b4500488b00488b4d108b090fb70448c1f80c6689 }
        $c10 = { f6c2010f45c18945c0e9ba030000488b45e0488b08488b45c84889 }
        $c11 = { ffff90554881ec80000000488dac2480000000448945b4488955b8 }
        $c12 = { c18945c0e980060000488b45108b00488b4d083b010f92c0240188 }
        $c13 = { 0f45c18945c0e9f6040000488b45c8488b08488b45f8488b0048 }
        $c14 = { 8908488b45f0488b008b40504189c0488b45c8488b10488b45d0 }
        $c15 = { 010000488b45d0488b08488b45c88b004189c031d24883ec20 }
        $c16 = { 89e148894d00488b4dc0488911488b4dc0488b09488908488b }
        $c17 = { 488b45e88908488b45e88338000f9dc024018845fa8b0d }
        $c18 = { 83ec20ffd04883c4204889c1488b45e8488908488b45 }
        $c19 = { 00004829c44889e0458911498910498b104883c2 }
    condition:
        any of them
}
