rule VIGIA_CatStorm_1e38edcb {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "afec0511-b67e-4465-9cdd-e62bfce218f5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a86ee4d3865465f0e2218528ad93f0df"
        contact = "javigp@usal.es"
        vigia_rule_id = "1e38edcb-5c9c-4416-bcfa-51973eac78cd"
        family = "CatStorm"
        description = "CatStorm: code shared by its builds (snapshot malware_snapshot_001.json); held-out 8/8, 0 benign or other-family hits"
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
        * Family files matched: 17 of the CatStorm files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 73746f726d2f426f742f4d6574686f64732f6c372e666d744865780063617473746f726d2f426f742f4d6574686f64732f6c372e666d74446563006f732f7369 }
        $c1 = { 69782f656163636573732e676f0063617473746f726d2f426f742f4d6574686f64732f6d6f6e65726f2e676f0063617473746f726d2f426f742f4d6574686f64 }
        $c2 = { 636f72647564702d707073687474703a2f2f312e312e312e31312e302e302e31382e382e382e38382e382e342e34392e392e392e396e6574666c6978747769 }
        $c3 = { 676f0063617473746f726d2f426f742f4d6574686f64732f6c342f7070732e676f0063617473746f726d2f426f742f4d6574686f64732f6c342f7373682e67 }
        $c4 = { 496e740063617473746f726d2f426f742f4d6574686f64732f6c342e4d696e656372616674666c6f6f640063617473746f726d2f426f742f4d6574686f64 }
        $c5 = { 2f687474702e676f0063617473746f726d2f426f742f4d6574686f64732f6c372f687474706279706173732e676f006f732f7369676e616c2f736967 }
        $c6 = { 55696e7436340063617473746f726d2f426f742f4d6574686f64732f6c342e41636b666c6f6f640063617473746f726d2f426f742f4d6574686f64 }
        $c7 = { 676f0063617473746f726d2f426f742f4d6574686f64732f6c342f646e732e676f0063617473746f726d2f426f742f4d6574686f64732f6c342f66 }
        $c8 = { 6c342f666f72746e6974652e676f0063617473746f726d2f426f742f4d6574686f64732f6c342f6d696e6563726166742e676f0063617473746f72 }
        $c9 = { 676f0063617473746f726d2f426f742f4d6574686f64732f6c342f7564706279706173732e676f0063617473746f726d2f426f742f4d6574686f64 }
        $c10 = { 676f0063617473746f726d2f426f742f4d6574686f64732f6c342f61636b2e676f0063617473746f726d2f426f742f4d6574686f64732f6c342f }
        $c11 = { 676f0063617473746f726d2f426f742f4d6574686f64732f6c342f73796e2e676f0063617473746f726d2f426f742f4d6574686f64732f6c342f }
        $c12 = { 353434333336353339343236343320260a202020203b3b0a202073746f70290a202020206b696c6c616c6c2073797374656d642d7570646174 }
        $c13 = { 696e7465726573746861736869636f72707465727261666f726d61746c61737369616e6865726f6b756170702257696e646f7773222241 }
        $c14 = { 73746f726d2f426f742f4d6574686f64732f6c342e53796e666c6f6f642e66756e63310063617473746f726d2f426f742f4d6574686f64 }
        $c15 = { 65666c6f6f642e66756e63312e646566657277726170320063617473746f726d2f426f742f4d6574686f64732f6c342e466f72 }
        $c16 = { 6e6769746875626769746c61626c696e6f64656865726f6b7561706163686564656269616e7562756e747563656e746f7364 }
        $c17 = { 73746f726d2f426f742f4d6574686f64732f6c372e48747470666c6f6f640063617473746f726d2f426f742f4d6574686f64 }
        $c18 = { 73746f726d2f426f742f4d6574686f64732f6c342e6d635061636b65740063617473746f726d2f426f742f4d6574686f64 }
        $c19 = { 73746f726d2f426f742f4d6574686f64732f6c342e537368666c6f6f640063617473746f726d2f426f742f4d6574686f64 }
    condition:
        any of them
}
