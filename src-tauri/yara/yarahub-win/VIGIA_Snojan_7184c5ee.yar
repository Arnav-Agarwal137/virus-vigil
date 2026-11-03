rule VIGIA_Snojan_7184c5ee {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "ed082bcc-006e-4b48-991c-e929ac74873f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c136eb87f379f002fa9b245245d6db10"
        contact = "javigp@usal.es"
        vigia_rule_id = "7184c5ee-3199-46a1-86e7-f9d92b5ba766"
        family = "Snojan"
        description = "Snojan: code shared by its builds (snapshot malware_snapshot_001.json); held-out 25/25, 0 benign or other-family hits"
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
        * Family files matched: 50 of the Snojan files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 6170f69805e370656e8a118cf0c1ee8858f9717561fe2019cb760d6e650ee2134405e61e02f803d894d05902d7b4131cb92abab25b27187bc002d8903d7c }
        $c1 = { 344dd3333a41484f4dd3344d565d646b7279745dd735b54bbf03c10bcb03d5df344dd3dfe9f3fd048741000b344dd334121920272ed3344dd3353c434a }
        $c2 = { a80be46c0beed82f584723174e5aa60030170a66b3d94e5a180b2f0e0a9c09beefa63804896223e9d361181e8941000078fa0d3a070587d3dd1200dc83 }
        $c3 = { 780000fe5f03110d4cdc43727970744163714f40260076ab78b1ff8fb974591543726561746548617368000110ff5cc0fe44657374726f7911d40d }
        $c4 = { 6c6c0543002a2a205265d0acf8e073756d7674e92be8006297532099ff8f0104ac0a002020252520546f74615d04e8dc6c20000b52 }
        $c5 = { 8a02428807474975f7e963ffffff908b0283c204890783c70483e90477f101cfe94cffffff5e89f7b98e0900008a07472ce83c01 }
        $c6 = { 035dd7755de91fc803abaf72ff840398344dd334a9bbcadaec4dd37cd3fb0b4302001a2b3e51344dd3345d6a78858fd3344dd3 }
        $c7 = { 051b3ceaeb90ea1dd5fb2533315bbda48a41a468ffecd5c0015d006764cd044f646fd90e5d034d6f6eff4d35fd00547565 }
        $c8 = { c00000b1a000001db8000018a60000b5b70000f2c200004eb90000f35dd3fdbbbe13b600008cbc00005a0326cd73067df7 }
        $c9 = { 62042bb4001277610817c264b5766d766e9030215c765276700be10fec76731e7368617265f0b0d9126612ef0ff7ff090b }
        $c10 = { 4d617200417072079bfeffee79004a344a756c0041756700536570004f6374737600699aaefb44656300c833cc03d0 }
        $c11 = { 380cbb460767a2e0f002afcd0bc4c1bd87a348080397aae0e00ef40b8bab8243e7a60a007fab5c151c9e0b7fb0e7aa }
        $c12 = { 282f363d44d3344dd34b525960674dd3344d6e757c838a91755dd73498d457de03c90bd3df344dd303dde7f1fb02 }
        $c13 = { 4c5864d3344dd3707c8890984dd3344da0acb8c4d0d8b94dd334e4f0fc0858bbd3344dd303202c3844503bcc34 }
        $c14 = { 746f7763446d656d6368d0070668f77baf07707929656df7cf86ed6208e00001837b7173666e47c76f72407267 }
        $c15 = { 1120646f6501871a62b4126d202b8860c8ae319094c7538e1e732e20d80072fc108061c06519d024bae945 }
        $c16 = { 3b61090c736e0e812322610d7622064213e75fa58b05fb3f8c5f61737369676e5f27a6608667092466644b }
        $c17 = { 9ca8bccde24de7364df0fe0b444303283e344dd3345063748999df344dd3acc5d7e90245020018344dd3 }
        $c18 = { 8756a08e22e7285eb3010e02e43aa261896301731733fccf2b737363616e6600011677076b70efbd7707 }
        $c19 = { 422b1061761777402e692743615d11d04b00c7105700f8ff6e27c000600200000000009a640200000000 }
    condition:
        any of them
}
