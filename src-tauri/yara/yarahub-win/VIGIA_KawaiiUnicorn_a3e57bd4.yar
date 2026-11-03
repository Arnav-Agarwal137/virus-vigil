rule VIGIA_KawaiiUnicorn_a3e57bd4 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "38d3d868-e3a6-44fa-8241-abf3a159f905"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "54b941d5e5ecc3119a68ec005ad095c0"
        contact = "javigp@usal.es"
        vigia_rule_id = "a3e57bd4-6e07-4c07-a43c-ce4c81ddfa94"
        family = "KawaiiUnicorn"
        description = "KawaiiUnicorn: code shared by its builds (snapshot malware_snapshot_001.json); held-out 7/7, 0 benign or other-family hits"
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
        * Family files matched: 14 of the KawaiiUnicorn files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { cfd22c683e24b1d6426c716df9b6d636b68adcc758f3a8dad6b0ece5adf7bdbfbdfe9153f4c8387638c96b8d9534680d9b21adfe5bdd5fb58a8f5afaa9675c0d }
        $c1 = { 2073744576743a616374696f6e3d227361766564222073744576743a696e7374616e636549443d22786d702e6969643a64353937343839392d636138382d3766 }
        $c2 = { 50f55ed6a9155bcb0bfdc3ff004735ff00d72f94caeecd97b17f807fe7cb19ec2fcdfedad8edc846a412fa5403fb2bd50ca4ca01f5eafab6f7caaf8e1f26a0eb }
        $c3 = { 0c2c18bb756d96ff0088ff007bf70bc0753c8d5e8da11a41af5dfb51d307249ebdefdd7baf7bf75eebdef44541eb6a68ca7e7d5677c8df8ea5b378dcbe377d76 }
        $c4 = { e4c8e49185d3c37f53457e2d6f7e9106e565137a53f97fab3d07e02f0926beb8ff0007fabfcdd083b330d89a2cc4b45430e7271b63078fa5a5cd646a8fd86e2f }
        $c5 = { 0c6758d6d3e4f3992addc596ca6271388c665b75e1738bb7f0b9a39ccad2f0b8cc985fc575be9112ccaca2252682b927f3fb29c7870a70a642fad4f4a6d9fdb1 }
        $c6 = { 0352f45bfabfb937874dff0091d07fbf8f61dbfcab64e4aab8a3ff00c34f2dff002e5bff00cebffe2d7ed6dfece841955a847cff00d5e9f6fa53a552d929ee1d }
        $c7 = { c753b9635a2c4517dc54d6d7c83058d7869c4d1b4626d0b1b3b27097362d9ac1082d6ce58002a083524e7181e5434c91d2692103286bd0e187cee1370d29aec0 }
        $c8 = { 56e4daf9803f8de13371eab86537e39bd8dccf67dde7dbe649ade520822a2a40603c8f90238a9e2320d41a75e142284754edbc32bb93e34eefc6f5ef79647efb }
        $c9 = { db45b28ad4f16e3c3f61a9fb280d70a2180c99385e9e36875f6136d65b73ee28ea33f92dc5bdaa71f2ee3cb6773791cb4f553e1b1c98c8e3a7a2c8b7da6dfc1a }
        $c10 = { 3ff2f4aeeb5ca4399ebfda19287fcd546d8c6ffb6fe1838f68661491be641fe63a48789fb7a5d7e3da76f84f4df5d03eda47f3a757500b0078741c7696c76df9 }
        $c11 = { 90f98f8cbd8949b2771c2d41d3ddb1992db26b2a5a0971dd7bd99927646da7e7864963fe0dbfe463fc2d356b8f2adf6047f97515c9b708ac7728e4b9dbe50ec9 }
        $c12 = { eff1103328afd87a4ed661bbeb70d58a69f09fc328a574fb89ebb766370f4691160257823db93ee4cccb2aa12555a58958d8165fa8318f75d9edd6b1c5a9c70e }
        $c13 = { 89a027a4eeebc1d1ee7c2d6616b3cb04751122453c323c5343344caf14d0c919592396291432b021811707ddac2429dc72b5208f975eb494962adc3a06fa7bb3 }
        $c14 = { 000000f8974200ffffffff00000000d09d4200000000000000000000000000ffffffff0000000050994200e8984200fcc24200509942007899420000c3420050 }
        $c15 = { 6b5874659f47c9e3dc5bfdb6fb90f1329d7d96d6e89ac34c8f13b9ae69ff003119ed0f6963b40783e046ad70feab90228d15535725adaf23d53ed16803d41c }
        $c16 = { 8be846f8d7bcbfbe3d11d599e925fdea8d9d8fa6aafebfc430e3f83e5edfec715ec8b70842cf312be7fca951fcc9e958f857a1d0cbf4e57fdbff00c6fd9543 }
        $c17 = { 3f5a6c0dabd7184334589dad8d349aa7a83595f97ae66fe2d96dcd96d4cc4e6f71669aaabd8dec4d5fd07d044dcc7b8b5edd78c1ce926bc7f3e861b4ec7e05 }
        $c18 = { 67200e48f778e379a448a35264634007a9ebdd6b37f387b1771fc83f90389c06170d5d599b8063f686dcdbf4a22a8a8b6e0a8b506daa2d4b0fdbe72b3f8ac6 }
        $c19 = { 3f87c88cb621bfc6cca07fac7daeb1b836f203abb4e0fd9402bfb453ece94a1c115cf5c3a7fb021df7b5219aabf637161cff000cdcf8da8ff81d4791c59f55 }
    condition:
        any of them
}
