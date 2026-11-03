rule VIGIA_SharpHound_2025ac70 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "c94e8965-86fa-4ab4-a0a1-54917089ce4e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "99bfdc2576148bfe62b9534be5bf4d70"
        contact = "javigp@usal.es"
        vigia_rule_id = "2025ac70-0ae7-4f91-bd89-9d9157ca52a1"
        family = "SharpHound"
        description = "SharpHound: code shared by its builds (snapshot malware_snapshot_001.json); held-out 25/25, 0 benign or other-family hits"
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
        * Family files matched: 50 of the SharpHound files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 73746174757320696e206d696c6c697365636f }
        $c1 = { 7a50a01a2b38e380536c83a052a62fec955ae724e90b2b9cdce474ef6dd468bfbab7a73675eca8aadeef51a057237c37df93eebdaf96614f20319a6589bf0efb }
        $c2 = { a8fc1cdc900a25f1f0ae6ae664d25de355824e02a1d5201c60dea52e74d8031b16d725c9a15cdd3085d775ada512e86e300b5a4e46495f0a1d3f674ec6cfa981 }
        $c3 = { d39acc6d2ac6aa776ab85706ef62df4d062b828eae32a54d7aca29545c872313474b48075b6ef01e786ecea34378d6c06b9d9c1bbccfd308fadc4f436bf24f8d }
        $c4 = { 9b6bb264270720504081245b93dd1d6d48fe9694a61d833255c30f0f656bfa55badafcb6a79e871eccc342ad93ad4dd4b2d5d472c59e61054ca91813a61df7e5 }
        $c5 = { f34762479f33faaa5f100d87994fe452c9cf10dd2ad33105330433bfc8efd6a01d1f316d5139bcfd1d31b6d1a3a636b9dce6a8d1e698a90dbca1d4e877d09649 }
        $c6 = { 1d41b5710effae55a7fdd841d112ffd71d4854e7412ba6073bc25bb602528add3901b0bd32aba20db1d9e6d81a69dcbf02f9b0e3cf20c778053bb5467ffa7d00 }
        $c7 = { ff344ccbd7cd603ae6c65739e22bf3906562eecc426fa9bc49f16546e64fea30e6c902a924989959189546d2fbab28f288663ef4deca97c5333f96449e29e469 }
        $c8 = { e8a6f917e21abee661607f96c849eeaa5c17ba7025a9a943b1b64dc672efa658171235e6907f74631ff7ac181762828d31515539a10dae0950730bef49554e28 }
        $c9 = { b590189d8c2d9cb0b94e24c61396b59ea279a654c1eff2f6167413c80fe671a49114cdc5abf85115a468ce80a94087289a4f063b2c2f682a1124798c0fcb63fa }
        $c10 = { 33f11965df3ef799716c7686d9ec8ce3af33217f9d51fe8a020ab38efdcd76637f9a64de4f12617f9a80bea11d6eb61b1798f599a5abbed8ad7a8a5066995c3d }
        $c11 = { 49a221ea2255e31b18a4f3d142fd1543c34ef9fcae97f619b470587de1176e85454e5157b1de0e5ed6755455ea20dc19a88e9721f32ea32357d0fcefc5303c0f }
        $c12 = { 5822d26e405fef8ed902c931139fc909b608291cb108d9f86c2468b7b51a4c8b91c8a68dc6b13129399f6e8713f3e5a4917eabd048bf11a3f1f80feb613ac679 }
        $c13 = { 58ead724545bf11abd7d680ee66fc877a286da82e6c7311fb2225e4fca59b060d478546f5b856f86acc99fa455d01b844c496a08b932fc16de9568121abe6e3d }
        $c14 = { dfd57b996b6d4cf2fb431f77ebafeb596ade7fd0a5d177cd3ce777bf7d63f097bcfd929d0fd25f9cd1360f78edfca599dbf800bd44c7277b6ea7073c098c53ce }
        $c15 = { 9230e5da17ad5e73b332dbcfefbcfbf9b2b5c35ddbaea9795a16f1b0b3f4b8f7c57de5fc813ddcefa46c3cb9e3cea4b1f766afa1baedda93b3ca724046f28d4f }
        $c16 = { 70b95ce5c0ee27d622e3140903fb25b0f088bde13ca5c93a3fa1d170eba8fad15b11a2aba29adb7c5e3729f4969ab1318bfafc4bb5c40232184550a41b641f1f }
        $c17 = { 741a0278011461b396456d86c7a36b75a1403464406623f6adb5f5db17ab0964f11aefa2162ee290a56c1e64ec9b87f78e1b5eced616ca57765ed5c06a807c8d }
        $c18 = { e740651a1b0be42466f0e042f9a375571ac742ea41e3f36cd8367c5ad5a755cf332a23466226b7e6dcd28a184ade579ea5f2e31398f50526ab48168623b56648 }
        $c19 = { fbf7b07ddd3aeeed63ff3e32f93d6dffa04d28fb29bdec63428c24efd7f61f50f61f64fbba453dd4c7fec364f2fbdafe2336a1ec077bd9c7ec11493eaaed3fa6 }
    condition:
        any of them
}
