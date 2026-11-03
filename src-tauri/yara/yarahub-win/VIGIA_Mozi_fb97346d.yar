rule VIGIA_Mozi_fb97346d {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "67ef56ac-4faa-4f53-8ca0-8960548dde4c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "272029a2087a3d9cf74c539cf41b71c2"
        contact = "javigp@usal.es"
        vigia_rule_id = "fb97346d-243f-4a7e-94f9-1bae012a22cb"
        family = "Mozi"
        description = "Mozi: code shared by its builds (snapshot malware_snapshot_001.json); held-out 11/20, 0 benign or other-family hits"
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
        * Family files matched: 23 of the Mozi files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 8617efff36ec5038285b4317f356f27b854b174708855eb8f0373fd6269cffd516a752262b6432c8170cff37f3274800a327802da4af78b75ba4274b9beebb38 }
        $c1 = { 8ec17b24f0bb903352265fd5454ee2a71b52d7829a2ecf4dcbd0ff820ae701e718a73a550443bfbb1e988eec00648027f82353ca80a18b5371b9e3ac414396fb }
        $c2 = { c8c163501324d7052b36fe8a858fcc4150f7c8df5fc2fe663f0fac8985b313709c1c90938502b0890907e4e480408403648939392027046086050ec8c901c883 }
        $c3 = { 5700f312bbd30783042ebd1383b312db704b086cb3a7dfe7e724e4208121e3df6c122c8117f3e3cf29e4254f2000c6c003b006e1e49400c1bb0fbc53d1618440 }
        $c4 = { f80f23172a6c2ef917b081009802ffb7d66f47fb026006046228c7018b626230d8caf60ecb27bf8313a0b66c0233234b67a438ebf8e030885fc0b74053407c }
        $c5 = { 0acc34c8601fe520f7238e41ab8d135f7310a2bf97ad99eb27a7e5008390239fff532cc0ed6224ff43301a8706dfb705cdd5a57f13a1a03788cef4bd2313ea }
        $c6 = { fba63a075c2070371b2603939f26403ed7d035e7061b2fcb093f876046803ba1b70c5b93da9b9303ac0010448c655897a3de6ea7575bc3a40f04ae0c4377ba }
        $c7 = { 2ad38b61c3bbcb29ce919e8f187f82acbfc911523177c12c82c5c9b8b9cf0785e9870dfbc2ff721541553f84842307bfff9215929fc0a24d5bbaffd2170215 }
        $c8 = { 059b44779f7aaebbfbe2ff525f22aedc3b031f1bd26b4346df20741baf8eefb9ef46341704231787e80fb13535680f964f34e7a7b1a547c19f7b17480667 }
        $c9 = { 1a12ad9623f37f32d866d0ec03eb25d3e11d981117efe71fc9c059100714cb8f40a12bc69bb322d32b2b71d273b080a33f7baf119286bf97371ff6bdac40 }
        $c10 = { 64d786c48913ebcbeb31841327dfeb9bc8837c21e39400aba5ff8044c850c8a6940f244332589490fff029e423901687ffd0196400f982ffb0162c407e07 }
        $c11 = { 6b8603078c83756c26fd82ba2b783fc48f9344ffeda833de277752005312180fce7628031fdb045b0cd03b04931f4bdc82440f474373a210e12282f134 }
        $c12 = { 961702398c38406706882bb9e484064442c811cb63b7eb82410639bdb7b882908bb0f7840ab930e24867a50c932be4a19c90e0420e21cf447c699aa669 }
        $c13 = { 87032c30523760041b400344cbe682b70d4807a7ef3f53bf8482d69027afbc0504261deac47b1b07fbe770370c915f18d35c89994b102a3854bf876f41 }
        $c14 = { ac60b0cb47172b3b580d1913dc84233c48c846cf4007a689420b6f038a7307c380c0031b546b0917be901f3d1beff082708382237f4fa28f4690bf }
        $c15 = { f7a78f970382ae3fdf90896c1957370141f6011b2c739b0380ae3bb09511cd3a2cc73303f87a8c3757218b150fd65bcf43802047870365e241e8 }
        $c16 = { 8f8f8f34679aa68f8f8fff37b07a941fff00216f7b2e2e953bd4e32b3423479eb9416de9602743005f0d8c5103e4dbffa7a0eca80607ef8faf37 }
        $c17 = { e3354df71d3f472ae3082e0ae8bec3cb434b434b2f432cdd4903652b072d062330aee93e0c4b8b01233b381b19e1ba0d60ae392b3a03df5423 }
        $c18 = { f06423fb4323aedd82240218677b702b2b6d4bf0c15f24bb156e26fbfcea8c17286730a2a005172dcb3d0fe002970f5f683a9297171503c0 }
        $c19 = { ad02625724c5000706c002f7a0b25907d204b70b82c9e6648b050b6306438846c887b3f324bf29dcae4cab1b53005310440cb25cc8c9a7e2 }
    condition:
        any of them
}
