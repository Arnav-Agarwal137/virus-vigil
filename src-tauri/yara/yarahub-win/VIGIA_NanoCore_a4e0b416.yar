rule VIGIA_NanoCore_a4e0b416 {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "a3ab4170-d030-46ee-abb4-aee70bf9a093"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1313996429cbe0ddb1f0c4d7f3a40980"
        contact = "javigp@usal.es"
        vigia_rule_id = "a4e0b416-795d-4689-9555-cb86664cd100"
        family = "NanoCore"
        description = "NanoCore: code shared by its builds (snapshot malware_snapshot_001.json); held-out 23/25, 0 benign or other-family hits"
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
        * Family files matched: 46 of the NanoCore files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 3901000012000011736600000a192d142616028eb717591a2d0d26162c0d2638a20000000a2bea13042bf00b2bf1732c0000060c0802079a7948000001714800 }
        $c1 = { 1201289300000a13041204289400000a1201289300000a13051205289500000a285200000a289600000a11066f9700000a1201289800000a2dc3086f9900000a }
        $c2 = { 262bfc00033009002200000000000000283e0100062c1a14fe06c000000673ea00000a28eb00000a1e2d03262b03262b002a0000133004004200000038000011 }
        $c3 = { 440f007b8500000428d80000062b360f007b8500000428d90000062b280f007b8500000428da0000062b1a0f007b8500000428db0000062b0c0f007b85000004 }
        $c4 = { e6262bee262bf1000003300a000f00000000000000031b182d072628b50000062a262bf700133004003e0100006c00001120bd00000073090100061b2d472617 }
        $c5 = { d01e28ff000006168c4c0000012853010006794c000001714c0000012a13300200240000000c000011208b2ed01e28ff00000620a00f00008c4c000001285301 }
        $c6 = { 8c4c0000012853010006794c000001714c0000012a13300200240000000c000011207c2ed01e28ff00000620c40900008c4c0000012853010006794c00000171 }
        $c7 = { e93c9c4db498b2cdb1eaad2d6d2c4f6cc6e3a73462943f52aa8bbfb9f94fbfa3ba58dc2aa1173141e84fbfa337956f90cd81e4d621c12551c69218712a990717 }
        $c8 = { b85cbfa33ed3a46c6a4cee8fc57b412dd0aaa3a718c7a0e6c8103aeebc3b362429533ee446e7a0ec0042534a4201000100000000000c00000076322e302e3530 }
        $c9 = { 4f00c4000a010000ec11000009034f00d6000001000008120000c9015500d6008001100038120000c9015500e3000301100068120000c9015600e80003011000 }
        $c10 = { 1100d580250535010ca900000000110005812b05350144a90000000016006581320536018ca9000000001600b9813a053801dca900000000110005823a053901 }
        $c11 = { 000002003d4200000100894200000200a54200000100f142000001001944000002003544000001008144000002009d4400000100e94400000100354500000100 }
        $c12 = { 00233d715379434d7a61303949744237396c725a6c46427551513d3d00233d71366f796b754161657a6f5057435148774946424759514a6f545f646f474b4d6d }
        $c13 = { 73386351565269384a773d3d00233d71634d62366878427064795477436a76707a61516343356453337762706c50714f74613745527a5f6c4d496f3d00233d71 }
        $c14 = { 7045796c34305f3449617249787a4d3d00233d7172496262786e69496d6532714c5464527736693077446f5a464d48354257733033694d65536e6a6f6a51553d }
        $c15 = { 3d715255587a5f33665032316a754e48576a44594c3136513d3d00233d71316a6a324c6f3355424b555a6b644932624c636734516c58754e474e575a2443596e }
        $c16 = { 5769386775715172766f47423535646a6f306b615f38343479546d5669426e355f4672325836484163654f37414a45726b5f5268376e666b6671745562710023 }
        $c17 = { 4530546170715872506e7179424f317800233d714e7a74246d4a616b68314e787634764452446a547361314f56444b4d416c52434f5f5f716e63784d6f58527a }
        $c18 = { 314b5a6254434b54415a72656b6f314c75673d3d00233d714a353938566e725f524977476e4871466651735943773d3d00233d7148616d466963796b70443966 }
        $c19 = { 596b445674546e4c706259796a54665a4e4b6d385f344a6b756f464850784f42466f3d00233d71796f36736c544d6667443849725a376e7236696e48413d3d00 }
    condition:
        any of them
}
