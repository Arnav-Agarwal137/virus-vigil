rule VIGIA_Adware_Neoreklami_3b585c6e {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "005daae4-4825-4cb4-84a6-7e40a19a5f9e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "504ef3357bae688d1930fb51de4fe6e8"
        contact = "javigp@usal.es"
        vigia_rule_id = "3b585c6e-5e6b-4750-81a8-52d5d9984d07"
        family = "Adware.Neoreklami"
        description = "Adware.Neoreklami: code shared by its builds (snapshot malware_snapshot_001.json); held-out 25/25, 0 benign or other-family hits"
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
        * Family files matched: 50 of the Adware.Neoreklami files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 7508578d8ea8000000e85205000084c0740ab804400080e99e0400008b464c33db3bc374098b0850ff5108895e4c66895da866895daa8b460c8b7d0c8d55a889 }
        $c1 = { 15e8b0410085c00f95c05ec9c3b86c954100e84bf0000083ec108365f000568bf1528d4de4e864d3ffff8365fc00ff15b8b04100f7d81bc08d55e4408bce50e8 }
        $c2 = { caffff8d45e48bce50e885e8ffffff75e4e8f5e5ffff598bc68b4df45e64890d00000000c9c2040056578b7c240c8bf1ff7704e8c3cfffff8b46048b0f03068a }
        $c3 = { 1cb1410083f8ff8906750432c0eb108b550c8d8dc0feffffe807000000b0015ec9c208005356578bf98bf26a018b076a008946208b47048946088b470889460c }
        $c4 = { 8beca15c04420039450c760389450cff7510ff750cff7508e8b5ffffff5dc20c00558bec568b7510578bf98326008d451083651000508bcfff750cff7508e8bc }
        $c5 = { 558bec53568b750c578bf98b572c8b47283bf277347205394508732d8b47248b4f203bf072237705394d08761c8b5d086a0a2bd9591bf08b4728e823ae00003b }
        $c6 = { 568bf1578d7e408bcfe838feffff84c07407b001e9e2000000538bcee8d501000057ff15a0b041008b47248b5f208945f08b47288945e08b472c578945e4ff15 }
        $c7 = { 5083c110e87bf2ffff52508d4dd4e8898dffffe9e10000005353ebefff7004ff30ebe88a401de99a0000003958140f84c50000008d50108d4de4e8ebdaffffff }
        $c8 = { 0955d8ff4dec8345e808ff4de075df8b45d4f6450b1089078b45d889470474158b4e18e8b3fbffff8947148b4e18e8a8fbffffeb066a0158894714f6450b2089 }
        $c9 = { 083bca7cf483c9ff85c97c08463b75f072deeb098b4d0856e80458ffff837b3001741fe861f9ffffeb1885ff76148b4e18e89cfaffff8b4d0850e8e257ffff4f }
        $c10 = { 8b4f18e8d0eaffff8b4dec894108433b5d0872d38d8d60ffffffc645fc0be83ce8ffff8d8d1cffffffc645fc09e8a650ffff33dbff75d08d8e58010000ff75cc }
        $c11 = { 008b4c2404ff490c8b410c750d85c974078b016a01ff501c33c0c20400568bf1e81b000000f644240801740756e80b33ffff598bc65ec204008bcae9a1090000 }
        $c12 = { 01388b4c24305f5e5dc7010300000033c05b83c410c210008b5424305f5e5dc70202000000b8010000005b83c410c21000cccccc568bf28b4604578bf98b5710 }
        $c13 = { b90200000051e87ce4ffff5d595bc9c20c0056e81f020000ff156cb0410083f8ffa340074200743a6a746a01e8211a00008bf05985f659742956ff3540074200 }
        $c14 = { 3a08ffff8b4df081c18c000000e9b908ffff8b4df081c1a0000000e92dfffeff8b4df081c1b4000000e91ffffeffb858d64100e96798ffffcccc8b4df0e9509a }
        $c15 = { fdfeffb828d84100e93397ffffccccff75f0e8b89bfeff59c3b850d84100e91d97ffffff75f0e8a49bfeff59c3b878d84100e90997ffff8b4df083c114e93afd }
        $c16 = { b4904100e8911e010051568d71088975f0c7063cb341008365fc008bcee8fa270000834dfcff8bcee8c62700008b4df45e64890d00000000c9c3b8c8904100 }
        $c17 = { 4dfcff8d4de4e885daffff8bc3e9c500000066837de408750f8b5d0cff75ec8bcbe85199ffffeb1566397de40f85940000008b5d0c8b03897b04668938834d }
        $c18 = { f8feffffc645fc02e85c020000c745d040b74100c645fc11eb5a8b43188b40083943280f84870000006a028bcbe8030900008bf08b451085f6c645fc097461 }
        $c19 = { 088b45fc8b400cff3438e8d064ffff83c704ff4d085975e95f8b4dfc5356e8446effff5e5bc9c20800568bf1e874fefffff644240801740756e8a164ffff59 }
    condition:
        any of them
}
