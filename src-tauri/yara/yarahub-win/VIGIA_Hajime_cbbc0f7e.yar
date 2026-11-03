rule VIGIA_Hajime_cbbc0f7e {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "b0f10571-2281-4e7c-a7d5-8668d79c3312"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "bff18a0246ac8adc81b4a178356bf091"
        contact = "javigp@usal.es"
        vigia_rule_id = "cbbc0f7e-ad4a-4674-add6-928847b5d624"
        family = "Hajime"
        description = "Hajime: code shared by its builds (snapshot malware_snapshot_001.json); held-out 15/18, 0 benign or other-family hits"
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
        * Family files matched: 31 of the Hajime files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { a09e64c6629f9944e0e4892c6640621be6abd40c40679e44b28becd1134d940dd2fcf9173ad1f313c4879c9ce8c171b7dfca311d81bc3127a24e9be40f14ea5a }
        $c1 = { 0000000000000000000600010000e7d4a0bdf596a4b512a00d89000000000003a4940003a494000000b40000005e0e0000001a03003f91458468348a090a40 }
        $c2 = { a003ff39b8087d5cec1e91853dbaeee86c99f04afee36d4d3189e468f8def08a8b28c7ff21ad476ceecfadc5a4b929e8e7173ebea90e14f7ef5b1e9010439d }
        $c3 = { 58623966a38a373c682bca59bb975c29745c77631885e439e38a6eeba3513a1630e4209d58c2e6f984b3531b2d8458f40ca4d0028485fcbd2dff84dd31bae0 }
        $c4 = { 0f9aeae155aba88a4ac0abb6cdf5292bfd087175ca6fed066637d2ab4e3eee996fae2c97d93ea33b1f4d63d97020adb1c9cd8fb6b0af21b1ea90d22198c88b }
        $c5 = { fecd25ca70e7db3632d6961b99586562898b168d6dd53b32be20d61a4544847114104b921fedfd3bd85d4808d992652b0f8563d7a792afe595e065e45214 }
        $c6 = { 04a7baa2a0296a48b51b2645f20118109687a66266a4496232680207af9ea12a7e7561db03ce6c522c0bc04f4898fe369d8724198c2fb4f174192f572b86 }
        $c7 = { 90ab81ed4447dd09fcbd3cede30afe2051a5504b50f497eb7c28b2d513f3d02d963ef0b2cadab6a49b809e58665c0c39659280c4ea9e1f1a26e124b5c550 }
        $c8 = { ad1e6518764a557035c84169949b8ea834a1a826c74cbc61515d3e0219fbff8f1c2e938960d22a4d0e5caa5e4d302d0c94251424db628b2197709d8137 }
        $c9 = { 6b8edaf796aa4574fb92411a2df5b5e82eeca34479547d015f02f4967cd3708d6855ea984abe6405cf41d46591d7d88fa5277effd29d43a611d789587c }
        $c10 = { a9fdf2f740eac31b9441ce5060e68b999a194ae23e2a7b10e1e56a28c60dd981461bc4f0c4b9b977b319734e7c3ada6581a1baf9c2b9e268784d4983 }
        $c11 = { 42323f5380d84aa735b9c3e0c27ba9b2eddd8dbfe3a7578738cfa81033a71fcfa2c64660611d05d853477f8f4b142e107b18de7bdb17801e55afad }
        $c12 = { 99f1028f4383b42f541bbc0301866622666f6772ce737c8981fdeff356711c8f6f1e6ce6753b8dd2991ca3bfd3daa0d9639193e741868df44e4565 }
        $c13 = { d07d72e0ecdb9fa68fae57e6fe55c35c28c8c2b5f5ba1c4c9119ce62e72311d56156d170de9f2034eb8640a3bb6fb6146df68dea1ca4d3aa0dfd }
        $c14 = { 02a2044ea7d182ba05619d28ccae0a8ac90b85cdfbccbaa943c8a9adc3b24cd0dd9ff7bc76872cebbcb7c1c4fcb3478c96f2e365c7186763f4cd }
        $c15 = { 8b263c81e0cd04144c431347a01b114902cbead2c2b321be531f34983dceb411d44a92ff507a5db6c7e4af2d73218ebea7719f4fc37a6e0e8320 }
        $c16 = { 75818a99cbf55df481524f864029d556f2a6469e97e3baae95370586798fc134813cae3e234220feb24d60f3a2abc51d0475fced2fad7a256d1c }
        $c17 = { b93e7d2e7de8aa437e1e6c6dc3dc544c77f6f23b8eb0fb350cf1a9ee6c167b8e24da780d55c35c3a8a35b330eacda2481a05a63a9d0997fb54 }
        $c18 = { 3ee83428f0c41c390bf735deedce1fea65249e7923d913ae5059b3829eb3b7e988eeafb219d6a422a10390264e13a4f23b434d457111cf9922 }
        $c19 = { 2452f22f8ebb5112f53364e4a8445f7c369395d78708da4aafa388f77e176147369efc41d2999d08522d7ab913ca322d1c0c0daf9c874f4b07 }
    condition:
        any of them
}
