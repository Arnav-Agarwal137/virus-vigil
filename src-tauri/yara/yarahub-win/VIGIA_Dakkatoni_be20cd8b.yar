rule VIGIA_Dakkatoni_be20cd8b {
    meta:
        date = "2026-11-01"
        yarahub_uuid = "fafc8d04-8f10-405d-863c-abbdefce9167"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5e101fd3db323f653cd41713e559e810"
        contact = "javigp@usal.es"
        vigia_rule_id = "be20cd8b-f0c1-43aa-9388-a139bc38a362"
        family = "Dakkatoni"
        description = "Dakkatoni: code shared by its builds (snapshot malware_snapshot_001.json); held-out 10/11, 0 benign or other-family hits"
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
        * Family files matched: 21 of the Dakkatoni files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    strings:
        $c0 = { 8ff5ae22fff86a09e16de1065fbb677fe60363ae854f6f80b291eba3533c03a54f2e4d733317f53a }
        $c1 = { c773679b10830046d89be40ea040f7df9ba3c3f3c333 }
        $c2 = { cf8f1604fff30205b31bfc2f1e3ce46d9723b36beb }
        $c3 = { 5c9b05527f688c343073b95c2e1f835be0d9ab }
        $c4 = { e70527dc3ed73b455347431f04810f00 }
        $c5 = { 8fbffbeabdf24d8c7b832b87c5dca4ab }
        $c6 = { 01fff803a1e824a78f8787f856bee1f78f88845033afa8fba20014afbdffc83e36e4855c8b00ffff00007f793258f300d2582da4afbe2da00bffffffafb72d9c }
        $c7 = { fe2b722b998c4b05d3a103728f8b4b1b3f1781ac0edd070b5b43697e35929d3f02e4904846b834a881c047f0580358c443060b633c5eed26700e272b1b5047 }
        $c8 = { 8107478b826285606f2105a29e77956fbccf12040b77014e2bddb08e216b4f4f233f07703da2030ff767210157f42bef0b684c1a84302b8eb7ef96833a2377 }
        $c9 = { 602354431f852da145fda343df0460b02305df435060dd7b521b16002307036b37800cc9064c07232316b684cf1fb75272d69a67111f980c9001e9870140e1 }
        $c10 = { 482128e2118c430cd93eeeda8d2ae8672430c69b406ba2c9c9cba5e728e3010240a59c744fe010e2df30835f0491b6d1766f130931440f0a1c2f17216bb17d }
        $c11 = { d71ea4e98b34305880834fc7bd3cdf41f24f288084000510ee3097d0a525360317b058b4b302d7049a6ad55b937b77e8f73c6a18f287a80718b74b5bf114 }
        $c12 = { 9e9f30122905830ed394248635ff083337849e62522f2b1387a1429d628b27d39fd419121a748b952a801c205768b093e5174f4726320014285577c84298 }
        $c13 = { d12f2b04b8bda845d3605b131587b80b07e7934e771a1fe3378f630112d038302b2b959a4a65a7778f807b348302236bc0bfbfeb2d95040f3b9823062308 }
        $c14 = { 299f4658c208f31f299041a640a5a269461e6406660377a28343286c07508867661723443204081f2a61940d329f28e31b12ce7b2f02b897371bc850c8 }
        $c15 = { 57db5f4d02f7289b0b679355bc88b773bb87cd446da230c727a5c37362e4d8cc27de4741375b918acf827318a7a3f762e6897ed79222bb107765549d96 }
        $c16 = { a7b33413377337bdd7c6682c0b73354b8bc91fd8880f63474b13d3004c6f20f006cf4fc78d121802534f0b0346e0ef53964b403209b4c62f53a0019391 }
        $c17 = { 0bc0096483d00cd215a90d3be86da40955bfc3384bc31ce082a807af13017b5d538bf013de67279a6e489afed9c013d440562147223b2ef8ae2f3d1647 }
        $c18 = { 7bf98027c4f3f810218c2f007c18231b37226d7f08e3b5c8273f48375d77d327a3b7a42d5cff78133828afa34cd735cd2d6074681f30172cd3746f37 }
        $c19 = { 0c73bfad1f0fde1b633b0242ab1b6f584d7323bbeb77f3dbe2d121017f579827316261697e8f284705d3c7a18316533b43cf1b683bdd8323a38b3f30 }
    condition:
        any of them
}
