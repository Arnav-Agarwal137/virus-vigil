import "pe"

rule VIGIA_CoinMiner_0077e3b6 {
    meta:
        date = "2026-10-28"
        yarahub_uuid = "6460796d-dd88-45a2-b704-a075d690f67e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "60ceea8dc27ee552cbad31ea16f0d734"
        contact = "javigp@usal.es"
        vigia_rule_id = "0077e3b6-a24e-4a13-a472-41f2c17fb3dd"
        family = "CoinMiner"
        description = "Miner dropper posing as Google Update Setup: Google LLC version info on a MinGW-w64 build (msvcrt imports, .xdata/.idata sections); real Google binaries are MSVC builds"
        author = "VIG-IA - Cognitive Threat Intelligence System for Smart Territories and Tourism Sector"

    
        /*
        * DISCLAIMER
        * This rule's condition was written by the VIG-IA platform on the file structure shared by samples
        * obtained from MalwareBazaar (https://bazaar.abuse.ch).
        *
        * The resulting rule has undergone refinement via AI-assisted processing and validation against
        * curated goodware and malware corpora. However, this pipeline cannot guarantee high generalization
        * across all malware variants and environments. False positives and blind spots may occur.
        *
        * === Rule Evaluation Summary ===
        * False Positive Rate: 0.00% (on validated goodware corpus)
        * Family files matched: 11 of the CoinMiner files in the VIG-IA audit (0 goodware, 0 other families)
        *
        * === TLP:WHITE Classification Justification ===
        * - All rules are derived from publicly available samples from MalwareBazaar (TLP:WHITE).
        * - No proprietary, internal, or inferred intelligence has been used in their creation.
        * - All matching logic and strings are directly observable in the analyzed binaries.
        * - Rules are designed for general-purpose sharing and deployment without restrictions.
        * - Licensing and classification conform to YARAhub and YARAify community guidelines.
        */

    condition:
        pe.is_pe and
        pe.version_info["CompanyName"] == "Google LLC" and
        pe.version_info["FileDescription"] startswith "Google Update" and
        pe.imports("msvcrt.dll") and
        for any s in pe.sections : ( s.name == ".xdata" ) and
        for any s in pe.sections : ( s.name == ".idata" )
}
