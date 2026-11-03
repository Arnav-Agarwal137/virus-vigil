import "hash"


rule UNK_DeadDrop_Recruitment_Email_Exact_Hash_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Exact SHA-256 identifiers for three retained recruitment-lure messages"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/10-investigation-connections/"
        yarahub_reference_md5 = "cbdcffd4619cf1693cfbed2c480cbe50"
        yarahub_uuid = "2cc8c83d-5e4a-4032-9a0d-6f7781ecb98a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "exact RFC message bytes only; no addresses or message content are included and header changes will evade"
    condition:
        (filesize == 7185 and hash.sha256(0, filesize) == "6c1835159c8da69aaf0743fce634c3345e6b4f16eb4a492cfda5cf893b98eb5b") or
        (filesize == 9176 and hash.sha256(0, filesize) == "3efb15d6cc89e3690bd1e19fbc96034110f55066d69ef25dc2d30ca057d2ee21") or
        (filesize == 9462 and hash.sha256(0, filesize) == "924db78f6fe47e7696c42d77d42d8f030c80e4a04965f7529731bfab4353d6ec")
}
