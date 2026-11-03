import "hash"


rule Surge_Group_Received_Lure_Email_Exact_Hash_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Exact SHA-256 identifier for the retained 23 July Surge Group lure email"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/10-investigation-connections/"
        yarahub_reference_md5 = "5a624bb9474076108bb691e1d8951e36"
        yarahub_uuid = "3c8eedc1-ab10-4fa7-a546-d76ecd97a7a4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "exact RFC message bytes only; does not establish shared control or relation to UNK_DeadDrop"
    condition:
        filesize == 9174 and hash.sha256(0, filesize) == "d062c3115237bfe03cb17ec992186db9e2aa5a6f34e791c7df58aa0d9550b3a3"
}
