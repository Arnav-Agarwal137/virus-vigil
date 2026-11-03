import "hash"


rule UNK_DeadDrop_Windows_Launchers_Exact_Hash_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Exact SHA-256 identifiers for the retained VBS, CMD and shell launch wrappers"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        yarahub_reference_md5 = "70280fd83204611bb107e14cd5e307fc"
        yarahub_uuid = "578ccec6-3732-4dab-80de-1af824fb62b5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "exact-byte identification only; does not generalize to rebuilt or modified files"
    condition:
        (filesize == 1464 and hash.sha256(0, filesize) == "4c0d9b802c075be79e9edb52d88f8dd72e6904f5c58267213745818470945c78") or
        (filesize == 23356 and hash.sha256(0, filesize) == "62761f38ed194c59abe15c49f09f0ebc431ac852c965180c9327ed84d3a454fb") or
        (filesize == 25357 and hash.sha256(0, filesize) == "734699773e53d995f20d485eb61261033d9d00b4332b39ca26071bcd60cd352f")
}
