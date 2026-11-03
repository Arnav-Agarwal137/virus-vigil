import "hash"


rule ECHOES_RAR_Lure_Archives_Exact_Hash_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Exact SHA-256 identifiers for four retained ECHOES lure archive revisions that could not be opened by the available archive reader"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/09-echoes-lineage-image-provenance/"
        yarahub_reference_md5 = "6cb6c07235b881f226ff6dc65827761a"
        yarahub_uuid = "eff0e7b8-4976-4814-a419-863afd2349c0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "exact-byte identification only; no claim about unrecovered archive contents"
    condition:
        (filesize == 2294526 and hash.sha256(0, filesize) == "7db6789c09e29305c728bf3d7b94c5ef1c3e13eef1b321ee52d3ae3997731f56") or
        (filesize == 2292670 and hash.sha256(0, filesize) == "4ff03731d2061ad2f50da9f63dc1481374908d5bc837c86d0c7574d23b23a37b") or
        (filesize == 2294542 and hash.sha256(0, filesize) == "11bf34ccce585fe051abaa8d01ba1b29e2d44727c070b56ab0dd84a9dc9f91b2") or
        (filesize == 2292622 and hash.sha256(0, filesize) == "2bd4cfd495fdcad6d7b2adaedc31614ca2984ea1246aed7608c339eaa82eb978")
}
