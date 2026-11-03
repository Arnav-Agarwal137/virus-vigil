import "hash"


rule ECHOES_LNK_Launchers_Exact_Hash_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Exact SHA-256 identifiers for four retained ECHOES shortcut launchers"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/09-echoes-lineage-image-provenance/"
        yarahub_reference_md5 = "ad569ecf38c949763c228f696dde1d9e"
        yarahub_uuid = "c2354e3c-0175-4f12-8ddd-80e43b15a9b7"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "exact-byte identification only; the unrecovered final payload is not inferred"
    condition:
        (filesize == 429728 and hash.sha256(0, filesize) == "a44068e9758262a65861b91f2b00d0a3eca019d3b35543dd60c1c7f2e0ba1952") or
        (filesize == 420736 and hash.sha256(0, filesize) == "9c7b507eba958ecee653ff42f13cf4e084f49cd38985d3abfd77ab2bfa40b4e2") or
        (filesize == 429662 and hash.sha256(0, filesize) == "b80028534a414f199992a49610f8d5ffa94f8098d5a820653f68b8a9eb51e3ca") or
        (filesize == 420512 and hash.sha256(0, filesize) == "bbbeadae38bf1406f331c9e42ab49cbdd22f503cd9caecb6b390964bafa1b56f")
}
