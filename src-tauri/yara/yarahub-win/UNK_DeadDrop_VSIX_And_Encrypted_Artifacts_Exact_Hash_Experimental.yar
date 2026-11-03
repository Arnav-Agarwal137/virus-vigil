import "hash"


rule UNK_DeadDrop_VSIX_And_Encrypted_Artifacts_Exact_Hash_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Exact SHA-256 identifiers for the retained VSIX, obfuscated loader, nested agent archive and encrypted payload members"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        yarahub_reference_md5 = "04ab74ac797e71bc29f1c203c2e9520f"
        yarahub_uuid = "e5a9c1fe-b211-4d6b-9ddb-181e94b437dc"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "exact-byte identification only; does not generalize to rebuilt or modified files"
    condition:
        (filesize == 17647582 and hash.sha256(0, filesize) == "52886aab179f26421678ff23af1b0fabf0a17ffbb534369cdbbac8008cbed8e7") or
        (filesize == 606460 and hash.sha256(0, filesize) == "d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e") or
        (filesize == 17283435 and hash.sha256(0, filesize) == "e1bf1b29e6fa3525d7f32f429290a88d6ea2890e61c06574b8ff6372aa5d0667") or
        (filesize == 60082 and hash.sha256(0, filesize) == "fa5312c5d190c619fa48ea0ff63c6a794d4dd874527ca42e4336f0cf040cf3b0") or
        (filesize == 56121 and hash.sha256(0, filesize) == "82cf5955e5b8b575343ba73289468b476c39c92961dcdd90885772dcc37182d4") or
        (filesize == 32352 and hash.sha256(0, filesize) == "6aa0c5b29da370e93a9760322ac4378f3f06a72124550580c400c671ca6cf154") or
        (filesize == 60082 and hash.sha256(0, filesize) == "9bbe197504bed49d152b5053fd5eff09ba6dfb0a8facd90618a7ee471509ad09") or
        (filesize == 56121 and hash.sha256(0, filesize) == "ee1b016374ff6a076bbd2474a21e2c0e82e9abcc84e44992a23faf800c36cf21") or
        (filesize == 32352 and hash.sha256(0, filesize) == "e4898fe06377006411342940acd7f2602fc12c8ed9ab246623f7e4ccedb3ca4b")
}
