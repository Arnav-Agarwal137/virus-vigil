rule MAL_Win_Lold_GoCrypter_Loader
{
    meta:
        description = "Go loader used to deliver the Lold Update Client: carved4/go-crypter stub (AEAD-encrypted CBOR payload, indirect syscalls via go-wincall) with the actor's '2detect' build path. go-crypter is public, so the generic part may hit other actors' builds"
        date = "2026-10-19"
        author = "anonymous"
        hash1 = "256dece3e4fc17be20b7b045c4845f8e62114160346ebe53e7b6abbbb70a8854"
        yarahub_uuid = "bcc0de29-2614-47ef-9a16-9584e3c33bb9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f24fb2bb8a024cd6b6a830dd3eff6d9c"

    strings:
        $go    = "Go build ID" ascii
        $actor = "/MyProgram/2detect/" ascii
        $c1    = "github.com/carved4/go-crypter/pkg/executor" ascii
        $c2    = "github.com/carved4/go-crypter/pkg/loader" ascii
        $c3    = "github.com/carved4/go-wincall" ascii
        $m1    = "main.bcryptAEADDecrypt" ascii
        $m2    = "main.executePayload" ascii
        $m3    = "main.getPayloadType" ascii
        $m4    = "cbor:\"payload_type\"" ascii

    condition:
        uint16(0) == 0x5A4D and $go and
        (
            $actor or
            (2 of ($c*) and 2 of ($m*))
        )
}
