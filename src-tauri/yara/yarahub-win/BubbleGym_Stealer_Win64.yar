import "pe"

rule BubbleGym_Stealer_Win64
{
    meta:
        description = "BubbleGym stealer (win.bubblegym; supersedes FakeTorrent_Stealer_Win64, yarahub uuid 3b938374-ccbd-4fdf-871c-b2a104f5288a). Second-stage C++ infostealer of the fake TV-episode torrent campaign (C2 beenetprotect.com, YouTube/GitHub Gist dead drops; Thereallo, Oct 2026). Decrypted from the loader's ChaCha20 overlay. Hard-coded YouTube consent cookie used for dead-drop requests, Chromium profile lock-file names and browser User Data paths, CRT-only import table, bundled zlib 1.3.1.2-audit, and a dense byte-argument call idiom (likely its string-protection call sites). Built from one build; matches the decrypted in-memory payload, not the padded loader on disk."
        author = "PeterFellow"
        family = "BubbleGym"
        date = "2026-10-23"
        modified = "2026-10-23"
        reference = "https://bazaar.abuse.ch/sample/9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce/"
        report = "https://github.com/PeterFellow/bubblegym"
        hash1 = "9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce"
        yarahub_uuid = "70600362-308e-4f57-8357-83e59d218a7b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a0d70c2b63679d52f687da23e00c57ad"

    strings:
        // YouTube consent cookie sent with the dead-drop requests
        $ck1 = "CAISEwgDEgk2ODE5MTY1NTQaAmVuIAEaBgiA_LyaBg" wide ascii
        $ck2 = "CONSENT=YES+cb.20210328-17-p0.en+FX+634" wide ascii
        // Chromium profile lock files (checked before copying browser databases)
        $sl1 = "SingletonLock" wide
        $sl2 = "SingletonCookie" wide
        $sl3 = "SingletonSocket" wide
        // Browser profile roots
        $br1 = "Google\\Chrome\\User Data" wide
        $br2 = "Microsoft\\Edge\\User Data" wide
        $br3 = "BraveSoftware\\Brave-Browser\\User Data" wide
        $br4 = "Opera Software\\Opera Stable" wide
        $br5 = "Opera Software\\Opera GX Stable" wide
        // zlib development build string bundled for archive creation
        $zl = "1.3.1.2-audit" ascii
        // mov r9b,imm8 ... mov r8b,imm8 ; mov dl,imm8 ; mov cl,imm8 ; call (string-protection call sites)
        $arg = { 41 B1 ?? [0-10] 41 B0 ?? B2 ?? B1 ?? E8 }

    condition:
        uint16(0) == 0x5A4D
        and pe.is_64bit()
        and filesize < 8MB
        and pe.number_of_imports <= 3
        and 2 of ($sl*)
        and 3 of ($br*)
        and (
            any of ($ck*)
            or (#arg >= 50 and $zl)
        )
}
