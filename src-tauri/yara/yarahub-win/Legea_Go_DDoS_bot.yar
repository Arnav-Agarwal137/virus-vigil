rule Legea_Go_DDoS_bot
{
    meta:
        author      = "eFeSpain"
        description = "Legea: Go DDoS bot with a control plane, obfuscated with garble, built for eight architectures"
        date        = "2026-10-17"
        malware     = "Legea"
        malware_type = "ddos"
        note        = "Build-specific markers. A rebuild with a different garble seed will need a new rule."

        yarahub_uuid              = "30775a31-2754-4738-86b4-cfdd9a7301de"
        yarahub_reference_link    = "https://blog.efespain.com/en/legea/"
        yarahub_license           = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_reference_md5     = "ab3d33e3b2d59ab8cfb0473f788f3e82"

        hash0 = "0cc42472a07cf14668e899b73adafe666d02495bf9349715613c8e7ba57244ea"
        hash1 = "0475f2831e60ac0b229f346036e339d20ad1d1165b005a89b634dc7c67318c74"
        hash2 = "e59547abdff8019da736bcb8c252cbf5ce96b9695775031b10da334867b59b62"
        hash3 = "9d0891f849ccc8c0eff4ea961702087eeeceeb00cff94a7cb0542839be3421f5"
        hash4 = "536a376337fed899e58a86baca1fc584d570be8e708b6c302cc6f24626dfcfd7"
        hash5 = "8c21db937a85cf7ed804501cdfee7d1c543aa9a56d4d1187951b8f8048af1c10"
        hash6 = "f5cf1b8ee8ddced3fb5e081dc1543669c3b62767c45da63002032da87632839d"
        hash7 = "d570a1702448fac805fe39e9a49fd1ca24e4505161eec68cf6e7f5e2b6a34ce0"

    strings:
        // Nothing the bot says out loud is usable here: garble encrypts the
        // literals, and not one published indicator is present in the file
        // ("legea=", the fallback domains, the persistence paths: 0 in the
        // binary, 124 in the live process). What garble cannot hide are the
        // names it rewrites, which leak through Go's reflection type strings.
        // The seed belongs to the build, so these three are in all eight
        // binaries -- x86 through mips64 -- and in none of the other 679
        // samples in the collection they were checked against.
        $garble1 = "internal/sync.pksidK bool" ascii
        $garble2 = "unique.pksidK bool" ascii
        $garble3 = "d_otDs string; f48CrIBGdd string" ascii

        // garble's own string decryptor, seen through its type name. This
        // belongs to garble, not to Legea: supporting evidence, not an ID.
        $decfunc = "*main.decFunc" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize > 25MB and filesize < 60MB and
        (2 of ($garble*) or (1 of ($garble*) and $decfunc))
}
