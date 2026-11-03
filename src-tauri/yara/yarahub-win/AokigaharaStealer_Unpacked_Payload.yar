rule AokigaharaStealer_Unpacked_Payload
{
    meta:
        description = "AokigaharaStealer payload, unpacked or in process memory: gate protocol headers, akg_ working-file names, debug log markers and loot folder names"
        author = "Daydream"
        date = "2026-10-12"
        reference_sample = "c9aee62eb43b64c0a09592027ab61d5aa287247f61de598d07e8da6998af4141 (Go wrapper; payload carved from memory, image sha256 9f89ee873b2548612fc8ea876f11629d9e87a39eea594dc88a676e492399e9cf)"
        note = "Does not match the packed wrapper on disk; use on memory dumps and unpacked files"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c1bc6228b1f8bd610af0947edcef1ef5"
        yarahub_uuid = "d22564da-79c8-4c26-87aa-da7a7be2723f"
    strings:
        $p1 = "X-Gate-Token: %s" ascii
        $p2 = "X-KEX: x25519" ascii
        $p3 = "X-Chunk-Index: %u" ascii
        $p4 = "X-Build-ID: %s" ascii
        $f1 = "akg_debug.txt" ascii
        $f2 = "%sakg_%lx_%lx.tmp" ascii
        $f3 = "\\\\.\\pipe\\akg_%lx_%lx" ascii
        $d1 = "AOKIGAHARA DEBUG LOG" ascii
        $d2 = "HAMMERING: started" ascii
        $l1 = "AISessions/ClaudeCode/credentials.json" ascii
        $l2 = "Messengers/DiscordForks/Tokens.txt" ascii
        $l3 = "PassMan/Bitwarden/data.json" ascii
    condition:
        (2 of ($p*) and 1 of ($f*, $d*, $l*)) or (2 of ($f*) and 1 of ($l*, $d*)) or 5 of them
}
