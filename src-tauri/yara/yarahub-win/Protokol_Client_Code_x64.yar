rule Protokol_Client_Code_x64
{
    meta:
        author = "wristhulk (honeypot lab)"
        date = "2026-11-01"
        description = "protokol-client x86-64 code shapes that stay the same when the campaign constants change. Record framing for the XChaCha20-Poly1305 channel (len+40 / len+44, at least 40 bytes, 64 KB cap), attack-order bounds (method 1-18, duration 1-60 s), Noise-NK label fetches (string ids 0x38/0x39). 4 of 5."
        reference = "Ghidra/radare2 of 4cae4c53 (pk_recv_msg 0x4099e7, pk_send_msg 0x409862, cmd15_attack_start 0x402e4d, pk_noise_nk_handshake 0x409568)"
        note = "Tested 2026-11-01 in the lab: matches 4cae4c53; no match on potassium 0c5486f0 (shared FiveM packet, different code), on the WinHealth miner 4423cd21, or on the REMnux system corpus (see malware-triage notes)."
        yarahub_uuid = "2b1c07c7-e1f6-4c94-ade3-fcfd63836f0d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6d3a062d525ce2a836d72e6a1c0321fe"

    strings:
        // pk_recv_msg: bswap len; cmp len,0x27; jbe; mov eax,0xffff   (record >= 24 nonce + 16 tag, payload <= 64 KB)
        $recv = { 0F (C8|C9|CA|CB|CD|CE|CF) 83 ?? 27 76 ?? B8 FF FF 00 00 }
        // pk_send_msg: lea r32,[len+0x28]; lea r64,[len+0x2c]   (wire length field, buffer size)
        $send = { 8D ?? 28 48 8D ?? 2C ?? 89 }
        // cmd15_attack_start: cmp dl,0x11; ja; lea edx,[r-1]; cmp edx,0x3b; ja   (method 1..18, seconds 1..60)
        $atk = { 80 FA 11 0F 87 ?? ?? ?? ?? 8D ?? FF 83 FA 3B 0F 87 }
        // pk_noise_nk_handshake: pk_str(0x38) twice ("protokol-v1-nk" + its strlen), then pk_str(0x39) ("-conf")
        $lbl_nk   = { BF 38 00 00 00 E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? BF 38 00 00 00 }
        $lbl_conf = { BF 39 00 00 00 E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? BF 39 00 00 00 }

    condition:
        uint32(0) == 0x464c457f and uint16(0x12) == 0x3e and filesize < 8MB and 4 of them
}
