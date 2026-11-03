rule Protokol_Client_CryptoConstants
{
    meta:
        author = "wristhulk (honeypot lab)"
        date = "2026-10-19"
        description = "protokol-client bot: pinned Noise-NK server key, ChaCha20 keys for the string table and the C2 lists, BitTorrent DHT BEP44 target hashes. Any 2 together."
        reference = "static RE + C2 emulation of 4cae4c533e96cfa71e62966c8fa6339e1188629d2f0cfe86e040e733e10450e1"
        yarahub_uuid = "9a13a137-0618-4f02-b512-61149be52cb1"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6d3a062d525ce2a836d72e6a1c0321fe"

    strings:
        // Noise-NK pinned server static key (0x41f0e0; the back-connect channel pins the same bytes at 0x41f420)
        $srvkey  = { 31 4b c9 1b d4 e8 b6 c5 b0 5b d4 45 30 17 58 15 92 df eb 79 ea 51 2f 7d 09 c0 41 60 34 88 11 17 }
        // ChaCha20 key for the string table (0x4212a0)
        $k_strtab = { 9f 96 c7 d6 cd 55 74 09 1f 8e b6 ab ea ce 8c 8d 60 11 ab 74 3d 23 28 b9 ac b4 71 76 f0 4e a6 bb }
        // ChaCha20 key for C2 list 1 / the DNS TXT dead-drop records (0x41f600)
        $k_list1 = { 64 a8 63 90 d6 b2 df 65 6c f5 15 c9 23 40 f1 bc 43 52 95 d3 76 71 b8 46 6e 4d c0 96 dc 38 ee 70 }
        // ChaCha20 key for C2 list 2 / the refreshed peer pool (0x41f520)
        $k_list2 = { 7d 0c cd 1a e3 fd dc 41 5c cb 00 8e db 34 04 cb ad 17 f7 19 f4 ec e0 97 d4 b6 43 a2 35 db 68 55 }
        // DHT BEP44 'get' target hashes: list 1 (0x41f4c0) and list 2 (0x41f540)
        $t_list1 = { ff 34 6d ce 37 38 90 86 fa 8d 9e 04 0e ff 35 a4 50 5e 9a 35 }
        $t_list2 = { 98 08 ee e4 af b9 7c cf 6e 9b f7 03 ec d9 09 72 ca be 2b 35 }

    condition:
        filesize < 8MB and 2 of them
}
