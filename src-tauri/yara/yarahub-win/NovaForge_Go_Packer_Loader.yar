rule NovaForge_Go_Packer_Loader
{
    meta:
        description = "NovaForge Go 1.23+ reflective PE packer/loader: matches the NovaForge Go build module path, SplitMix64 (Stafford Mix13) PRNG 64-bit mixing constants in .text, and embedded IT helpdesk ticket-classifier decoy strings"
        author = "Daydream"
        date = "2026-10-31"
        reference = "https://bazaar.abuse.ch/sample/c9aee62eb43b64c0a09592027ab61d5aa287247f61de598d07e8da6998af4141/"
        reference_sample = "c9aee62eb43b64c0a09592027ab61d5aa287247f61de598d07e8da6998af4141"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b8574c6599e08ee86e8acd0743b15342"
        yarahub_uuid = "9a4c71e8-25f0-4b83-8c14-3e72d905a612"
    strings:
        $go = "Go buildinf:" ascii
        $mod = "NovaForge" ascii
        $sm_inc = { 15 7C 4A 7F B9 79 37 9E }
        $sm_m1  = { B9 E5 E4 1C 6D 47 58 BF }
        $sm_m2  = { EB 11 31 13 BB 49 D0 94 }
        $decoy1 = "Ticket routed to L2 queue" ascii
        $decoy2 = "VPN token sync failed" ascii
    condition:
        uint16(0) == 0x5A4D and
        $go and
        (
            ($mod and all of ($sm_*)) or
            (all of ($sm_*) and 1 of ($decoy*))
        )
}
