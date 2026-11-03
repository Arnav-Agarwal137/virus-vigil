rule Linux_Akuma_Bot
{
    meta:
        description = "akuma IoT bot ELF (Mirai-based): plain-text persistence strings for its systemd-network-helper service and init scripts"
        author = "KSI Digital"
        date = "2026-10-11"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/akuma-loader"
        tlp = "clear"
        yarahub_uuid = "307564ea-4fab-48bd-81d3-ae84b836d0a4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fd35a79721c98ed973e8c9efa4426cd6"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/akuma-loader"
        // Built from akuma_x64 ddaadef1 (match). No hits on ~92,000 honeypot captures, 142 recent MalwareBazaar
        // Mirai/Gafgyt/Mozi ELFs (incl. the 143.20.154.42 kit bot 0f103597) or Ubuntu 24.04 system binaries.
    strings:
        $svc  = "systemd-network-helper.service" ascii
        $desc = "Description=System Network Helper" ascii
        $i1   = "/etc/init.d/S99system" ascii
        $i2   = "/system/etc/init.d/99system" ascii
        $i3   = "/system/etc/rc.local" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and
        $svc and $desc and 1 of ($i*)
}
