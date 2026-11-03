rule Ancient_Telnet_Dropper
{
    meta:
        description = "Ancient botnet shell dropper (persist.sh) that installs the .ancient IoT bot"
        author = "KSI Digital"
        date = "2026-10-05"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/ancient-botnet"
        tlp = "clear"
        yarahub_uuid = "b9586f13-a118-4025-b9c0-a536ab18dec1"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "402bc4899ffd26dc1306755e58d951f0"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/ancient-botnet"
        // Tested against the 3 captured dropper versions (match) and ~500 other
        // honeypot samples incl. the Ancient ELF payloads (no false positives).
    strings:
        $hdr  = "ancient telnet persistence payload" ascii
        $f    = "/.ancient" ascii
        $m1   = "ANCIENT_STARTED" ascii
        $m2   = "ANCIENT_NOCONN" ascii
        $m3   = "ANCIENT_FAIL" ascii
        $port = ":8A0E" ascii            // C2 port 35342 checked in /proc/net/tcp
        $arch = "BIN=x86_64" ascii
    condition:
        // shell script (not ELF), small, self-identifying OR >=2 behaviour markers
        uint16(0) != 0x457f and filesize < 64KB and
        ($hdr or ($f and 2 of ($m1, $m2, $m3, $port, $arch)))
}
