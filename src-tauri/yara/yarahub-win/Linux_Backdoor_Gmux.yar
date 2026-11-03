rule Linux_Backdoor_Gmux {
    meta:
        author = "Darses"
        date = "2026-11-01"
        description = "Generic detection and embedded configuration extraction for Linux Go-based gmux backdoor"
        yarahub_uuid = "6e599c81-9721-4266-8f89-097bfaff8a09"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "01fdb8d047d6cbd2c4d199a8bed7ff4f"

    strings:
        $name1 = "gmux/cmd/agent" ascii
        
        $pkg1 = "internal/agent" ascii
        $pkg2 = "internal/common/rudp" ascii
        $pkg3 = "internal/common/icmp.go" ascii

        $func1 = "main.resolveProxyChain" ascii
        $func2 = "main.NewBeaconCmd" ascii
        $func3 = "agent.GenerateAgentID" ascii

        $msg1 = "Using proxy chain: %s" ascii
        $msg2 = "Using server-provided SSH host key" ascii
        $msg3 = "Run agent in beacon mode (heartbeat-based)" ascii

        $tag1 = "toml:\"server_addr\"" ascii
        $tag2 = "toml:\"listen_addr\"" ascii
        $tag3 = "toml:\"target_agent\"" ascii
        $tag4 = "toml:\"default_agent\"" ascii

    condition:
        // ELF 64-bit binary header
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        (
            $name1 or
            all of ($pkg*) or
            all of ($msg*) or
            all of ($func*) or
            all of ($tag*)
        )
}
