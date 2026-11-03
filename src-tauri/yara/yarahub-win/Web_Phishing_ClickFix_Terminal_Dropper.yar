rule Web_Phishing_ClickFix_Terminal_Dropper {
    meta:
        description = "Detects 'ClickFix' social engineering phishing landing pages that instruct macOS users to execute a malicious terminal command via Spotlight copy-paste injection, leveraging base64-encoded curl payloads."
        author = "Serhii Kocherhan"
        date = "2026-10-08"
        yarahub_twitter = "@skocherhan"
        yarahub_uuid = "0849d0de-dba1-498a-a958-10c8b95f1616"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "eecc34901d1ee1680e5970025d0fad25"
        yarahub_reference = "https://x.com/FABO97662188/status/2107819401319735711"

    strings:
        // ClickFix / Spotlight Instructions & Keycap Elements
        $s_spotlight = "to open Spotlight" ascii wide
        $s_terminal = "Terminal" ascii wide
        $s_paste = "to paste the token" ascii wide

        // DOM Element IDs & UI Class Hooks specific to this template
        $s_elem1 = "verifyTrigger" ascii wide
        $s_elem2 = "checkWidget" ascii wide
        $s_elem3 = "stepsPanel" ascii wide

        // Obfuscated Payload Pattern (Base64-encoded curl execution string component)
        $s_payload_marker = "base64 -d" ascii wide
        $s_bash_wrapper = "bash <<< $(echo" ascii wide

    condition:
        filesize < 100KB and (
            ($s_spotlight and $s_terminal and $s_paste) or
            ($s_payload_marker and $s_bash_wrapper) or
            (2 of ($s_elem*) and ($s_spotlight or $s_payload_marker))
        )
}