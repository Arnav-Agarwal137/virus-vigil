rule SCRIPT_Dropper_Unknown_ForgeAuto_89707478
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "89707478b54e35b76b9ef2f43b897713ddd1e425db3bcc8cbbdc5b210b61d9d8"
        yarahub_uuid = "f6c89cac-1aaa-4493-bf2e-1b73194233ae"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fd9037c3f40515e2bd128ce031153fde"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "/usr/bin/env python3" ascii
        $s1 = "action=\"store_true\"," ascii
        $s2 = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)" ascii
        $s3 = "args = parser.parse_args()" ascii
        $s4 = "sys.exit(1)" ascii
        $s5 = "if __name__ == \"__main__\":" ascii
        $s6 = "store_true" ascii
        $s7 = "User-Agent" ascii
        $s8 = "type=int," ascii
        $s9 = "def main():" ascii
        $s10 = "parser = argparse.ArgumentParser(" ascii
        $s11 = "parser.add_argument(\"host\", nargs=\"?\", help=\"Host to perform stress test on\")" ascii
        $s12 = "\"-p\", \"--port\", default=80, help=\"Port of webserver, usually 80\", type=int" ascii
        $s13 = "\"--randuseragents\"," ascii
        $s14 = "help=\"Randomizes user-agents with each request\"," ascii
        $s15 = "help=\"Use a SOCKS5 proxy for connecting\"," ascii
        $s16 = "\"--proxy-host\", default=\"127.0.0.1\", help=\"SOCKS5 proxy host\"" ascii
        $s17 = "\"--proxy-port\", default=\"8080\", help=\"SOCKS5 proxy port\", type=int" ascii
        $s18 = "help=\"Time to sleep between each header sent.\"," ascii
        $s19 = "parser.set_defaults(verbose=False)" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s17, $s18, $s19) and 1 of ($s16)
}
