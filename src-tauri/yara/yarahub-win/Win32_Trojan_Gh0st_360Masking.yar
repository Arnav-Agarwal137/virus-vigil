import "pe"
import "hash"

rule Win32_Trojan_Gh0st_360Masking {
    meta:
        description = "Detects Gh0st RAT variants masking as 360 Safe Browser containing specific Windows service manipulation strings and C2 domain artifacts."
        author = "Serhii Kocherhan"
        date = "2026-09-25"
        yarahub_twitter = "@skocherhan"
        yarahub_uuid = "28afa615-73de-4b3e-8bbc-e1ec3794a099"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e5a8df35182b193af1542093d8ebc5e7"

    strings:
        // C2 Domain Artifact
        $s_domain = "conf.f.360.cn" ascii wide nocase

        // Product Name
        $s_product = { 33 36 30 e5 ae 89 e5 85 a8 e6 b5 8f e8 a7 88 e5 99 a8 }

        // Selected Windows Services Targeted or Enumerated
        $svc1 = "fastuserswitchingcompatibility" ascii wide nocase
        $svc2 = "helpsvc" ascii wide nocase
        $svc3 = "ias" ascii wide nocase
        $svc4 = "irmon" ascii wide nocase
        $svc5 = "logonhours" ascii wide nocase
        $svc6 = "nla" ascii wide nocase
        $svc7 = "ntmssvc" ascii wide nocase
        $svc8 = "nwcworkstation" ascii wide nocase
        $svc9 = "pcaudit" ascii wide nocase
        $svc10 = "srservice" ascii wide nocase
        $svc11 = "uploadmgr" ascii wide nocase
        $svc12 = "wmdmpmsp" ascii wide nocase
        $svc13 = "wmi" ascii wide nocase
        $svc14 = "xcvs" ascii wide nocase

    condition:
        // Validate PE Header Magic (MZ)
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            hash.md5(0, filesize) == "e5a8df35182b193af1542093d8ebc5e7" or
            ($s_domain and $s_product) or
            ($s_domain and 4 of ($svc*))
        )
}