rule Malicious_MMC_Meeting_Invitation_Downloader
{
    meta:
        description = "Detects a malicious MMC (.msc) meeting invitation that abuses APDS.DLL to execute embedded script code and silently download and install a remote MSI payload."
        author = "tjx34"
        date = "2026-10-18"
	yarahub_uuid = "3cfce1b4-3c58-4081-9f77-135bdf7b0842"
	yarahub_license = "CC0 1.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_reference_md5 = "c9bf96f6e5273fda4822e79752e2140a"

    strings:
        $redirect = "s.dll/redirect.html?target=jav" ascii
        $install1 = "wshshell.installproduct" ascii nocase
        $install2 = "wshshell.uilevel" ascii nocase
        $xslt = "NTaqcK.loadXML" ascii
        $mmc = "<?xml version=\"1.0\"?><MMC_ConsoleFile" ascii

    condition:
        filesize < 200KB and
        uint16(0) == 0x3f3c and
        2 of them
}