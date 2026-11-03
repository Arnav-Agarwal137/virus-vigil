import "pe"

rule TELEPUZ_SessionId_DualHash_Oct2026
{
    meta:
        description = "TELEPUZ main DLL, build seen October 2026 (ClickFix chain via Everything.exe side-loading). Anchors on the session-ID routine that runs an FNV hash and a rotate-left-5 plus 0x9E3779B9 hash side by side over the computer name, volume serial and install date, together with the family's rdtsc junk-code idiom or its import profile. Elastic's Windows_Trojan_Telepuz_9e2c9a0b does not match this build"
        author = "Daydream"
        date = "2026-10-12"
        reference = "https://www.elastic.co/security-labs/threat-command/telepuz-maas-malware-clickfix"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "20d3db1254f5f77a928fe4c6bff3ba1f"
        yarahub_uuid = "2aa8e8e5-faed-40ab-a1fa-646c1127de60"
    strings:
        // imul r32, [rsp+x], 0x01000193 ... shl r32, 5 ... shr r32, 0x1b ; or ... add r32, 0x9E3779B9  (one loop body)
        $dual = { 69 [1-3] 93 01 00 01 [16-64] C1 E? 05 [2-10] C1 E? 1B [0-3] 0B ?? [2-14] ( 05 | 81 C? ) B9 79 37 9E }
        // rdtsc ; shl rdx, 0x20 ; or rax, rdx  (opaque timing junk scattered through the code)
        $rdtsc = { 0F 31 48 C1 E2 20 48 0B C2 }
    condition:
        uint16(0) == 0x5A4D and pe.is_64bit() and filesize < 4MB and
        #dual >= 2 and
        (
            #rdtsc > 20 or
            ( pe.imports("Secur32.dll", "InitializeSecurityContextA") and pe.imports("KERNEL32.dll", "WaitForDebugEvent") and pe.imports("KERNEL32.dll", "UpdateProcThreadAttribute") )
        )
}
