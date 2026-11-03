import "pe"

rule SeroRAT_ABE_Helper_DLL
{
    meta:
        author = "Daydream"
        description = "SeroRAT helper DLL that runs inside chrome.exe, brave.exe or msedge.exe and asks the browser elevation service (COM DecryptData) to decrypt the App-Bound Encryption key, returning it over a named pipe whose name is derived from the process ID"
        date = "2026-10-11"
        yarahub_uuid = "8f88ccb4-747d-4faa-bff9-28c47f210eaa"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "79145aeb30802f73692b4aed57ea50f3"
    strings:
        // pipe name: four values, each ror32(pid ^ constant, n), printed as %08X
        $fmt     = "%08X%08X%08X%08X" ascii
        $pipe    = "\\\\.\\pipe\\%s" ascii
        $k1      = { 81 (F1 | F2 | F3 | F6 | F7) E1 A7 F5 1B }      // xor r32, 0x1BF5A7E1
        $k2      = { 81 (F1 | F2 | F3 | F6 | F7) B9 79 37 9E }      // xor r32, 0x9E3779B9
        // elevation service class IDs written as 32-bit immediates, not as contiguous GUID bytes
        $chrome  = { E0 60 88 70 [3-4] 41 F6 11 46 [3-4] 88 95 7D 86 [3-4] 7D D3 67 5B }
        $brave   = { AF 31 6B 57 [3-4] 69 63 6B 4B [3-4] 85 60 E4 B2 [3-4] 03 A9 7A 8B }
        $edge    = { 6C E9 CB 1F [3-4] 97 16 AF 43 [3-4] 91 40 28 97 [3-4] C7 C6 97 67 }
        $n1      = "chrome.exe" ascii
        $n2      = "brave.exe" ascii
        $n3      = "msedge.exe" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        pe.imports("ole32.dll", "CoCreateInstance") and
        $fmt and $pipe and
        all of ($k*) and
        2 of ($chrome, $brave, $edge) and
        2 of ($n*)
}
