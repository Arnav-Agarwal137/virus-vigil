rule NK_PowerShell_FreeHost_AesJs_Cookie_Solver
{
    meta:
        description = "PowerShell that defeats a free web host JavaScript anti-bot page: downloads /aes.js and the challenge page, rewrites it to echo slowAES.decrypt, runs it with cscript.exe and sends the result as the __test cookie. Matches the routine in clear text (decrypted script, memory, decoded logs); seen in a Konni-tagged backdoor, September 2026, and in obfuscated form in Kimsuky-tagged scripts, June 2026"
        author = "Daydream"
        date = "2026-10-11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "29d63166-1c9b-4089-8717-7fcb4cfe1071"
        yarahub_reference_md5 = "9eb39bfa5c5ba5493aa9ee3cfd63048d"
    strings:
        $a1 = "WScript.Echo(toHex(slowAES.decrypt(c,2,a,b)));" ascii wide
        $a2 = "aes.js" ascii wide
        $a3 = "__test" ascii wide
        $a4 = "cscript" ascii wide nocase
        $a5 = ".replace('document.', '')" ascii wide nocase
        $a6 = ".Replace(\"document.\", \"\")" ascii wide nocase
        $p1 = "Invoke-WebRequest" ascii wide nocase
        $p2 = "System.Net.Cookie" ascii wide nocase
    condition:
        filesize < 5MB and
        $a1 and $a2 and $a3 and $a4 and 1 of ($a5, $a6) and all of ($p*)
}
