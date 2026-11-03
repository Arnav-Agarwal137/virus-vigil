rule SCRIPT_Dropper_Unknown_ForgeAuto_24c73432
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "24c73432d81bc677c123c4acc728b015cfe090d2fe22d3ba0dad2ec9cc52eaf4"
        yarahub_uuid = "c82ef124-5bb7-4a4c-9866-41761b6ac6dd"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "eeb9a6d6830f1b95caf30ede55aebdf4"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const _0x8efc5822ec1b = promisify(execFile);" ascii
        $s1 = "return new Promise((resolve, _0x8efc5822ec11) => {" ascii
        $s2 = "const _0x8efc5822ecx = url.startsWith('https') ? https : http;" ascii
        $s3 = "const file = fs.createWriteStream(destPath);" ascii
        $s4 = "if (_0x8efc5822ec12.statusCode >= 300 && _0x8efc5822ec12.statusCode < 400 && _0x8efc5822ec12.headers.location) {" ascii
        $s5 = "fs.unlinkSync(destPath);" ascii
        $s6 = "if (_0x8efc5822ec12.statusCode !== 200) {" ascii
        $s7 = "return _0x8efc5822ec11(new Error(`HTTP ${_0x8efc5822ec12.statusCode}`));" ascii
        $s8 = "_0x8efc5822ec12.pipe(file);" ascii
        $s9 = "-NonInteractive" ascii
        $s10 = "-ExecutionPolicy" ascii
        $s11 = "const fs = require('fs');" ascii
        $s12 = "const path = require('path');" ascii
        $s13 = "const os = require('os');" ascii
        $s14 = "const { promisify } = require('util');" ascii
        $s15 = "const http = require('http');" ascii
        $s16 = "const https = require('https');" ascii
        $s17 = "file.close();" ascii
        $s18 = "windowsHide: true," ascii
        $s19 = "msiexec.exe" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
