rule SCRIPT_Dropper_Unknown_ForgeAuto_53097786
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "530977865daeb57f0fe89f7f1f67f302e9d04f589dd2d28f29f079311a59e1b6"
        yarahub_uuid = "e5cf9da3-b5e5-4301-bd25-1af6c7a27889"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3897aa086a98636d5910e9a0cca8317b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const { execFile } = require('child_process');" ascii
        $s1 = "const _0x8efc5822ec1b = promisify(execFile);" ascii
        $s2 = "fs.writeFileSync(_0x8efc5822ec1w, script, 'utf8');" ascii
        $s3 = "const { stdout, stderr } = await _0x8efc5822ec1b(" ascii
        $s4 = "{ timeout: _0x8efc5822ecr, maxBuffer: 10 * 1024 * 1024, windowsHide: true }" ascii
        $s5 = "stdout: err.stdout || ''," ascii
        $s6 = "exitCode: err.code," ascii
        $s7 = "fs.unlinkSync(_0x8efc5822ec1w);" ascii
        $s8 = "-NonInteractive" ascii
        $s9 = "-ExecutionPolicy" ascii
        $s10 = "const fs = require('fs');" ascii
        $s11 = "const os = require('os');" ascii
        $s12 = "const path = require('path');" ascii
        $s13 = "const { promisify } = require('util');" ascii
        $s14 = "'powershell.exe'," ascii
        $s15 = "stderr: err.stderr || err.message," ascii
        $s16 = "-NoProfile" ascii
        $s17 = "} catch (err) {" ascii
        $s18 = "success: false," ascii
        $s19 = ", stderr: stderr ||" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
