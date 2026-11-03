rule SCRIPT_Dropper_Unknown_ForgeAuto_628f41a1
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "628f41a18f3b3d0b37885b45b0216280294d71f36e9a25b8f1d00dae94035f61"
        yarahub_uuid = "544351af-ad83-48c4-93bf-8bbfa3df2e2c"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "61029a8b695250f803aabe4df0c282e2"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const { execFile } = require('child_process');" ascii
        $s1 = "const { getInstallRoot } = require('../installMeta');" ascii
        $s2 = "const _0x8efc5822ec1b = promisify(execFile);" ascii
        $s3 = "const { loadInstallMeta } = require('../installMeta');" ascii
        $s4 = "Add-Type -AssemblyName System.Windows.Forms" ascii
        $s5 = "Add-Type -AssemblyName System.Drawing" ascii
        $s6 = "fs.writeFileSync(_0x8efc5822ec1w, script, 'utf8');" ascii
        $s7 = "fs.unlinkSync(_0x8efc5822ec1w);" ascii
        $s8 = "-NonInteractive" ascii
        $s9 = "-ExecutionPolicy" ascii
        $s10 = "const fs = require('fs');" ascii
        $s11 = "const os = require('os');" ascii
        $s12 = "const path = require('path');" ascii
        $s13 = "const { promisify } = require('util');" ascii
        $s14 = "windowsHide: true," ascii
        $s15 = "'powershell.exe'," ascii
        $s16 = "../installMeta" ascii
        $s17 = "CaptureScreen.exe" ascii
        $s18 = "-NoProfile" ascii
        $s19 = "image/png" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
