rule SCRIPT_Dropper_Formbook_ForgeAuto_a070f81e_Script
{
    meta:
        author = "Marjoriefort"
        description = "Detects Formbook (script_js, etat script)"
        date = "2026-10-02"
        reference_sha256 = "a070f81e54b7aeb3d6212b01869c9817840663d2ea5c71d216b0ad60e0a81b43"
        yarahub_uuid = "66acba18-61ae-4a3a-a2a0-8b14de5de1b4"
        famille = "Formbook"
        famille_source = "reputation"
        classe = "script_js"
        etat = "script"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0437ef61612341ff7afaa312cf9439ac"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" ascii
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ascii
        $s2 = "m1lcHbNdJaZcHeFdTHqYeG7cL8o+W4ZdS8oReGSbW61UfeddOgddLSofmmkibuqfWOmLWQ5igevxv8kxW4VdHfHlxSkAWQpdHSoCydH0W4bXvmkpW7afBW" ascii
        $s3 = "pLpcJe3cQrDSWPG7W4bJE8k2W77cJCkYD8kWeCoGDmoLW4fGW6BdPW" ascii
        $s4 = "WOVdGSoiAmolBq1qW5FdP8kPzmozWQneqgxdVSkPF8oLkSocW7GcW6G" ascii
        $s5 = "WRDxchWeW7fXyd0SzSkkw8kpW5bpWQJcJSkNWOnThmoFuSkrjsD5WP7dVCkOW4JcLwFcKW4fW63dQcRcMtzLlKSQEmkqWRFcRH93WRlcGMlcRmoEwSohCmoNWQXFW5OeWP7dS8kUcSkagMuBffyPva" ascii
        $s6 = "WOGYW5q8WPHpySoNsmoRW5lcMSoPEmkeuCopCSk0W7JcS8oMW64" ascii
        $s7 = "t8kFwJKOWR7cOmkzW7JdHrG6W4hdIMddPcGvFfNdLbZdTCkzWRmfWOK" ascii
        $s8 = "zmkktcaUWR7cOSkuWQZcJYXVWOddJwtcQIW2ButdNGNdSSoeWRmo" ascii
        $s9 = "W6/dRHn0WQbAWRqiW4hcPSokWPaWW4tcV8k0W6jkb8kHkmocW4ddKmk2naq" ascii
        $s10 = "DmoZAbPCWR9EW4v+W6/cSCoxW65ReqbYW490b8oahmkPpW/dJINdKSkxtqVdKmkUq8kGWPvvBqVdPSkMkWn4p1/cMSkBW6BcKbtcU2ldO8kFmqjfW453EColtNBdOHNcOf00WPj8WRpcGcm" ascii
        $s11 = "gSkcWQCqW6NcQeRdKvOpWOVcIGT7WQb8xgZcTSo0zhSGWQtdOCop" ascii
        $s12 = "function _0x2c02(_0x5ecc63, _0x4d5f2b) {" ascii
        $s13 = "if (_0x2c02['wPFsLh'] === undefined) {" ascii
        $s14 = "var _0x483384 = function (_0x4b75d6) {" ascii
        $s15 = "var _0x5d1347 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';" ascii
        $s16 = "_0x68b636 = _0x5d1347['indexOf'](_0x68b636);" ascii
        $s17 = "for (var _0x14ce89 = 0x0, _0x4d7cb7 = _0x9f7b90['length']; _0x14ce89 < _0x4d7cb7; _0x14ce89++) {" ascii
        $s18 = "_0x2e9b5a += '%' + ('00' + _0x9f7b90['charCodeAt'](_0x14ce89)['toString'](0x10))['slice'](-0x2);" ascii
        $s19 = "var _0xd77601 = function (_0x5bc2d7, _0x1c3a91) {" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
