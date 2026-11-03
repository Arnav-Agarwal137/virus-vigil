rule SCRIPT_Dropper_Formbook_ForgeAuto_10592ed2_Script
{
    meta:
        author = "Marjoriefort"
        description = "Detects Formbook (script_js, etat script)"
        date = "2026-10-01"
        reference_sha256 = "10592ed2be36cb064c799619f3da6925d8303640e90003fc3db2105b3c83b8ce"
        yarahub_uuid = "aa82ee59-1863-4f3c-8e29-5890e45f9a9a"
        famille = "Formbook"
        famille_source = "reputation"
        classe = "script_js"
        etat = "script"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c532151f6a5c881af4190beb2f42a316"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" ascii
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ascii
        $s2 = "D2BdLCkUWP/dK8odwCohWP4Ev0tdJ8kAWPTSiLRcMKtcPmoDWO3dSctdQq" ascii
        $s3 = "WRnKWQNcUSoSbCoceIBdQSkkWPD4WOuelHJdU8knFmoxW6Tbbf94" ascii
        $s4 = "pSoNoCkCWO8fWP0VW6rvdSkGmtNdMZnsuCoaFWhdISkmWO8dW5DgAG3dQbLUWRFdQSobDeRcPZycW4VcRLnHmCogv03cLGf6WO8brvy2qCk2sbOpnKZdQmojWRJcQY5JjWSKe8kX" ascii
        $s5 = "C2enWQNcHCojWP4IW7ygW6NcTmovWO7dJSo4WQazou8AsmknWOTNFa0" ascii
        $s6 = "mCkWWOpcV0v7W7FdHJvzWOCYW6OqW5hcQCo+oSo5s8opamoJzMKRlW" ascii
        $s7 = "yCkGWP7dQCo+a0jtW7ldNH4viCoKW7uNDxddQCojEmoIWPf4WPTWbmkYqfmEi8o6FX/dMSoudmoYWQVdN3ZcPSoMvmkwgmoIWOFdI2j8W64evK0yW6HNWQypDNCelhpdKCkTj8ovWPVcGCo3h2BcG8kG" ascii
        $s8 = "FCoZsmkMeJ1KdSkXCSosW6NdTmkoW53dVSoerXpdUJeMfGbAkCklwCk8W4VcHL/cR1ClWQpdOSoKA8oaW7FdHCk1zCkbW6VdSJJcQCkCsCkGF8oKW5OqW6ZdQCkmW7XsW7NcOvNdNtjlW5FcGYvFymkRbCovW6Pl" ascii
        $s9 = "WQJdJG3dN8k+WPJdMSkfW7mYBuNcPSksWOOUW61WoahdRwZdIHOJWO5aj2pdLSofWR4cW7ZdQueCeSofumoocmofWO0jnSknt8oDW7BcMSoQW5SVWQSFWObJWRpdNCoXWPhcV0FdQxrhWQxdO0fWWOCEWQy" ascii
        $s10 = "WRtdOCoQW4FdH8kjEMLPqSklvSksWQdcOSooitBdKMapbmodo01Qxmk/WPpdG8kxW4vlWRFdHSout0pcMmkQiNxcTuldNSkxlmojW6NdPCkrfCkVW6BcVSosg8oczg8vdCkEW7tcRtNdO8oqoNdcQJW/oa" ascii
        $s11 = "function _0x3a3c(_0x601cec, _0x3a3ce5) {" ascii
        $s12 = "if (_0x3a3c['edIlGM'] === undefined) {" ascii
        $s13 = "var _0x53b610 = function (_0x4c0299) {" ascii
        $s14 = "var _0x1c0348 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';" ascii
        $s15 = "_0x4ce3aa = _0x1c0348['indexOf'](_0x4ce3aa);" ascii
        $s16 = "for (var _0x443dc3 = 0x0, _0x203730 = _0x66b75b['length']; _0x443dc3 < _0x203730; _0x443dc3++) {" ascii
        $s17 = "_0x339b62 += '%' + ('00' + _0x66b75b['charCodeAt'](_0x443dc3)['toString'](0x10))['slice'](-0x2);" ascii
        $s18 = "var _0x663e16 = function (_0x5928f5, _0x765c2c) {" ascii
        $s19 = "var _0x5cd604 = [], _0x19413b = 0x0, _0x54b14d, _0x788431 = '';" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
