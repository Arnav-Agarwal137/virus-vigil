rule MULTI_Sample_Unique_07e9ff28_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat extrait)"
        date = "2026-10-01"
        reference_sha256 = "07e9ff28cbd221e518a4f63618530854f19b7da2206471261afc34a1a2784e58"
        yarahub_uuid = "5090597c-e2bf-44cb-a915-794edb825456"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7d093d1e9bf722aa7d61ae92177e5483"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "html[data-mscreen=xxScreen]" ascii
        $s1 = "docs/design-system.md" ascii
        $s2 = "m-x{display:none;}" ascii
        $s3 = "--m-safe-t:env(safe-area-inset-top,0px);" ascii
        $s4 = "--m-safe-r:env(safe-area-inset-right,0px);" ascii
        $s5 = "--m-safe-b:env(safe-area-inset-bottom,0px);" ascii
        $s6 = "--m-safe-l:env(safe-area-inset-left,0px);" ascii
        $s7 = "-webkit-text-size-adjust:100%;text-size-adjust:100%;" ascii
        $s8 = "html.m.m-land{--m-top:40px;}" ascii
        $s9 = "html.m body{min-height:0;height:100%;-webkit-tap-highlight-color:transparent;overscroll-behavior:none;}" ascii
        $s10 = "html.m *{-webkit-touch-callout:none;}" ascii
        $s11 = "html.m input,html.m select,html.m textarea{-webkit-touch-callout:default;user-select:text;font-size:16px;}   /*" ascii
        $s12 = "html.m .screen{padding-left:var(--m-safe-l);padding-right:var(--m-safe-r);}" ascii
        $s13 = "html.m .screen > .content{margin-top:calc(var(--m-top) + var(--m-safe-t));}" ascii
        $s14 = "html.m #topbar{height:calc(var(--m-top) + var(--m-safe-t));padding:var(--m-safe-t) calc(8px + var(--m-safe-r)) 0 calc(10px + var(--m-safe-l));gap:8px;}" ascii
        $s15 = "html.m #topbar .logo,html.m #topbar > .sep,html.m #hStatus{display:none;}" ascii
        $s16 = "html.m #topbar .hitem{gap:5px;}" ascii
        $s17 = "html.m #topbar .hitem .ic{width:15px;height:15px;}" ascii
        $s18 = "html.m #topbar .hitem b{font-size:15px;}" ascii
        $s19 = "html.m #topbar .grow{min-width:0;}" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
