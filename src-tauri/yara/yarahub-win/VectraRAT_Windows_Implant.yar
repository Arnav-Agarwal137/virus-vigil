rule VectraRAT_Windows_Implant
{
    meta:
        description = "VectraRAT (formerly Nyxel) x64 Windows RAT/stealer implant: static mutex Local\\Vectra.Client.SingleInstance, MessagePack TCP C2 transport ([TcpConnectionManager]/[ImageSender]/[Keyboard]), callback.json dynamic C2 override, and UACME #41 debug-object hijacking UAC bypass"
        author = "Daydream"
        date = "2026-10-17"
        reference = "https://socradar.io/blog/vectrarat-undocumented-stack-maas"
        reference_sample = "3ab56c9fb6b7c404c1e5b36788959c877ea819fb124c3847fa0498e9915ef9a7 (also matches b738c03fef5e3d26419e4aab1818a0a7ad206c67fb3eeedcdfb3ef1ee07eb620)"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a8619784bfe927e551e831d4adaf8ba5"
        yarahub_uuid = "0c762bfa-e0ae-4496-b90d-e9a8932849dc"
    strings:
        $mutex = "Local\\Vectra.Client.SingleInstance" wide ascii
        $cfg1 = "callback.json" ascii wide
        $cfg2 = "uacEnabled" ascii
        $mod_tcp = "[TcpConnectionManager] Auto-reconnect disabled by server disconnect command" ascii
        $mod_img = "[ImageSender] Received START_SCREEN command" ascii
        $mod_kbd = "[Keyboard] Failed to parse MessagePack data, size=" ascii
        $mod_cb  = "Calling high priority callback for message type: 0x" ascii
        $uac1 = "NtRemoveProcessDebug" ascii wide
        $uac2 = "DbgUiSetThreadDebugObject" ascii wide
        $uac3 = "computerdefaults.exe" wide ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            ($mutex and 1 of ($mod_*)) or
            (3 of ($mod_*) and all of ($cfg*)) or
            (2 of ($mod_*) and all of ($uac*))
        )
}
