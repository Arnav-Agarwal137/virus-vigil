rule MAL_Win_DesktopStreamClient
{
    meta:
        description = "DesktopStreamClient hVNC/stealer module of the Lold campaign: screen streaming over WebSocket/WebRTC (:8080 /ws/publisher), browser credential theft via IElevator App-Bound-Encryption bypass, exfil to :8787 /api/client/report"
        date = "2026-10-19"
        author = "anonymous"
        hash1 = "611bf055ec285421c6cf774f22d1baf4f4710f966af97e8d3ca9ea18ed3195fb"
        yarahub_uuid = "60303fcf-9ceb-41a3-96fc-5f54e9b1deec"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fbb21872381bf046446842034a2da9c3"

    strings:
        $ua1   = "DesktopStreamClient/0.1" ascii wide
        $ua2   = "DesktopStreamClient/1.0" ascii wide
        $reg   = "Software\\DesktopStreamClient\\Identity" ascii wide
        $dl    = "DesktopStreamDownloads" ascii wide
        $cls1  = "WebSocketVideoPublisher@streaming@rdp@@" ascii
        $cls2  = "WebRtcPublisher@streaming@rdp@@" ascii
        $cls3  = "IVideoPublisher@streaming@rdp@@" ascii
        $msg1  = "Browser rejected the WebSocket H.264 fallback" ascii wide
        $msg2  = "Generated device identity is invalid" ascii wide
        $msg3  = "Local State path does not match a known browser profile layout" ascii wide
        $net1  = "/ws/publisher" ascii wide
        $net2  = "/api/client/report" ascii wide
        $abe1  = "IElevatorChrome" ascii wide
        $abe2  = "IElevator2Chrome" ascii wide
        $abe3  = "IElevatorEdge" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 40MB and
        (
            any of ($ua*, $reg, $dl) or
            2 of ($cls*, $msg*) or
            (all of ($net*) and 1 of ($abe*))
        )
}
