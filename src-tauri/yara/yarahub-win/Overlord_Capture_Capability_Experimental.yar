rule Overlord_Capture_Capability_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Overlord framework agent with multiple capture and frame-difference symbols"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/05-screen-capture-analysis/"
        yarahub_reference_md5 = "15e2f4004a4c896636e1ee8948cc63e8"
        yarahub_uuid = "9b168fde-7593-47ae-88e5-817a59719a22"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "capability and lineage; not campaign attribution"
    strings:
        $environment = "OVERLORD_SERVER_RAW" ascii wide
        $capture1 = "overlord-client/cmd/agent/capture.CaptureAndSend" ascii
        $capture2 = "overlord-client/cmd/agent/capture.encodeBlocks" ascii
        $capture3 = "overlord-client/cmd/agent/capture.blockChanged" ascii
        $capture4 = "overlord-client/cmd/agent/capture.copyPrev" ascii
        $capture5 = "overlord-client/cmd/agent/capture.frameFPS" ascii
        $capture6 = "overlord-client/cmd/agent/capture.CaptureDisplay" ascii
    condition:
        filesize < 64MB and $environment and 4 of ($capture*)
}
