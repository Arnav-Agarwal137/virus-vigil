rule MULTI_Sample_GuLoader_834e1a1e
{
    meta:
        author = "Marjoriefort"
        description = "Detects GuLoader (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "834e1a1e86773f9bc09e32b950d792b6eb4a89abdbd68853dd6606d1031e0ebd"
        yarahub_uuid = "d19f88b1-3d70-42f7-b98f-4b9ce2bff20f"
        famille = "GuLoader"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "cdfdc8ea45c4d53bf2fa62b0532c4871"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "cVtdUEQyDSoRAgcfRSoQVVxAQlVfZCIEHlpRX2QNW0RXRRYyT1xFWUtUbVUqFQ8OC2tHXUFcVVV0RE02BRcBIhoVX11QUWpF" ascii
        $s1 = "LAEZAB9fS2sBHxEIDAojEAMXBQsBIQceXgULSxERGxkHCQ0qEh4EDQ4QagYDAA==" ascii
        $s2 = "set \"bekldes=%SystemRoot%\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe\"" ascii
        $s3 = ");function dityrambes ($bortcensurair86) { [void][System.TimeZoneInfo]::Local.Id;$irritatory=-24164+24164;$outslander = [System.Int32]::Parse(" ascii
        $s4 = "DD4uJVY5JiETAgIIFw0qEh4WHgQANhQKFQIAOAEYHg==" ascii
        $s5 = "DBADAwUCEDcYHgMFAgF2Qg==" ascii
        $s6 = ";[System.IO.Path]::Combine(" ascii
        $s7 = "1;$amfibiebaadenes = [System.Math]::Cbrt(27);$naitly=$afdelingskonsulent[0];Semiliquidity" ascii
        $s8 = "1;[System.DateTime]::UtcNow.ToBinary();while (!$rowdier) {Semiliquidity" ascii
        $s9 = "1;$pyrheliometer = [System.String]::Join(" ascii
        $s10 = "1;[System.Environment]::SystemPageSize;if ($ligemndene) {Semiliquidity" ascii
        $s11 = "1;$trresnorenes = [System.Math]::Min(73, 19);Semiliquidity" ascii
        $s12 = "1;[System.Guid]::NewGuid().ToByteArray();Semiliquidity" ascii
        $s13 = "1;$naitly=$afdelingskonsulent[$vinstues3];$omtaltes = [System.BitConverter]::DoubleToInt64Bits(1.23)}$nonpossibly=164152;$suppressedly=33542;[System.DateTime]::DaysInMonth(2027, 4);Semiliquidity" ascii
        $s14 = "1;$deerstalker63 = [System.IO.Path]::GetFileNameWithoutExtension(" ascii
        $s15 = "1;Myndigst $unhumbly;function pzx_murg {    $sydostens = [System.Math]::Exp(1.5);    return $sydostens};;;" ascii
        $s16 = "bekldes=%SystemRoot%\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe" ascii
        $s17 = "if not exist \"%bekldes%\" (" ascii
        $s18 = "blar_grok" ascii
        $s19 = "snork_zib" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
