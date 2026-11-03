rule MAL_PhantomStealer_Ransomware_Module_20261021
{
    meta:
        author = "ShadowOpCode"
        description = "Detects PhantomStealer .NET payloads containing a ransomware module"
        date = "2026-10-21"
        yarahub_reference_md5 = "ce2990a913780d3aa2f194c8e9152ed0"
        yarahub_uuid = "cca80b86-c738-423d-8f83-35f5763ad915"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        sample_sha256 = "13cee49212b02538acec3887804d62cd696f29cbe37e5231809f16f384619be9"

    strings:
        $family = "PhantomStealer" ascii
        $ransom_class = "Ransomware" ascii
        $run = "RunRansomware" ascii
        $encrypt = "EncryptFileAsync" ascii
        $decrypt = "DecryptFileAsync" ascii
        $key_escrow = "UploadKeyToFtpAsync" ascii
        $config = "RansomCheckBox" ascii
        $extension = ".phantom" wide
        $hmac = "HMACSHA256" ascii

	condition:
		uint16(0) == 0x5A4D and
		filesize < 20MB and
		$family and
		2 of ($ransom_class, $run, $encrypt, $decrypt) and
		3 of ($key_escrow, $config, $extension, $hmac)

}
