rule VShell_Linux_Shell_Dropper
{
    meta:
        author = "Daydream"
        description = "Shell dropper for the VShell Linux implant: probes writable system directories with a 'writeablex' file, downloads a per-architecture stage (stage=true&k=) and starts it with nohup"
        date = "2026-10-10"
        yarahub_uuid = "82b25885-bba0-4169-ac25-5c3e14875349"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "d52aa0f6cf8620c50d8d7aea561b783a"
    strings:
        $probe  = "writeablex"
        $stage  = "&stage=true&k="
        $arch1  = "&a=l64&"
        $arch2  = "&a=a64&"
        $uname  = "uname -m"
        $nohup  = "nohup "
        $py     = "urllib.urlretrieve"
    condition:
        filesize < 8KB and all of them
}
