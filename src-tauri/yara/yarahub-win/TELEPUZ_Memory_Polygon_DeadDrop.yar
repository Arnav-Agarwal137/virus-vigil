rule TELEPUZ_Memory_Polygon_DeadDrop
{
    meta:
        description = "TELEPUZ running in memory (or an unpacked dump): the JSON-RPC eth_call template with function selector 0xc3f909d4 that it sends to public Polygon endpoints to read its C2 address from a smart contract, with the operator contract or the endpoint path seen in October 2026"
        author = "Daydream"
        date = "2026-10-12"
        reference = "https://www.elastic.co/security-labs/threat-command/telepuz-maas-malware-clickfix"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "20d3db1254f5f77a928fe4c6bff3ba1f"
        yarahub_uuid = "1c561b17-532d-4844-88be-d3ea6da4d549"
    strings:
        $tmpl = "\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"0xc3f909d4\"},\"latest\"]}" ascii wide
        $req  = "\"data\":\"0xc3f909d4\"},\"latest\"]}" ascii wide
        $contract = "f55Bea1FdCf1c3ABb39ab92567C09aC1BFf6753E" ascii wide nocase
        $path = "/polygon-mainnet" ascii wide
        $h1 = "polygon.gateway.tenderly.co" ascii wide
        $h2 = "rpc-mainnet.matic.quiknode.pro" ascii wide
        $h3 = "polygon-bor.publicnode.com" ascii wide
    condition:
        $tmpl or ( $req and ( $contract or ( $path and 2 of ($h*) ) ) )
}
