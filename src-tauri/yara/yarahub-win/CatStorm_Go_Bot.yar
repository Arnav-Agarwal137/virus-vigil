// CatStorm: Go 1.25 Linux DDoS bot with a Monero miner (MalwareBazaar signature "CatStorm", 136 ELF builds for
// x86_64/aarch64/arm5-7/mips/mipsel/ppc64/ppc64le since 2026-10-01). Static analysis 2026-11-01 of
// 0a659a6ab785bbcdd8b85ccd155f0c428f9863fe5221d6e30da4c7606aba7cf5 (x86_64).
// Go keeps the module and package paths in every build (pclntab function names, buildinfo), stripped or not and
// on every architecture, so the rule keys on the author's own package paths. A rename of the module defeats it.
// YARAhub (yaraify.abuse.ch) meta below; re-uploading with the same yarahub_uuid + rule name updates the rule.

rule CatStorm_Go_Bot
{
    meta:
        author = "wristhulk (honeypot lab)"
        date = "2026-11-01"
        description = "CatStorm Go DDoS bot: module catstorm/Bot with its attack-method, miner and process packages. Any 3 package paths in an ELF."
        reference = "static RE of 0a659a6ab785bbcdd8b85ccd155f0c428f9863fe5221d6e30da4c7606aba7cf5"
        yarahub_uuid = "db0352e9-93fd-4cb2-b53b-df378046b570"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "794c7b7b09aa2b644e9155b08146e642"

    strings:
        $m_root = "catstorm/Bot" ascii
        $p_l4   = "catstorm/Bot/Methods/l4" ascii
        $p_l7   = "catstorm/Bot/Methods/l7" ascii
        $p_proc = "catstorm/Bot/process" ascii
        $f_mine = "catstorm/Bot/Methods.MoneroMiner" ascii
        $f_pers = "catstorm/Bot/process.Persist" ascii

    condition:
        uint32(0) == 0x464c457f and $m_root and 3 of ($p_*, $f_*)
}
