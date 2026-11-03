rule MULTI_Sample_RustyStealer_51a371c2_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects RustyStealer (inconnu, etat extrait)"
        date = "2026-10-01"
        reference_sha256 = "51a371c23d6bb298259d5cd10f8bd86b16e992a9d80c107a69eaa60e2bc793a3"
        yarahub_uuid = "2411317a-80e3-4cba-8394-1f5dceae8675"
        famille = "RustyStealer"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "bdd47842beb8d609433dfad5d86dbd80"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "name: thorp-browser" ascii
        $s1 = "Use Thorp browser environments from Codex, Claude Code, WorkBuddy, or Hermes. Inventories and deterministically" ascii
        $s2 = "reuses persistent signed-in profiles, gives each MCP process its own browser target, hands" ascii
        $s3 = "unavailable sign-ins and personal challenges to a human, and completes authorized work with existing sessions." ascii
        $s4 = "An environment is a persistent browser profile owned by the user. It holds login state, proxy," ascii
        $s5 = "fingerprint, and extensions. An MCP process is only a temporary caller: it owns one window/target" ascii
        $s6 = "per environment and must never treat the environment or browser process as its property." ascii
        $s7 = "regardless of sign-in or cloud navigation. Cloud sync or team sharing requires an explicit," ascii
        $s8 = "accessible category; team members still need create permission there. The desktop environment directory" ascii
        $s9 = "includes this PC's local profiles and all accessible personal/team cloud profiles. The team's" ascii
        $s10 = "protocol-private root is internal, not a user-facing default category." ascii
        $s11 = "Use the MCP tools actually discovered in this session. A refreshed Skill does not replace" ascii
        $s12 = "tools or instructions already loaded into an ongoing conversation. Check tool availability" ascii
        $s13 = "before using a new capability; reload the connection or start a new session only when needed." ascii
        $s14 = "connection page. Keep the stable entry; never rewrite it to a particular `mcp-runtime` version." ascii
        $s15 = "Windows and WSL can share the same Windows program and Skill. Thorp maintains its registered" ascii
        $s16 = "independent Skill copies when necessary. Do not run an independent upgrade, replace managed" ascii
        $s17 = "files, or turn a custom URL/native installation into Windows stdio without the user's choice." ascii
        $s18 = "The Automation Server `/api` URL is not an HTTP MCP endpoint." ascii
        $s19 = "Only use browser engines advertised by the connected tools. Builds exposing `dovra` use the" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
