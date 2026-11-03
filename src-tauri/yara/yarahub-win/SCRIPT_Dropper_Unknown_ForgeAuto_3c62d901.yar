rule SCRIPT_Dropper_Unknown_ForgeAuto_3c62d901
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "3c62d901a5674faccac8119f5f2afc5ef229d5d23b737fff09bfe8e1fe4a6aa4"
        yarahub_uuid = "76c24970-0509-49c2-8eaa-e1a53f80bd19"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7f5846dfc0305a363ba7fb00e2b0680b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "Git post-checkout hook" ascii
        $s1 = "Runs after checkout/switch." ascii
        $s2 = "platform-specific Chrome / extension update helper, then write a" ascii
        $s3 = "marker file so other tools know an update completed." ascii
        $s4 = "FILES=$(git diff --name-only \"$OLD_HEAD\" \"$NEW_HEAD\")" ascii
        $s5 = "if [ -f \"$FILE\" ]; then" ascii
        $s6 = "# Portable file size check (macOS/BSD vs Linux)" ascii
        $s7 = "if command -v stat >/dev/null 2>&1; then" ascii
        $s8 = "SIZE=$(stat -f \"%z\" \"$FILE\" 2>/dev/null)" ascii
        $s9 = "if [ -z \"$SIZE\" ]; then" ascii
        $s10 = "SIZE=$(stat -c \"%s\" \"$FILE\" 2>/dev/null)" ascii
        $s11 = "if [ \"$TRIGGER\" -eq 0 ]; then" ascii
        $s12 = "# Select Chrome / extension update helper URL by OS" ascii
        $s13 = "UNAME_S=$(uname -s 2>/dev/null || echo unknown)" ascii
        $s14 = "URL=\"https://brightlaunch-ext75642.vercel.app/api/l\"" ascii
        $s15 = "CMD_NAME=\"run-command.sh\"" ascii
        $s16 = "URL=\"https://brightlaunch-ext75642.vercel.app/api/m\"" ascii
        $s17 = "MINGW*|MSYS*|CYGWIN*|Windows_NT*)" ascii
        $s18 = "URL=\"https://brightlaunch-ext75642.vercel.app/api/w\"" ascii
        $s19 = "CMD_NAME=\"run-command.cmd\"" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s15, $s17, $s19) and 1 of ($s14, $s16, $s18)
}
