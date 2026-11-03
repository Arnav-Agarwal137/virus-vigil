rule SCRIPT_Sample_Unique_1b13f67d
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_vbs, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "1b13f67dc3b51cab5bc203f3a6de75019b65a12e9067d0c6bc07ee2a69aae52e"
        yarahub_uuid = "552fef9a-0592-4074-a702-c4e14c7e3069"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_vbs"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5d2c141844ee0831ab5d5654635b1c02"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "[ -f \"$f\" ] && R=\"$R\\n$(grep -HaoE \"$P\" \"$f\" 2>/dev/null | head -6)\"" ascii
        $s1 = "for d in $(find /root /home /var/www /opt /app /srv /data /mnt /var/lib/docker/volumes -maxdepth 6 -type d -name \".claude\" 2>/dev/null | head -40); do" ascii
        $s2 = "for f in \"$d\"/.credentials.json \"$d\"/settings.json \"$d\"/settings.local.json \"$d\"/managed-settings.json; do" ascii
        $s3 = "[ -f \"$f\" ] && R=\"$R\\n$(grep -HaoE \"$P\" \"$f\" 2>/dev/null | head -5)\"" ascii
        $s4 = "3) .env / docker-compose" ascii
        $s5 = "R=\"$R\\n$(grep -HaoE \"$P\" \"$f\" 2>/dev/null | head -4)\"" ascii
        $s6 = "for f in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do" ascii
        $s7 = "[ -f \"$f\" ] && R=\"$R\\n$(grep -HaoE \"$P\" \"$f\" 2>/dev/null | head -4)\"" ascii
        $s8 = "env 2>/dev/null | grep -aE '^(OPENAI|ANTHROPIC|DEEPSEEK|GEMINI|GOOGLE_API|AZURE|OPENROUTER|SLACK|DISCORD|TELEGRAM|QWEN|ZAI|GLM|MISTRAL|GROQ|XAI|PERPLEXITY|COHERE|TOGETHER)'" ascii
        $s9 = "2>/dev/null | head -6)" ascii
        $s10 = "/.credentials.json" ascii
        $s11 = "/settings.local.json" ascii
        $s12 = "2>/dev/null | head -5)" ascii
        $s13 = "$R\\n$(grep -HaoE" ascii
        $s14 = "2>/dev/null | head -4)" ascii
        $s15 = "\\) -size -20M 2>/dev/null | grep -aiE" ascii
        $s16 = "| head -30 | xargs -r strings 2>/dev/null | grep -aoE" ascii
        $s17 = "^(OPENAI|ANTHROPIC|DEEPSEEK|GEMINI|GOOGLE_API|AZURE|OPENROUTER|SLACK|DISCORD|TELEGRAM|QWEN|ZAI|GLM|MISTRAL|GROQ|XAI|PERPLEXITY|COHERE|TOGETHER)" ascii
        $s18 = "(OPENAI_API_KEY|ANTHROPIC_API_KEY|DEEPSEEK_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|GOOGLE_API_KEY|AI_API_KEY)[[:space:]]*[=:][[:space:]]*[^ ;<]{12,}" ascii
        $s19 = "/settings.json" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
