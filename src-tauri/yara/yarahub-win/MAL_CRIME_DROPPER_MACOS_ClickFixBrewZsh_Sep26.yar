/*
    AtomicStealer/7baaa2d5 -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: AtomicStealer/7baaa2d5/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_DROPPER_MACOS_ClickFixBrewZsh_Sep26
{
    meta:
        description = "Detects the AtomicStealer/brew-for-terminal stage-1 zsh dropper by its diagnostic-log decoy and its AES-128-CTR + gunzip stager"
        author = "IAmForeverAloneToo"
        date = "2026-09-01"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "7baaa2d56dbd1b405f283746264c868ab27794cd92f2e253d76bdb14bdd97310"
        yarahub_reference_md5 = "28c072d6acf42bea175ecff80e186dc1"
        yarahub_uuid = "9c117dbb-4c5f-486c-98fc-b98d4decaa8f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan"
        note = "The three hex-constant variable names, the openssl aes-128-ctr stager and the update_x7vd9r marker subdir co-occur only in this dropper. The DiagnosticReports block is a benign-looking decoy prepended to the malicious stager. Counts verified by grep on the delivered file."

    strings:
        $a1 = "#!/bin/zsh" ascii

        $x1 = "_cache_seed" ascii
        $x2 = "_license_salt" ascii
        $x3 = "_feature_flags" ascii
        $x4 = "update_x7vd9r" ascii

        $s1 = "aes-128-ctr" ascii
        $s2 = "DiagnosticReports" ascii

    condition:
        $a1 at 0 and
        filesize < 32KB and
        all of ($x*) and
        1 of ($s*)
}
