/*
    EssentialStealer/18a029fc -- https://github.com/IAmForeverAloneToo/malware-analysis
    Full analysis and deployment scoping: EssentialStealer/18a029fc/REPORT.md, section 6.1.
    Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
*/

rule MAL_CRIME_DROPPER_MACOS_EssentialStealerClickFix_Sep26
{
    meta:
        description = "Detects the EssentialStealer ClickFix stage-1 dropper: a single-line osascript wrapper around a base64 AppleScript that installs a LaunchAgent"
        author = "IAmForeverAloneToo"
        date = "2026-09-01"
        reference = "https://github.com/IAmForeverAloneToo/malware-analysis"
        reference_sample = "18a029fc8e5d40069bae12217f59f3177ae11deca46925408646f6cd913c2c7f"
        yarahub_reference_md5 = "40e2a4379a32c04d59df9e61ded83457"
        yarahub_uuid = "92f07522-67d6-494f-976d-45d47689817d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        confidence = "high"
        deploy = "safe to alert -- file scan"
        note = "The file is one line with no terminator. $x1/$x2 are the exact wrapper; $x3 is the head of the embedded base64, which decodes to the SCRIPT_PATH assignment and is stable for this build. Served identically from every subdomain and regardless of User-Agent."

    strings:
        $x1 = "osascript -e \"$(echo \"" ascii
        $x2 = "\" | base64 -d)\"" ascii
        $x3 = "ZG8gc2hlbGwgc2NyaXB0ICINClNDUklQVF9QQVRIPVwiJEhPTUUvTGlicmFyeS9m" ascii
        $x4 = "TGF1bmNoQWdlbnRz" ascii   /* "LaunchAgents" in base64 */

    condition:
        filesize < 200KB and $x1 at 0 and $x2 and ($x3 or $x4)
}
