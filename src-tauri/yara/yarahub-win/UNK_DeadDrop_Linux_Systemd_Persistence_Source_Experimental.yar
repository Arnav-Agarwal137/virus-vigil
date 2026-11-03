rule UNK_DeadDrop_Linux_Systemd_Persistence_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recovered Linux agent source that writes and manages the google-agent systemd unit"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/04-credential-wallet-collection/"
        yarahub_reference_md5 = "61f3b3b608a24e4aee5571a85afd7451"
        yarahub_uuid = "16dd1078-9054-4938-998c-3b05332324e4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "static installer-source identification; not evidence that a unit was written or started"
    strings:
        $system_unit = "/etc/systemd/system/google-agent.service" ascii
        $user_unit = ".config/systemd/user/google-agent.service" ascii
        $agent_dir = ".local/share/google/agent" ascii
        $unit_staging = "unitStaging" ascii
        $enable = "systemctl enable google-agent.service" ascii
        $restart = "systemctl restart google-agent.service" ascii
        $desktop = "google-agent.desktop" ascii
    condition:
        filesize < 8MB and 1 of ($system_unit, $user_unit) and
        1 of ($enable, $restart) and 1 of ($unit_staging, $agent_dir, $desktop)
}
