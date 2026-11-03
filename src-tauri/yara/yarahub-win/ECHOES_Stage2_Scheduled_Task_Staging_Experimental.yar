rule ECHOES_Stage2_Scheduled_Task_Staging_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "ECHOES archive-derived PowerShell stage that installs the WORD/DDD scheduled-task chain"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/09-echoes-lineage-image-provenance/"
        yarahub_reference_md5 = "70c5d8b76bdf839bfda26b998217dba2"
        yarahub_uuid = "9929f42b-64d8-4652-beab-8597fb457849"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "decoded ECHOES stage-two script only; does not attribute it to UNK_DeadDrop or identify the unavailable final payload"
    strings:
        $task = "OneDrive Reporting Task-" ascii nocase
        $register = "Register-ScheduledTask" ascii nocase
        $trigger = "New-ScheduledTaskTrigger" ascii nocase
        $vbs = "whale.vbs" ascii nocase
        $script = "wale.ps1" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
    condition:
        filesize < 2MB and $task and $register and $trigger and
        1 of ($vbs, $script) and $hidden
}
