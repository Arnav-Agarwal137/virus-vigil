rule UNK_DeadDrop_Electron_COM_Elevation_Source_Experimental
{
    meta:
        author = "Ilja Krasnjanski"
        description = "Recovered COM elevation builder paired with Electron Node collection source"
        date = "2026-10-26"
        yarahub_reference_link = "https://krasforge.github.io/UNK_DeadDrop/articles/02-vsix-editor-execution/"
        yarahub_reference_md5 = "61f3b3b608a24e4aee5571a85afd7451"
        yarahub_uuid = "80ebea02-23e7-4934-b20a-8113e59b3e1a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        evidence_cutoff = "2026-07-24"
        status = "experimental"
        scope = "plaintext or decoded JavaScript source; not evidence of successful elevation"
    strings:
        $clsid = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" ascii nocase
        $moniker = "Elevation:Administrator!new:" ascii
        $electron = "ELECTRON_RUN_AS_NODE" ascii
        $exec_path = "process.execPath" ascii
        $job_vsix = "--company-wallet-job" ascii
        $job_clickfix = "--win-build-ep-only" ascii
        $temp_vsix = "gus-phase2-" ascii
        $temp_clickfix = "sa-elev-done-" ascii
        // Retained implementation syntax, not just markers quoted in research.
        $impl_builder = /function buildCOMElevationScript\(exePath, *exeArgs\) *\{/ ascii
        $impl_runner = /function (runPhase2Elevated|runPhase2WindowsCOMElevated)\([^\r\n]{0,120}\) *\{/ ascii
        $impl_dispatch = "$fa=$vt.func[9]" ascii
        $impl_invoke = "$f.Invoke($pv,$us,$ua,0,0,0)" ascii
    condition:
        all of ($impl_*) and
        filesize < 4MB and $clsid and $moniker and $electron and $exec_path and
        1 of ($job_*) and 1 of ($temp_*)
}
