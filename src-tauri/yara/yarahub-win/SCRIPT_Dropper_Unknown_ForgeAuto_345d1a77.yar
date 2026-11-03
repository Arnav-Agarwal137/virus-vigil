rule SCRIPT_Dropper_Unknown_ForgeAuto_345d1a77
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "345d1a775867b9e79ee6b0825e1e2416d715550f2162ac32c076f0371c8553e1"
        yarahub_uuid = "7762b775-8e66-4f79-ae69-3935d6e8893f"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "39f1980ac18b42469a278ab336574355"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "} catch (err) {" ascii
        $s1 = "const { runPowerShell } = require('./handlers/powershell');" ascii
        $s2 = "const { runCmd } = require('./handlers/cmd');" ascii
        $s3 = "const { runEval } = require('./handlers/eval');" ascii
        $s4 = "const { downloadAndRun } = require('./handlers/downloadRun');" ascii
        $s5 = "const { handleFilesCommand } = require('./handlers/files');" ascii
        $s6 = "const { takeScreenshot } = require('./handlers/screenshot');" ascii
        $s7 = "const { handleDeploy } = require('./handlers/deploy');" ascii
        $s8 = "const { applyAgentUpdate } = require('./handlers/agentUpdate');" ascii
        $s9 = "const { scheduleKillClient } = require('./install');" ascii
        $s10 = "const { runWalletCheck } = require('./walletScheduler');" ascii
        $s11 = "const { getRemoteScript } = require('./remoteScript');" ascii
        $s12 = "function setReconnectFn(_0x8efc5822ec0) {" ascii
        $s13 = "const _0x8efc5822ec2 = getRemoteScript();" ascii
        $s14 = "if (_0x8efc5822ec2?.extraCommands?.[type]) {" ascii
        $s15 = "const result = await _0x8efc5822ec2.extraCommands[type](payload);" ascii
        $s16 = "result = await runPowerShell(payload.command, payload.timeoutMs);" ascii
        $s17 = "result = await runCmd(payload.command, payload.timeoutMs);" ascii
        $s18 = "result = await runEval(payload.code, payload.timeoutMs);" ascii
        $s19 = "result = await downloadAndRun(payload.url, payload.args);" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
