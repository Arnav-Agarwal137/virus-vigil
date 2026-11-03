//! The browser fixer's undo, run for real but NOT elevated: fix.ps1 is pointed at a scratch
//! HKCU key and a scratch Firefox folder (-Root / -FirefoxDir), which the app never passes.

use super::*;

/// The registry tests share HKCU:\Software\VirusVigilTest and one checks it is gone at the end, so they
/// must never overlap (8 Oct 2026: system_fixes_... running alongside made that check fail at random).
static REG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join("virus-vigil-tests");
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn ps(cmd: &str) -> String {
    let out = powershell().arg("-Command").arg(cmd).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn run_fix(plan: &Value, root: &str, ff: &Path, tag: &str) -> Value {
    let script = write_script(&format!("fix-{tag}.ps1"), FIX_PS).unwrap();
    let plan_file = scratch(&format!("plan-{tag}.json"));
    let out = scratch(&format!("out-{tag}.json"));
    let _ = std::fs::remove_file(&out);
    std::fs::write(&plan_file, plan.to_string()).unwrap();
    let o = powershell().arg("-File").arg(&script).arg("-Plan").arg(&plan_file).arg("-Out").arg(&out)
        .arg("-Root").arg(root).arg("-FirefoxDir").arg(ff).output().unwrap();
    let text = std::fs::read_to_string(&out).unwrap_or_else(|_| panic!("no result: {}", String::from_utf8_lossy(&o.stderr)));
    serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap()
}

/// Apply twice, undo once: values that existed get their old value, values that did not exist
/// are gone again, a value the fixer never touches is untouched, and Firefox's file is
/// byte-identical. A tampered record is refused and writes nothing.
#[test]
fn fixer_changes_can_be_undone_exactly() {
    let _reg = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let id = std::process::id();
    let root = format!(r"HKCU:\Software\VirusVigilTest\t{id}");
    let chrome = format!(r"{root}\Google\Chrome");
    let edge = format!(r"{root}\Microsoft\Edge");
    let ff = scratch(&format!("ff-{id}"));
    // Cleans up even when an assertion below panics (a failed run used to leave its key behind).
    struct Cleanup(String, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            ps(&format!("Remove-Item -LiteralPath '{}' -Recurse -Force -ErrorAction SilentlyContinue; $p = 'HKCU:\\Software\\VirusVigilTest'; if ((Test-Path $p) -and -not (Get-ChildItem $p)) {{ Remove-Item $p }}", self.0));
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _cleanup = Cleanup(root.clone(), ff.clone());
    let _ = std::fs::remove_dir_all(&ff);
    std::fs::create_dir_all(ff.join("distribution")).unwrap();
    let pj = ff.join("distribution").join("policies.json");
    let original = "{\"policies\":{\"DisableTelemetry\":true,\"Homepage\":{\"URL\":\"https://example.com/\u{e9}\"}}}\r\n";
    std::fs::write(&pj, original).unwrap();
    ps(&format!("New-Item -Path '{chrome}' -Force | Out-Null; New-ItemProperty -Path '{chrome}' -Name SafeBrowsingProtectionLevel -Value 1 -PropertyType DWord | Out-Null; New-ItemProperty -Path '{chrome}' -Name KeepMe -Value 'his own' -PropertyType String | Out-Null"));
    assert_eq!(ps(&format!("(Get-Item '{chrome}').GetValueNames() -join ','")), "SafeBrowsingProtectionLevel,KeepMe", "seeding failed");

    let plan = json!({"browsers": ["chrome", "edge", "firefox"], "blockPasswords": false, "blockCards": true});
    let r1 = run_fix(&plan, &root, &ff, "a1");
    assert_eq!(r1["ok"], true, "{r1}");
    assert!(r1["changes"].as_array().unwrap().iter().all(|c| c["ok"] == true), "{r1}");
    assert_eq!(ps(&format!("(Get-ItemProperty '{chrome}').SafeBrowsingProtectionLevel")), "2", "apply did not write");
    let rec1 = undo::merge(None, &r1);
    let sb = |rec: &Value| rec["registry"].as_array().unwrap().iter()
        .find(|r| r["where"] == r"Google\Chrome" && r["name"] == "SafeBrowsingProtectionLevel").unwrap()["before"].clone();
    assert_eq!(sb(&rec1), json!({"existed": true, "value": 1, "type": "DWord"}));

    // Second run: its "before" is OUR value (2); the record must keep the person's (1).
    let r2 = run_fix(&plan, &root, &ff, "a2");
    let rec2 = undo::merge(Some(rec1.clone()), &r2);
    assert_eq!(sb(&rec2), json!({"existed": true, "value": 1, "type": "DWord"}));
    assert_eq!(rec2["firefox"]["text"], original);
    assert_eq!(rec2["registry"].as_array().unwrap().len(), rec1["registry"].as_array().unwrap().len());
    assert_eq!(undo::summary(&Some(rec2.clone()))["browsers"], json!(["Chrome", "Edge", "Firefox"]));

    let u = run_fix(&json!({"undo": rec2}), &root, &ff, "u");
    assert_eq!(u["ok"], true, "{u}");
    assert_eq!(u["mode"], "undo");
    assert_eq!(ps(&format!("(Get-ItemProperty '{chrome}').SafeBrowsingProtectionLevel")), "1");
    assert_eq!(ps(&format!("(Get-ItemProperty '{chrome}').KeepMe")), "his own");
    assert_eq!(ps(&format!("(Get-Item '{chrome}').GetValueNames() -join ','")), "SafeBrowsingProtectionLevel,KeepMe");
    assert_eq!(ps(&format!("(Get-Item '{edge}').GetValueNames().Count")), "0");
    assert_eq!(std::fs::read_to_string(&pj).unwrap(), original);

    // A record edited to reach other settings is refused, and nothing is written.
    let bad = json!({"undo": {"registry": [
        {"where": r"Microsoft\Windows\System", "name": "EnableSmartScreen", "before": {"existed": true, "value": 0, "type": "DWord"}},
        {"where": r"Google\Chrome", "name": "ExtensionInstallForcelist", "before": {"existed": true, "value": "x", "type": "String"}}
    ], "firefox": null}});
    let t = run_fix(&bad, &root, &ff, "t");
    assert_eq!(t["ok"], false);
    assert_eq!(t["errors"].as_array().unwrap().iter().filter(|e| e.as_str().unwrap().starts_with("refused")).count(), 2, "{t}");
    assert_eq!(ps(&format!(r"Test-Path '{root}\Microsoft\Windows\System'")), "False");
    assert_eq!(ps(&format!("(Get-Item '{chrome}').GetValueNames() -join ','")), "SafeBrowsingProtectionLevel,KeepMe");

    drop(_cleanup);
    assert_eq!(ps(&format!("Test-Path '{root}'")), "False");
    assert_eq!(ps(r"Test-Path 'HKCU:\Software\VirusVigilTest'"), "False", "empty parent key left behind");
}

/// Defender attack-blocking rules through a stand-in store (-AsrStore): only the four allowed ids
/// are raised, a rule already at Block is left alone (so undo can never lower it), an unknown id
/// is refused, and undo puts every rule back exactly - including removing ones that were absent.
#[test]
fn asr_rules_raise_and_undo_exactly() {
    let _reg = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    const RARE: &str = "01443614-cd74-433a-b99e-2ecdc07bfc25";
    const LSASS: &str = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";
    const DRV: &str = "56a863a9-875e-4185-98a7-b882c64b5ce5";
    const OTHER: &str = "d1e49aac-8f56-4280-b9ba-993a6d77406c"; // a real rule Vigil does not set
    let id = std::process::id();
    let store = scratch(&format!("asr-{id}.json"));
    let original = json!({RARE: 2, LSASS: 1, OTHER: 2});
    std::fs::write(&store, original.to_string()).unwrap();
    let read = || -> Value { serde_json::from_str(std::fs::read_to_string(&store).unwrap().trim_start_matches('\u{feff}')).unwrap() };
    let run = |plan: &Value, tag: &str| -> Value {
        let script = write_script(&format!("fix-asr-{tag}.ps1"), FIX_PS).unwrap();
        let plan_file = scratch(&format!("plan-asr-{tag}.json"));
        let out = scratch(&format!("out-asr-{tag}.json"));
        let _ = std::fs::remove_file(&out);
        std::fs::write(&plan_file, plan.to_string()).unwrap();
        let o = powershell().arg("-File").arg(&script).arg("-Plan").arg(&plan_file).arg("-Out").arg(&out)
            .arg("-Root").arg(r"HKCU:\Software\VirusVigilTest\unused").arg("-AsrStore").arg(&store).output().unwrap();
        let text = std::fs::read_to_string(&out).unwrap_or_else(|_| panic!("no result: {}", String::from_utf8_lossy(&o.stderr)));
        serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap()
    };

    let r = run(&json!({"asr": [RARE, DRV, LSASS, OTHER.to_uppercase()]}), "a");
    let changed: Vec<&str> = r["changes"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(changed, vec![RARE, DRV], "{r}");
    assert!(r["changes"].as_array().unwrap().iter().all(|c| c["ok"] == true), "{r}");
    assert_eq!(r["errors"].as_array().unwrap().len(), 1, "unknown id not refused: {r}");
    assert_eq!(read(), json!({RARE: 1, LSASS: 1, OTHER: 2, DRV: 1}));
    let rec = undo::merge(None, &r);
    assert_eq!(undo::summary(&Some(rec.clone()))["browsers"], json!(["Defender rules"]));

    let u = run(&json!({"undo": rec}), "u");
    assert_eq!(u["ok"], true, "{u}");
    assert_eq!(read(), original, "undo did not restore exactly");

    // A record edited to lower a rule Vigil never sets is refused and writes nothing.
    let bad = json!({"undo": {"registry": [{"where": "Defender ASR", "name": OTHER, "before": {"existed": true, "value": 0, "type": null}}], "firefox": null}});
    let t = run(&bad, "t");
    assert_eq!(t["ok"], false, "{t}");
    assert_eq!(read(), original);
    let _ = std::fs::remove_file(&store);
}

/// The deep check (deep.ps1), read-only, against fixtures instead of the admin-only real places:
/// prefetch files built in Windows' compressed format, a scratch HKCU task tree, a fixture
/// exclusion list. Also: without the list, it says so instead of reporting "no exclusions".
#[test]
fn deep_check_reads_fixtures_right() {
    let _reg = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let id = std::process::id();
    let tree = format!(r"HKCU:\Software\VirusVigilTest\tree{id}");
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            ps(&format!(r"Remove-Item -LiteralPath '{}' -Recurse -Force -ErrorAction SilentlyContinue; $p = 'HKCU:\Software\VirusVigilTest'; if ((Test-Path $p) -and -not (Get-ChildItem $p)) {{ Remove-Item $p }}", self.0));
        }
    }
    let _cleanup = Cleanup(tree.clone());
    ps(&format!(r"$t = '{tree}'; New-Item ($t + '\Microsoft\Windows\Defrag\ScheduledDefrag') -Force | Out-Null; Set-ItemProperty ($t + '\Microsoft\Windows\Defrag\ScheduledDefrag') Id '{{A}}'; Set-ItemProperty ($t + '\Microsoft\Windows\Defrag\ScheduledDefrag') SD ([byte[]](1,2)); New-Item ($t + '\HardwareMonitorUpdate') -Force | Out-Null; Set-ItemProperty ($t + '\HardwareMonitorUpdate') Id '{{B}}'; Set-ItemProperty ($t + '\HardwareMonitorUpdate') Index 0"));
    let excl = scratch(&format!("excl-{id}.json"));
    std::fs::write(&excl, json!({"ExclusionPath": [r"C:\Users\x\AppData\Roaming\JMicron"], "ExclusionExtension": [".exe"], "ExclusionProcess": null, "ExclusionIpAddress": null}).to_string()).unwrap();
    let na = scratch(&format!("excl-na-{id}.json"));
    std::fs::write(&na, json!({"ExclusionPath": ["N/A: Must be an administrator to view exclusions"]}).to_string()).unwrap();

    let run = |exclusions: &Path, tag: &str| -> Value {
        let script = write_script(&format!("deep-{tag}.ps1"), DEEP_PS).unwrap();
        let out = scratch(&format!("deep-{tag}.json"));
        let _ = std::fs::remove_file(&out);
        let o = powershell().arg("-File").arg(&script).arg("-Out").arg(&out)
            .arg("-PrefetchDir").arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(r"tests\fixtures\prefetch"))
            .arg("-TreeRoot").arg(&tree).arg("-ExclusionsFile").arg(exclusions).output().unwrap();
        let text = std::fs::read_to_string(&out).unwrap_or_else(|_| panic!("no result: {}", String::from_utf8_lossy(&o.stderr)));
        serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap()
    };
    let r = run(&excl, "a");
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["exclusions"]["ExclusionPath"], json!([r"C:\Users\x\AppData\Roaming\JMicron"]));
    assert_eq!(r["exclusions"]["ExclusionExtension"], json!([".exe"]));
    assert_eq!(r["tasksRead"], 2);
    assert_eq!(r["hiddenTasks"], json!([{"path": r"\HardwareMonitorUpdate", "id": "{B}", "index": 0}]));
    let p = &r["prefetch"];
    assert_eq!((p["read"].as_u64(), p["unread"].as_u64()), (Some(6), Some(1)), "{p}");
    let mut risky: Vec<(&str, &str)> = p["risky"].as_array().unwrap().iter().map(|x| (x["exe"].as_str().unwrap(), x["path"].as_str().unwrap())).collect();
    risky.sort();
    assert_eq!(risky, vec![
        ("INSTALL.EXE", r"\USERS\TESTER\APPDATA\LOCAL\TEMP\TEMP1_CRACK.ZIP\INSTALL.EXE"),
        ("OLD.EXE", r"\USERS\TESTER\APPDATA\LOCAL\TEMP\RAR$EXA1234.5678\OLD.EXE"),
        ("SETUP.EXE", r"\USERS\TESTER\DOWNLOADS\FREEGAME\SETUP.EXE"),
    ]);

    let n = run(&na, "n");
    assert_eq!(n["ok"], false);
    assert!(n["exclusions"].is_null(), "an unreadable list must not read as an empty one: {n}");
    assert!(n["errors"][0].as_str().unwrap().contains("administrator"), "{n}");
    let _ = std::fs::remove_file(&excl);
    let _ = std::fs::remove_file(&na);
}

/// "Do it all for me" Windows settings (plan.system) against a scratch key (-SysRoot) and a stand-in
/// for Defender / firewall / Guest / SMB1 (-SysStore): unsafe values are raised, safe ones are left
/// alone, an unknown fix id is refused, and undo puts every value back exactly (removed ones too).
#[test]
fn system_fixes_raise_and_undo_exactly() {
    let _reg = REG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let id = std::process::id();
    let root = format!(r"HKCU:\Software\VirusVigilTest\s{id}");
    let ts = format!(r"{root}\HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server");
    let ra = format!(r"{root}\HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance");
    let lsa = format!(r"{root}\HKLM\SYSTEM\CurrentControlSet\Control\Lsa");
    let uac = format!(r"{root}\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
    let ux = format!(r"{root}\HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings");
    let ss = format!(r"{root}\HKLM\SOFTWARE\Policies\Microsoft\Windows\System");
    let adv = format!(r"{root}\HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced");
    let store = scratch(&format!("sys-{id}.json"));
    struct Cleanup(String, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            ps(&format!(r"Remove-Item -LiteralPath '{}' -Recurse -Force -ErrorAction SilentlyContinue; $p = 'HKCU:\Software\VirusVigilTest'; if ((Test-Path $p) -and -not (Get-ChildItem $p)) {{ Remove-Item $p }}", self.0));
            let _ = std::fs::remove_file(&self.1);
        }
    }
    let _cleanup = Cleanup(root.clone(), store.clone());
    let seed = |k: &str, n: &str, v: &str, t: &str| ps(&format!("if (-not (Test-Path '{k}')) {{ New-Item -Path '{k}' -Force | Out-Null }}; New-ItemProperty -Path '{k}' -Name {n} -Value {v} -PropertyType {t} -Force | Out-Null"));
    seed(&ts, "fDenyTSConnections", "0", "DWord");
    seed(&ts, "KeepMe", "'his own'", "String");
    seed(&ra, "fAllowToGetHelp", "1", "DWord");
    seed(&lsa, "RunAsPPL", "2", "DWord");
    seed(&uac, "EnableLUA", "1", "DWord");
    seed(&uac, "ConsentPromptBehaviorAdmin", "0", "DWord");
    seed(&ux, "PauseUpdatesExpiryTime", "'2099-01-01T00:00:00Z'", "String");
    seed(&adv, "HideFileExt", "1", "DWord");
    let original = json!({"mp:DisableRealtimeMonitoring": true, "mp:MAPSReporting": 0, "fw:Domain": true, "fw:Private": false, "fw:Public": false, "guest:Enabled": true, "smb1:EnableSMB1Protocol": false});
    std::fs::write(&store, original.to_string()).unwrap();
    let read = || -> Value { serde_json::from_str(std::fs::read_to_string(&store).unwrap().trim_start_matches('\u{feff}')).unwrap() };
    let val = |k: &str, n: &str| ps(&format!("$i = Get-Item -LiteralPath '{k}' -ErrorAction SilentlyContinue; if ($i -and $i.GetValueNames() -contains '{n}') {{ [string]$i.GetValue('{n}') }} else {{ 'ABSENT' }}"));
    let run = |plan: &Value, tag: &str| -> Value {
        let script = write_script(&format!("fix-sys-{tag}.ps1"), FIX_PS).unwrap();
        let plan_file = scratch(&format!("plan-sys-{tag}.json"));
        let out = scratch(&format!("out-sys-{tag}.json"));
        let _ = std::fs::remove_file(&out);
        std::fs::write(&plan_file, plan.to_string()).unwrap();
        let o = powershell().arg("-File").arg(&script).arg("-Plan").arg(&plan_file).arg("-Out").arg(&out)
            .arg("-Root").arg(r"HKCU:\Software\VirusVigilTest\unused").arg("-SysRoot").arg(&root).arg("-SysStore").arg(&store).output().unwrap();
        let text = std::fs::read_to_string(&out).unwrap_or_else(|_| panic!("no result: {}", String::from_utf8_lossy(&o.stderr)));
        serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap()
    };
    const SID: &str = "S-1-5-21-1111-2222-3333-1001";

    let mut all: Vec<&str> = SYSTEM_FIXES.to_vec();
    all.push("evil");
    let r = run(&json!({"system": all, "userSid": SID}), "a");
    assert!(r["changes"].as_array().unwrap().iter().all(|c| c["ok"] == true), "{r}");
    let errs: Vec<&str> = r["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect();
    assert_eq!(errs, vec!["refused evil: not a setting Virus Vigil changes"], "{r}");
    let mut changed: Vec<&str> = r["changes"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    changed.sort();
    assert_eq!(changed, vec!["assist|fAllowToGetHelp", "cloud|mp:MAPSReporting", "ext|HideFileExt", "fw|fw:Private", "fw|fw:Public",
        "guest|guest:Enabled", "pause|PauseUpdatesExpiryTime", "rdp|fDenyTSConnections", "realtime|mp:DisableRealtimeMonitoring",
        "sigs|Update-MpSignature", "smartscreen|EnableSmartScreen", "smartscreen|ShellSmartScreenLevel", "uac|ConsentPromptBehaviorAdmin"], "{r}");
    assert_eq!(val(&ts, "fDenyTSConnections"), "1");
    assert_eq!(val(&ra, "fAllowToGetHelp"), "0");
    assert_eq!(val(&lsa, "RunAsPPL"), "2", "an already-safe value was touched");
    assert_eq!(val(&uac, "ConsentPromptBehaviorAdmin"), "5");
    assert_eq!(val(&ux, "PauseUpdatesExpiryTime"), "ABSENT");
    assert_eq!(val(&ss, "ShellSmartScreenLevel"), "Warn");
    assert_eq!(val(&adv, "HideFileExt"), "0");
    let s = read();
    assert_eq!((s["mp:DisableRealtimeMonitoring"].clone(), s["mp:MAPSReporting"].clone(), s["fw:Private"].clone(), s["guest:Enabled"].clone()), (json!(false), json!(2), json!(true), json!(false)));
    assert_eq!(s["smb1:EnableSMB1Protocol"], json!(false));

    let rec = undo::merge(None, &r);
    assert_eq!(undo::summary(&Some(rec.clone()))["browsers"], json!(["Windows settings"]));
    let u = run(&json!({"undo": rec, "userSid": SID}), "u");
    assert_eq!(u["ok"], true, "{u}");
    assert_eq!(val(&ts, "fDenyTSConnections"), "0");
    assert_eq!(val(&ts, "KeepMe"), "his own");
    assert_eq!(val(&ra, "fAllowToGetHelp"), "1");
    assert_eq!(val(&uac, "ConsentPromptBehaviorAdmin"), "0");
    assert_eq!(val(&ux, "PauseUpdatesExpiryTime"), "2099-01-01T00:00:00Z");
    assert_eq!(val(&ss, "EnableSmartScreen"), "ABSENT");
    assert_eq!(val(&adv, "HideFileExt"), "1");
    let mut back = read();
    back.as_object_mut().unwrap().remove("sigs:updated");
    assert_eq!(back, original, "undo did not restore the stand-in exactly");

    // A record edited to reach other values is refused and writes nothing.
    let bad = json!({"undo": {"registry": [
        {"where": "System", "name": "rdp|SomethingElse", "before": {"existed": true, "value": 0, "type": "DWord"}},
        {"where": "System", "name": "evil|mp:DisableRealtimeMonitoring", "before": {"existed": true, "value": true, "type": null}}
    ], "firefox": null}, "userSid": SID});
    let t = run(&bad, "t");
    assert_eq!(t["ok"], false, "{t}");
    assert_eq!(t["errors"].as_array().unwrap().iter().filter(|e| e.as_str().unwrap().starts_with("refused")).count(), 2, "{t}");
    assert_eq!(val(&ts, "SomethingElse"), "ABSENT");
    assert_eq!(read()["mp:DisableRealtimeMonitoring"], json!(true));

    // A per-user value with no valid SID is an error, never a write to the elevated account's hive.
    let n = run(&json!({"system": ["ext"], "userSid": "nonsense"}), "n");
    assert_eq!(n["ok"], false, "{n}");
    assert_eq!(val(&adv, "HideFileExt"), "1");
}
