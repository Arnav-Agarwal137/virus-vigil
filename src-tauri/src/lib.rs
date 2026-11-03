// Virus Vigil - the native half. Everything here runs on this computer only:
// Rust opens no connection itself (PowerShell / Kotlin post to fixed addresses). The page
// decides what to show; this file only reads the system, runs the one admin-approved fix,
// checks files, and strips a question before the online AI may see it.

mod apkcheck;
mod axml;
mod cards;
mod deeplook;
mod folderscan;
mod hashlist;
mod hashonline;
mod phish;
mod phone;
mod qr;
mod redact;
mod sniff;
mod apksig;
mod stalker;
mod undo;
mod yara;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const SCAN_PS: &str = include_str!("../ps/scan.ps1");
const EXTRA_PS: &str = include_str!("../ps/extra.ps1");
const SCAN_TAIL: &str = "$out | ConvertTo-Json";
const THREATS_PS: &str = include_str!("../ps/threats.ps1");
const STARTUP_PS: &str = include_str!("../ps/startup.ps1");
const EXTENSIONS_PS: &str = include_str!("../ps/extensions.ps1");
const PHISH_UPDATE_PS: &str = include_str!("../ps/phish-update.ps1");
const HASHLIST_UPDATE_PS: &str = include_str!("../ps/hashlist-update.ps1");
const PWNED_PS: &str = include_str!("../ps/pwned.ps1");
const HASHLOOKUP_PS: &str = include_str!("../ps/hashlookup.ps1");
const AI_PS: &str = include_str!("../ps/ai.ps1");
const ONLINE_PS: &str = include_str!("../ps/online.ps1");
const SOFTWARE_PS: &str = include_str!("../ps/software.ps1");
const CAMERA_PS: &str = include_str!("../ps/camera.ps1");
const FIX_PS: &str = include_str!("../ps/fix.ps1");
const DEEP_PS: &str = include_str!("../ps/deep.ps1");
const OFFLINE_PS: &str = include_str!("../ps/offline.ps1");
const REMOTE_PS: &str = include_str!("../ps/remote.ps1");
const SCANRECORD_PS: &str = include_str!("../ps/scanrecord.ps1");

/// Our own folder under %TEMP%. Visible to an elevated process too (unlike R:).
fn work_dir() -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join("virus-vigil");
    std::fs::create_dir_all(&d).map_err(|e| format!("cannot create work folder: {e}"))?;
    Ok(d)
}

fn write_script(name: &str, body: &str) -> Result<PathBuf, String> {
    let p = work_dir()?.join(name);
    std::fs::write(&p, body).map_err(|e| format!("cannot write {name}: {e}"))?;
    Ok(p)
}

fn powershell() -> Command {
    let mut c = Command::new("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]);
    #[cfg(windows)]
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

/// scan.ps1 with the deeper checks (extra.ps1) inserted before its final JSON line.
/// extra.ps1 uses scan.ps1's Get-RegValue and $out. It runs inside try/catch so a
/// failure there costs only the deeper checks, never the main scan.
fn scan_script() -> Result<String, String> {
    join_scan(SCAN_PS, EXTRA_PS)
}

fn join_scan(scan: &str, extra: &str) -> Result<String, String> {
    let at = scan
        .rfind(SCAN_TAIL)
        .ok_or("scan.ps1 lost its final JSON line; deeper checks cannot be joined")?;
    Ok(format!(
        "{}try {{\n{}\n}} catch {{ $out.extraError = [string]$_ }}\n{}",
        &scan[..at],
        extra,
        &scan[at..]
    ))
}

/// Run one of our read-only scripts and parse the single JSON object it prints.
fn run_json_script(name: &str, body: &str) -> Result<Value, String> {
    let path = write_script(name, body)?;
    let out = powershell()
        .arg("-File")
        .arg(&path)
        .output()
        .map_err(|e| format!("could not start PowerShell: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim_start_matches('\u{feff}').trim();
    serde_json::from_str(text).map_err(|e| {
        let err = String::from_utf8_lossy(&out.stderr);
        format!("check gave unreadable output ({e}); stderr: {}", err.trim())
    })
}

#[tauri::command]
async fn scan_system() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        // Old attack-prone programs (software.ps1, ~1.5 s) run alongside the main scan.
        let sw = std::thread::spawn(|| run_json_script("software.ps1", SOFTWARE_PS));
        let mut v = run_json_script("scan.ps1", &scan_script()?)?;
        v["cards"] = cards::saved_cards(); // counts only; never card details
        v["software"] = match sw.join() {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => json!({"ok": false, "error": e}),
            Err(_) => json!({"ok": false, "error": "the program check crashed"}),
        };
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Defender's own record of its last quick and full scans (start, end, definitions, engine).
#[tauri::command]
async fn scan_record() -> Result<Value, String> {
    if cfg!(target_os = "android") { return Err("phone".to_string()); }
    tauri::async_runtime::spawn_blocking(|| run_json_script("scanrecord.ps1", SCANRECORD_PS))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn threat_history() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_json_script("threats.ps1", THREATS_PS))
        .await
        .map_err(|e| e.to_string())?
}

/// A Windows Defender quick scan of the whole laptop (the places malware lives: running
/// programs, startup, system folders). Runs without admin. What it caught is read afterwards
/// from threat_history, which is Defender's own record - this only says whether it ran.
#[tauri::command]
async fn defender_quick_scan() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        if cfg!(target_os = "android") {
            return Err("phone".to_string());
        }
        let exe = find_mpcmdrun().ok_or("Windows Defender's scanner was not found")?;
        let mut c = Command::new(exe);
        c.args(["-Scan", "-ScanType", "1"]);
        #[cfg(windows)]
        c.creation_flags(CREATE_NO_WINDOW);
        let o = c.output().map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        Ok(defender_verdict(o.status.code().unwrap_or(-1), &text, None))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Defender FULL scan (every file; an hour or more). Started in the background and NOT waited
/// for - its findings land in Defender's history, which "Was I hacked before?" reads.
#[tauri::command]
fn defender_full_scan() -> Result<Value, String> {
    if cfg!(target_os = "android") {
        return Err("phone".to_string());
    }
    let exe = find_mpcmdrun().ok_or("Windows Defender's scanner was not found")?;
    let mut c = Command::new(exe);
    c.args(["-Scan", "-ScanType", "2"]);
    #[cfg(windows)]
    c.creation_flags(CREATE_NO_WINDOW);
    let child = c.spawn().map_err(|e| format!("could not start the scan: {e}"))?;
    Ok(json!({"started": true, "pid": child.id()}))
}

/// Is the full scan Vigil started still running? Checked by the process id it was given AND the
/// program's name, so a reused id (another program that later got the same number) never reads as
/// "still scanning". tasklist is called by its full path so PATH can't pick a different program.
#[tauri::command]
fn scan_alive(pid: u32) -> Result<Value, String> {
    if cfg!(target_os = "android") { return Err("phone".to_string()); }
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut c = Command::new(format!(r"{sys}\System32\tasklist.exe"));
    c.args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"]);
    #[cfg(windows)]
    c.creation_flags(CREATE_NO_WINDOW);
    let o = c.output().map_err(|e| e.to_string())?;
    Ok(json!({"alive": tasklist_has(&String::from_utf8_lossy(&o.stdout), pid, "mpcmdrun.exe")}))
}

/// tasklist CSV rows: "Image Name","PID",... - true only for that pid running that program.
pub fn tasklist_has(csv: &str, pid: u32, image: &str) -> bool {
    csv.lines().any(|l| {
        let f: Vec<&str> = l.split("\",\"").map(|s| s.trim_matches('"')).collect();
        f.len() > 1 && f[0].eq_ignore_ascii_case(image) && f[1].trim() == pid.to_string()
    })
}

/// The deep check (deep.ps1): elevated, read-only. Exclusions, hidden tasks, programs run from
/// Downloads or an archive.
#[tauri::command]
async fn deep_check() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_elevated("deep.ps1", DEEP_PS, json!({})))
        .await
        .map_err(|e| e.to_string())?
}

/// Defender OFFLINE scan. THE PC RESTARTS within about a minute - the page asks first.
#[tauri::command]
async fn defender_offline_scan() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_elevated("offline.ps1", OFFLINE_PS, json!({})))
        .await
        .map_err(|e| e.to_string())?
}

/// Browser add-ons in every Chrome/Edge/Brave/Opera profile, matched locally against the
/// public known-bad ID list (the only download; nothing about this PC is sent).
#[tauri::command]
async fn extension_audit() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_json_script("extensions.ps1", EXTENSIONS_PS))
        .await
        .map_err(|e| e.to_string())?
}

/// Refresh the public phishing-domain list (at most daily; a bad download never replaces it).
#[tauri::command]
async fn update_phish_list(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if cfg!(target_os = "android") {
            Ok(phone::update_phish(&app))
        } else {
            run_json_script("phish-update.ps1", PHISH_UPDATE_PS)
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Refresh MalwareBazaar's list of known malware fingerprints (full weekly, last-48-hours daily;
/// a bad download never replaces a good list), then build the sorted file so the first file
/// check does not wait for it. On the phone Kotlin downloads and phone.rs checks (full list only
/// off mobile data).
#[tauri::command]
async fn update_hash_list(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if cfg!(target_os = "android") {
            // The phone compiles the malware patterns now (guarded), before the long download.
            if phone::lists_dir(&app).is_ok() {
                yara::warm();
            }
            return Ok(phone::update_hash(&app));
        }
        let mut v = run_json_script("hashlist-update.ps1", HASHLIST_UPDATE_PS)?;
        v["ready"] = hashlist::lookup(&"0".repeat(64));
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Which of these host names are on the phishing list. Local only.
#[tauri::command]
async fn phish_lookup(app: tauri::AppHandle, names: Vec<String>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dir = if cfg!(target_os = "android") {
            match phone::lists_dir(&app) {
                Ok(p) => p,
                Err(e) => return json!({ "count": 0, "found": [], "error": e, "ageHours": null }),
            }
        } else {
            phish::lists_dir()
        };
        phish::lookup_many(&dir, &names)
    })
    .await
    .map_err(|e| e.to_string())
}

/// Which system this is: the page shows the laptop card or the phone card.
#[tauri::command]
fn platform() -> &'static str {
    if cfg!(target_os = "android") { "android" } else { "windows" }
}

/// The page's door to the phone side (only the commands in phone::ALLOWED).
#[tauri::command]
async fn phone(app: tauri::AppHandle, cmd: String, args: Option<Value>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || phone::page_call(&app, &cmd, args.unwrap_or_else(|| json!({}))))
        .await
        .map_err(|e| e.to_string())?
}

/// Only a 5-character SHA-1 prefix may leave, so refuse anything else before PowerShell runs.
fn valid_prefix(p: &str) -> bool {
    p.len() == 5 && p.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

/// Leaked-password check (Have I Been Pwned, k-anonymity). Takes the hash PREFIX only.
#[tauri::command]
async fn pwned_range(app: tauri::AppHandle, prefix: String) -> Result<Value, String> {
    if !valid_prefix(&prefix) {
        return Err("only a 5-character hash prefix may be sent".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        if cfg!(target_os = "android") {
            Ok(phone::pwned(&app, &prefix))
        } else {
            pwned_laptop(&prefix)
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The online fingerprint look-up's asking half (hashonline.rs): PowerShell on the laptop, Kotlin
/// on the phone. Only fingerprints that pass `sendable` are handed over; every one asked gets a
/// reply row, and a helper that failed as a whole gives each a status-0 row with the reason.
fn online_fetch(app: &tauri::AppHandle, shas: &[String]) -> Vec<hashonline::Reply> {
    let shas: Vec<String> = shas.iter().filter(|s| hashonline::sendable(s)).cloned().collect();
    let got: Result<Value, String> = if cfg!(target_os = "android") {
        tauri_plugin_vigil_phone::call(app, "hashLookup", json!({"hashes": shas})).map(|v| v["rows"].clone())
    } else {
        write_script("hashlookup.ps1", HASHLOOKUP_PS).and_then(|p| {
            powershell().arg("-File").arg(&p).env("VV_HASHES", shas.join(",")).output()
                .map_err(|e| format!("could not start PowerShell: {e}"))
        }).and_then(|out| {
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').trim())
                .map_err(|e| format!("unreadable reply ({e})"))
        })
    };
    match got {
        Ok(Value::Array(a)) => a.iter().filter_map(|r| {
            Some((r["sha"].as_str()?.to_string(), r["status"].as_u64().unwrap_or(0) as u16, r["body"].as_str().unwrap_or("").to_string()))
        }).collect(),
        Ok(_) => shas.iter().map(|s| (s.clone(), 0, "the look-up helper gave no list".to_string())).collect(),
        Err(e) => shas.iter().map(|s| (s.clone(), 0, e.clone())).collect(),
    }
}

/// The laptop half of pwned_range (PowerShell). Checks the prefix itself too.
fn pwned_laptop(prefix: &str) -> Result<Value, String> {
    if !valid_prefix(prefix) {
        return Err("only a 5-character hash prefix may be sent".into());
    }
    let path = write_script("pwned.ps1", PWNED_PS)?;
    let out = powershell().arg("-File").arg(&path).env("VV_PREFIX", prefix).output()
        .map_err(|e| format!("could not start PowerShell: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).map_err(|e| format!("unreadable reply ({e})"))
}

/// The online AI (his 24 Sep 19:45 rule): only when Vigil's own library has no answer, and only
/// the typed question with personal details stripped HERE (redact.rs) - never files, pictures,
/// scan results or anything read from the device. `send: false` returns only what WOULD leave
/// (the page shows it and asks first); `send: true` strips the original again (the page's copy
/// is never trusted) and posts it. Rust opens no connection itself: PowerShell (laptop) or
/// Kotlin (phone) posts the body Rust built to the one fixed Groq address.
#[tauri::command]
async fn ask_online_ai(app: tauri::AppHandle, question: String, device: String, send: bool) -> Result<Value, String> {
    let r = redact::redact(&question);
    let mut out = json!({"ok": false, "error": null, "sent": r.text, "removed": r.removed,
                         "provider": "Groq", "model": ONLINE_MODEL, "answer": null, "secs": null});
    if !has_question(&r.text) {
        out["error"] = json!("nothing-left");
        return Ok(out);
    }
    if !send {
        out["ok"] = json!(true);
        return Ok(out);
    }
    let device = if device == "phone" { "phone" } else { "laptop" };
    let body = online_body(&r.text, device).to_string();
    let started = std::time::Instant::now();
    let reply = tauri::async_runtime::spawn_blocking(move || online_post(&app, body))
        .await
        .map_err(|e| e.to_string())?;
    let (answer, error) = online_reply(&reply);
    out["ok"] = json!(answer.is_some());
    out["answer"] = json!(answer);
    out["error"] = json!(error);
    out["secs"] = json!((started.elapsed().as_secs_f64() * 10.0).round() / 10.0);
    Ok(out)
}

const ONLINE_MODEL: &str = "openai/gpt-oss-120b";

static PLACEHOLDER: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\[(?:link|email|upi id|hidden|id|number|code|name)\]").unwrap());

/// Is there still a question once the [number] / [name] placeholders are gone?
fn has_question(stripped: &str) -> bool {
    PLACEHOLDER.replace_all(stripped, "").chars().filter(|c| c.is_alphabetic()).count() >= 6
}

/// The key: the laptop's GROQ_API_KEY (PowerShell also reads the user scope), else the one
/// build-android.sh baked in from that same variable (the phone has no environment).
fn online_key() -> String {
    std::env::var("GROQ_API_KEY").ok().filter(|k| !k.trim().is_empty())
        .or_else(|| option_env!("VV_GROQ_KEY").map(str::to_string))
        .unwrap_or_default()
}

fn online_body(question: &str, device: &str) -> Value {
    let vigil = if device == "phone" {
        "- \"Check my phone\": reads this phone's security settings and the apps that hold dangerous powers (accessibility, device admin, screen sharing, reading SMS).\n- \"Was I hacked before?\": looks for takeover signs and walks through your accounts.\n- Share a link, message or app file to Virus Vigil (Share -> Virus Vigil) to check it.\n- It cannot scan apps for viruses; Google Play Protect does that (Play Store -> profile picture -> Play Protect)."
    } else {
        "- \"Check my laptop\": checks that Windows security and browser settings are switched on. It does NOT scan files for viruses.\n- \"Was I hacked before?\": reads what Windows Defender has caught, and walks through your accounts.\n- \"Is this safe?\": paste a link or message into the box; a FILE is checked with the paper-clip button.\n- For a full virus scan: Windows Security -> Virus & threat protection -> Scan options -> Full scan."
    };
    let system = format!(
"You are Vigil, the calm helper inside the Virus Vigil app on a {device}. The person is an adult in India with no computer background. Talk to them as an equal.

How to answer:
- Plain words. If you must use a technical word, explain it in the same sentence.
- At most 120 words. Short numbered steps are better than paragraphs. No tables, no headings.
- Be direct and kind. No scare words, no jokes, no sign-off.
- Words in square brackets like [number], [name], [link], [code] were removed for privacy before the question reached you. Never ask for them.

What Vigil itself can do (mention one only when it truly helps; never invent others):
{vigil}

Safety rules you must never break:
- Never tell anyone to switch off antivirus, the firewall, Play Protect or any security setting, for any reason.
- Never ask for, or tell people to share, a password, OTP, PIN, CVV or screen-sharing access. Banks never ask for these.
- Only when money was lost or an account was taken over: call 1930 (India's cyber-crime helpline) at once, report at cybercrime.gov.in, and call the bank on the number printed on the card.
- If you are not sure, say so. Never make up facts, phone numbers, laws, websites or app features.
- Do not judge a link, message or file you cannot see - ask them to paste or share it into Vigil.");
    json!({
        "model": ONLINE_MODEL,
        "temperature": 0.3,
        "max_tokens": 1200,
        "reasoning_effort": "low",
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": question}],
    })
}

/// {status, body, error} from the transport.
fn online_post(app: &tauri::AppHandle, body: String) -> Value {
    let key = online_key();
    if cfg!(target_os = "android") {
        if key.is_empty() {
            return json!({"status": 0, "body": "", "error": "no-key"});
        }
        return phone::ask_online(app, &body, &key);
    }
    let _ = app;
    let run = || -> Result<Value, String> {
        let path = write_script("online.ps1", ONLINE_PS)?;
        let out = powershell().arg("-File").arg(&path).env("VV_BODY", &body).env("VV_KEY", &key).output()
            .map_err(|e| format!("could not start PowerShell: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).map_err(|e| format!("unreadable reply ({e})"))
    };
    run().unwrap_or_else(|e| json!({"status": 0, "body": "", "error": e}))
}

/// Turn the transport's {status, body, error} into (answer, error-in-words). Pure; tested.
fn online_reply(r: &Value) -> (Option<String>, Option<String>) {
    let status = r["status"].as_i64().unwrap_or(0);
    if let Some(e) = r["error"].as_str() {
        return (None, Some(if e == "no-key" { "no-key".into() } else { format!("no connection ({e})") }));
    }
    let body: Value = serde_json::from_str(r["body"].as_str().unwrap_or("")).unwrap_or(Value::Null);
    match status {
        200 => {
            let a = body["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();
            if a.is_empty() { (None, Some("the AI sent back an empty answer".into())) } else { (Some(a), None) }
        }
        429 => (None, Some("busy".into())),
        401 | 403 => (None, Some("no-key".into())),
        s => (None, Some(format!("the AI service answered with an error ({s})"))),
    }
}

/// Ask the local AI (Ollama on this laptop, vetted models only). An empty question only
/// reports whether a vetted model is available. Nothing leaves the laptop.
#[tauri::command]
async fn ask_local_ai(question: String) -> Result<Value, String> {
    let q: String = question.chars().take(2000).collect();
    tauri::async_runtime::spawn_blocking(move || {
        let path = write_script("ai.ps1", AI_PS)?;
        let out = powershell().arg("-File").arg(&path).env("VV_Q", &q).output()
            .map_err(|e| format!("could not start PowerShell: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).map_err(|e| format!("unreadable reply ({e})"))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// What starts by itself (Run keys, Startup folders, non-Microsoft scheduled tasks). Read-only.
#[tauri::command]
async fn startup_items() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_json_script("startup.ps1", STARTUP_PS))
        .await
        .map_err(|e| e.to_string())?
}

/// Which apps Windows has RECORDED using the camera and microphone (its own log; not every
/// program is logged, so an empty list never proves nobody listened). Read-only.
#[tauri::command]
async fn camera_use() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_json_script("camera.ps1", CAMERA_PS))
        .await
        .map_err(|e| e.to_string())?
}

/// Screen-sharing / remote-control programs running right now (the check before a big payment).
/// Read-only.
#[tauri::command]
async fn remote_tools() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| run_json_script("remote.ps1", REMOTE_PS))
        .await
        .map_err(|e| e.to_string())?
}

/// Apply browser protections. Windows shows its own Yes/No (UAC) prompt first;
/// if the person says No, nothing is changed and we say so. What each setting was before
/// is kept (undo.rs) so it can be put back.
#[tauri::command]
async fn apply_fixes(browsers: Vec<String>, block_passwords: bool, block_cards: Option<bool>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let allowed = ["chrome", "edge", "brave", "firefox"];
        let browsers: Vec<String> = browsers
            .into_iter()
            .filter(|b| allowed.contains(&b.as_str()))
            .collect();
        if browsers.is_empty() {
            return Ok(json!({"ok": true, "cancelled": false, "changes": [], "errors": [], "note": "nothing to change"}));
        }
        let mut v = run_fix_elevated(json!({"browsers": browsers, "blockPasswords": block_passwords, "blockCards": block_cards.unwrap_or(false)}))?;
        if v["cancelled"] != true {
            // Saved even when some settings failed: the ones that DID change must stay undoable.
            let record = undo::merge(undo::load(), &v);
            v["undoSaved"] = json!(undo::save(&record).is_ok());
        }
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Raise Defender attack-blocking (ASR) rules to Block. Only the four rules the card offers;
/// fix.ps1 refuses anything else too. Same Windows Yes/No, same undo record as the browsers.
#[tauri::command]
async fn apply_asr(ids: Vec<String>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let allowed = [
            "01443614-cd74-433a-b99e-2ecdc07bfc25",
            "56a863a9-875e-4185-98a7-b882c64b5ce5",
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
            "e6db77e5-3df2-4cf1-b95a-636979351e5b",
        ];
        let ids: Vec<String> = ids.into_iter().map(|i| i.to_lowercase()).filter(|i| allowed.contains(&i.as_str())).collect();
        if ids.is_empty() {
            return Ok(json!({"ok": true, "cancelled": false, "changes": [], "errors": [], "note": "nothing to change"}));
        }
        let mut v = run_fix_elevated(json!({"asr": ids}))?;
        if v["cancelled"] != true {
            let record = undo::merge(undo::load(), &v);
            v["undoSaved"] = json!(undo::save(&record).is_ok());
        }
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Windows settings fix.ps1 may change (plan.system). Anything else is dropped here and refused there.
const SYSTEM_FIXES: [&str; 14] =
    ["realtime", "sigs", "fw", "smartscreen", "uac", "guest", "smb1", "rdp", "assist", "ext", "pause", "cloud", "lsa", "drivers"];

/// The SID of the person running the app (NOT elevated), so per-user settings land in their own
/// registry hive even when the Yes box is answered with another account's admin password.
fn current_user_sid() -> Option<String> {
    let out = powershell().arg("-Command").arg("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value").output().ok()?;
    let sid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    sid.starts_with("S-1-5-21-").then_some(sid)
}

/// "Do it all for me" (7 Oct 2026): browsers, attack-blocking rules and Windows settings in ONE
/// Windows Yes/No. Same read-back and the same undo record as the single fixes.
#[tauri::command]
async fn apply_all(browsers: Vec<String>, block_passwords: bool, block_cards: bool, asr: Vec<String>, system: Vec<String>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let browsers: Vec<String> = browsers.into_iter().filter(|b| ["chrome", "edge", "brave", "firefox"].contains(&b.as_str())).collect();
        let asr: Vec<String> = asr.into_iter().map(|i| i.to_lowercase()).collect();
        let system: Vec<String> = system.into_iter().filter(|s| SYSTEM_FIXES.contains(&s.as_str())).collect();
        if browsers.is_empty() && asr.is_empty() && system.is_empty() {
            return Ok(json!({"ok": true, "cancelled": false, "changes": [], "errors": [], "note": "nothing to change"}));
        }
        let sid = current_user_sid().unwrap_or_default();
        let mut v = run_fix_elevated(json!({"browsers": browsers, "blockPasswords": block_passwords, "blockCards": block_cards,
            "asr": asr, "system": system, "userSid": sid}))?;
        if v["cancelled"] != true {
            let record = undo::merge(undo::load(), &v);
            v["undoSaved"] = json!(undo::save(&record).is_ok());
        }
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Is there anything the fixer changed that can be put back?
#[tauri::command]
fn undo_available() -> Value {
    undo::summary(&undo::load())
}

/// Put every setting the fixer changed back the way it was (same Windows Yes/No first).
/// The record is removed only when everything was restored and read back.
#[tauri::command]
async fn undo_fixes() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let record = undo::load().ok_or("there is nothing to undo")?;
        let v = run_fix_elevated(json!({"undo": record, "userSid": current_user_sid().unwrap_or_default()}))?;
        if v["cancelled"] != true && v["ok"] == true {
            undo::clear();
        }
        Ok(v)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Run fix.ps1 elevated with this plan; {cancelled: true} if the person pressed No.
fn run_fix_elevated(plan_json: Value) -> Result<Value, String> {
    run_elevated("fix.ps1", FIX_PS, plan_json)
}

/// Run a bundled script elevated (Windows' Yes/No box first) with -Plan/-Out; {cancelled: true} on No.
fn run_elevated(name: &str, content: &str, plan_json: Value) -> Result<Value, String> {
    {
        let dir = work_dir()?;
        let script = write_script(name, content)?;
        let stem = name.trim_end_matches(".ps1");
        let plan = dir.join(format!("{stem}-plan.json"));
        let out = dir.join(format!("{stem}-result.json"));
        let _ = std::fs::remove_file(&out); // a stale result must never read as this run's
        std::fs::write(&plan, plan_json.to_string()).map_err(|e| format!("cannot write plan: {e}"))?;

        let inner = format!(
            "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{}\" -Plan \"{}\" -Out \"{}\"",
            script.display(),
            plan.display(),
            out.display()
        );
        let launcher = format!(
            "try {{ Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '{}' -ErrorAction Stop; 'ran' }} catch {{ 'cancelled' }}",
            inner.replace('\'', "''")
        );
        let res = powershell()
            .arg("-Command")
            .arg(launcher)
            .output()
            .map_err(|e| format!("could not start PowerShell: {e}"))?;
        let said = String::from_utf8_lossy(&res.stdout).trim().to_string();
        if said.ends_with("cancelled") {
            return Ok(json!({"ok": false, "cancelled": true, "changes": [], "errors": []}));
        }
        let text = std::fs::read_to_string(&out)
            .map_err(|_| "the fix ran but left no result - nothing is confirmed".to_string())?;
        let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|e| format!("fix result unreadable: {e}"))?;
        Ok(v)
    }
}

fn find_mpcmdrun() -> Option<PathBuf> {
    // The newest platform copy first; the Program Files copy is older but always there.
    let platform = Path::new(r"C:\ProgramData\Microsoft\Windows Defender\Platform");
    if let Ok(rd) = std::fs::read_dir(platform) {
        let mut dirs: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        dirs.sort();
        for d in dirs.into_iter().rev() {
            let p = d.join("MpCmdRun.exe");
            if p.exists() {
                return Some(p);
            }
        }
    }
    let p = PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Windows refuses to open a file Defender's real-time protection has caught: error 225
/// (ERROR_VIRUS_INFECTED) or 226 (ERROR_VIRUS_DELETED). That refusal IS Defender's verdict
/// (seen on the EICAR test file, 24 Sep 2026), so it must not surface as "cannot open file".
fn defender_blocked(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(225) | Some(226))
}

fn blocked_by_defender(p: &Path, name: &str, ext: &str, size: u64) -> Value {
    json!({
        "name": name, "ext": ext, "size": size, "sha256": null,
        "apk": null, "qr": null,
        "defender": {"ran": true, "found": true, "blocked": true, "threat": null, "exitCode": null},
        "stillThere": p.exists(),
    })
}

/// Windows only: is the program signed, by whom, and is the signature intact? A broken
/// signature means the file was changed after its maker signed it. The path goes in through
/// an environment variable, never into the command text.
fn signature(p: &Path) -> Value {
    if !cfg!(windows) {
        return Value::Null;
    }
    let script = "$s = Get-AuthenticodeSignature -LiteralPath $env:VV_SIGFILE; \
        $n = if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { $null }; \
        [ordered]@{ status = [string]$s.Status; signer = $n; message = [string]$s.StatusMessage } | ConvertTo-Json -Compress";
    let out = powershell().env("VV_SIGFILE", p.as_os_str()).args(["-Command", script]).output();
    match out {
        Ok(o) => serde_json::from_slice::<Value>(String::from_utf8_lossy(&o.stdout).trim().as_bytes())
            .unwrap_or_else(|_| json!({"status": "Unread", "message": String::from_utf8_lossy(&o.stderr).trim().to_string()})),
        Err(e) => json!({"status": "Unread", "message": e.to_string()}),
    }
}

/// Reads MpCmdRun's answer. 0 = nothing found. 2 = a threat was found - BUT MpCmdRun also exits
/// 2 when the scan itself failed ("CmdTool: Failed with hr = 0x..."), and calling that a threat
/// would tell the person to delete a clean file. So a failed scan is "didn't run", never "found".
fn defender_verdict(code: i32, text: &str, threat: Option<String>) -> Value {
    let failed = text.lines().find_map(|l| l.split_once("Failed with hr =").map(|(_, hr)| hr.trim().to_string()));
    if let Some(hr) = failed {
        return json!({"ran": false, "exitCode": code, "found": false, "reason": format!("its scan failed, error {hr}"), "output": text.trim()});
    }
    json!({"ran": code == 0 || code == 2, "exitCode": code, "found": code == 2, "threat": threat, "output": text.trim()})
}

/// What an APK asks for and what special services it offers, read from its manifest.
/// The proper parser (axml.rs) is tried first. If the manifest is malformed - which
/// malware does on purpose to break scanners - we fall back to searching the raw bytes
/// and SAY so, because a failed parse must never read as "asks for nothing".
fn apk_permissions(path: &Path) -> Result<Value, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("cannot open file: {e}"))?;
    let mut zip = zip::ZipArchive::new(f).map_err(|_| "this does not open as an Android app (APK)".to_string())?;
    let mut entry = zip
        .by_name("AndroidManifest.xml")
        .map_err(|_| "no AndroidManifest.xml inside - not a normal Android app".to_string())?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).map_err(|e| format!("cannot read manifest: {e}"))?;

    if let Some(m) = axml::parse(&bytes) {
        // `permissions` keeps the page's old contract: android.* requests plus offered BIND_* services.
        let mut perms: Vec<String> = m.requested.iter().chain(m.offers.iter()).filter(|p| p.starts_with("android.permission.")).cloned().collect();
        perms.sort();
        perms.dedup();
        return Ok(json!({"read": true, "method": "parsed", "requested": m.requested, "offers": m.offers, "permissions": perms, "package": m.package}));
    }

    let utf16: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let as16 = String::from_utf16_lossy(&utf16);
    let as8 = String::from_utf8_lossy(&bytes);
    let re = regex::Regex::new(r"android\.permission\.[A-Z0-9_]+").unwrap();
    let mut found: Vec<String> = Vec::new();
    for hay in [as16.as_ref(), as8.as_ref()] {
        for m in re.find_iter(hay) {
            let s = m.as_str().to_string();
            if !found.contains(&s) {
                found.push(s);
            }
        }
    }
    found.sort();
    Ok(json!({"read": true, "method": "fallback", "requested": [], "offers": [], "permissions": found}))
}

/// Every installed app's APK file(s) against the known-malware list (phone; the page sends the
/// paths the phone's own app list gave). Fingerprints are remembered, so only new apps are read.
/// One check at a time: a second call while one runs answers `busy` (the page waits, then asks again).
#[tauri::command]
async fn check_installed(app: tauri::AppHandle, apps: Vec<apkcheck::App>) -> Result<Value, String> {
    let Some(turn) = folderscan::APPS_TURN.take() else {
        return Ok(json!({"checked": false, "busy": true, "apps": apps.len(), "files": 0, "found": [], "unread": []}));
    };
    tauri::async_runtime::spawn_blocking(move || {
        // Held by the thread doing the work, so the turn ends when the work does.
        let _turn = turn;
        if cfg!(target_os = "android") {
            let _ = phone::lists_dir(&app);
        }
        match hashlist::active_dir() {
            // 29 Sep: every app file is also read by the pattern rules and the deep look (premium
            // antivirus apps scan installed apps' code). No rules here = fingerprints only, said.
            Some(d) => {
                let mut v = match yara::tag() {
                    Some(tag) => {
                        let crumbs = cfg!(target_os = "android").then(|| d.join("apps-reading.txt"));
                        apkcheck::check_reading(&d, &apps, &apkcheck::Reader { read: &yara::scan, tag, crumbs })
                    }
                    None => {
                        let mut v = apkcheck::check_in(&d, &apps);
                        v["patterns"] = json!({"ran": false, "reason": "the malware rules are not ready on this device"});
                        v
                    }
                };
                // Apps he installed that no list knew: their fingerprints asked online (his 29 Sep tap).
                let a = hashonline::ask(&d, &hashonline::apps_candidates(&v), hashonline::now_secs(), |h| online_fetch(&app, h));
                hashonline::apply_to_apps(&mut v, &a);
                Ok(v)
            }
            None => Ok(json!({"checked": false, "apps": apps.len(), "files": 0, "found": [], "unread": [], "error": "the phone gave no folder for the list"})),
        }
    })
        .await
        .map_err(|e| e.to_string())?
}

/// Laptop: every file in Downloads, Desktop and Temp against the known-malware list and the YARA
/// rules (folderscan.rs). Only one sweep at a time; a second call while one runs says so.
/// Phone (29 Sep 2026, his report "two seconds to scan my entire phone"): the same sweep over the
/// phone's shared storage - Download, WhatsApp/Telegram files, Bluetooth, Documents, the SD card.
/// Needs Android's "All files access" (Android 11+); without it Android shows an app only its own
/// files and pictures, so the answer is `needsAccess`, never "0 files, clean".
#[tauri::command]
async fn check_folders(app: tauri::AppHandle) -> Result<Value, String> {
    let mut phone_roots: Option<Vec<(String, std::path::PathBuf)>> = None;
    if cfg!(target_os = "android") {
        let st = tauri_plugin_vigil_phone::call(&app, "storage", json!({}))?;
        if st["allowed"] != true {
            return Ok(json!({"checked": false, "needsAccess": true, "files": 0, "found": [], "sdk": st["sdk"].clone()}));
        }
        let roots: Vec<(String, std::path::PathBuf)> = st["volumes"].as_array().map(|a| a.iter().filter_map(|v| {
            Some((v["name"].as_str().unwrap_or("Phone storage").to_string(), std::path::PathBuf::from(v["path"].as_str()?)))
        }).filter(|(_, p)| p.is_dir()).collect()).unwrap_or_default();
        if roots.is_empty() {
            return Ok(json!({"checked": false, "files": 0, "found": [], "error": "Android showed no storage to read"}));
        }
        phone_roots = Some(roots);
    }
    let Some(turn) = folderscan::FOLDERS_TURN.take() else {
        return Ok(json!({"checked": false, "busy": true, "files": 0, "found": []}));
    };
    tauri::async_runtime::spawn_blocking(move || {
        let _turn = turn;
        let dir = if let Some(roots) = phone_roots {
            let dir = phone::lists_dir(&app)?;
            let skip: Vec<std::path::PathBuf> = roots.iter().flat_map(|(_, p)| [p.join("Android").join("data"), p.join("Android").join("obb")]).collect();
            let book = hashlist::open_book(&dir);
            let lookup = |sha: &str| match &book {
                Ok(b) => b.lookup(sha),
                Err(v) => v.clone(),
            };
            let tag = yara::tag();
            // Four threads: a phone throttles when hot, and the person is still using it.
            let opts = folderscan::Opts { threads: 4, skip, progress: Some(&folderscan::PROGRESS), crumbs: Some(dir.join("sweep-reading.txt")), ..Default::default() };
            let mut v = folderscan::sweep_with(&roots, &dir.join(folderscan::PHONE_CACHE), lookup, yara::scan, tag, &opts);
            let a = hashonline::ask(&dir, &hashonline::sweep_candidates(&v), hashonline::now_secs(), |h| online_fetch(&app, h));
            hashonline::apply_to_sweep(&mut v, &a);
            v["phone"] = json!(true);
            return Ok(v);
        } else {
            hashlist::lists_dir()
        };
        let _ = std::fs::create_dir_all(&dir);
        let book = hashlist::open_book(&dir);
        let lookup = |sha: &str| match &book {
            Ok(b) => b.lookup(sha),
            Err(v) => v.clone(),
        };
        let tag = yara::tag();
        let opts = folderscan::Opts { progress: Some(&folderscan::PROGRESS), ..Default::default() };
        let mut v = folderscan::sweep_with(&folderscan::default_roots(), &dir.join(folderscan::CACHE), lookup, yara::scan, tag, &opts);
        let a = hashonline::ask(&dir, &hashonline::sweep_candidates(&v), hashonline::now_secs(), |h| online_fetch(&app, h));
        hashonline::apply_to_sweep(&mut v, &a);
        Ok(v)
    })
        .await
        .map_err(|e| e.to_string())
        .and_then(|x| x)
}

/// Live counts of the running sweep and app check, for the page to show while they work.
#[tauri::command]
fn sweep_progress() -> Value {
    json!({"files": folderscan::PROGRESS.snapshot(), "apps": folderscan::APPS_PROGRESS.snapshot()})
}

/// "Read every file again from scratch": forget the remembered fingerprints, so the next sweep and
/// app check read every byte again instead of trusting (path, size, time). Returns what was removed.
/// Everything "Read everything again from scratch" forgets. 29 Sep 2026: the installed apps' code
/// memory was missing, so a fresh start re-read every app's fingerprint but none of their code.
pub const FORGET: [&str; 4] = [folderscan::CACHE, folderscan::PHONE_CACHE, apkcheck::CACHE, apkcheck::PATTERN_CACHE];

#[tauri::command]
fn forget_fingerprints(app: tauri::AppHandle) -> Value {
    let dir = if cfg!(target_os = "android") { phone::lists_dir(&app).ok() } else { Some(hashlist::lists_dir()) };
    let mut removed = Vec::new();
    if let Some(d) = dir {
        for name in FORGET {
            if std::fs::remove_file(d.join(name)).is_ok() {
                removed.push(name);
            }
        }
    }
    json!({"removed": removed})
}

#[tauri::command]
async fn check_file(app: tauri::AppHandle, path: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // The phone's known-malware list lives in the app's own folder; tell hashlist.rs where.
        if cfg!(target_os = "android") {
            let _ = phone::lists_dir(&app);
        }
        let mut v = check_file_blocking(&path)?;
        // Its fingerprint asked online too, unless a list already named it (his 29 Sep tap).
        if v["known"]["found"] != true {
            if let Some(sha) = v["sha256"].as_str().map(String::from) {
                let dir = hashlist::active_dir().unwrap_or_else(hashlist::lists_dir);
                let _ = std::fs::create_dir_all(&dir);
                let a = hashonline::ask(&dir, &[sha.clone()], hashonline::now_secs(), |h| online_fetch(&app, h));
                v["online"] = hashonline::single(&a, &sha);
            }
        }
        Ok(v)
    })
        .await
        .map_err(|e| e.to_string())?
}

fn check_file_blocking(path: &str) -> Result<Value, String> {
    {
        let p = PathBuf::from(path);
        let meta = std::fs::metadata(&p).map_err(|e| format!("cannot read that file: {e}"))?;
        if !meta.is_file() {
            return Err("that is a folder, not a file".into());
        }
        let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let ext = p
            .extension()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Fingerprint, computed here; it only leaves the computer if the person
        // presses the VirusTotal button, and then only the fingerprint goes.
        // Each step's own time, shown on the page with what it checked (never a fake delay).
        let clock = std::time::Instant::now();
        let lap = |t: &mut std::time::Instant| { let ms = t.elapsed().as_millis() as u64; *t = std::time::Instant::now(); ms };
        let mut t = std::time::Instant::now();
        let mut hasher = Sha256::new();
        let mut f = match std::fs::File::open(&p) {
            Ok(f) => f,
            Err(e) if defender_blocked(&e) => return Ok(blocked_by_defender(&p, &name, &ext, meta.len())),
            Err(e) => return Err(format!("cannot open file: {e}")),
        };
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).map_err(|e| format!("cannot read file: {e}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256 = format!("{:x}", hasher.finalize());
        drop(f);
        let hash_ms = lap(&mut t);
        // Its fingerprint against MalwareBazaar's known malware samples (local list, nothing sent).
        let known = hashlist::lookup(&sha256);
        let known_ms = lap(&mut t);

        let apk = if ext == "apk" || ext == "xapk" || ext == "apks" {
            match apk_permissions(&p) {
                Ok(v) => v,
                Err(e) => json!({"read": false, "error": e}),
            }
        } else {
            Value::Null
        };
        let apk_ms = lap(&mut t);

        // A picture may hold a QR code (read before Defender, which may remove the file).
        let qr = if qr::IMAGE_EXTS.contains(&ext.as_str()) { qr::read(&p) } else { Value::Null };
        let qr_ms = lap(&mut t);
        // Vigil's own look inside (real type, name tricks, macros, scripts...), where it came
        // from, and who signed it - all before Defender, which may remove the file.
        let look = sniff::sniff(&p, &name, &ext);
        let look_ms = lap(&mut t);
        let origin = sniff::downloaded_from(&p);
        let signer = if sniff::SIGNABLE.contains(&ext.as_str()) || look["kind"] == "program" { signature(&p) } else { Value::Null };
        let sign_ms = lap(&mut t);
        // Layer 2: YARA-X with 1,300+ public malware patterns (laptop and phone), before Defender.
        let yara = yara::scan(&p);
        let yara_ms = lap(&mut t);

        // Windows Defender scans the file. If it is bad, Defender also removes it.
        let defender = match if cfg!(target_os = "android") { None } else { find_mpcmdrun() } {
            None if cfg!(target_os = "android") => json!({"ran": false, "reason": "phone"}),
            None => json!({"ran": false, "reason": "Windows Defender's scanner was not found"}),
            Some(exe) => {
                let mut c = Command::new(exe);
                // MpCmdRun fails (hr 0x80508023, exit 2) on some paths written with forward
                // slashes, and exit 2 is also its "threat found" code - so always pass backslashes.
                let win_path = p.to_string_lossy().replace('/', "\\");
                c.args(["-Scan", "-ScanType", "3", "-File"]).arg(&win_path);
                #[cfg(windows)]
                c.creation_flags(CREATE_NO_WINDOW);
                match c.output() {
                    Err(e) => json!({"ran": false, "reason": e.to_string()}),
                    Ok(o) => {
                        let code = o.status.code().unwrap_or(-1);
                        let text = String::from_utf8_lossy(&o.stdout).to_string();
                        let threat = text
                            .lines()
                            .find_map(|l| l.trim().strip_prefix("Threat").map(|r| r.trim_start_matches(|c: char| c == ' ' || c == ':').trim().to_string()));
                        json!(defender_verdict(code, &text, threat))
                    }
                }
            }
        };

        let defender_ms = lap(&mut t);
        Ok(json!({
            "ms": {"hash": hash_ms, "known": known_ms, "apk": apk_ms, "qr": qr_ms, "look": look_ms, "sign": sign_ms, "yara": yara_ms, "defender": defender_ms, "total": clock.elapsed().as_millis() as u64},
            "name": name, "ext": ext, "size": meta.len(), "sha256": sha256,
            "apk": apk, "qr": qr, "defender": defender,
            "look": look, "origin": origin, "signer": signer, "yara": yara, "known": known,
            "stillThere": p.exists()
        }))
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_undo;
#[cfg(test)]
mod tests_sniff;
#[cfg(all(test, not(target_os = "android")))]
mod tests_yara;
#[cfg(test)]
mod tests_hashlist;
#[cfg(test)]
mod tests_apkcheck;
#[cfg(test)]
mod tests_folderscan;
#[cfg(test)]
mod tests_deeplook;
#[cfg(test)]
mod tests_apksig;
#[cfg(test)]
mod tests_hashonline;
#[cfg(test)]
mod testdir;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Laptop: compile the patterns at once. Phone: after its folder is known (update_hash_list).
    if !cfg!(target_os = "android") {
        yara::warm();
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_vigil_phone::init())
        .invoke_handler(tauri::generate_handler![platform, phone, scan_system, scan_record, scan_alive, threat_history, defender_quick_scan, startup_items, camera_use, remote_tools, extension_audit, update_phish_list, update_hash_list, phish_lookup, pwned_range, ask_local_ai, ask_online_ai, apply_fixes, apply_asr, apply_all, deep_check, defender_full_scan, defender_offline_scan, undo_available, undo_fixes, check_file, check_installed, check_folders, sweep_progress, forget_fingerprints])
        .run(tauri::generate_context!())
        .expect("error while running Virus Vigil");
}
