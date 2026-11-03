//! Phone-only glue. The page's `phone` command reaches the Kotlin side (plugins/vigil-phone)
//! only for the commands listed in ALLOWED; the phishing list and the password range are
//! fetched by Kotlin (Android's own TLS) and checked here, exactly as the laptop's
//! PowerShell scripts check them.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};
use tauri::{AppHandle, Runtime};

/// What the page may ask the phone side for. Network and file-writing commands are NOT here:
/// only Rust calls those, with arguments Rust built.
pub const ALLOWED: &[&str] = &["scan", "openSettings", "copyToCache", "takeShare"];

pub fn page_call<R: Runtime>(app: &AppHandle<R>, cmd: &str, args: Value) -> Result<Value, String> {
    if !ALLOWED.contains(&cmd) {
        return Err(format!("not a phone command: {cmd}"));
    }
    tauri_plugin_vigil_phone::call(app, cmd, args)
}

static FILES: OnceLock<PathBuf> = OnceLock::new();

/// The app's private files folder on the phone (Context.filesDir).
fn files_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    if let Some(p) = FILES.get() {
        return Ok(p.clone());
    }
    let v = tauri_plugin_vigil_phone::call(app, "dataDir", json!({}))?;
    let p = PathBuf::from(v["path"].as_str().ok_or("the phone gave no data folder")?);
    Ok(FILES.get_or_init(|| p).clone())
}

fn fresh_for(p: &Path, hours: u64) -> bool {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .is_some_and(|age| age < Duration::from_secs(hours * 3600))
}

/// Same answer shape as ps/phish-update.ps1: the first list's fields at the top, CERT Polska's
/// under "certpl". A bad download never replaces a list.
pub fn update_phish<R: Runtime>(app: &AppHandle<R>) -> Value {
    let mut v = update_one_phish(app, "pdb", crate::phish::SOURCES[0].1, 100_000, 24);
    v["certpl"] = update_one_phish(app, "certpl", crate::phish::SOURCES[1].1, 10_000, 6);
    v
}

/// One list: `source` names it to Kotlin (which holds the address), `file` in the lists folder.
/// CERT Polska changes its list every few minutes, so it is refreshed every 6 hours, not daily.
fn update_one_phish<R: Runtime>(app: &AppHandle<R>, source: &str, file: &str, min_lines: usize, hours: u64) -> Value {
    let dest = match lists_dir(app) {
        Ok(d) => d.join(file),
        Err(e) => return json!({"ok": true, "updated": false, "skipped": false, "error": e, "lines": null}),
    };
    if fresh_for(&dest, hours) {
        return json!({"ok": true, "updated": false, "skipped": true, "error": null, "lines": null});
    }
    let tmp = dest.with_extension("txt.download");
    let mut error = String::new();
    for attempt in 1..=3u64 {
        let _ = std::fs::remove_file(&tmp);
        let got = tauri_plugin_vigil_phone::call(app, "downloadPhishList", json!({"dest": tmp.to_string_lossy(), "source": source}))
            .and_then(|v| crate::phish::accept_download(&tmp, &dest, min_lines).map(|n| (n, v)));
        match got {
            Ok((n, v)) => {
                crate::phish::write_since(&dest, v["upstream"].as_str());
                return json!({"ok": true, "updated": true, "skipped": false, "error": null, "lines": n});
            }
            Err(e) => error = e,
        }
        std::thread::sleep(Duration::from_secs(3 * attempt));
    }
    let _ = std::fs::remove_file(&tmp);
    json!({"ok": true, "updated": false, "skipped": false, "error": error, "lines": null})
}

/// The folder the phone keeps its downloaded lists in; also tells hashlist.rs where to look.
pub fn lists_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let d = files_dir(app)?.join("lists");
    crate::hashlist::set_phone_dir(d.clone());
    crate::yara::set_guard_dir(d.clone());
    Ok(d)
}

fn age_under(p: &Path, hours: u64) -> bool {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .is_some_and(|age| age < Duration::from_secs(hours * 3600))
}

/// One of MalwareBazaar's two lists, fetched by Kotlin, checked by hashlist::accept_download.
/// Same answer shape as each half of ps/hashlist-update.ps1, plus `metered` when the full list
/// was left for Wi-Fi (43 MB is too much to take from someone's mobile data unasked).
fn update_one<R: Runtime>(app: &AppHandle<R>, dir: &Path, name: &str, full: bool, max_hours: u64, min: usize) -> Value {
    let dest = dir.join(name);
    if age_under(&dest, max_hours) {
        return json!({"updated": false, "skipped": true, "lines": null, "error": null});
    }
    let tmp = dir.join(format!("{name}.download"));
    let mut error = String::new();
    for attempt in 1..=3u64 {
        let _ = std::fs::remove_file(&tmp);
        let got = tauri_plugin_vigil_phone::call(app, "downloadHashList", json!({"dest": tmp.to_string_lossy(), "full": full, "key": crate::hashlist::mb_key()}));
        match got {
            Ok(v) if v["metered"] == true => {
                let _ = std::fs::remove_file(&tmp);
                return json!({"updated": false, "skipped": true, "metered": true, "lines": null, "error": null});
            }
            Ok(_) => match crate::hashlist::accept_download(&tmp, &dest, min) {
                Ok(n) => return json!({"updated": true, "skipped": false, "lines": n, "error": null}),
                Err(e) => error = e,
            },
            Err(e) => error = e,
        }
        std::thread::sleep(Duration::from_secs(3 * attempt));
    }
    let _ = std::fs::remove_file(&tmp);
    json!({"updated": false, "skipped": false, "lines": null, "error": error})
}

/// The phone's ps/hashlist-update.ps1: full list weekly, or sooner when the recent list no longer
/// reaches back to it (hashlist::full_due), and only off mobile data; the
/// last-48-hours list at most daily. Then builds the sorted file, so the first check is quick.
pub fn update_hash<R: Runtime>(app: &AppHandle<R>) -> Value {
    let dir = match lists_dir(app) {
        Ok(d) => d,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let _ = std::fs::create_dir_all(&dir);
    // The recent list first: whether the full one is due depends on how far back it now reaches.
    let recent = update_one(app, &dir, crate::hashlist::RECENT, false, 20, 50);
    use crate::hashlist::{age_hours, full_due};
    let due = full_due(age_hours(&dir.join(crate::hashlist::FULL)), age_hours(&dir.join(crate::hashlist::RECENT)));
    let full = update_one(app, &dir, crate::hashlist::FULL, true, if due { 0 } else { 24 * 7 }, 1_000_000);
    json!({"ok": true, "full": full, "recent": recent, "ready": crate::hashlist::lookup_in(&dir, &"0".repeat(64))})
}

/// Same answer shape as ps/pwned.ps1. The prefix was already checked by the caller.
pub fn pwned<R: Runtime>(app: &AppHandle<R>, prefix: &str) -> Value {
    tauri_plugin_vigil_phone::call(app, "pwned", json!({"prefix": prefix}))
        .unwrap_or_else(|e| json!({"ok": false, "error": e, "body": null}))
}

/// The online AI's request, posted by Kotlin to its one fixed address. Rust built `body` from a
/// question it had already stripped of personal details (redact.rs).
pub fn ask_online<R: Runtime>(app: &AppHandle<R>, body: &str, key: &str) -> Value {
    tauri_plugin_vigil_phone::call(app, "askOnline", json!({"body": body, "key": key}))
        .unwrap_or_else(|e| json!({"status": 0, "body": "", "error": e}))
}
