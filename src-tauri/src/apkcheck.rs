//! Every installed app's own APK file against MalwareBazaar's known malware samples (25 Sep 2026,
//! his tap "build virus detection and hardening quality more"). Before this the phone only looked
//! up a file the person picked; the apps actually installed were never fingerprinted.
//!
//! A side-loaded APK installs as the same bytes it was downloaded as, so its SHA-256 is the one
//! MalwareBazaar published. A Play Store app installed as splits has a base.apk no sample list
//! will hold - a miss there says nothing either way, and the page words it that way.
//!
//! Fingerprints are remembered by (path, size, modified time), so only new or updated apps are
//! read again. Nothing leaves the device.

use crate::hashlist;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

pub const CACHE: &str = "apk-fingerprints.tsv";
/// What the pattern rules and the deep look found in each app file: `key \t rules-tag \t set/rule,...`.
pub const PATTERN_CACHE: &str = "apk-patterns.tsv";

#[derive(serde::Deserialize, Clone)]
pub struct App {
    pub pkg: String,
    pub paths: Vec<String>,
    /// Came with the phone (29 Sep: fingerprinted and pattern-read too; cheap phones have shipped
    /// with malware built in). Only marks the find; nothing here judges permissions.
    #[serde(default)]
    pub maker: bool,
}

/// Reading every installed app's code with the pattern rules (29 Sep 2026, his "equal to premium
/// antivirus or better": premium apps scan installed apps' code; Vigil only fingerprinted them).
pub struct Reader<'a> {
    /// yara::scan (the pattern rules + deeplook: files hidden inside, the test file, file shapes).
    pub read: &'a dyn Fn(&Path) -> Value,
    /// The rules' identity: a remembered result counts only while the rules are the same.
    pub tag: String,
    /// Crash notes as in folderscan (0.1.26's crash loop): the file being read is written here
    /// first; a note left at the next start = died there, and that file is never read again.
    pub crumbs: Option<std::path::PathBuf>,
}

/// Vigil's own app rules judge what an app ASKS for. For an installed app the page already does
/// that from the phone's own records (permissions, enabled screen helpers, the spy list), so here
/// they would say the same thing twice, in different words. Everything else is kept.
/// Other sets' rules made ONLY of permission names are the same judgement (29 Sep 2026: YARAhub's
/// admin + accessibility rule called Android's own permission manager "worth a look" on the
/// emulator). A test keeps this list equal to every such rule in yara/ (tests_apkcheck.rs).
pub const PERMISSION_ONLY: &[(&str, &str)] = &[("YARAhub", "Android_Admin_And_Accessibility")];

pub fn keep_rule(set: &str, rule: &str) -> bool {
    !(set == "Vigil" && rule.starts_with("App")) && !PERMISSION_ONLY.contains(&(set, rule))
}

fn load_patterns(f: &Path) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    if let Ok(s) = std::fs::read_to_string(f) {
        for line in s.lines() {
            // path \t size \t mtime \t tag \t rules
            let mut it = line.rsplitn(3, '\t');
            if let (Some(rules), Some(tag), Some(k)) = (it.next(), it.next(), it.next()) {
                if !tag.is_empty() && k.matches('\t').count() == 2 {
                    out.insert(k.to_string(), (tag.to_string(), rules.to_string()));
                }
            }
        }
    }
    out
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

/// The cache key: a file whose size or modified time changed is read again.
fn key(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
    Some(format!("{}\t{}\t{}", p.to_string_lossy(), m.len(), t))
}

fn load_cache(f: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Ok(s) = std::fs::read_to_string(f) {
        for line in s.lines() {
            // path \t size \t mtime \t sha256
            if let Some((k, sha)) = line.rsplit_once('\t') {
                if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    out.insert(k.to_string(), sha.to_string());
                }
            }
        }
    }
    out
}

/// {checked, apps, files, unread:[pkg], found:[{pkg, path, sha256}], count, full, recent, fresh, ms, error}.
/// `checked: false` = NOT LOOKED UP (no list yet) - never "none found".
pub fn check_in(list_dir: &Path, apps: &[App]) -> Value {
    check_with(list_dir, apps, |sha| hashlist::lookup_in(list_dir, sha))
}

/// `check_in` with the look-up handed in, so a test can make the list fail part-way through.
pub(crate) fn check_with(list_dir: &Path, apps: &[App], lookup: impl Fn(&str) -> Value) -> Value {
    check_full(list_dir, apps, lookup, None)
}

/// `check_in`, and every app file also read by the pattern rules and the deep look. Adds
/// `patterns: {ran, read, remembered, failed, reason, recovered, crashSkipped}` and
/// `ruleHits: [{pkg, path, maker, rules:[{set, rule, weak}], why, weak}]`.
pub fn check_reading(list_dir: &Path, apps: &[App], reader: &Reader) -> Value {
    check_full(list_dir, apps, |sha| hashlist::lookup_in(list_dir, sha), Some(reader))
}

pub(crate) fn check_full(list_dir: &Path, apps: &[App], lookup: impl Fn(&str) -> Value, reader: Option<&Reader>) -> Value {
    let t0 = std::time::Instant::now();
    // No list to look in: say "not looked up" before reading a single APK - the first run reads
    // every app on the phone, and that work is wasted with nothing to compare it against.
    let probe = lookup(&"0".repeat(64));
    if probe["checked"] != true {
        return json!({"checked": false, "apps": apps.len(), "files": 0, "found": [], "unread": [],
                      "error": probe["error"].clone(), "ms": t0.elapsed().as_millis() as u64});
    }
    let cache_file = list_dir.join(CACHE);
    let old = load_cache(&cache_file);
    let prog = &*crate::folderscan::APPS_PROGRESS;
    prog.start(3);
    prog.total.store(apps.len(), std::sync::atomic::Ordering::Relaxed);
    let mut new: Vec<String> = Vec::new();
    let (mut files, mut fresh) = (0u64, 0u64);
    let mut unread: Vec<String> = Vec::new();
    let mut found: Vec<Value> = Vec::new();
    // Apps he installed that no list knew: worth asking the online checker about (hashonline.rs).
    let mut unknown_apps: Vec<Value> = Vec::new();
    // The pattern read (only with a reader).
    let pat_file = list_dir.join(PATTERN_CACHE);
    let pat_old = if reader.is_some() { load_patterns(&pat_file) } else { HashMap::new() };
    let mut pat_new: Vec<String> = Vec::new();
    let (mut p_read, mut p_mem, mut p_failed) = (0u64, 0u64, 0u64);
    let mut p_reason: Option<String> = None;
    let mut rule_hits: Vec<Value> = Vec::new();
    let crumbs = reader.and_then(|r| r.crumbs.clone());
    let (died, crash_skip) = crumbs.as_deref().map_or((false, Default::default()), crate::folderscan::recover_crumbs);
    let mut crash_skipped: Vec<String> = Vec::new();
    for (ai, a) in apps.iter().enumerate() {
        prog.done.store(ai + 1, std::sync::atomic::Ordering::Relaxed);
        *prog.current.lock().unwrap() = a.pkg.clone();
        let mut app_unread = false;
        for ps in &a.paths {
            let p = Path::new(ps);
            let k = key(p);
            let sha = match k.as_ref().and_then(|k| old.get(k)) {
                Some(s) => s.clone(),
                None => match sha256_file(p) {
                    Ok(s) => {
                        fresh += 1;
                        prog.fresh.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        prog.bytes.fetch_add(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
                        s
                    }
                    Err(_) => {
                        app_unread = true;
                        continue;
                    }
                },
            };
            if let Some(k) = &k {
                new.push(format!("{k}\t{sha}"));
            }
            files += 1;
            let v = lookup(&sha);
            if v["checked"] != true {
                // The list went away mid-run (an update replacing it): "not looked up", said as such.
                prog.finish();
                return json!({"checked": false, "apps": apps.len(), "files": files, "found": [], "unread": [],
                              "error": v["error"].clone(), "ms": t0.elapsed().as_millis() as u64});
            }
            if v["found"] == true {
                found.push(json!({"pkg": a.pkg, "path": ps, "sha256": sha, "stalkerware": v["stalkerware"].clone()}));
            } else if !a.maker && unknown_apps.len() < crate::hashonline::MAX_ASK {
                unknown_apps.push(json!({"pkg": a.pkg, "path": ps, "sha256": sha}));
            }
            let Some(r) = reader else { continue };
            let rules = match k.as_ref().and_then(|k| pat_old.get(k)).filter(|(t, _)| *t == r.tag) {
                Some((_, rl)) => {
                    p_mem += 1;
                    Some(rl.clone())
                }
                None if crash_skip.contains(ps) => {
                    // Virus Vigil died reading this app file before: fingerprinted, never pattern-read again.
                    p_failed += 1;
                    crash_skipped.push(ps.clone());
                    None
                }
                None => {
                    if let Some(c) = &crumbs {
                        let _ = std::fs::write(c, ps);
                    }
                    // A panic inside the pattern reader costs this one app file, never the app.
                    let v = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (r.read)(p)))
                        .unwrap_or_else(|_| json!({"ran": false, "reason": "the pattern check broke on this file"}));
                    if let Some(c) = &crumbs {
                        let _ = std::fs::remove_file(c);
                    }
                    if v["ran"] == true {
                        p_read += 1;
                        let mut rl: Vec<String> = v["matches"].as_array().into_iter().flatten()
                            .map(|m| (m["set"].as_str().unwrap_or(""), m["rule"].as_str().unwrap_or("")))
                            // Remembered UNFILTERED: keep_rule runs at report time below, so a change
                            // to it reaches remembered results too (the memory is keyed by the rules only).
                            .map(|(s, r)| format!("{s}/{r}")).collect();
                        // A file inside the app on the known-malware list (a payload tucked in its assets).
                        if v["memberShas"].as_array().map_or(false, |a| a.iter().any(|s| lookup(s.as_str().unwrap_or(""))["found"] == true)) {
                            rl.push("Vigil/ListedInside".into());
                        }
                        Some(rl.join(","))
                    } else {
                        p_failed += 1;
                        if p_reason.is_none() {
                            p_reason = v["reason"].as_str().map(String::from);
                        }
                        None
                    }
                }
            };
            let Some(rl) = rules else { continue };
            if let Some(k) = &k {
                pat_new.push(format!("{k}\t{}\t{rl}", r.tag));
            }
            let list: Vec<Value> = rl.split(',').filter(|s| !s.is_empty()).map(|s| {
                let (set, rule) = s.split_once('/').unwrap_or(("", s));
                (set, rule)
            }).filter(|(set, rule)| keep_rule(set, rule)).map(|(set, rule)| {
                json!({"set": set, "rule": rule, "weak": crate::yara::weak_rule(set, rule)})
            }).collect();
            if !list.is_empty() {
                let why: Vec<String> = list.iter().filter(|x| x["set"] == "Vigil")
                    .map(|x| crate::deeplook::words(x["rule"].as_str().unwrap_or(""))).collect();
                let weak = list.iter().all(|x| x["weak"] == true);
                rule_hits.push(json!({"pkg": a.pkg, "path": ps, "maker": a.maker, "rules": list, "why": why, "weak": weak}));
            }
        }
        if app_unread {
            unread.push(a.pkg.clone());
        }
    }
    prog.finish();
    // Remember only what is installed now (an uninstalled app's line is dropped).
    let _ = std::fs::write(&cache_file, new.join("\n"));
    if reader.is_some() {
        let _ = std::fs::write(&pat_file, pat_new.join("\n"));
    }
    // The list's size and age come from the probe taken before the run (the same list).
    let l = probe;
    let mut out = json!({"checked": true, "apps": apps.len(), "files": files, "unread": unread, "found": found,
           "count": l["count"], "full": l["full"], "recent": l["recent"], "ageHours": l["ageHours"],
           "fresh": fresh, "ms": t0.elapsed().as_millis() as u64, "error": null, "unknownApps": unknown_apps});
    if let Some(r) = reader {
        out["patterns"] = json!({"ran": true, "tag": r.tag, "read": p_read, "remembered": p_mem, "failed": p_failed,
                                 "reason": p_reason, "recovered": died, "crashSkipped": crash_skipped});
        out["ruleHits"] = json!(rule_hits);
    }
    out
}
