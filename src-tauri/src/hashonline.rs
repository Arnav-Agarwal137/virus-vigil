//! Online fingerprint look-up (his tap, 29 Sep 2026 20:11: "Yes, fingerprints only").
//! A file's SHA-256 fingerprint - 64 hex characters, never the file, its name or its path - is
//! asked of CIRCL hashlookup, a free public service with no key. It narrows the "brand-new file"
//! gap a little: CIRCL knows billions of files, and names the ones a malware collection reported.
//! It does NOT close that gap - a truly new file is unknown to CIRCL too.
//!
//! Rust opens no connection itself: Kotlin (phone) or PowerShell (laptop) does the asking and
//! hands back the raw replies; everything is judged here.
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

/// Where the helpers ask (Kotlin and PowerShell each hold it; a test checks they agree).
#[cfg(test)]
pub const ADDRESS: &str = "https://hashlookup.circl.lu/lookup/sha256/";
/// Answers remembered here, so a second sweep asks nothing it asked in the last three days.
pub const CACHE: &str = "online-answers.tsv";
/// At most this many fingerprints leave per run (about 40 s at 8 at a time, ~1 s each).
pub const MAX_ASK: usize = 300;
const KEEP_SECS: u64 = 3 * 24 * 3600;

#[derive(Clone, Debug, PartialEq)]
pub enum Said {
    /// A malware collection reported it; the String names which one (e.g. "malshare.com").
    Bad(String),
    /// CIRCL knows the file and no malware collection is named.
    Known,
    /// CIRCL has never seen it.
    Unknown,
}

/// One raw reply per fingerprint: (sha256, HTTP status, body). Status 0 = no answer at all, and
/// the body then carries the reason.
pub type Reply = (String, u16, String);

/// Only a well-formed fingerprint may leave: exactly 64 lowercase hex characters.
pub fn sendable(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What one CIRCL reply means. Err = it did not answer the question (never read as "clean").
pub fn read_answer(status: u16, body: &str) -> Result<Said, String> {
    match status {
        200 => {
            let v: Value = serde_json::from_str(body).map_err(|_| "the checker's reply was unreadable".to_string())?;
            if !v.is_object() || (v.get("SHA-256").is_none() && v.get("SHA-1").is_none()) {
                return Err("the checker's reply was not about a file".into());
            }
            match &v["KnownMalicious"] {
                Value::String(s) if !s.trim().is_empty() => Ok(Said::Bad(s.trim().to_string())),
                Value::Array(a) if !a.is_empty() => Ok(Said::Bad(a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))),
                _ => Ok(Said::Known),
            }
        }
        // Only CIRCL's own "never seen it" counts: any other 404 (a moved address) is a failure.
        404 if body.contains("Non existing") => Ok(Said::Unknown),
        0 => Err(if body.is_empty() { "no connection".into() } else { body.to_string() }),
        s => Err(format!("the checker answered {s}")),
    }
}

pub struct Answers {
    pub said: HashMap<String, Said>,
    /// {ran, asked, remembered, bad, known, unknown, failed, notAsked, error}
    pub summary: Value,
}

fn load(file: &Path, now: u64) -> HashMap<String, Said> {
    let mut out = HashMap::new();
    let Ok(s) = std::fs::read_to_string(file) else { return out };
    for line in s.lines() {
        // sha256 \t bad|known|unknown \t source \t seconds since 1970
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 || !sendable(f[0]) {
            continue;
        }
        let Ok(t) = f[3].parse::<u64>() else { continue };
        if now.saturating_sub(t) > KEEP_SECS || t > now + 3600 {
            continue;
        }
        let said = match f[1] {
            "bad" => Said::Bad(f[2].to_string()),
            "known" => Said::Known,
            "unknown" => Said::Unknown,
            _ => continue,
        };
        out.insert(f[0].to_string(), said);
    }
    out
}

fn line(sha: &str, s: &Said, now: u64) -> String {
    let (k, src) = match s {
        Said::Bad(x) => ("bad", x.replace(['\t', '\n', '\r'], " ")),
        Said::Known => ("known", String::new()),
        Said::Unknown => ("unknown", String::new()),
    };
    format!("{sha}\t{k}\t{src}\t{now}")
}

/// Ask about `shas` (duplicates and malformed ones dropped, remembered ones not re-sent, at most
/// MAX_ASK sent). `fetch` is called once with the list to send, only if it is not empty.
pub fn ask(dir: &Path, shas: &[String], now: u64, fetch: impl FnOnce(&[String]) -> Vec<Reply>) -> Answers {
    let file = dir.join(CACHE);
    let mem = load(&file, now);
    let mut seen = std::collections::HashSet::new();
    let wanted: Vec<String> = shas.iter().map(|s| s.to_ascii_lowercase()).filter(|s| sendable(s) && seen.insert(s.clone())).collect();
    let mut said: HashMap<String, Said> = HashMap::new();
    let mut todo: Vec<String> = Vec::new();
    let mut remembered = 0usize;
    for s in &wanted {
        match mem.get(s) {
            Some(x) => {
                said.insert(s.clone(), x.clone());
                remembered += 1;
            }
            None => todo.push(s.clone()),
        }
    }
    let not_asked = todo.len().saturating_sub(MAX_ASK);
    todo.truncate(MAX_ASK);
    let (mut failed, mut error) = (0usize, None::<String>);
    let mut fresh: Vec<(String, Said)> = Vec::new();
    if !todo.is_empty() {
        let replies = fetch(&todo);
        let by: HashMap<&str, (u16, &str)> = replies.iter().map(|(s, st, b)| (s.as_str(), (*st, b.as_str()))).collect();
        for s in &todo {
            // A fingerprint the helper never answered is a failure, never "unknown".
            let got = by.get(s.as_str()).map_or(Err("no reply for it".to_string()), |(st, b)| read_answer(*st, b));
            match got {
                Ok(x) => {
                    said.insert(s.clone(), x.clone());
                    fresh.push((s.clone(), x));
                }
                Err(e) => {
                    failed += 1;
                    error.get_or_insert(e);
                }
            }
        }
    }
    if !fresh.is_empty() {
        let mut all = mem;
        for (s, x) in fresh {
            all.insert(s, x);
        }
        let mut out: Vec<String> = all.iter().map(|(s, x)| line(s, x, now)).collect();
        out.sort();
        let _ = std::fs::write(&file, out.join("\n"));
    }
    let count = |f: fn(&Said) -> bool| said.values().filter(|x| f(x)).count();
    let summary = json!({
        "ran": true, "asked": todo.len(), "remembered": remembered,
        "bad": count(|x| matches!(x, Said::Bad(_))), "known": count(|x| *x == Said::Known),
        "unknown": count(|x| *x == Said::Unknown), "failed": failed, "notAsked": not_asked, "error": error,
    });
    Answers { said, summary }
}

pub const RULE: &str = "KnownMaliciousOnline";

fn online_rule() -> Value {
    json!({"set": "Vigil", "rule": RULE, "weak": false})
}

/// The fingerprints a sweep wants asked about: app files no list knew (the zero-day gap on a
/// phone is mostly apps), then the weak "worth a look" finds. Strong finds are already a Stop.
pub fn sweep_candidates(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v["unknownApps"].as_array().into_iter().flatten()
        .filter_map(|a| a["sha256"].as_str().map(String::from)).collect();
    out.extend(v["found"].as_array().into_iter().flatten().filter(|f| f["weak"] == true)
        .filter_map(|f| f["sha256"].as_str().map(String::from)));
    out
}

/// Fold the answers into a sweep result: a weak find CIRCL names as malware becomes a Stop, and an
/// app file no list knew but CIRCL names becomes a new found row. `unknownApps` is removed.
pub fn apply_to_sweep(v: &mut Value, a: &Answers) {
    let apps = v.as_object_mut().and_then(|o| o.remove("unknownApps")).unwrap_or(json!([]));
    let bad = |sha: &str| match a.said.get(sha) {
        Some(Said::Bad(src)) => Some(src.clone()),
        _ => None,
    };
    if let Some(found) = v["found"].as_array_mut() {
        for f in found.iter_mut() {
            let Some(src) = f["sha256"].as_str().and_then(bad) else { continue };
            if let Some(r) = f["rules"].as_array_mut() {
                r.push(online_rule());
            }
            if let Some(w) = f["why"].as_array_mut() {
                w.push(json!(crate::deeplook::words(RULE)));
            }
            f["weak"] = json!(false);
            f["online"] = json!(src);
        }
        for app in apps.as_array().into_iter().flatten() {
            let Some(src) = app["sha256"].as_str().and_then(bad) else { continue };
            let mut row = app.clone();
            row["list"] = json!(false);
            row["listWeak"] = json!(false);
            row["rules"] = json!([online_rule()]);
            row["weak"] = json!(false);
            row["why"] = json!([crate::deeplook::words(RULE)]);
            row["stalkerware"] = Value::Null;
            row["online"] = json!(src);
            found.push(row);
        }
    }
    v["online"] = a.summary.clone();
}

/// The installed-apps check's fingerprints to ask about: apps he installed that no list knew.
pub fn apps_candidates(v: &Value) -> Vec<String> {
    v["unknownApps"].as_array().into_iter().flatten().filter_map(|a| a["sha256"].as_str().map(String::from)).collect()
}

/// Fold the answers into the installed-apps result: an app CIRCL names as malware joins `found`
/// (the page's Stop), carrying `online` = who reported it. `unknownApps` is removed.
pub fn apply_to_apps(v: &mut Value, a: &Answers) {
    let apps = v.as_object_mut().and_then(|o| o.remove("unknownApps")).unwrap_or(json!([]));
    if let Some(found) = v["found"].as_array_mut() {
        for app in apps.as_array().into_iter().flatten() {
            if let Some(Said::Bad(src)) = app["sha256"].as_str().and_then(|s| a.said.get(s)) {
                found.push(json!({"pkg": app["pkg"], "path": app["path"], "sha256": app["sha256"], "stalkerware": null, "online": src}));
            }
        }
    }
    v["online"] = a.summary.clone();
}

/// One file's answer for the single-file check: {said: "bad"|"known"|"unknown"|null, source, error}.
/// `said: null` = not answered (no connection, or refused) - the page says so, never "clean".
pub fn single(a: &Answers, sha: &str) -> Value {
    let (said, source) = match a.said.get(&sha.to_ascii_lowercase()) {
        Some(Said::Bad(s)) => (json!("bad"), json!(s)),
        Some(Said::Known) => (json!("known"), Value::Null),
        Some(Said::Unknown) => (json!("unknown"), Value::Null),
        None => (Value::Null, Value::Null),
    };
    json!({"said": said, "source": source, "error": a.summary["error"].clone()})
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
