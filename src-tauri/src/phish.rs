//! Local look-up in the public phishing-domain lists, which ps/phish-update.ps1 (laptop) and
//! phone.rs (phone) keep in the app's lists folder. Nothing is sent anywhere: the page passes
//! host names in, and gets back which of them are on a list, and on which.
//! Two lists since 2 Nov 2026 (SOURCES): Phishing.Database (MIT, ~400k names, its makers stopped
//! on 2 Oct 2026) and CERT Polska's Warning List (~126k names, changed every few minutes, data
//! policy: "may be used by any user for any purpose, including commercial purposes").
//! Each is held sorted in memory, searched by binary search, re-read only when its file changes.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

struct Loaded {
    path: PathBuf,
    modified: SystemTime,
    names: Vec<Box<str>>,
}

/// One entry per list file, so two lists never evict each other on every look-up.
static CACHE: Mutex<Vec<Loaded>> = Mutex::new(Vec::new());

/// (name shown to the person, file name in the lists folder). The first is the original list.
pub const SOURCES: [(&str, &str); 2] = [("Phishing.Database", "phishing-domains.txt"), ("CERT Polska", "phishing-certpl.txt")];

/// Beside the list: when its MAKERS last changed it (unix seconds, from GitHub's commit record).
/// 31 Oct 2026: Phishing.Database stopped updating on 2 Oct while the file's own age (our download
/// time) kept saying "today". No sidecar = no claim either way.
pub fn since_path(list: &Path) -> PathBuf {
    list.with_extension("since")
}

/// "2026-10-02T15:30:28Z" -> unix seconds. Only this exact UTC shape; anything else is None.
pub fn parse_iso_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

/// Record the makers' last change after a good download; an unreadable date removes the old one,
/// so a stale sidecar never describes a newer list.
pub fn write_since(list: &Path, iso: Option<&str>) {
    match iso.and_then(parse_iso_utc) {
        Some(t) => { let _ = std::fs::write(since_path(list), t.to_string()); }
        None => { let _ = std::fs::remove_file(since_path(list)); }
    }
}

/// Whole days since the makers last changed the list, or None when that is not known.
pub fn source_days(list: &Path) -> Option<i64> {
    let t: i64 = std::fs::read_to_string(since_path(list)).ok()?.trim().parse().ok()?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some((now - t).max(0) / 86400)
}

pub fn lists_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("VirusVigil").join("lists")
}

fn load(path: &Path) -> Result<Vec<Box<str>>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read the list: {e}"))?;
    let mut v: Vec<Box<str>> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase().into_boxed_str())
        .collect();
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

/// One list line as ps/phish-update.ps1 accepts it: `^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$`,
/// case-insensitive (PowerShell's -match ignores case).
pub fn looks_like_host(line: &str) -> bool {
    let b = line.as_bytes();
    let edge = |c: u8| c.is_ascii_alphanumeric();
    let mid = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-';
    match b {
        [] => false,
        [one] => edge(*one) || *one == b'_',
        [first, inner @ .., last] => (edge(*first) || *first == b'_') && inner.iter().all(|c| mid(*c)) && edge(*last),
    }
}

/// Checks a downloaded list the way ps/phish-update.ps1 does (enough lines, 99% host names),
/// then swaps it in. A download that fails is deleted and the old list stays.
pub fn accept_download(tmp: &Path, dest: &Path, min_lines: usize) -> Result<usize, String> {
    let text = std::fs::read_to_string(tmp).map_err(|e| format!("cannot read the download: {e}"))?;
    let (mut n, mut good) = (0usize, 0usize);
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        n += 1;
        if looks_like_host(line) {
            good += 1;
        }
    }
    if n < min_lines || (good as f64) < 0.99 * n as f64 {
        let _ = std::fs::remove_file(tmp);
        return Err(format!("downloaded list failed its checks ({good} of {n} lines valid, need {min_lines})"));
    }
    std::fs::rename(tmp, dest).map_err(|e| format!("cannot put the new list in place: {e}"))?;
    Ok(n)
}

/// Which of `names` are on the list at `path`. `count` 0 with an `error` means NOT CHECKED.
pub fn lookup_in(path: &Path, names: &[String]) -> Value {
    let modified = match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(m) => m,
        Err(_) => return json!({ "count": 0, "found": [], "error": "no phishing list on this laptop yet", "ageHours": null }),
    };
    let mut guard = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let at = guard.iter().position(|l| l.path == path);
    let i = match at {
        Some(i) if guard[i].modified == modified => i,
        _ => match load(path) {
            Ok(names) => {
                let l = Loaded { path: path.to_path_buf(), modified, names };
                match at {
                    Some(i) => { guard[i] = l; i }
                    None => { guard.push(l); guard.len() - 1 }
                }
            }
            Err(e) => return json!({ "count": 0, "found": [], "error": e, "ageHours": null }),
        },
    };
    let l = &guard[i];
    let found: Vec<&String> = names
        .iter()
        .filter(|n| l.names.binary_search_by(|x| (**x).cmp(n.to_ascii_lowercase().as_str())).is_ok())
        .collect();
    let age = SystemTime::now().duration_since(modified).map(|d| d.as_secs_f64() / 3600.0).unwrap_or(0.0);
    json!({ "count": l.names.len(), "found": found, "error": null, "ageHours": (age * 10.0).round() / 10.0, "sourceDays": source_days(path) })
}

/// Every list in SOURCES under `dir`, asked at once. `found` = on ANY list (in the order asked),
/// `foundBy` = which lists each was on, `lists` = each list's own count / ages / error.
/// `count` 0 with an `error` means NO list could be read = NOT CHECKED. One list missing while
/// the other answers is still a check, and `lists` says which one was missing.
/// `ageHours` = the OLDEST download among the lists read; `sourceDays` = the most recent change
/// by any list's makers (null when no list's makers' date is known).
pub fn lookup_many(dir: &Path, names: &[String]) -> Value {
    let mut lists = Vec::new();
    let mut by: Vec<(String, Vec<&str>)> = Vec::new();
    let (mut count, mut age, mut days): (u64, Option<f64>, Option<i64>) = (0, None, None);
    for (src, file) in SOURCES {
        let r = lookup_in(&dir.join(file), names);
        let c = r["count"].as_u64().unwrap_or(0);
        if c > 0 {
            count += c;
            if let Some(a) = r["ageHours"].as_f64() { age = Some(age.map_or(a, |x: f64| x.max(a))); }
            if let Some(d) = r["sourceDays"].as_i64() { days = Some(days.map_or(d, |x: i64| x.min(d))); }
            for n in r["found"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
                match by.iter_mut().find(|(k, _)| k == n) {
                    Some((_, v)) => v.push(src),
                    None => by.push((n.to_string(), vec![src])),
                }
            }
        }
        lists.push(json!({ "source": src, "count": c, "ageHours": r["ageHours"], "sourceDays": r.get("sourceDays").cloned().unwrap_or(Value::Null), "error": r["error"] }));
    }
    let found: Vec<&String> = names.iter().filter(|n| by.iter().any(|(k, _)| k == *n)).collect();
    let found_by: serde_json::Map<String, Value> = by.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let error = if count > 0 { Value::Null } else {
        lists.iter().find_map(|l| l["error"].as_str().map(String::from)).map(Value::from).unwrap_or_else(|| "no phishing list on this device yet".into())
    };
    json!({ "count": count, "found": found, "foundBy": found_by, "lists": lists, "error": error, "ageHours": age, "sourceDays": days })
}
