//! Local look-up of a file's fingerprint (SHA-256) in MalwareBazaar's public list of known
//! malware samples, which ps/hashlist-update.ps1 keeps in %LOCALAPPDATA%\VirusVigil\lists.
//! Nothing is sent anywhere. The full list (~1.14 million) is turned once into a sorted file of
//! 32-byte records and searched on disk by binary search (about 21 reads), so it is never held
//! in memory; it is rebuilt only when the downloaded text is newer. The small "last 48 hours"
//! list is read whole. On the phone Kotlin downloads the same two lists into the app's own
//! folder (phone.rs `update_hash`), and `accept_download` below does the script's checks.

use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FULL: &str = "malwarebazaar-full.txt";
pub const RECENT: &str = "malwarebazaar-recent.txt";
pub const BIN: &str = "malwarebazaar.bin";

/// An abuse.ch Auth-Key, only if it has a key's shape (letters/digits, 20-100); anything else is
/// treated as no key, so a stray value can never be pasted into the download address.
pub fn valid_mb_key(k: &str) -> Option<String> {
    let k = k.trim();
    (k.len() >= 20 && k.len() <= 100 && k.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| k.to_string())
}

/// The phone's abuse.ch Auth-Key: since Oct 2026 the lists are served only with one (keyless =
/// 410 Gone). The laptop's PowerShell reads ABUSE_CH_AUTH_KEY itself; the phone has no
/// environment, so `build-android.sh ... personal` bakes it in as VV_MB_KEY. Shareable builds
/// carry none - each user needs their own free key (abuse.ch limits per account).
pub fn mb_key() -> String {
    std::env::var("ABUSE_CH_AUTH_KEY").ok().and_then(|k| valid_mb_key(&k))
        .or_else(|| option_env!("VV_MB_KEY").and_then(valid_mb_key))
        .unwrap_or_default()
}

/// Whether the full list must be fetched again, from the two files' ages in hours (None = no file).
/// Weekly by default - AND sooner whenever the last-48-hours list no longer reaches back to it.
/// 29 Sep 2026: full from 25 Sep 15:34, recent reaching back only to 27 Sep 02:21, so malware first
/// shared in the 35 hours between was in NEITHER list; with a weekly rule that hole grows to ~5 days,
/// and it holds the newest samples. 40, not 48: the export lags, and 8 hours of overlap is cheap.
/// ps/hashlist-update.ps1 carries the same rule for the laptop.
pub fn full_due(full_age_h: Option<f64>, recent_age_h: Option<f64>) -> bool {
    match (full_age_h, recent_age_h) {
        (None, _) => true,
        (Some(f), _) if f >= FULL_MAX_H => true,
        (Some(f), Some(r)) => f - r > RECENT_REACH_H,
        (Some(_), None) => false,
    }
}
/// Hours since the file was last written; None = no file. A clock set back reads as 0, not None.
pub fn age_hours(p: &Path) -> Option<f64> {
    let m = std::fs::metadata(p).and_then(|m| m.modified()).ok()?;
    Some(std::time::SystemTime::now().duration_since(m).map(|d| d.as_secs_f64() / 3600.0).unwrap_or(0.0))
}
pub const FULL_MAX_H: f64 = 24.0 * 7.0;
pub const RECENT_REACH_H: f64 = 40.0;

/// Only one thread builds the sorted file at a time.
static BUILD: Mutex<()> = Mutex::new(());

pub fn lists_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("VirusVigil").join("lists")
}

pub(crate) fn parse_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Read line by line (the full text is ~75 MB; a phone should not hold it whole).
fn read_hashes(path: &Path) -> Result<Vec<[u8; 32]>, String> {
    use std::io::BufRead;
    let f = std::fs::File::open(path).map_err(|e| format!("cannot read the list: {e}"))?;
    let mut out = Vec::new();
    for line in std::io::BufReader::with_capacity(1 << 16, f).lines() {
        let line = line.map_err(|e| format!("cannot read the list: {e}"))?;
        if !line.trim_start().starts_with('#') {
            out.extend(parse_hex(&line));
        }
    }
    Ok(out)
}

/// The phone's version of ps/hashlist-update.ps1's checks: a download replaces the list only if
/// it has at least `min` hash lines and 99% of them are valid, so a bad download never wipes a
/// good list. Returns the line count. The new file keeps its arrival time (rename), so the
/// sorted file is rebuilt from it.
pub fn accept_download(tmp: &Path, dest: &Path, min: usize) -> Result<usize, String> {
    use std::io::BufRead;
    let f = std::fs::File::open(tmp).map_err(|e| format!("cannot read the download: {e}"))?;
    let (mut n, mut good) = (0usize, 0usize);
    for line in std::io::BufReader::new(f).lines() {
        let line = line.map_err(|e| format!("cannot read the download: {e}"))?;
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        n += 1;
        if parse_hex(l).is_some() {
            good += 1;
        }
    }
    if n < min || (good as f64) < 0.99 * n as f64 {
        let _ = std::fs::remove_file(tmp);
        return Err(format!("downloaded list failed its checks ({good} of {n} lines valid, need {min})"));
    }
    std::fs::rename(tmp, dest).map_err(|e| format!("cannot put the new list in place: {e}"))?;
    Ok(n)
}

fn modified(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Make sure `dir/BIN` exists and is not older than `dir/FULL`. Returns the number of records.
fn ensure_bin(dir: &Path) -> Result<u64, String> {
    let (full, bin) = (dir.join(FULL), dir.join(BIN));
    let _g = BUILD.lock().unwrap_or_else(|p| p.into_inner());
    let full_t = modified(&full);
    let fresh = matches!((modified(&bin), full_t), (Some(b), Some(f)) if b >= f) || (full_t.is_none() && bin.exists());
    if !fresh {
        if full_t.is_none() {
            return Err("no list of known malware downloaded yet".into());
        }
        let mut v = read_hashes(&full)?;
        v.sort_unstable();
        v.dedup();
        let tmp = dir.join(format!("{BIN}.building"));
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("cannot write the sorted list: {e}"))?;
        for h in &v {
            f.write_all(h).map_err(|e| format!("cannot write the sorted list: {e}"))?;
        }
        f.sync_all().ok();
        drop(f);
        std::fs::rename(&tmp, &bin).map_err(|e| format!("cannot put the sorted list in place: {e}"))?;
    }
    let len = std::fs::metadata(&bin).map_err(|e| e.to_string())?.len();
    if len % 32 != 0 {
        let _ = std::fs::remove_file(&bin);
        return Err("the sorted list was damaged; it will be rebuilt".into());
    }
    Ok(len / 32)
}

fn on_disk(bin: &Path, n: u64, want: &[u8; 32]) -> Result<bool, String> {
    let mut f = std::fs::File::open(bin).map_err(|e| e.to_string())?;
    let (mut lo, mut hi) = (0u64, n);
    let mut rec = [0u8; 32];
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        f.seek(SeekFrom::Start(mid * 32)).map_err(|e| e.to_string())?;
        f.read_exact(&mut rec).map_err(|e| e.to_string())?;
        match rec.cmp(want) {
            std::cmp::Ordering::Equal => return Ok(true),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    Ok(false)
}

/// Is this fingerprint a known malware sample? {checked, found, count, recent, ageHours, error}.
/// `checked: false` means NOT LOOKED UP (no list yet, unreadable) - never "not found".
pub fn lookup_in(dir: &Path, sha256_hex: &str) -> Value {
    if parse_hex(sha256_hex).is_none() {
        return json!({"checked": false, "found": false, "error": "no fingerprint to look up"});
    }
    match open_book(dir) {
        Ok(b) => b.lookup(sha256_hex),
        // The stalkerware samples ship inside the app, so one is named even with no list downloaded.
        Err(v) => match parse_hex(sha256_hex).and_then(|w| crate::stalker::sample(&w)) {
            Some(app) => json!({"checked": true, "found": true, "stalkerware": app, "error": null, "listMissing": v["error"].clone()}),
            None => v,
        },
    }
}

/// The lists opened ONCE for many look-ups: a folder sweep asks about tens of thousands of files,
/// and re-reading the recent list for each would read gigabytes for nothing.
pub struct Book {
    recent: std::collections::HashSet<[u8; 32]>,
    n: u64,
    full: bool,
    bin: PathBuf,
    /// {checked: true, count, recent, full, ageHours, error: null} - what every answer carries.
    pub info: Value,
}

/// Err = the NOT-LOOKED-UP answer ({checked: false, found: false, error}), ready to return.
pub fn open_book(dir: &Path) -> Result<Book, Value> {
    // The recent list is optional while the full one is here: its absence never makes the
    // look-up "not checked".
    let recent: std::collections::HashSet<[u8; 32]> = read_hashes(&dir.join(RECENT)).unwrap_or_default().into_iter().collect();
    let (n, full) = match ensure_bin(dir) {
        Ok(n) => (n, true),
        // A phone on mobile data has only the last-48-hours list until it meets Wi-Fi: that is
        // a real (small) look-up, said as such with `full: false` - never passed off as the full one.
        Err(_) if !recent.is_empty() => (0, false),
        Err(e) => return Err(json!({"checked": false, "found": false, "error": e})),
    };
    let age = modified(&dir.join(FULL))
        .or_else(|| modified(&dir.join(BIN)))
        .or_else(|| modified(&dir.join(RECENT)))
        .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
        .map(|d| (d.as_secs_f64() / 360.0).round() / 10.0);
    let info = json!({"checked": true, "count": n, "recent": recent.len(), "full": full, "ageHours": age, "error": null});
    Ok(Book { recent, n, full, bin: dir.join(BIN), info })
}

impl Book {
    /// Ok(found) or Err(why the sorted list could not be read).
    pub fn has(&self, want: &[u8; 32]) -> Result<bool, String> {
        // The stalkerware samples ship inside the app (stalker.rs), so they count even before a
        // list has been downloaded into this book.
        if self.recent.contains(want) || crate::stalker::sample(want).is_some() {
            return Ok(true);
        }
        if !self.full {
            return Ok(false);
        }
        on_disk(&self.bin, self.n, want).map_err(|e| format!("cannot read the sorted list: {e}"))
    }

    /// The same answer `lookup_in` gives: {checked, found, count, recent, full, ageHours, error}.
    pub fn lookup(&self, sha256_hex: &str) -> Value {
        let Some(want) = parse_hex(sha256_hex) else {
            return json!({"checked": false, "found": false, "error": "no fingerprint to look up"});
        };
        match self.has(&want) {
            Ok(found) => {
                let mut v = self.info.clone();
                v["found"] = json!(found);
                if let Some(app) = crate::stalker::sample(&want) {
                    v["stalkerware"] = json!(app);
                }
                v
            }
            Err(e) => json!({"checked": false, "found": false, "error": e}),
        }
    }
}

/// The phone's lists folder (inside the app's own files), set by phone.rs before any look-up.
static PHONE_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub fn set_phone_dir(p: PathBuf) {
    let _ = PHONE_DIR.set(p);
}

/// The folder look-ups use: the phone's own (None until phone.rs set it), else the laptop's.
pub fn active_dir() -> Option<PathBuf> {
    if cfg!(target_os = "android") {
        return PHONE_DIR.get().cloned();
    }
    Some(lists_dir())
}

pub fn lookup(sha256_hex: &str) -> Value {
    if cfg!(target_os = "android") {
        return match PHONE_DIR.get() {
            Some(d) => lookup_in(d, sha256_hex),
            None => json!({"checked": false, "found": false, "error": "the phone gave no folder for the list"}),
        };
    }
    lookup_in(&lists_dir(), sha256_hex)
}
