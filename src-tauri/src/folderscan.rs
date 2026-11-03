//! The laptop's own folder sweep (25 Sep 2026, his tap "Laptop folder sweep"): every file in
//! Downloads, Desktop and Temp - where the 12 Sep fake-game Setup.exe landed - fingerprinted
//! against MalwareBazaar's known samples and read by the YARA rules. Before this the laptop only
//! ever checked the one file a person picked.
//!
//! Fingerprints and YARA verdicts are remembered by (path, size, modified time), so a repeat run
//! reads only new or changed files. Newest files go first, so a sweep stopped by its time or file
//! budget has covered what arrived most recently, and the next run carries on. Nothing leaves
//! the laptop.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

pub const CACHE: &str = "folder-fingerprints.tsv";
/// The phone's own memory of its storage sweep (kept apart from the laptop's name for clarity).
pub const PHONE_CACHE: &str = "storage-fingerprints.tsv";

pub struct Opts {
    /// Files larger than this are fingerprinted but not read by YARA (videos, disk images).
    pub max_yara: u64,
    /// At most this many files per run (newest first).
    pub max_files: usize,
    /// Stop starting new files after this long; what was done is remembered.
    pub budget: std::time::Duration,
    pub threads: usize,
    /// Folders never entered (exact paths). The phone's Android/data and Android/obb: Android
    /// seals them from every other app, so listing them says nothing about what is inside.
    pub skip: Vec<PathBuf>,
    /// Live counts the page reads while the sweep runs (29 Sep: "is it actually scanning?").
    pub progress: Option<&'static Progress>,
    /// Crash notes (29 Sep, 0.1.26 "crashing again and again" on his Vivo once storage was allowed):
    /// the file being read by the patterns is written here first. A note left over at the next start
    /// means the app died reading it: that file joins `<crumbs>.skip` (never pattern-read again, and
    /// said), and that run uses one thread. None = no notes (the laptop, the tests by default).
    pub crumbs: Option<PathBuf>,
}

/// The skip list that sits beside a crash-note file.
pub fn crash_skip_file(crumbs: &Path) -> PathBuf {
    crumbs.with_extension("skip")
}

/// Read and clear a leftover crash note. Returns (the app died last time, every file ever skipped
/// for it). Files named in the note are added to the skip list first.
pub fn recover_crumbs(crumbs: &Path) -> (bool, std::collections::HashSet<String>) {
    let skip_file = crash_skip_file(crumbs);
    let mut skip: std::collections::HashSet<String> = std::fs::read_to_string(&skip_file).unwrap_or_default()
        .lines().filter(|l| !l.is_empty()).map(String::from).collect();
    let died = match std::fs::read_to_string(crumbs) {
        Ok(s) => {
            skip.extend(s.lines().filter(|l| !l.is_empty()).map(String::from));
            let mut all: Vec<&String> = skip.iter().collect();
            all.sort();
            let _ = std::fs::write(&skip_file, all.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"));
            let _ = std::fs::remove_file(crumbs);
            true
        }
        Err(_) => false,
    };
    (died, skip)
}

impl Default for Opts {
    fn default() -> Self {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Opts { max_yara: 64 << 20, max_files: 300_000, budget: std::time::Duration::from_secs(900), threads: n.clamp(1, 8),
               skip: Vec::new(), progress: None, crumbs: None }
    }
}

/// What a running sweep (or app check) has done so far. His report 29 Sep 2026: "only two seconds
/// to scan my entire phone ... I believe that it is not actually scanning anything" - so the work
/// is shown while it happens, counted by the code doing it, never estimated.
#[derive(Default)]
pub struct Progress {
    pub running: AtomicBool,
    /// 0 idle, 1 listing folders, 2 reading files, 3 fingerprinting apps
    pub phase: AtomicUsize,
    pub listed: AtomicUsize,
    pub total: AtomicUsize,
    pub done: AtomicUsize,
    pub fresh: AtomicUsize,
    pub bytes: AtomicU64,
    pub current: Mutex<String>,
    pub started: Mutex<Option<std::time::Instant>>,
}

impl Progress {
    pub fn start(&self, phase: usize) {
        for a in [&self.listed, &self.total, &self.done, &self.fresh] {
            a.store(0, Ordering::Relaxed);
        }
        self.bytes.store(0, Ordering::Relaxed);
        self.phase.store(phase, Ordering::Relaxed);
        *self.current.lock().unwrap() = String::new();
        *self.started.lock().unwrap() = Some(std::time::Instant::now());
        self.running.store(true, Ordering::Relaxed);
    }
    pub fn finish(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.phase.store(0, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> Value {
        let ms = self.started.lock().unwrap().map(|t| t.elapsed().as_millis() as u64);
        json!({"running": self.running.load(Ordering::Relaxed), "phase": self.phase.load(Ordering::Relaxed),
               "listed": self.listed.load(Ordering::Relaxed), "total": self.total.load(Ordering::Relaxed),
               "done": self.done.load(Ordering::Relaxed), "fresh": self.fresh.load(Ordering::Relaxed),
               "bytes": self.bytes.load(Ordering::Relaxed), "current": self.current.lock().unwrap().clone(), "ms": ms})
    }
}

/// The one the app shows (laptop folders, phone storage, phone apps - one runs at a time each).
pub static PROGRESS: std::sync::LazyLock<Progress> = std::sync::LazyLock::new(Progress::default);
pub static APPS_PROGRESS: std::sync::LazyLock<Progress> = std::sync::LazyLock::new(Progress::default);

/// One run at a time. 29 Sep 2026: a page reload left the old app check running in Rust while the
/// new page started a second one - both counted into APPS_PROGRESS ("done 141, fresh 207 of 249")
/// and both wrote the fingerprint file. `take` hands out the only turn; the turn is given back when
/// it is dropped, so an early return or a panic cannot keep it for ever.
pub struct OneAtATime(AtomicBool);
pub struct Turn(&'static AtomicBool);
impl OneAtATime {
    pub const fn new() -> Self {
        OneAtATime(AtomicBool::new(false))
    }
    pub fn take(&'static self) -> Option<Turn> {
        if self.0.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(Turn(&self.0))
        }
    }
}
impl Drop for Turn {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
pub static FOLDERS_TURN: OneAtATime = OneAtATime::new();
pub static APPS_TURN: OneAtATime = OneAtATime::new();

/// An Android app file by its name (.apk, any case) - read by the rules however big it is.
pub fn is_apk(p: &Path) -> bool {
    p.extension().and_then(|x| x.to_str()).map_or(false, |x| x.eq_ignore_ascii_case("apk"))
}

/// The folders swept on this laptop: (label, path), only those that exist.
/// At most 1 KB, no NUL byte, not a program or archive header: boilerplate-sized text.
pub fn small_text(p: &Path) -> bool {
    let mut buf = Vec::new();
    match std::fs::File::open(p).and_then(|f| f.take(1025).read_to_end(&mut buf)) {
        Ok(n) if n > 0 && n <= 1024 => {
            !buf.contains(&0) && !buf.starts_with(b"MZ") && !buf.starts_with(b"\x7fELF") && !buf.starts_with(b"PK")
        }
        _ => false,
    }
}

pub fn default_roots() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        out.push(("Downloads".into(), home.join("Downloads")));
        out.push(("Desktop".into(), home.join("Desktop")));
        out.push(("OneDrive Desktop".into(), home.join("OneDrive").join("Desktop")));
    }
    out.push(("Temp".into(), std::env::temp_dir()));
    let mut seen = std::collections::HashSet::new();
    out.retain(|(_, p)| p.is_dir() && seen.insert(std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())));
    out
}

/// A cloud-only file (OneDrive "free up space"): opening it DOWNLOADS it, so it is not read.
#[cfg(windows)]
fn cloud_only(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x40000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x400000;
    m.file_attributes() & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0
}
#[cfg(not(windows))]
fn cloud_only(_m: &std::fs::Metadata) -> bool {
    false
}

struct Entry {
    root: usize,
    path: PathBuf,
    size: u64,
    mtime: u128,
}

/// Folders a programming tool fills with libraries it fetched (never the person's own downloads).
/// Measured 25 Sep on his laptop: 1,041,115 of the 1,090,578 files on OneDrive\Desktop sat in these,
/// and walking them pushed the sweep past its cap so that his own files were never all read.
const TOOL_DIRS: &[&str] = &["node_modules", ".git", ".venv", "venv", "site-packages", "__pycache__", ".gradle", ".next", ".tox", ".mypy_cache", ".pytest_cache"];
/// Build output folders, skipped only beside a project file (a plain folder called "build" is swept).
const OUTPUT_DIRS: &[&str] = &["dist", "build", "target"];
const PROJECT_FILES: &[&str] = &["package.json", "Cargo.toml", "pyproject.toml", "setup.py", "build.gradle", "CMakeLists.txt", "pom.xml"];

fn tool_dir(parent: &Path, name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    TOOL_DIRS.contains(&n.as_str()) || (OUTPUT_DIRS.contains(&n.as_str()) && PROJECT_FILES.iter().any(|f| parent.join(f).is_file()))
}

/// Every file under the roots. Links and junctions are not followed (a junction can loop, or lead
/// out of the folder being swept). Returns (files, folders that could not be listed, cloud-only,
/// program-building folders skipped).
fn walk(roots: &[(String, PathBuf)], skip: &[PathBuf], progress: Option<&Progress>) -> (Vec<Entry>, u64, u64, u64) {
    let (mut files, mut bad_dirs, mut cloud, mut skipped) = (Vec::new(), 0u64, 0u64, 0u64);
    for (ri, (_, root)) in roots.iter().enumerate() {
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            if skip.iter().any(|s| s == &d) {
                continue;
            }
            if let Some(p) = progress {
                p.listed.store(files.len(), Ordering::Relaxed);
            }
            let Ok(rd) = std::fs::read_dir(&d) else {
                bad_dirs += 1;
                continue;
            };
            for e in rd.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    if tool_dir(&d, &e.file_name().to_string_lossy()) {
                        skipped += 1;
                        continue;
                    }
                    stack.push(e.path());
                } else if ft.is_file() {
                    let Ok(m) = e.metadata() else { continue };
                    if cloud_only(&m) {
                        cloud += 1;
                        continue;
                    }
                    let mtime = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis()).unwrap_or(0);
                    files.push(Entry { root: ri, path: e.path(), size: m.len(), mtime });
                }
            }
        }
    }
    (files, bad_dirs, cloud, skipped)
}

fn key(e: &Entry) -> String {
    format!("{}\t{}\t{}", e.path.to_string_lossy(), e.size, e.mtime)
}

/// Remembered: key -> (sha256, yara tag it was read with or "", matched rules).
fn load_cache(f: &Path) -> HashMap<String, (String, String, String)> {
    let mut out = HashMap::new();
    if let Ok(s) = std::fs::read_to_string(f) {
        for line in s.lines() {
            // path \t size \t mtime \t sha256 \t tag \t rules
            let parts: Vec<&str> = line.rsplitn(4, '\t').collect();
            if parts.len() != 4 {
                continue;
            }
            let (rules, tag, sha, k) = (parts[0], parts[1], parts[2], parts[3]);
            if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) && k.matches('\t').count() == 2 {
                out.insert(k.to_string(), (sha.to_string(), tag.to_string(), rules.to_string()));
            }
        }
    }
    out
}

enum Read_ {
    Sha(String),
    Blocked,
    Failed,
}

fn sha256_file(p: &Path) -> Read_ {
    let mut f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) if matches!(e.raw_os_error(), Some(225) | Some(226)) => return Read_::Blocked,
        Err(_) => return Read_::Failed,
    };
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(e) if matches!(e.raw_os_error(), Some(225) | Some(226)) => return Read_::Blocked,
            Err(_) => return Read_::Failed,
        }
    }
    Read_::Sha(format!("{:x}", h.finalize()))
}

/// Sweep `roots`. `lookup(sha)` answers like hashlist::lookup_in; `yara(path)` like yara::scan;
/// `yara_tag` names the rule set (None = YARA not available, and every file says so).
/// {checked, list:{checked, count, full, recent, ageHours, error}, yara:{ran, rules, read, big, failed, reason},
///  roots:[{name, files}], files, bytes, fresh, unread, unreadNames, blocked:[{path, name, root}], cloud, badDirs,
///  found:[{path, name, root, sha256, list, rules:[{rule, set}]}], capped, left, ms}
/// `checked: false` = nothing could be looked up at all (no list AND no YARA) - never "none found".
pub fn sweep_with(roots: &[(String, PathBuf)], cache_file: &Path, lookup: impl Fn(&str) -> Value + Sync,
                  yara: impl Fn(&Path) -> Value + Sync, yara_tag: Option<String>, opts: &Opts) -> Value {
    let t0 = std::time::Instant::now();
    let probe = lookup(&"0".repeat(64));
    let list_ok = probe["checked"] == true;
    if !list_ok && yara_tag.is_none() {
        return json!({"checked": false, "list": probe, "yara": {"ran": false}, "files": 0, "found": [],
                      "ms": t0.elapsed().as_millis() as u64});
    }
    let prog = opts.progress;
    if let Some(p) = prog {
        p.start(1);
    }
    let (mut all, bad_dirs, cloud, skipped_dirs) = walk(roots, &opts.skip, prog);
    let walk_ms = t0.elapsed().as_millis() as u64; // the walk alone: listing folders, no file read
    let mut per_root = vec![0u64; roots.len()];
    for e in &all {
        per_root[e.root] += 1;
    }
    all.sort_by(|a, b| b.mtime.cmp(&a.mtime));
    let total = all.len();
    let capped_by_count = total > opts.max_files;
    // Every file still on disk, INCLUDING those past the cap: their remembered lines are kept.
    let here: std::collections::HashSet<String> = all.iter().map(key).collect();
    // The newest file the cap leaves out: every file not read is this old or older.
    let cut_mtime = all.get(opts.max_files).map(|e| e.mtime);
    all.truncate(opts.max_files);
    if let Some(p) = prog {
        p.listed.store(total, Ordering::Relaxed);
        p.total.store(all.len(), Ordering::Relaxed);
        p.phase.store(2, Ordering::Relaxed);
    }

    let old = load_cache(cache_file);
    let tag = yara_tag.clone().unwrap_or_default();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let out_of_time = AtomicBool::new(false);
    let lines: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    let found: Mutex<Vec<Value>> = Mutex::new(Vec::new());
    // App files no list or rule knew: the ones worth asking the online checker about (hashonline.rs).
    let unknown_apps: Mutex<Vec<(u64, Value)>> = Mutex::new(Vec::new());
    let blocked: Mutex<Vec<Value>> = Mutex::new(Vec::new());
    let unread_names: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let list_err: Mutex<Option<Value>> = Mutex::new(None);
    let (files, bytes, fresh, unread) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let (y_read, y_big, y_failed) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let y_reason: Mutex<Option<String>> = Mutex::new(None);
    // Crash notes: recover from a death last time, then keep a note of the files in the patterns now.
    let (died, crash_skip) = opts.crumbs.as_deref().map_or((false, Default::default()), recover_crumbs);
    let in_flight: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let crash_skipped: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let note = |add: Option<&str>, remove: Option<&str>| {
        let Some(c) = opts.crumbs.as_deref() else { return };
        let mut f = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(a) = add {
            f.push(a.to_string());
        }
        if let Some(r) = remove {
            if let Some(i) = f.iter().position(|x| x == r) {
                f.swap_remove(i);
            }
        }
        let _ = std::fs::write(c, f.join("\n"));
    };
    let threads = if died { 1 } else { opts.threads.max(1) };

    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if t0.elapsed() > opts.budget {
                    out_of_time.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(e) = all.get(i) else { break };
                let k = key(e);
                let name = e.path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                let path_s = e.path.to_string_lossy().into_owned();
                let root = roots[e.root].0.clone();
                let mem = old.get(&k);
                if let Some(p) = prog {
                    p.done.store(i + 1, Ordering::Relaxed);
                    // Every file, remembered or not: set only on fresh reads, a remembered sweep's
                    // row showed one stale name for minutes while the count climbed (29 Sep).
                    *p.current.lock().unwrap() = path_s.clone();
                }
                let sha = match mem {
                    Some((s, _, _)) => s.clone(),
                    None => match sha256_file(&e.path) {
                        Read_::Sha(s) => {
                            fresh.fetch_add(1, Ordering::Relaxed);
                            if let Some(p) = prog {
                                p.fresh.fetch_add(1, Ordering::Relaxed);
                                p.bytes.fetch_add(e.size, Ordering::Relaxed);
                            }
                            s
                        }
                        Read_::Blocked => {
                            // Windows refused it as a virus: Defender has already caught this one.
                            blocked.lock().unwrap().push(json!({"path": path_s, "name": name, "root": root}));
                            continue;
                        }
                        Read_::Failed => {
                            // In use or locked (Temp is full of these): named, never passed off as clean.
                            unread.fetch_add(1, Ordering::Relaxed);
                            let mut u = unread_names.lock().unwrap();
                            if u.len() < 5 {
                                u.push(name);
                            }
                            continue;
                        }
                    },
                };
                files.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(e.size as usize, Ordering::Relaxed);
                let mut listed = false;
                let mut stalker = Value::Null;
                if list_ok {
                    let v = lookup(&sha);
                    if v["checked"] != true {
                        // The list went away part-way: the whole list answer becomes "not looked up".
                        *list_err.lock().unwrap() = Some(v);
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    listed = v["found"] == true;
                    stalker = v["stalkerware"].clone();
                } else if let Some(app) = crate::hashlist::parse_hex(&sha).and_then(|w| crate::stalker::sample(&w)) {
                    // No list to look in, but the stalkerware samples ship inside the app.
                    listed = true;
                    stalker = json!(app);
                }
                // YARA: reuse the remembered verdict only if it was read by THIS rule set.
                let (mut ytag, mut rules) = (String::new(), String::new());
                if yara_tag.is_some() {
                    // An app file (.apk) is read however big it is: yara::scan caps its own view
                    // (64 MB of code) and maps the raw file rather than loading it. Before 29 Sep 14:40
                    // every APK over 64 MB (DuckDuckGo 170 MB, Firefox 122 MB) was only fingerprinted.
                    if (e.size > opts.max_yara && !is_apk(&e.path)) || e.size == 0 {
                        if e.size > opts.max_yara {
                            y_big.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if let Some((_, t, r)) = mem.filter(|(_, t, _)| *t == tag) {
                        ytag = t.clone();
                        rules = r.clone();
                        y_read.fetch_add(1, Ordering::Relaxed);
                    } else if crash_skip.contains(&path_s) {
                        // Virus Vigil died reading this file before: fingerprinted, never pattern-read again.
                        y_failed.fetch_add(1, Ordering::Relaxed);
                        crash_skipped.lock().unwrap_or_else(|p| p.into_inner()).push(path_s.clone());
                    } else {
                        note(Some(&path_s), None);
                        // A panic inside the pattern reader costs this one file, never the app.
                        let v = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| yara(&e.path)))
                            .unwrap_or_else(|p| {
                                let m = p.downcast_ref::<&str>().map(|s| s.to_string())
                                    .or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
                                json!({"ran": false, "reason": format!("the pattern check broke on this file ({m})")})
                            });
                        note(None, Some(&path_s));
                        if v["ran"] == true {
                            y_read.fetch_add(1, Ordering::Relaxed);
                            ytag = tag.clone();
                            rules = v["matches"].as_array().map(|m| {
                                m.iter().map(|x| format!("{}/{}", x["set"].as_str().unwrap_or(""), x["rule"].as_str().unwrap_or(""))).collect::<Vec<_>>().join(",")
                            }).unwrap_or_default();
                            // A file inside an archive on the known-malware list (samples travel zipped).
                            if list_ok && v["memberShas"].as_array().map_or(false, |a| a.iter().any(|s| lookup(s.as_str().unwrap_or(""))["found"] == true)) {
                                rules = if rules.is_empty() { "Vigil/ListedInside".into() } else { format!("{rules},Vigil/ListedInside") };
                            }
                        } else {
                            y_failed.fetch_add(1, Ordering::Relaxed);
                            let mut r = y_reason.lock().unwrap();
                            if r.is_none() {
                                *r = v["reason"].as_str().map(String::from);
                            }
                        }
                    }
                }
                if listed || !rules.is_empty() {
                    let rl: Vec<Value> = rules.split(',').filter(|s| !s.is_empty()).map(|s| {
                        let (set, rule) = s.split_once('/').unwrap_or(("", s));
                        json!({"set": set, "rule": rule, "weak": crate::yara::weak_rule(set, rule)})
                    }).collect();
                    // A list hit on a short plain-text file is not a verdict: the list holds ordinary
                    // files uploaded alongside malware (Vite's 161-byte template, 26 Sep 2026).
                    let list_weak = listed && small_text(&e.path);
                    let strong = (listed && !list_weak) || rl.iter().any(|r| r["weak"] != true);
                    // Vigil's own rules carry plain words for the page (remembered hits too: derived from the name).
                    let why: Vec<String> = rl.iter().filter(|r| r["set"] == "Vigil")
                        .map(|r| crate::deeplook::words(r["rule"].as_str().unwrap_or(""))).collect();
                    found.lock().unwrap().push(json!({"path": path_s, "name": name, "root": root, "sha256": sha, "list": listed,
                        "listWeak": list_weak, "rules": rl, "weak": !strong, "why": why,
                        "stalkerware": stalker}));
                } else if is_apk(&e.path) {
                    unknown_apps.lock().unwrap().push((e.mtime as u64, json!({"path": path_s, "name": name, "root": root, "sha256": sha})));
                }
                lines.lock().unwrap().push((k, format!("{sha}\t{ytag}\t{rules}")));
            });
        }
    });

    if let Some(p) = prog {
        p.finish();
    }
    // Every thread came back: no note may be left to be mistaken for a death.
    if let Some(c) = opts.crumbs.as_deref() {
        let _ = std::fs::remove_file(c);
    }
    let done = next.load(Ordering::Relaxed).min(all.len());
    // Newest first, so the first file not reached is the newest of those left (ms since 1970).
    let left_newest = all.get(done).map(|e| e.mtime).or(cut_mtime);
    let stopped = stop.load(Ordering::Relaxed);
    // Remember what was read now, plus old lines for files still here that this run did not reach.
    let mut new: HashMap<String, String> = lines.into_inner().unwrap().into_iter().collect();
    if stopped || capped_by_count {
        for (k, (s, t, r)) in &old {
            if here.contains(k) && !new.contains_key(k) {
                new.insert(k.clone(), format!("{s}\t{t}\t{r}"));
            }
        }
    }
    let mut out: Vec<String> = new.into_iter().map(|(k, v)| format!("{k}\t{v}")).collect();
    out.sort();
    let _ = std::fs::write(cache_file, out.join("\n"));

    let list = list_err.into_inner().unwrap().unwrap_or_else(|| {
        let mut p = probe.clone();
        if let Some(o) = p.as_object_mut() {
            o.remove("found"); // the probe's own "found" was about a made-up fingerprint
        }
        p
    });
    let list_checked = list["checked"] == true;
    let ran = yara_tag.is_some() && y_read.load(Ordering::Relaxed) > 0;
    let mut found = found.into_inner().unwrap();
    let mut unknown_apps = unknown_apps.into_inner().unwrap();
    unknown_apps.sort_by(|a, b| b.0.cmp(&a.0));
    unknown_apps.truncate(crate::hashonline::MAX_ASK);
    if !list_checked {
        // A list that failed part-way cannot vouch for anything: keep only YARA's own catches and
        // the stalkerware samples, which ship inside the app and need no downloaded list.
        found.retain(|f| f["rules"].as_array().map_or(false, |r| !r.is_empty()) || f["stalkerware"].is_string());
        for f in &mut found {
            if !f["stalkerware"].is_string() {
                f["list"] = json!(false);
            }
        }
    }
    json!({
        "checked": list_checked || ran,
        "list": list,
        "yara": {"ran": ran, "tag": yara_tag, "read": y_read.load(Ordering::Relaxed), "big": y_big.load(Ordering::Relaxed),
                 "failed": y_failed.load(Ordering::Relaxed), "reason": y_reason.into_inner().unwrap(), "maxMb": opts.max_yara >> 20},
        "roots": roots.iter().zip(&per_root).map(|((n, p), c)| json!({"name": n, "path": p.to_string_lossy(), "files": c})).collect::<Vec<_>>(),
        "files": files.load(Ordering::Relaxed), "bytes": bytes.load(Ordering::Relaxed), "fresh": fresh.load(Ordering::Relaxed),
        "unread": unread.load(Ordering::Relaxed), "unreadNames": unread_names.into_inner().unwrap(),
        "blocked": blocked.into_inner().unwrap(), "cloud": cloud, "badDirs": bad_dirs, "skippedDirs": skipped_dirs,
        "leftNewestMs": left_newest.map(|m| m as u64),
        "sealed": opts.skip.iter().filter(|p| p.is_dir()).count(),
        "found": found, "total": total, "capped": capped_by_count || out_of_time.load(Ordering::Relaxed),
        "left": total.saturating_sub(done), "ms": t0.elapsed().as_millis() as u64, "walkMs": walk_ms,
        "unknownApps": unknown_apps.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        "recovered": died, "crashSkipped": crash_skipped.into_inner().unwrap_or_else(|p| p.into_inner()),
    })
}
