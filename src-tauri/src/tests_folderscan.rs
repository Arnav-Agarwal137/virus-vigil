//! Tests for folderscan.rs: the laptop's Downloads/Desktop/Temp sweep. Every folder, list and file
//! is built in a temp folder; fingerprints are computed here from the files' own bytes, never typed.
//! YARA is stood in for by a closure that "matches" files containing the word EVIL, and counts
//! its calls - so what is re-read and what is remembered can be asserted exactly.

use super::folderscan::*;
use super::hashlist::{lookup_in, FULL};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

fn dir(tag: &str) -> super::testdir::TestDir {
    let d = super::testdir::TestDir::new(&format!("folders-{tag}"));
    std::fs::create_dir_all(d.join("lists")).unwrap();
    std::fs::create_dir_all(d.join("Downloads").join("sub")).unwrap();
    std::fs::create_dir_all(d.join("Temp")).unwrap();
    d
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn roots(d: &Path) -> Vec<(String, PathBuf)> {
    vec![("Downloads".into(), d.join("Downloads")), ("Temp".into(), d.join("Temp"))]
}
fn write_at(p: &Path, b: &[u8], secs_ago: u64) {
    std::fs::write(p, b).unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs_ago)).unwrap();
}
fn list_with(d: &Path, bad: &[&[u8]]) {
    let body: Vec<String> = bad.iter().map(|b| sha(b)).collect();
    std::fs::write(d.join("lists").join(FULL), format!("# sha256_hash\n{}\n{}\n", sha(b"filler"), body.join("\n"))).unwrap();
}
fn opts() -> Opts {
    Opts { max_yara: 1 << 20, max_files: 1000, budget: Duration::from_secs(60), threads: 3, skip: Vec::new(), progress: None, crumbs: None }
}
/// A stand-in YARA: matches files containing "EVIL"; counts calls.
fn fake_yara(calls: &AtomicUsize) -> impl Fn(&Path) -> Value + Sync + '_ {
    move |p: &Path| {
        calls.fetch_add(1, Ordering::SeqCst);
        let b = std::fs::read(p).unwrap_or_default();
        let hit = b.windows(4).any(|w| w == b"EVIL");
        json!({"ran": true, "matches": if hit { json!([{"rule": "Evil_Word", "set": "test"}]) } else { json!([]) }})
    }
}
fn run(d: &Path, calls: &AtomicUsize, tag: Option<&str>, o: &Opts) -> Value {
    let ld = d.join("lists");
    sweep_with(&roots(d), &ld.join(CACHE), |s: &str| lookup_in(&ld, s), fake_yara(calls), tag.map(String::from), o)
}
fn found_names(v: &Value) -> Vec<String> {
    let mut n: Vec<String> = v["found"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap().to_string()).collect();
    n.sort();
    n
}

#[test]
fn a_listed_file_and_a_yara_match_are_found_and_clean_files_are_not() {
    let d = dir("found");
    write_at(&d.join("Downloads").join("Setup.exe"), b"MZ pretend fake game", 10);
    write_at(&d.join("Downloads").join("sub").join("notes.txt"), b"shopping list", 10);
    write_at(&d.join("Temp").join("dropper.js"), b"var x = 'EVIL';", 10);
    list_with(&d, &[b"MZ pretend fake game"]);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(v["checked"], true, "{v}");
    assert_eq!(v["files"], 3, "{v}");
    assert_eq!(found_names(&v), vec!["Setup.exe", "dropper.js"], "{v}");
    let setup = v["found"].as_array().unwrap().iter().find(|f| f["name"] == "Setup.exe").unwrap();
    assert_eq!(setup["list"], true);
    assert_eq!(setup["sha256"], sha(b"MZ pretend fake game"));
    assert_eq!(setup["root"], "Downloads");
    let js = v["found"].as_array().unwrap().iter().find(|f| f["name"] == "dropper.js").unwrap();
    assert_eq!(js["list"], false);
    assert_eq!(js["rules"], json!([{"set": "test", "rule": "Evil_Word", "weak": false}]));
    assert_eq!(v["list"]["count"], 2, "{v}");
    assert!(v["list"].get("found").is_none(), "the probe's own found is not reported: {v}");
    assert_eq!(v["roots"], json!([{"name": "Downloads", "path": d.join("Downloads").to_string_lossy(), "files": 2},
                                  {"name": "Temp", "path": d.join("Temp").to_string_lossy(), "files": 1}]));
    assert_eq!(v["yara"]["read"], 3);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

/// A file INSIDE an archive that is on the known-malware list marks the archive (29 Sep; the list
/// holds unzipped samples, which travel zipped). The stand-in YARA reports inner fingerprints the
/// way yara::scan does (`memberShas`). Mutant: the lookup of memberShas never matching -> RED.
#[test]
fn a_listed_file_inside_an_archive_marks_the_archive() {
    let d = dir("inside");
    write_at(&d.join("Downloads").join("samples.zip"), b"PK pretend zip A", 10);
    write_at(&d.join("Downloads").join("photos.zip"), b"PK pretend zip B", 10);
    list_with(&d, &[b"inner sample"]);
    let ld = d.join("lists");
    let calls = AtomicUsize::new(0);
    let y = |p: &Path| {
        calls.fetch_add(1, Ordering::SeqCst);
        let inner: &[u8] = if p.ends_with("samples.zip") { b"inner sample" } else { b"holiday.jpg" };
        json!({"ran": true, "matches": [], "memberShas": [sha(b"unrelated"), sha(inner)]})
    };
    let v = sweep_with(&roots(&d), &ld.join(CACHE), |s: &str| lookup_in(&ld, s), y, Some("t-in".into()), &opts());
    assert_eq!(found_names(&v), vec!["samples.zip"], "{v}");
    let f = &v["found"][0];
    assert_eq!(f["list"], false, "the archive itself is not listed");
    assert_eq!(f["rules"], json!([{"set": "Vigil", "rule": "ListedInside", "weak": false}]), "{v}");
}

#[test]
fn nothing_to_look_with_means_not_looked_up_and_nothing_read() {
    let d = dir("nothing");
    write_at(&d.join("Downloads").join("a.exe"), b"a", 10);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, None, &opts());
    assert_eq!(v["checked"], false, "{v}");
    assert_eq!(v["files"], 0, "{v}");
    assert!(!d.join("lists").join(CACHE).exists(), "no fingerprints taken: {v}");
}

#[test]
fn no_list_but_yara_still_sweeps_and_says_the_list_was_not_used() {
    let d = dir("yaraonly");
    write_at(&d.join("Temp").join("x.ps1"), b"EVIL", 10);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(v["checked"], true, "{v}");
    assert_eq!(v["list"]["checked"], false, "{v}");
    assert_eq!(found_names(&v), vec!["x.ps1"]);
}

#[test]
fn a_repeat_run_reads_nothing_again_until_a_file_or_the_rules_change() {
    let d = dir("cache");
    let f = d.join("Downloads").join("tool.exe");
    write_at(&f, b"harmless tool", 100);
    write_at(&d.join("Temp").join("b.txt"), b"b", 100);
    list_with(&d, &[b"MZ never here"]);
    let calls = AtomicUsize::new(0);
    let first = run(&d, &calls, Some("t1"), &opts());
    assert_eq!((first["fresh"].clone(), calls.load(Ordering::SeqCst)), (json!(2), 2), "{first}");
    let second = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(second["fresh"], 0, "{second}");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "YARA verdicts remembered: {second}");
    assert_eq!(second["yara"]["read"], 2, "remembered verdicts still count as read: {second}");
    // New rules: every file is read by YARA again, but not fingerprinted again.
    let third = run(&d, &calls, Some("t2"), &opts());
    assert_eq!(third["fresh"], 0, "{third}");
    assert_eq!(calls.load(Ordering::SeqCst), 4, "{third}");
    // The file changes into a listed one: read again and caught.
    list_with(&d, &[b"MZ now bad"]);
    write_at(&f, b"MZ now bad", 5);
    let fourth = run(&d, &calls, Some("t2"), &opts());
    assert_eq!(fourth["fresh"], 1, "{fourth}");
    assert_eq!(found_names(&fourth), vec!["tool.exe"], "{fourth}");
}

#[test]
fn a_big_file_is_fingerprinted_but_not_read_by_yara() {
    let d = dir("big");
    let mut big = vec![b'A'; 2 << 20];
    big[10..14].copy_from_slice(b"EVIL");
    write_at(&d.join("Downloads").join("movie.mp4"), &big, 10);
    list_with(&d, &[&big]);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(calls.load(Ordering::SeqCst), 0, "{v}");
    assert_eq!(v["yara"]["big"], 1, "{v}");
    let f = &v["found"][0];
    assert_eq!((f["name"].clone(), f["list"].clone(), f["rules"].clone()), (json!("movie.mp4"), json!(true), json!([])), "{v}");
}

#[test]
fn the_newest_files_go_first_and_a_capped_run_keeps_what_it_did_not_reach() {
    let d = dir("cap");
    write_at(&d.join("Downloads").join("old.txt"), b"old", 5000);
    write_at(&d.join("Downloads").join("mid.txt"), b"mid", 500);
    write_at(&d.join("Temp").join("new.txt"), b"new EVIL", 5);
    list_with(&d, &[b"MZ never here"]);
    let calls = AtomicUsize::new(0);
    let all = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(all["capped"], false, "{all}");
    let o = Opts { max_files: 2, threads: 1, ..opts() };
    let v = run(&d, &calls, Some("t1"), &o);
    assert_eq!(v["capped"], true, "{v}");
    assert_eq!(v["total"], 3);
    assert_eq!(v["left"], 1, "{v}");
    assert_eq!(v["files"], 2, "{v}");
    assert_eq!(found_names(&v), vec!["new.txt"], "the newest was among those read: {v}");
    let mem = std::fs::read_to_string(d.join("lists").join(CACHE)).unwrap();
    assert!(mem.contains("old.txt"), "the unreached file's remembered line is kept: {mem}");
    // The date the page gives for "not read": the unreached old.txt's (~5000 s ago), never mid.txt's.
    assert!(all["leftNewestMs"].is_null(), "nothing left, no date: {all}");
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
    let left = v["leftNewestMs"].as_u64().expect("a date for what was left");
    assert!(left < now - 4_000_000 && left > now - 6_000_000, "left {left} vs now {now}: {v}");
}

#[test]
fn program_building_folders_are_skipped_and_counted_and_a_plain_build_folder_is_not() {
    let d = dir("tooldirs");
    let dl = d.join("Downloads");
    for sub in ["node_modules/pkg", ".git/objects", "proj/dist", "photos/build"] {
        std::fs::create_dir_all(dl.join(sub)).unwrap();
    }
    std::fs::write(dl.join("proj").join("package.json"), b"{}").unwrap();
    write_at(&dl.join("node_modules").join("pkg").join("a.exe"), b"MZ lib EVIL", 10);
    write_at(&dl.join(".git").join("objects").join("b.bin"), b"git EVIL", 10);
    write_at(&dl.join("proj").join("dist").join("c.js"), b"bundle EVIL", 10);
    // "build" with no project file beside it is an ordinary folder: swept.
    write_at(&dl.join("photos").join("build").join("d.exe"), b"MZ mine EVIL", 10);
    list_with(&d, &[b"MZ never here"]);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(v["skippedDirs"], 3, "{v}");
    assert_eq!(found_names(&v), vec!["d.exe"], "{v}");
    // package.json itself is swept (the project folder is, only its build output is not).
    assert_eq!(v["files"], 2, "{v}");
}

#[test]
fn a_list_that_fails_part_way_vouches_for_nothing() {
    let d = dir("midrun");
    // a.exe is the NEWEST, so the list answers "found" for it BEFORE failing on c.txt (26 Sep: with
    // a.exe oldest the list failed first, nothing list-found existed, and the check below passed
    // over an empty list whatever the code did - a mutant removing the clean-up survived).
    write_at(&d.join("Downloads").join("a.exe"), b"MZ listed", 10);
    write_at(&d.join("Downloads").join("b.js"), b"EVIL", 20);
    write_at(&d.join("Temp").join("c.txt"), b"plain", 30);
    list_with(&d, &[b"MZ listed"]);
    let ld = d.join("lists");
    let n = AtomicUsize::new(0);
    let calls = AtomicUsize::new(0);
    let o = Opts { threads: 1, ..opts() };
    let v = sweep_with(&roots(&d), &ld.join(CACHE), |s: &str| {
        if n.fetch_add(1, Ordering::SeqCst) < 3 { lookup_in(&ld, s) } else { json!({"checked": false, "found": false, "error": "list replaced"}) }
    }, fake_yara(&calls), Some("t1".into()), &o);
    assert_eq!(v["list"]["checked"], false, "{v}");
    assert_eq!(v["list"]["error"], "list replaced", "{v}");
    // Only YARA's own catch survives; a list "hit" from a list that then failed is not claimed.
    assert_eq!(n.load(Ordering::SeqCst), 4, "probe + a.exe (found) + b.js, then c.txt failed: {v}");
    assert_eq!(found_names(&v), vec!["b.js"], "{v}");
    for f in v["found"].as_array().unwrap() {
        assert_eq!(f["list"], false, "{v}");
        assert!(!f["rules"].as_array().unwrap().is_empty(), "{v}");
    }
    assert_eq!(v["checked"], true, "YARA still read files: {v}");

    // The same failure with no YARA at all: nothing could look, so never "checked".
    let _ = std::fs::remove_file(ld.join(CACHE));
    let n2 = AtomicUsize::new(0);
    let v = sweep_with(&roots(&d), &ld.join(CACHE), |s: &str| {
        if n2.fetch_add(1, Ordering::SeqCst) < 2 { lookup_in(&ld, s) } else { json!({"checked": false, "found": false, "error": "list replaced"}) }
    }, fake_yara(&calls), None, &o);
    assert_eq!(v["checked"], false, "{v}");
    assert_eq!(v["found"].as_array().unwrap().len(), 0, "{v}");
}

#[test]
fn a_run_out_of_time_says_capped_and_what_it_left() {
    let d = dir("budget");
    write_at(&d.join("Downloads").join("a.txt"), b"a", 10);
    write_at(&d.join("Temp").join("b.txt"), b"b EVIL", 20);
    list_with(&d, &[b"MZ never here"]);
    let calls = AtomicUsize::new(0);
    let o = Opts { budget: Duration::ZERO, threads: 1, ..opts() };
    let v = run(&d, &calls, Some("t1"), &o);
    assert_eq!(v["capped"], true, "{v}");
    assert_eq!(v["files"], 0, "{v}");
    assert_eq!(v["left"], 2, "{v}");
    assert!(v["leftNewestMs"].as_u64().is_some(), "{v}");
    assert_eq!(found_names(&v), Vec::<String>::new(), "{v}");
}

/// A junction (made without admin, unlike a symlink) leading out of the swept folder is not followed.
#[cfg(windows)]
#[test]
fn a_junction_out_of_the_folder_is_not_followed() {
    let d = dir("junction");
    let outside = d.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    write_at(&outside.join("far.exe"), b"MZ far EVIL", 10);
    write_at(&d.join("Downloads").join("here.txt"), b"here", 10);
    let link = d.join("Downloads").join("jump");
    let ok = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&link).arg(&outside).output().unwrap();
    assert!(ok.status.success() && link.exists(), "junction not made: {}", String::from_utf8_lossy(&ok.stdout));
    list_with(&d, &[b"MZ never here"]);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(found_names(&v), Vec::<String>::new(), "{v}");
    assert_eq!(v["files"], 1, "{v}");
}

#[test]
fn a_poisoned_memory_line_is_not_trusted() {
    let d = dir("poison");
    let f = d.join("Downloads").join("a.exe");
    write_at(&f, b"MZ listed", 50);
    list_with(&d, &[b"MZ listed"]);
    let m = std::fs::metadata(&f).unwrap();
    let t = m.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    std::fs::write(d.join("lists").join(CACHE), format!("{}\t{}\t{}\t{}\tt1\t", f.to_string_lossy(), m.len(), t, "0".repeat(63) + "z")).unwrap();
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(v["fresh"], 1, "{v}");
    assert_eq!(found_names(&v), vec!["a.exe"], "{v}");
}

/// Not a test: the real sweep on THIS laptop, run by hand
/// (`VV_SWEEP_CACHE=<scratch file> cargo test --lib real_folders -- --ignored --nocapture`).
/// Prints totals and the names of any hits only; the memory goes where VV_SWEEP_CACHE says.
#[test]
#[ignore]
fn real_folders() {
    let cache = PathBuf::from(std::env::var("VV_SWEEP_CACHE").expect("set VV_SWEEP_CACHE to a scratch file"));
    let dir = super::hashlist::lists_dir();
    let book = super::hashlist::open_book(&dir);
    let lookup = |s: &str| match &book { Ok(b) => b.lookup(s), Err(v) => v.clone() };
    let tag = super::yara::tag();
    let v = sweep_with(&default_roots(), &cache, lookup, super::yara::scan, tag, &Opts::default());
    let mut s = v.clone();
    for k in ["found", "blocked"] {
        s[k] = json!(v[k].as_array().map(|a| a.iter().map(|f| json!({"name": f["name"], "root": f["root"], "list": f["list"], "rules": f["rules"]})).collect::<Vec<_>>()));
    }
    s["roots"] = json!(v["roots"].as_array().unwrap().iter().map(|r| json!([r["name"], r["files"]])).collect::<Vec<_>>());
    s["unreadNames"] = json!(null);
    println!("REAL {}", s);
}

#[cfg(windows)]
#[test]
fn a_locked_file_is_counted_unread_never_clean() {
    use std::os::windows::fs::OpenOptionsExt;
    let d = dir("locked");
    let f = d.join("Temp").join("in-use.tmp");
    write_at(&f, b"busy", 10);
    write_at(&d.join("Temp").join("free.txt"), b"free", 10);
    list_with(&d, &[b"MZ never here"]);
    // Held open with no sharing, as a running installer holds its own file.
    let _hold = std::fs::OpenOptions::new().read(true).share_mode(0).open(&f).unwrap();
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(v["unread"], 1, "{v}");
    assert_eq!(v["unreadNames"], json!(["in-use.tmp"]), "{v}");
    assert_eq!(v["files"], 1, "{v}");
}

/// 26 Sep 2026: the first uncapped sweep of his files called Vite's stock 161-byte template
/// "harmful" because its fingerprint is on MalwareBazaar's list. A list hit on short plain text is
/// "worth a look"; on a program, or on longer text, it is still a verdict.
#[test]
fn a_list_hit_on_short_plain_text_is_weak_and_on_a_program_or_long_text_is_not() {
    let d = dir("weak-list");
    let template: &[u8] = b"import { defineConfig } from 'vite'\nimport react from '@vitejs/plugin-react'\n\n// https://vite.dev/config/\nexport default defineConfig({\n  plugins: [react()],\n})\n";
    let program: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00 a tiny program";
    let nul_text: &[u8] = b"looks like text\x00but has a NUL";
    let long_text = vec![b'a'; 1025];
    write_at(&d.join("Downloads").join("vite.config.js"), template, 10);
    write_at(&d.join("Downloads").join("tiny.exe"), program, 20);
    write_at(&d.join("Downloads").join("nul.bin"), nul_text, 30);
    write_at(&d.join("Downloads").join("long.js"), &long_text, 40);
    write_at(&d.join("Downloads").join("evil.txt"), b"EVIL", 50);
    list_with(&d, &[template, program, nul_text, &long_text]);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    let get = |n: &str| v["found"].as_array().unwrap().iter().find(|f| f["name"] == n).cloned().unwrap_or(Value::Null);
    assert_eq!(found_names(&v), vec!["evil.txt", "long.js", "nul.bin", "tiny.exe", "vite.config.js"]);
    assert_eq!(get("vite.config.js")["weak"], true);
    assert_eq!(get("vite.config.js")["listWeak"], true);
    assert_eq!(get("tiny.exe")["weak"], false);
    assert_eq!(get("nul.bin")["weak"], false);
    assert_eq!(get("long.js")["weak"], false);
    // a rule nobody marked weak (the stand-in's) stays strong
    assert_eq!(get("evil.txt")["weak"], false);
    assert_eq!(get("evil.txt")["rules"][0]["weak"], false);
    // remembered on the second run: the same answer
    let v2 = run(&d, &calls, Some("t1"), &opts());
    let w2: Vec<bool> = ["vite.config.js", "tiny.exe"].iter().map(|n| v2["found"].as_array().unwrap().iter().find(|f| f["name"] == *n).unwrap()["weak"] == true).collect();
    assert_eq!(w2, vec![true, false]);
}

#[test]
fn small_text_is_exactly_the_boilerplate_sized_plain_text() {
    let d = dir("small-text");
    let p = |n: &str, b: &[u8]| { let q = d.join("Temp").join(n); std::fs::write(&q, b).unwrap(); q };
    assert!(small_text(&p("a.js", &vec![b'x'; 1024])));
    assert!(!small_text(&p("b.js", &vec![b'x'; 1025])));
    assert!(!small_text(&p("c.js", b"")));
    assert!(!small_text(&p("d.bin", b"MZ plain")));
    assert!(!small_text(&p("e.bin", b"\x7fELF plain")));
    assert!(!small_text(&p("f.zip", b"PK plain")));
    assert!(!small_text(&p("g.txt", b"a\x00b")));
    assert!(!small_text(&d.join("Temp").join("missing")));
}

/// The phone's Android/data and Android/obb are skipped by exact path: a harmful file inside is
/// not read (Android seals them anyway), and the same file one folder away still is.
#[test]
fn skipped_folders_are_not_entered_and_their_neighbours_are() {
    let d = dir("skip");
    let sealed = d.join("Downloads").join("Android").join("data");
    std::fs::create_dir_all(&sealed).unwrap();
    std::fs::create_dir_all(d.join("Downloads").join("Android").join("media")).unwrap();
    write_at(&sealed.join("inside.js"), b"EVIL sealed", 10);
    write_at(&d.join("Downloads").join("Android").join("media").join("beside.js"), b"EVIL media", 10);
    list_with(&d, &[]);
    let calls = AtomicUsize::new(0);
    let o = Opts { skip: vec![sealed.clone()], ..opts() };
    let v = run(&d, &calls, Some("t1"), &o);
    assert_eq!(found_names(&v), vec!["beside.js"], "{v}");
    assert_eq!(v["total"], 1, "{v}");
    assert_eq!(v["sealed"], 1, "{v}");
    let v2 = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(found_names(&v2), vec!["beside.js", "inside.js"], "without the skip both are read: {v2}");
}

/// The live counts are the sweep's own: files listed, files reached, files read fresh and their
/// bytes - and a second run that remembers everything reads 0 fresh bytes.
#[test]
fn progress_counts_what_the_sweep_actually_read() {
    static P: std::sync::LazyLock<Progress> = std::sync::LazyLock::new(Progress::default);
    let d = dir("progress");
    write_at(&d.join("Downloads").join("a.bin"), &[7u8; 3000], 30);
    write_at(&d.join("Downloads").join("sub").join("b.bin"), &[8u8; 500], 20);
    write_at(&d.join("Temp").join("c.bin"), &[9u8; 25], 10);
    list_with(&d, &[]);
    let calls = AtomicUsize::new(0);
    let o = Opts { progress: Some(&P), threads: 1, ..opts() };
    let v = run(&d, &calls, Some("t1"), &o);
    let s = P.snapshot();
    assert_eq!(s["running"], false, "finished: {s}");
    assert_eq!(s["listed"], 3, "{s}");
    assert_eq!(s["total"], 3, "{s}");
    assert_eq!(s["done"], 3, "{s}");
    assert_eq!(s["fresh"], 3, "{s}");
    assert_eq!(s["bytes"], 3525, "{s}");
    assert_eq!(v["fresh"], 3, "{v}");
    let _ = run(&d, &calls, Some("t1"), &o);
    let s = P.snapshot();
    assert_eq!((s["done"].as_u64(), s["fresh"].as_u64(), s["bytes"].as_u64()), (Some(3), Some(0), Some(0)), "remembered run: {s}");
    // The row names the file it is on even when nothing is read fresh (it used to stay empty or stale).
    let cur = s["current"].as_str().unwrap_or("");
    assert!(["a.bin", "b.bin", "c.bin"].iter().any(|n| cur.ends_with(n)), "remembered run names a file: {s}");
}

/// 29 Sep 2026: a reloaded page started a second app check over a running one. Eight threads race
/// for one turn: exactly one gets it; the turn comes back when dropped, and after a panic.
#[test]
fn only_one_run_at_a_time_and_the_turn_comes_back() {
    static T: OneAtATime = OneAtATime::new();
    let barrier = std::sync::Barrier::new(8);
    let got = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                barrier.wait();
                if let Some(turn) = T.take() {
                    got.fetch_add(1, Ordering::SeqCst);
                    // Hold it until every thread has asked.
                    std::thread::sleep(Duration::from_millis(200));
                    drop(turn);
                }
            });
        }
    });
    assert_eq!(got.load(Ordering::SeqCst), 1, "exactly one run may start");
    let turn = T.take().expect("free again once the run ended");
    assert!(T.take().is_none(), "second ask while held must be refused");
    drop(turn);
    let r = std::panic::catch_unwind(|| {
        let _t = T.take().unwrap();
        panic!("a run that dies part-way");
    });
    assert!(r.is_err());
    assert!(T.take().is_some(), "a run that panicked must give its turn back");
}

#[test]
fn an_app_file_over_the_size_limit_is_still_read_but_a_big_video_is_not() {
    // 29 Sep 14:40: APKs over max_yara were only fingerprinted, so the rules never saw big apps.
    let d = dir("bigapk");
    let mut apk = vec![b'x'; 2 << 20];
    apk.extend_from_slice(b"EVIL");
    write_at(&d.join("Downloads").join("KYC-Update.APK"), &apk, 10);
    let mut video = vec![b'v'; 2 << 20];
    video.extend_from_slice(b"EVIL");
    write_at(&d.join("Downloads").join("movie.mp4"), &video, 10);
    list_with(&d, &[]);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only the app file goes to the rules: {v}");
    assert_eq!(found_names(&v), vec!["KYC-Update.APK"], "{v}");
    assert_eq!(v["yara"]["read"], 1, "{v}");
    assert_eq!(v["yara"]["big"], 1, "the video is counted as too big, not read: {v}");
}

#[test]
fn a_file_that_breaks_the_pattern_reader_costs_that_file_not_the_sweep() {
    // 29 Sep: 0.1.26 crashed again and again on his phone once storage was allowed; the release
    // build aborted on any panic. One odd file must be one failed file.
    let d = dir("panic");
    write_at(&d.join("Downloads").join("odd.bin"), b"BOOM inside", 10);
    write_at(&d.join("Downloads").join("fine.txt"), b"hello", 10);
    list_with(&d, &[]);
    let ld = d.join("lists");
    let yara = |p: &Path| {
        if std::fs::read(p).unwrap_or_default().starts_with(b"BOOM") {
            panic!("pretend parser bug");
        }
        json!({"ran": true, "matches": []})
    };
    let v = sweep_with(&roots(&d), &ld.join(CACHE), |s: &str| lookup_in(&ld, s), yara, Some("t1".into()), &opts());
    assert_eq!(v["files"], 2, "{v}");
    assert_eq!(v["yara"]["read"], 1, "{v}");
    assert_eq!(v["yara"]["failed"], 1, "{v}");
    assert!(v["yara"]["reason"].as_str().unwrap_or("").contains("pretend parser bug"), "{v}");
}

#[test]
fn a_crash_note_left_behind_skips_that_file_says_so_and_is_cleared() {
    let d = dir("crumbs");
    let bad = d.join("Downloads").join("killer.mp4");
    write_at(&bad, b"kills the app", 10);
    write_at(&d.join("Downloads").join("fine.txt"), b"hello", 10);
    list_with(&d, &[]);
    let crumbs = d.join("lists").join("sweep-reading.txt");
    std::fs::write(&crumbs, bad.to_string_lossy().as_bytes()).unwrap(); // the app died reading it
    let o = Opts { crumbs: Some(crumbs.clone()), ..opts() };
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &o);
    assert_eq!(v["recovered"], true, "{v}");
    assert_eq!(v["crashSkipped"], json!([bad.to_string_lossy()]), "{v}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only fine.txt went to the patterns: {v}");
    assert_eq!(v["files"], 2, "still fingerprinted: {v}");
    assert!(!crumbs.exists(), "a finished run leaves no note");
    assert!(std::fs::read_to_string(crash_skip_file(&crumbs)).unwrap().contains("killer.mp4"));
    // Next run: no death this time, the file stays skipped and said; still nothing re-read wrongly.
    std::fs::remove_file(d.join("lists").join(CACHE)).ok();
    let v2 = run(&d, &calls, Some("t1"), &o);
    assert_eq!(v2["recovered"], false, "{v2}");
    assert_eq!(v2["crashSkipped"].as_array().unwrap().len(), 1, "{v2}");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "{v2}");
}

#[test]
fn a_spy_app_sample_carries_its_name_to_the_found_row() {
    // The look-up names Echap stalkerware samples (hashlist::Book::lookup); the page words the hit
    // from this field, so it must reach the row. The ordinary list hit beside it carries none.
    let d = dir("stalker");
    write_at(&d.join("Downloads").join("spy.apk"), b"PK spy sample", 10);
    write_at(&d.join("Downloads").join("plain.exe"), b"MZ listed", 20);
    list_with(&d, &[b"PK spy sample", b"MZ listed"]);
    let ld = d.join("lists");
    let spy = sha(b"PK spy sample");
    let calls = AtomicUsize::new(0);
    let v = sweep_with(&roots(&d), &ld.join(CACHE), |s: &str| {
        let mut v = lookup_in(&ld, s);
        if s == spy {
            v["stalkerware"] = json!("TheTruthSpy");
        }
        v
    }, fake_yara(&calls), Some("t1".into()), &opts());
    let row = |n: &str| v["found"].as_array().unwrap().iter().find(|f| f["name"] == n).cloned().unwrap_or_else(|| panic!("{n} not found: {v}"));
    assert_eq!(row("spy.apk")["stalkerware"], "TheTruthSpy", "{v}");
    assert_eq!(row("spy.apk")["list"], true, "{v}");
    assert_eq!(row("plain.exe")["stalkerware"], Value::Null, "{v}");
}

#[test]
fn with_no_list_a_spy_app_sample_is_still_found() {
    // The Echap samples ship inside the app: a sweep before any list download still names one,
    // and an ordinary file is not claimed as listed.
    let d = dir("stalker-nolist");
    write_at(&d.join("Downloads").join("spy.apk"), b"PK spy sample no list", 10);
    write_at(&d.join("Downloads").join("plain.exe"), b"MZ plain", 20);
    let mut w = [0u8; 32];
    w.copy_from_slice(&Sha256::digest(b"PK spy sample no list"));
    super::stalker::TEST_SAMPLES.lock().unwrap().push(w);
    let calls = AtomicUsize::new(0);
    let v = run(&d, &calls, Some("t1"), &opts());
    assert_eq!(v["list"]["checked"], false, "no list: {v}");
    assert_eq!(found_names(&v), vec!["spy.apk"], "{v}");
    let f = &v["found"][0];
    assert_eq!(f["stalkerware"], "Test stalker", "{v}");
    assert_eq!(f["list"], true, "{v}");
    assert_eq!(f["weak"], false, "{v}");
}
