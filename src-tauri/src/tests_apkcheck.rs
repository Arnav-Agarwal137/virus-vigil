//! Tests for apkcheck.rs: installed apps' APK files against the known-malware list.
//! Every list and "APK" is built in a temp folder; the fingerprints are computed here from the
//! files' own bytes, never typed in.

use super::apkcheck::*;
use super::hashlist::FULL;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn dir(tag: &str) -> super::testdir::TestDir {
    super::testdir::TestDir::new(&format!("apkcheck-{tag}"))
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn app(pkg: &str, paths: &[&PathBuf]) -> App {
    App { pkg: pkg.into(), paths: paths.iter().map(|p| p.to_string_lossy().into_owned()).collect(), maker: false }
}

/// A list folder holding `bad`'s fingerprint, plus two APK-like files: one bad, one clean.
fn setup(tag: &str) -> (super::testdir::TestDir, PathBuf, PathBuf) {
    let d = dir(tag);
    let bad = d.join("bad-base.apk");
    let good = d.join("good-base.apk");
    std::fs::write(&bad, b"PK\x03\x04 pretend banking trojan").unwrap();
    std::fs::write(&good, b"PK\x03\x04 pretend calculator").unwrap();
    std::fs::write(d.join(FULL), format!("# sha256_hash\n{}\n{}\n", sha(b"something else"), sha(b"PK\x03\x04 pretend banking trojan"))).unwrap();
    (d, bad, good)
}

#[test]
fn a_listed_installed_app_is_found_and_a_clean_one_is_not() {
    let (d, bad, good) = setup("found");
    let v = check_in(&d, &[app("com.calc", &[&good]), app("com.trojan", &[&bad])]);
    assert_eq!(v["checked"], true, "{v}");
    assert_eq!(v["apps"], 2);
    assert_eq!(v["files"], 2);
    let f = v["found"].as_array().unwrap();
    assert_eq!(f.len(), 1, "exactly the listed one: {v}");
    assert_eq!(f[0]["pkg"], "com.trojan");
    assert_eq!(f[0]["sha256"], sha(b"PK\x03\x04 pretend banking trojan"));
    assert_eq!(v["count"], 2, "the list's size is reported: {v}");
}

#[test]
fn a_split_apk_is_checked_too() {
    // The listed file is the SECOND path of the app (a split), not its base.
    let (d, bad, good) = setup("split");
    let v = check_in(&d, &[app("com.split", &[&good, &bad])]);
    assert_eq!(v["files"], 2, "{v}");
    assert_eq!(v["found"][0]["pkg"], "com.split", "{v}");
}

#[test]
fn no_list_means_not_looked_up_never_none_found() {
    let d = dir("nolist");
    let good = d.join("good-base.apk");
    std::fs::write(&good, b"clean").unwrap();
    let good2 = d.join("good2-base.apk");
    std::fs::write(&good2, b"also clean").unwrap();
    let v = check_in(&d, &[app("com.calc", &[&good]), app("com.notes", &[&good2])]);
    assert_eq!(v["checked"], false, "{v}");
    assert!(v["error"].is_string(), "{v}");
    // Nothing to compare against, so not one APK is read (the first run reads every app).
    assert_eq!(v["files"], 0, "{v}");
    assert!(!d.join(CACHE).exists(), "no fingerprints were taken: {v}");
}

#[test]
fn a_list_that_fails_part_way_is_not_looked_up_never_none_found() {
    // The probe and the first app's look-up work; then the list goes (an update replacing it).
    // The listed app comes AFTER that, so "checked, nothing found" would be a false all-clear.
    let (d, bad, good) = setup("midrun");
    let calls = std::cell::Cell::new(0);
    let v = check_with(&d, &[app("com.calc", &[&good]), app("com.trojan", &[&bad])], |s| {
        calls.set(calls.get() + 1);
        if calls.get() <= 2 {
            super::hashlist::lookup_in(&d, s)
        } else {
            serde_json::json!({"checked": false, "found": false, "error": "list replaced"})
        }
    });
    assert_eq!(v["checked"], false, "{v}");
    assert_eq!(v["error"], "list replaced", "{v}");
}

#[test]
fn a_list_but_no_readable_app_is_checked_and_names_the_app() {
    let (d, _bad, _good) = setup("noneread");
    let v = check_in(&d, &[app("com.gone", &[&d.join("missing.apk")])]);
    assert_eq!(v["checked"], true, "{v}");
    assert_eq!(v["files"], 0, "{v}");
    assert_eq!(v["unread"], serde_json::json!(["com.gone"]), "{v}");
    assert_eq!(v["count"], 2, "the list's size still comes from the list: {v}");
}

#[test]
fn an_unreadable_apk_is_named_not_passed_off_as_clean() {
    let (d, _bad, good) = setup("unread");
    let v = check_in(&d, &[app("com.calc", &[&good]), app("com.gone", &[&d.join("missing.apk")])]);
    assert_eq!(v["checked"], true, "{v}");
    assert_eq!(v["unread"], serde_json::json!(["com.gone"]), "{v}");
    assert_eq!(v["files"], 1, "only the file actually read is counted: {v}");
}

#[test]
fn fingerprints_are_remembered_and_a_changed_file_is_read_again() {
    let (d, bad, good) = setup("cache");
    let first = check_in(&d, &[app("com.calc", &[&good])]);
    assert_eq!(first["fresh"], 1, "{first}");
    let second = check_in(&d, &[app("com.calc", &[&good])]);
    assert_eq!(second["fresh"], 0, "unchanged file taken from memory: {second}");
    // The app updates to the bad bytes (a different size): it must be read again and found.
    std::fs::write(&good, std::fs::read(&bad).unwrap()).unwrap();
    let third = check_in(&d, &[app("com.calc", &[&good])]);
    assert_eq!(third["fresh"], 1, "{third}");
    assert_eq!(third["found"][0]["pkg"], "com.calc", "the updated app is caught: {third}");
}

// ---- 29 Sep: installed apps' code read by the pattern rules and the deep look (check_reading).

/// A stand-in reader: "matches" files containing EVIL (a pattern rule), files containing TEST
/// (Vigil's test-file rule), and always reports Vigil's own app rule, which must be dropped here
/// (the page judges an installed app's permissions itself). Counts its calls.
fn fake_read(calls: &std::sync::atomic::AtomicUsize) -> impl Fn(&std::path::Path) -> serde_json::Value + '_ {
    move |p: &std::path::Path| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let b = std::fs::read(p).unwrap_or_default();
        let has = |w: &[u8]| b.windows(w.len()).any(|x| x == w);
        let mut m = vec![serde_json::json!({"set": "Vigil", "rule": "AppBankerShape"})];
        if has(b"EVIL") { m.push(serde_json::json!({"set": "test", "rule": "Evil_Word"})); }
        if has(b"TEST") { m.push(serde_json::json!({"set": "Vigil", "rule": "TestFileInside"})); }
        let inner: Vec<String> = if has(b"PAYLOAD") { vec![sha(b"inner payload")] } else { vec![] };
        serde_json::json!({"ran": true, "matches": m, "memberShas": inner})
    }
}
fn reader<'a>(read: &'a dyn Fn(&std::path::Path) -> serde_json::Value, tag: &str, crumbs: Option<PathBuf>) -> Reader<'a> {
    Reader { read, tag: tag.into(), crumbs }
}
fn hit_rules(v: &serde_json::Value, pkg: &str) -> Vec<String> {
    v["ruleHits"].as_array().unwrap().iter().filter(|h| h["pkg"] == pkg)
        .flat_map(|h| h["rules"].as_array().unwrap().iter().map(|r| format!("{}/{}", r["set"].as_str().unwrap(), r["rule"].as_str().unwrap())).collect::<Vec<_>>()).collect()
}

#[test]
fn installed_apps_are_pattern_read_and_own_permission_rules_are_left_to_the_page() {
    let (d, _bad, good) = setup("read");
    let evil = d.join("evil-base.apk");
    std::fs::write(&evil, b"PK\x03\x04 code with EVIL in it").unwrap();
    let test = d.join("test-base.apk");
    std::fs::write(&test, b"PK\x03\x04 assets with TEST inside").unwrap();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let f = fake_read(&calls);
    let apps = [app("com.calc", &[&good]), app("com.evil", &[&evil]), app("com.test", &[&test])];
    let v = check_full(&d, &apps, |s| super::hashlist::lookup_in(&d, s), Some(&reader(&f, "t1", None)));
    assert_eq!(v["patterns"]["ran"], true, "{v}");
    assert_eq!(v["patterns"]["read"], 3, "{v}");
    assert!(hit_rules(&v, "com.calc").is_empty(), "only Vigil's app rule matched, and it is dropped: {v}");
    assert_eq!(hit_rules(&v, "com.evil"), ["test/Evil_Word"]);
    assert_eq!(hit_rules(&v, "com.test"), ["Vigil/TestFileInside"]);
    let t = v["ruleHits"].as_array().unwrap().iter().find(|h| h["pkg"] == "com.test").unwrap();
    assert_eq!(t["weak"], false);
    assert!(t["why"][0].as_str().unwrap().contains("TEST file (EICAR)"), "{t}");
    assert_eq!(v["found"].as_array().unwrap().len(), 0, "a pattern hit is not a list hit: {v}");
}

#[test]
fn a_listed_file_inside_an_installed_app_is_named() {
    let (d, _bad, _good) = setup("inner");
    std::fs::write(d.join(super::hashlist::FULL), format!("# sha256_hash\n{}\n", sha(b"inner payload"))).unwrap();
    let carrier = d.join("carrier-base.apk");
    std::fs::write(&carrier, b"PK\x03\x04 assets PAYLOAD").unwrap();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let f = fake_read(&calls);
    let v = check_full(&d, &[app("com.carrier", &[&carrier])], |s| super::hashlist::lookup_in(&d, s), Some(&reader(&f, "t1", None)));
    assert_eq!(hit_rules(&v, "com.carrier"), ["Vigil/ListedInside"], "{v}");
}

#[test]
fn pattern_results_are_remembered_until_the_file_or_the_rules_change() {
    let (d, _bad, _good) = setup("patmem");
    let evil = d.join("evil-base.apk");
    std::fs::write(&evil, b"PK\x03\x04 code with EVIL in it").unwrap();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let f = fake_read(&calls);
    let apps = [app("com.evil", &[&evil])];
    let run = |tag: &str| check_full(&d, &apps, |s| super::hashlist::lookup_in(&d, s), Some(&reader(&f, tag, None)));
    run("t1");
    let second = run("t1");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1, "not read again: {second}");
    assert_eq!(second["patterns"]["remembered"], 1);
    assert_eq!(hit_rules(&second, "com.evil"), ["test/Evil_Word"], "a remembered hit is still reported");
    let third = run("t2");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2, "new rules: read again: {third}");
    std::fs::write(&evil, b"PK\x03\x04 updated, clean now").unwrap();
    let fourth = run("t2");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3, "a changed file is read again");
    assert!(hit_rules(&fourth, "com.evil").is_empty(), "{fourth}");
}

#[test]
fn an_app_file_that_crashed_the_reader_is_skipped_and_named() {
    let (d, _bad, good) = setup("crumbs");
    let evil = d.join("evil-base.apk");
    std::fs::write(&evil, b"PK\x03\x04 code with EVIL in it").unwrap();
    let crumbs = d.join("apps-reading.txt");
    // The app died reading evil-base.apk last time: the note is still there.
    std::fs::write(&crumbs, evil.to_string_lossy().as_bytes()).unwrap();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let f = fake_read(&calls);
    let apps = [app("com.calc", &[&good]), app("com.evil", &[&evil])];
    let v = check_full(&d, &apps, |s| super::hashlist::lookup_in(&d, s), Some(&reader(&f, "t1", Some(crumbs.clone()))));
    assert_eq!(v["patterns"]["recovered"], true, "{v}");
    assert_eq!(v["patterns"]["crashSkipped"], serde_json::json!([evil.to_string_lossy()]), "{v}");
    assert_eq!(v["patterns"]["read"], 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1, "the crashing file is not read again");
    assert!(!crumbs.exists(), "no note left after a clean run");
    // And it stays skipped on later runs.
    let again = check_full(&d, &apps, |s| super::hashlist::lookup_in(&d, s), Some(&reader(&f, "t1", Some(crumbs.clone()))));
    assert_eq!(again["patterns"]["crashSkipped"], serde_json::json!([evil.to_string_lossy()]), "{again}");
    assert_eq!(again["patterns"]["recovered"], false);
}

#[test]
fn a_reader_that_panics_costs_one_file() {
    let (d, _bad, good) = setup("panic");
    let other = d.join("other-base.apk");
    std::fs::write(&other, b"PK\x03\x04 another").unwrap();
    let boom = |p: &std::path::Path| -> serde_json::Value {
        if p.ends_with("good-base.apk") { panic!("odd file") }
        serde_json::json!({"ran": true, "matches": []})
    };
    let v = check_full(&d, &[app("com.calc", &[&good]), app("com.other", &[&other])], |s| super::hashlist::lookup_in(&d, s), Some(&reader(&boom, "t1", None)));
    assert_eq!(v["patterns"]["failed"], 1, "{v}");
    assert_eq!(v["patterns"]["read"], 1, "{v}");
    assert!(v["patterns"]["reason"].as_str().unwrap().contains("broke"), "{v}");
}

#[test]
fn without_a_reader_nothing_changes() {
    let (d, _bad, good) = setup("noreader");
    let v = check_in(&d, &[app("com.calc", &[&good])]);
    assert!(v.get("patterns").is_none() && v.get("ruleHits").is_none(), "{v}");
}

/// The real reader (yara::scan + deeplook) on a real app file with a program named like a photo
/// in its assets: the name trick is found inside; the app's own permission rules are not reported.
#[test]
fn the_real_reader_finds_a_disguised_program_inside_an_app() {
    use std::io::Write;
    let d = dir("realread");
    std::fs::write(d.join(FULL), format!("# sha256_hash\n{}\n", sha(b"filler"))).unwrap();
    let base = std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vv-hidden-stealer.apk")).unwrap();
    let mut c = std::io::Cursor::new(base);
    {
        let mut w = zip::ZipWriter::new_append(&mut c).unwrap();
        w.start_file("assets/photo.jpg.exe", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(&[b"MZ".as_slice(), &[0u8; 300]].concat()).unwrap();
        w.finish().unwrap();
    }
    let apk = d.join("base.apk");
    std::fs::write(&apk, c.into_inner()).unwrap();
    let Some(tag) = crate::yara::tag() else { panic!("rules not compiled") };
    let v = check_reading(&d, &[app("com.whatsapp.update", &[&apk])], &Reader { read: &crate::yara::scan, tag, crumbs: None });
    let r = hit_rules(&v, "com.whatsapp.update");
    assert!(r.contains(&"Vigil/Shape_double-ending".to_string()), "{v}");
    assert!(!r.iter().any(|x| x.starts_with("Vigil/App")), "{r:?}");
}

#[test]
fn a_poisoned_memory_line_is_not_trusted() {
    // A remembered line with a broken fingerprint is ignored and the file read again.
    let (d, bad, _good) = setup("poison");
    let k = {
        let m = std::fs::metadata(&bad).unwrap();
        let t = m.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        format!("{}\t{}\t{}", bad.to_string_lossy(), m.len(), t)
    };
    std::fs::write(d.join(CACHE), format!("{k}\tnot-a-fingerprint")).unwrap();
    let v = check_in(&d, &[app("com.trojan", &[&bad])]);
    assert_eq!(v["fresh"], 1, "{v}");
    assert_eq!(v["found"][0]["pkg"], "com.trojan", "{v}");
}

// ---- 29 Sep evening: the emulator's 249 stock apps gave one "worth a look": YARAhub's admin +
// accessibility rule on Android's own permission manager.

/// Every rule in yara/ whose strings are ALL permission names, as (set, rule). Found by what the
/// rule IS, so a new rule of that kind fails the test below until it joins PERMISSION_ONLY.
fn permission_only_rules() -> Vec<(String, String)> {
    fn walk(d: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() { walk(&p, root, out); continue; }
            if p.extension().and_then(|x| x.to_str()) != Some("yar") { continue; }
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let set = if rel.starts_with("rl/") { "ReversingLabs" } else if rel.starts_with("bartblaze/") { "bartblaze" } else if rel.starts_with("yarahub/") { "YARAhub" } else { "other" };
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            for block in text.split("rule ").skip(1) {
                let name: String = block.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                let Some(s) = block.split("strings:").nth(1) else { continue };
                let s = s.split("condition:").next().unwrap_or("");
                let defs: Vec<&str> = s.lines().map(str::trim).filter(|l| l.starts_with('$') && l.contains('=')).collect();
                if !name.is_empty() && !defs.is_empty() && defs.iter().all(|l| l.contains("android.permission.")) {
                    out.push((set.to_string(), name));
                }
            }
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("yara");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    out
}

#[test]
fn every_permission_only_rule_is_left_to_the_page_for_installed_apps() {
    let found = permission_only_rules();
    assert!(!found.is_empty(), "the finder must see at least the admin + accessibility rule");
    let mut listed: Vec<(String, String)> = PERMISSION_ONLY.iter().map(|(s, r)| (s.to_string(), r.to_string())).collect();
    listed.sort();
    assert_eq!(found, listed, "a rule made only of permission names must be in PERMISSION_ONLY");
    for (s, r) in &found {
        assert!(!keep_rule(s, r), "{s}/{r} still reported for installed apps");
    }
    assert!(keep_rule("YARAhub", "Android_BankingTrojan_Hydra"), "code rules with some permissions stay");
}

#[test]
fn a_remembered_hit_from_a_rule_now_dropped_is_not_reported() {
    // The memory is keyed by the rules only, so a filter change must act on remembered results too.
    let (d, _bad, good) = setup("dropmem");
    let k = {
        let m = std::fs::metadata(&good).unwrap();
        let t = m.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        format!("{}\t{}\t{}", good.to_string_lossy(), m.len(), t)
    };
    std::fs::write(d.join(PATTERN_CACHE), format!("{k}\tt1\tYARAhub/Android_Admin_And_Accessibility,Vigil/AppBankerShape,test/Evil_Word")).unwrap();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let f = fake_read(&calls);
    let v = check_full(&d, &[app("com.google.android.permissioncontroller", &[&good])], |s| super::hashlist::lookup_in(&d, s), Some(&reader(&f, "t1", None)));
    assert_eq!(v["patterns"]["remembered"], 1, "{v}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0, "taken from memory, not read: {v}");
    assert_eq!(hit_rules(&v, "com.google.android.permissioncontroller"), ["test/Evil_Word"], "{v}");
}

#[test]
fn starting_from_scratch_forgets_the_app_code_memory_too() {
    for name in [super::folderscan::CACHE, super::folderscan::PHONE_CACHE, CACHE, PATTERN_CACHE] {
        assert!(crate::FORGET.contains(&name), "{name} is not forgotten");
    }
}

#[test]
fn an_installed_spy_app_sample_carries_its_name_to_the_found_row() {
    let (d, bad, good) = setup("stalker");
    let spy = sha(b"PK\x03\x04 pretend banking trojan");
    let v = check_full(&d, &[app("com.calc", &[&good]), app("com.spy", &[&bad])], |s| {
        let mut v = super::hashlist::lookup_in(&d, s);
        if s == spy {
            v["stalkerware"] = serde_json::json!("TheTruthSpy");
        }
        v
    }, None);
    assert_eq!(v["found"][0]["pkg"], "com.spy", "{v}");
    assert_eq!(v["found"][0]["stalkerware"], "TheTruthSpy", "{v}");
    // An ordinary list hit carries no spy-app name.
    let v = check_in(&d, &[app("com.trojan", &[&bad])]);
    assert_eq!(v["found"][0]["stalkerware"], serde_json::Value::Null, "{v}");
}
