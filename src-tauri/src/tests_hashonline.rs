//! Tests for hashonline.rs: the online fingerprint look-up. Nothing here goes online: `fetch` is a
//! closure that records what it was handed and replays CIRCL's REAL replies, saved once from the
//! live service into tests/circl/ (never typed in). "Never seen" and "could not ask" are opposite
//! facts, so each has its own test, and a failure must never read as either answer.

use super::hashonline::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::path::Path;
use std::sync::atomic::AtomicUsize;

const BAD_REPLY: &str = include_str!("../tests/circl/eicar-known-malicious.json");
const UNKNOWN_REPLY: &str = include_str!("../tests/circl/never-seen-404.json");
const NOW: u64 = 2_000_000_000;

fn dir(tag: &str) -> super::testdir::TestDir {
    super::testdir::TestDir::new(&format!("online-{tag}"))
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
/// The reply a KNOWN-but-harmless file gets: CIRCL's real reply with the malware field taken out.
fn known_reply() -> String {
    let mut v: Value = serde_json::from_str(BAD_REPLY).unwrap();
    v.as_object_mut().unwrap().remove("KnownMalicious");
    v.to_string()
}

#[test]
fn circls_real_replies_read_as_bad_known_and_never_seen() {
    let src = serde_json::from_str::<Value>(BAD_REPLY).unwrap()["KnownMalicious"].as_str().unwrap().to_string();
    assert!(!src.is_empty());
    assert_eq!(read_answer(200, BAD_REPLY), Ok(Said::Bad(src)));
    assert_eq!(read_answer(200, &known_reply()), Ok(Said::Known));
    assert_eq!(read_answer(404, UNKNOWN_REPLY), Ok(Said::Unknown));
}

#[test]
fn anything_that_is_not_an_answer_is_a_failure_never_clean_or_unknown() {
    for (st, body) in [(404, "<html>Not Found</html>"), (0, ""), (0, "timeout"), (500, "{}"), (429, "slow down"),
                       (200, "not json"), (200, "[]"), (200, r#"{"message": "hello"}"#)] {
        assert!(read_answer(st, body).is_err(), "{st} {body:?} must be a failure");
    }
}

#[test]
fn only_well_formed_fingerprints_are_sent_once_each_in_lowercase() {
    let d = dir("send");
    let a = sha(b"one");
    let sent = RefCell::new(Vec::new());
    let r = ask(&d, &[a.to_uppercase(), a.clone(), "C:\\Users\\me\\secret.pdf".into(), "abc".into(), "g".repeat(64)], NOW, |h| {
        sent.borrow_mut().extend_from_slice(h);
        h.iter().map(|s| (s.clone(), 404, UNKNOWN_REPLY.to_string())).collect()
    });
    assert_eq!(*sent.borrow(), vec![a.clone()]);
    assert_eq!(r.said.get(&a), Some(&Said::Unknown));
    assert_eq!(r.summary["asked"], 1);
    assert_eq!(r.summary["unknown"], 1);
}

#[test]
fn answers_are_remembered_for_three_days_then_asked_again() {
    let d = dir("mem");
    let (a, b) = (sha(b"a"), sha(b"b"));
    let calls = AtomicUsize::new(0);
    let fetch = |h: &[String]| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        h.iter().map(|s| if *s == a { (s.clone(), 200, BAD_REPLY.to_string()) } else { (s.clone(), 404, UNKNOWN_REPLY.to_string()) }).collect()
    };
    let first = ask(&d, &[a.clone(), b.clone()], NOW, fetch);
    assert_eq!(first.summary["asked"], 2);
    let second = ask(&d, &[a.clone(), b.clone()], NOW + 3600, |_| panic!("nothing should be asked again"));
    assert_eq!(second.summary["asked"], 0);
    assert_eq!(second.summary["remembered"], 2);
    assert!(matches!(second.said.get(&a), Some(Said::Bad(_))), "the source survives the memory: {:?}", second.said);
    assert_eq!(second.said.get(&b), Some(&Said::Unknown));
    let later = ask(&d, &[a.clone()], NOW + 3 * 24 * 3600 + 1, |h| h.iter().map(|s| (s.clone(), 404, UNKNOWN_REPLY.to_string())).collect());
    assert_eq!(later.summary["asked"], 1, "older than three days is asked again");
}

#[test]
fn a_failure_is_counted_and_named_and_never_remembered() {
    let d = dir("fail");
    let (a, b) = (sha(b"a"), sha(b"b"));
    // a: no connection; b: the helper returned no row at all.
    let r = ask(&d, &[a.clone(), b.clone()], NOW, |_| vec![(a.clone(), 0, "no route to host".into())]);
    assert_eq!(r.summary["failed"], 2);
    assert_eq!(r.summary["asked"], 2);
    assert_eq!(r.summary["unknown"], 0);
    assert_eq!(r.summary["error"], "no route to host");
    assert!(r.said.is_empty());
    let again = ask(&d, &[a.clone()], NOW + 60, |h| h.iter().map(|s| (s.clone(), 404, UNKNOWN_REPLY.to_string())).collect());
    assert_eq!(again.summary["asked"], 1, "a failure was not remembered as an answer");
}

#[test]
fn at_most_max_ask_leave_per_run_and_the_rest_are_counted() {
    let d = dir("cap");
    let all: Vec<String> = (0..MAX_ASK + 5).map(|i| sha(format!("f{i}").as_bytes())).collect();
    let r = ask(&d, &all, NOW, |h| {
        assert_eq!(h.len(), MAX_ASK);
        h.iter().map(|s| (s.clone(), 404, UNKNOWN_REPLY.to_string())).collect()
    });
    assert_eq!(r.summary["asked"], MAX_ASK);
    assert_eq!(r.summary["notAsked"], 5);
}

// ------------------------------------------------------------------ the sweep, end to end

fn sweep_dir(tag: &str) -> super::testdir::TestDir {
    let d = dir(tag);
    std::fs::create_dir_all(d.join("lists")).unwrap();
    std::fs::create_dir_all(d.join("Downloads")).unwrap();
    std::fs::write(d.join("lists").join(super::hashlist::FULL), format!("# sha256_hash\n{}\n", sha(b"filler"))).unwrap();
    std::fs::write(d.join("Downloads").join("new-bank.apk"), b"PK\x03\x04 an app no list knows").unwrap();
    std::fs::write(d.join("Downloads").join("maybe.bin"), b"MEH worth a look").unwrap();
    std::fs::write(d.join("Downloads").join("notes.txt"), b"plain clean text").unwrap();
    std::fs::write(d.join("Downloads").join("strong.bin"), b"BAD! already a stop").unwrap();
    d
}
/// A stand-in rule reader: "MEH" = one WEAK Vigil rule; "BAD!" = a strong rule; else nothing.
fn weak_yara(p: &Path) -> Value {
    let b = std::fs::read(p).unwrap_or_default();
    let m = if b.windows(3).any(|w| w == b"MEH") { json!([{"rule": "AppHidden", "set": "Vigil"}]) }
        else if b.windows(4).any(|w| w == b"BAD!") { json!([{"rule": "Strong_Test", "set": "test"}]) } else { json!([]) };
    json!({"ran": true, "matches": m})
}
fn sweep(d: &Path) -> Value {
    use super::folderscan::*;
    let ld = d.join("lists");
    let o = Opts { max_yara: 1 << 20, max_files: 1000, budget: std::time::Duration::from_secs(60), threads: 2, skip: Vec::new(), progress: None, crumbs: None };
    sweep_with(&[("Downloads".into(), d.join("Downloads"))], &ld.join(CACHE), |s: &str| super::hashlist::lookup_in(&ld, s), weak_yara, Some("t".into()), &o)
}
fn row<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["found"].as_array().unwrap().iter().find(|f| f["name"] == name).unwrap_or(&Value::Null)
}

#[test]
fn a_sweep_asks_about_unknown_apps_and_weak_finds_only_and_a_named_one_becomes_a_stop() {
    let d = sweep_dir("sweep");
    let mut v = sweep(&d);
    let apk = sha(b"PK\x03\x04 an app no list knows");
    let weak = sha(b"MEH worth a look");
    assert_eq!(row(&v, "maybe.bin")["weak"], true, "{v}");
    assert_eq!(row(&v, "strong.bin")["weak"], false, "{v}");
    assert_eq!(row(&v, "new-bank.apk"), &Value::Null, "the app is not a find before the look-up: {v}");
    let sent = RefCell::new(Vec::new());
    let a = ask(&d.join("lists"), &sweep_candidates(&v), NOW, |h| {
        sent.borrow_mut().extend_from_slice(h);
        h.iter().map(|s| (s.clone(), 200, BAD_REPLY.to_string())).collect()
    });
    let mut s = sent.borrow().clone();
    s.sort();
    let mut want = vec![apk.clone(), weak.clone()];
    want.sort();
    assert_eq!(s, want, "exactly the unknown app and the weak find - never the clean file or a find already a Stop");
    apply_to_sweep(&mut v, &a);
    assert!(v.get("unknownApps").is_none(), "the helper list never reaches the page");
    for name in ["new-bank.apk", "maybe.bin"] {
        let f = row(&v, name);
        assert_eq!(f["weak"], false, "{name} is now a Stop: {v}");
        assert!(f["online"].as_str().is_some_and(|s| !s.is_empty()), "{name} names who reported it: {f}");
        assert!(f["rules"].as_array().unwrap().iter().any(|r| r["rule"] == RULE && r["weak"] == false), "{f}");
        assert!(f["why"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("fingerprint")), "{f}");
    }
    assert_eq!(v["online"]["bad"], 2);
    assert_eq!(row(&v, "notes.txt"), &Value::Null);
}

#[test]
fn a_sweep_whose_look_up_failed_changes_nothing_and_says_so() {
    let d = sweep_dir("sweepfail");
    let mut v = sweep(&d);
    let before = v["found"].clone();
    let a = ask(&d.join("lists"), &sweep_candidates(&v), NOW, |h| h.iter().map(|s| (s.clone(), 0, "no connection".to_string())).collect());
    apply_to_sweep(&mut v, &a);
    assert_eq!(v["found"], before);
    assert_eq!(v["online"]["failed"], 2);
    assert_eq!(v["online"]["error"], "no connection");
}

#[test]
fn a_sweep_where_circl_knows_nothing_bad_changes_nothing() {
    let d = sweep_dir("sweepknown");
    let mut v = sweep(&d);
    let before = v["found"].clone();
    let k = known_reply();
    let a = ask(&d.join("lists"), &sweep_candidates(&v), NOW, |h| {
        h.iter().enumerate().map(|(i, s)| if i == 0 { (s.clone(), 200, k.clone()) } else { (s.clone(), 404, UNKNOWN_REPLY.to_string()) }).collect()
    });
    apply_to_sweep(&mut v, &a);
    assert_eq!(v["found"], before, "known-harmless and never-seen do not calm or raise anything");
    assert_eq!(v["online"]["known"], 1);
    assert_eq!(v["online"]["unknown"], 1);
}

// ------------------------------------------------------------------ installed apps

#[test]
fn installed_apps_he_added_are_asked_about_and_the_phones_own_are_not() {
    use super::apkcheck::*;
    let d = dir("apps");
    std::fs::write(d.join(super::hashlist::FULL), format!("# sha256_hash\n{}\n", sha(b"filler"))).unwrap();
    let mine = d.join("mine.apk");
    let maker = d.join("maker.apk");
    std::fs::write(&mine, b"PK\x03\x04 his app").unwrap();
    std::fs::write(&maker, b"PK\x03\x04 the phone's own").unwrap();
    let apps = [
        App { pkg: "com.his".into(), paths: vec![mine.to_string_lossy().into_owned()], maker: false },
        App { pkg: "com.vivo.thing".into(), paths: vec![maker.to_string_lossy().into_owned()], maker: true },
    ];
    let mut v = check_in(&d, &apps);
    assert_eq!(apps_candidates(&v), vec![sha(b"PK\x03\x04 his app")], "{v}");
    let a = ask(&d, &apps_candidates(&v), NOW, |h| h.iter().map(|s| (s.clone(), 200, BAD_REPLY.to_string())).collect());
    apply_to_apps(&mut v, &a);
    let f = v["found"].as_array().unwrap();
    assert_eq!(f.len(), 1, "{v}");
    assert_eq!(f[0]["pkg"], "com.his");
    assert!(f[0]["online"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v.get("unknownApps").is_none());
}

#[test]
fn the_single_file_answer_names_all_four_outcomes() {
    let d = dir("single");
    let (b, k, u, f) = (sha(b"b"), sha(b"k"), sha(b"u"), sha(b"f"));
    let kr = known_reply();
    let a = ask(&d, &[b.clone(), k.clone(), u.clone(), f.clone()], NOW, |h| h.iter().map(|s| {
        if *s == b { (s.clone(), 200, BAD_REPLY.to_string()) } else if *s == k { (s.clone(), 200, kr.clone()) }
        else if *s == u { (s.clone(), 404, UNKNOWN_REPLY.to_string()) } else { (s.clone(), 0, "offline".to_string()) }
    }).collect());
    assert_eq!(single(&a, &b)["said"], "bad");
    assert!(single(&a, &b)["source"].is_string());
    assert_eq!(single(&a, &k)["said"], "known");
    assert_eq!(single(&a, &u)["said"], "unknown");
    assert_eq!(single(&a, &f)["said"], Value::Null, "not answered is its own answer");
    assert_eq!(single(&a, &f)["error"], "offline");
}

/// The two helpers that do the asking hold their own copy of the address; both must be CIRCL's.
#[test]
fn both_helpers_ask_the_same_one_address_and_nothing_else() {
    let ps = include_str!("../ps/hashlookup.ps1");
    let kt = include_str!("../../plugins/vigil-phone/android/src/main/java/PhonePlugin.kt");
    assert!(ps.contains(&format!("{ADDRESS}$_")), "hashlookup.ps1");
    let start = kt.find("fun hashLookup").expect("Kotlin hashLookup");
    let body = &kt[start..start + kt[start..].find("\n  }\n").or_else(|| kt[start..].find("\r\n  }\r\n")).unwrap()];
    assert!(body.contains(&format!("{ADDRESS}$s")), "Kotlin hashLookup");
    assert_eq!(body.matches("http(").count(), 1, "Kotlin hashLookup opens one kind of connection only");
    assert_eq!(ps.matches("https://").count(), 1, "hashlookup.ps1 names one address only");
}
