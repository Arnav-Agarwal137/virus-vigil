//! Tests for hashlist.rs. Every list is built in a temp folder; nothing is downloaded.
//! "Not looked up" (checked:false) and "looked up, not there" (checked:true, found:false) are
//! opposite facts, so each has its own test.

use super::hashlist::*;
use std::collections::HashSet;

fn dir(tag: &str) -> super::testdir::TestDir {
    super::testdir::TestDir::new(&format!("hashlist-{tag}"))
}
/// A deterministic 64-hex fingerprint from a number (no randomness crate needed).
fn h(i: u64) -> String {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
    (0..4).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; format!("{x:016x}") }).collect()
}

#[test]
fn no_list_means_not_looked_up() {
    let d = dir("none");
    let v = lookup_in(&d, &h(1));
    assert_eq!(v["checked"], false, "{v}");
    assert_eq!(v["found"], false);
    assert!(v["error"].as_str().unwrap().contains("no list"));
}

#[test]
fn finds_a_listed_fingerprint_and_not_an_unlisted_one() {
    let d = dir("basic");
    // The real export's shape: a # header, then one hash per line, CRLF; plus junk to skip.
    let body = format!("#####\r\n# sha256_hash\r\n{}\r\n{}\r\nnot-a-hash\r\n\r\n{}\r\n", h(1), h(2).to_uppercase(), h(1));
    std::fs::write(d.join(FULL), body).unwrap();
    let v = lookup_in(&d, &h(1));
    assert_eq!((v["checked"].clone(), v["found"].clone()), (true.into(), true.into()), "{v}");
    assert_eq!(v["count"], 2, "duplicates and junk not counted: {v}");
    assert_eq!(lookup_in(&d, &h(2))["found"], true, "an upper-case line is still found");
    assert_eq!(lookup_in(&d, &h(1).to_uppercase())["found"], true, "an upper-case question is still found");
    let miss = lookup_in(&d, &h(3));
    assert_eq!((miss["checked"].clone(), miss["found"].clone()), (true.into(), false.into()), "{miss}");
}

#[test]
fn the_last_48_hours_list_counts_too() {
    let d = dir("recent");
    std::fs::write(d.join(FULL), format!("{}\n", h(1))).unwrap();
    std::fs::write(d.join(RECENT), format!("# recent\n{}\n", h(9))).unwrap();
    let v = lookup_in(&d, &h(9));
    assert_eq!(v["found"], true, "{v}");
    assert_eq!(v["recent"], 1);
}

#[test]
fn a_newer_download_rebuilds_the_sorted_file() {
    let d = dir("rebuild");
    std::fs::write(d.join(FULL), format!("{}\n", h(1))).unwrap();
    assert_eq!(lookup_in(&d, &h(5))["found"], false);
    std::fs::write(d.join(FULL), format!("{}\n{}\n", h(1), h(5))).unwrap();
    // Make the text clearly newer than the sorted file, whatever the clock resolution.
    let later = std::fs::metadata(d.join(BIN)).unwrap().modified().unwrap() + std::time::Duration::from_secs(5);
    std::fs::File::options().write(true).open(d.join(FULL)).unwrap().set_modified(later).unwrap();
    let v = lookup_in(&d, &h(5));
    assert_eq!(v["found"], true, "{v}");
    assert_eq!(v["count"], 2);
}

#[test]
fn a_damaged_sorted_file_is_not_looked_up_and_not_trusted() {
    let d = dir("damaged");
    std::fs::write(d.join(BIN), [0u8; 33]).unwrap();
    let v = lookup_in(&d, &h(1));
    assert_eq!(v["checked"], false, "{v}");
    assert!(!d.join(BIN).exists(), "the damaged file is removed so it gets rebuilt");
}

#[test]
fn a_bad_fingerprint_is_not_looked_up() {
    let d = dir("badinput");
    std::fs::write(d.join(FULL), format!("{}\n", h(1))).unwrap();
    for bad in ["", "abc", &"g".repeat(64)] {
        assert_eq!(lookup_in(&d, bad)["checked"], false, "{bad}");
    }
}

#[test]
fn binary_search_agrees_with_a_plain_set_at_scale() {
    // 20,000 listed, checked against a HashSet: every listed one found (first, last and every
    // position between), and 2,000 unlisted ones not found.
    let d = dir("scale");
    let listed: Vec<String> = (0..20_000).map(h).collect();
    std::fs::write(d.join(FULL), listed.join("\n")).unwrap();
    let set: HashSet<&String> = listed.iter().collect();
    assert_eq!(lookup_in(&d, &listed[0])["count"], set.len() as u64);
    for x in &listed {
        assert_eq!(lookup_in(&d, x)["found"], true, "{x}");
    }
    for i in 100_000..102_000 {
        let x = h(i);
        assert_eq!(lookup_in(&d, &x)["found"], set.contains(&x), "{x}");
    }
    // Lowest and highest possible fingerprints fall off both ends cleanly.
    assert_eq!(lookup_in(&d, &"0".repeat(64))["found"], false);
    assert_eq!(lookup_in(&d, &"f".repeat(64))["found"], false);
}

#[test]
fn only_the_recent_list_is_a_small_real_lookup_said_as_such() {
    // A phone on mobile data: no full list yet, only the last 48 hours.
    let d = dir("recentonly");
    std::fs::write(d.join(RECENT), format!("# recent\n{}\n", h(7))).unwrap();
    let hit = lookup_in(&d, &h(7));
    assert_eq!((hit["checked"].clone(), hit["found"].clone(), hit["full"].clone()), (true.into(), true.into(), false.into()), "{hit}");
    assert_eq!(hit["count"], 0, "the full list is not claimed: {hit}");
    let miss = lookup_in(&d, &h(8));
    assert_eq!((miss["checked"].clone(), miss["found"].clone()), (true.into(), false.into()), "{miss}");
    // With the full list present the answer says so.
    std::fs::write(d.join(FULL), format!("{}\n", h(1))).unwrap();
    assert_eq!(lookup_in(&d, &h(1))["full"], true);
}

#[test]
fn a_download_replaces_the_list_only_if_it_passes() {
    let d = dir("accept");
    let dest = d.join(FULL);
    std::fs::write(&dest, "old\n").unwrap();
    // Too few lines: refused, the old list untouched, the bad download removed.
    let tmp = d.join("t1");
    std::fs::write(&tmp, format!("# h\n{}\n{}\n", h(1), h(2))).unwrap();
    assert!(accept_download(&tmp, &dest, 3).unwrap_err().contains("2 of 2"));
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "old\n");
    assert!(!tmp.exists());
    // Enough lines but mostly junk (an error page): refused.
    let tmp = d.join("t2");
    std::fs::write(&tmp, "<html>\n<body>\nnot found\n".to_string() + &h(1)).unwrap();
    assert!(accept_download(&tmp, &dest, 3).is_err());
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "old\n");
    // A good one (CRLF, comments, blank lines): accepted and in place.
    let tmp = d.join("t3");
    let body: String = (0..100).map(|i| format!("{}\r\n", h(i))).collect();
    std::fs::write(&tmp, format!("#####\r\n\r\n{body}")).unwrap();
    assert_eq!(accept_download(&tmp, &dest, 100).unwrap(), 100);
    assert!(!tmp.exists());
    assert_eq!(lookup_in(&d, &h(42))["found"], true);
}

/// 29 Sep 2026: the full list is due weekly OR once the recent (48 h) list no longer reaches back to
/// it - with a weekly rule alone, samples shared between the two were in neither list.
#[test]
fn full_list_is_due_when_the_recent_one_no_longer_reaches_it() {
    let cases: [(Option<f64>, Option<f64>, bool, &str); 8] = [
        (None, Some(1.0), true, "no full list yet"),
        (Some(168.0), Some(1.0), true, "a week old"),
        (Some(167.0), None, false, "no recent list: weekly rule only"),
        (Some(30.0), Some(1.0), false, "recent reaches back past it"),
        (Some(41.0), Some(1.0), false, "exactly 40 h apart is still covered"),
        (Some(41.5), Some(1.0), true, "40.5 h apart: a gap"),
        (Some(82.8), Some(0.1), true, "his laptop tonight: 82.8 h vs a fresh recent list"),
        (Some(60.0), Some(30.0), false, "30 h apart"),
    ];
    for (f, r, want, why) in cases {
        assert_eq!(full_due(f, r), want, "{why}: full {f:?} recent {r:?}");
    }
}

/// The laptop's copy of the rule, in ps/hashlist-update.ps1, run for real against local files
/// (file:/// addresses - nothing is downloaded from the internet).
fn run_update(tag: &str, full_age_h: u64, recent_age_h: u64) -> serde_json::Value {
    let d = dir(tag);
    let src = d.path().join("src");
    let lists = d.path().join("lists");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&lists).unwrap();
    let hashes: Vec<String> = (0..5).map(h).collect();
    std::fs::write(src.join("full.txt"), format!("# full\n{}\n", hashes.join("\n"))).unwrap();
    std::fs::write(src.join("recent.txt"), format!("# recent\n{}\n", hashes[..2].join("\n"))).unwrap();
    let zip = src.join("full.zip");
    let made = super::powershell().arg("-Command")
        .arg(format!("Compress-Archive -LiteralPath '{}' -DestinationPath '{}'", src.join("full.txt").display(), zip.display()))
        .output().unwrap();
    assert!(zip.is_file(), "fixture zip: {}", String::from_utf8_lossy(&made.stderr));
    // The copies already on "this laptop", aged by hand.
    let now = std::time::SystemTime::now();
    for (name, age) in [(FULL, full_age_h), (RECENT, recent_age_h)] {
        let p = lists.join(name);
        std::fs::write(&p, format!("{}\n", h(99))).unwrap();
        std::fs::File::options().write(true).open(&p).unwrap()
            .set_modified(now - std::time::Duration::from_secs(age * 3600)).unwrap();
    }
    let script = d.path().join("hashlist-update.ps1");
    std::fs::write(&script, super::HASHLIST_UPDATE_PS).unwrap();
    let url = |p: &std::path::Path| format!("file:///{}", p.display().to_string().replace('\\', "/"));
    let out = super::powershell().arg("-File").arg(&script)
        .env("VV_LISTS_DIR", &lists).env("VV_MB_FULL_URL", url(&zip)).env("VV_MB_RECENT_URL", url(&src.join("recent.txt")))
        .env("VV_MB_FULL_MIN", "3").env("VV_MB_RECENT_MIN", "1")
        .output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn laptop_script_fetches_the_full_list_when_the_recent_one_no_longer_reaches_it() {
    // 60 h vs 1 h: a 59-hour hole - the full list is fetched although it is not a week old.
    let v = run_update("gap", 60, 1);
    assert_eq!(v["recent"]["skipped"], true, "{v}");
    assert_eq!(v["full"]["updated"], true, "{v}");
    assert_eq!(v["full"]["lines"], 5, "{v}");
    // 30 h vs 1 h: covered - left alone.
    let v = run_update("covered", 30, 1);
    assert_eq!(v["full"]["skipped"], true, "{v}");
    assert_eq!(v["full"]["updated"], false, "{v}");
    // A stale recent list is fetched first, and THEN measured against: 30 h full, 25 h recent ->
    // the new recent is ~0 h old, 30 h apart - still covered.
    let v = run_update("stale-recent", 30, 25);
    assert_eq!(v["recent"]["updated"], true, "{v}");
    assert_eq!(v["full"]["skipped"], true, "{v}");
}

/// The stalkerware samples ship inside the app (stalker.rs, 29 Sep) and count as known-bad on top
/// of the downloaded list, named; an ordinary fingerprint still is not (read OUT of the built list).
#[test]
fn a_stalkerware_sample_is_known_bad_and_named() {
    let d = dir("stalker");
    std::fs::write(d.join(FULL), format!("{}\n", h(1))).unwrap();
    let mut s: Vec<(&[u8; 32], &String)> = crate::stalker::LIST.samples.iter().collect();
    s.sort();
    let (sha, app) = s[0];
    let hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    let v = lookup_in(&d, &hex);
    assert_eq!((v["checked"].clone(), v["found"].clone()), (true.into(), true.into()), "{v}");
    assert_eq!(v["stalkerware"], app.as_str());
    let miss = lookup_in(&d, &h(2));
    assert_eq!(miss["found"], false);
    assert!(miss.get("stalkerware").is_none(), "{miss}");

    // No list downloaded at all: the shipped sample is still named; anything else stays "not looked up".
    let empty = dir("stalker-nolist");
    let v = lookup_in(&empty, &hex);
    assert_eq!((v["checked"].clone(), v["found"].clone()), (true.into(), true.into()), "{v}");
    assert_eq!(v["stalkerware"], app.as_str());
    assert!(v["listMissing"].is_string(), "{v}");
    let miss = lookup_in(&empty, &h(2));
    assert_eq!(miss["checked"], false, "{miss}");
    assert_eq!(miss["found"], false, "{miss}");
}

/// Only a key-shaped value may reach the download address (1 Nov 2026: abuse.ch keyed exports).
#[test]
fn only_a_key_shaped_value_is_used_as_the_abuse_ch_key() {
    let good = "c0ffee0123456789abcdefABCDEF0123456789aa";
    assert_eq!(valid_mb_key(good).as_deref(), Some(good));
    assert_eq!(valid_mb_key(&format!("  {good}\n")).as_deref(), Some(good), "trimmed");
    assert_eq!(valid_mb_key(""), None);
    assert_eq!(valid_mb_key("short1234"), None);
    assert_eq!(valid_mb_key(&"a".repeat(101)), None);
    assert_eq!(valid_mb_key(&format!("{good}/../x")), None, "no path characters");
    assert_eq!(valid_mb_key(&format!("{good}?x=1")), None);
    assert_eq!(valid_mb_key("abcdefghij klmnopqrstuvwxyz"), None, "no spaces inside");
}
