//! Tests for yara.rs (the rules run on laptop and phone alike; the crash guard is phone-only in use
//! but a plain function, so it is tested here). The positive sample is glued together from pieces at run
//! time, so neither this source nor the test binary holds the whole pattern. Every positive has
//! a CLEAN twin that must stay quiet: a check that only ever fires proves nothing.

use super::yara::*;
use serde_json::Value;

fn tmp(name: &str, bytes: &[u8]) -> super::testdir::TestFile {
    super::testdir::TestFile::new("yara", name, bytes)
}
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}
/// Text written backwards and turned round at run time: glued literals are folded back together
/// by the compiler (found 29 Sep 2026), reversed ones cannot be, so this binary never holds them.
fn unrev(s: &str) -> String {
    std::hint::black_box(s).chars().rev().collect()
}
fn rule_names(v: &Value) -> Vec<String> {
    v["matches"].as_array().unwrap().iter().map(|m| m["rule"].as_str().unwrap().to_string()).collect()
}

#[test]
fn every_rule_file_compiles_except_the_quiet_ones() {
    let c = rules().as_ref().expect("rules compile");
    assert!(c.failed.is_empty(), "failed: {:?}", c.failed);
    // 455 main rule files (rl 310 + bartblaze 110 + YARAhub Android 35), the QUIET ones left out;
    // since 2 Nov 2026 the YARAhub laptop set (yarahub-win/) compiles as its own second set.
    let extra_n = RULE_FILES.iter().filter(|(r, _)| is_extra(r)).count();
    assert_eq!(RULE_FILES.len() - extra_n, 455);
    let main_quiet = QUIET.iter().filter(|(q, _)| !is_extra(q)).count();
    assert_eq!(c.files, 455 - main_quiet);
    assert!(c.count > 1300, "only {} rules", c.count);
    let x = extra().as_ref().expect("the laptop's second set compiles");
    assert!(x.failed.is_empty(), "failed: {:?}", x.failed);
    let extra_quiet = QUIET.iter().filter(|(q, _)| is_extra(q)).count();
    assert_eq!(x.files, extra_n - extra_quiet);
    assert!(extra_n > 1000 && x.count >= x.files, "{extra_n} files, {} rules", x.count);
}

/// 29 Sep 2026: with the rule texts embedded as plain text, Vigil's own APK matched 78 rules (the
/// storage sweep would have called the APK he downloads "harmful"). This test binary holds the same
/// embedded rules as the app, so scanning ITSELF checks that no rule's strings sit in it readable.
#[test]
fn vigils_own_program_matches_none_of_its_rules() {
    let me = std::env::current_exe().unwrap();
    let v = scan(&me);
    assert_eq!(v["ran"], true, "{v}");
    assert_eq!(rule_names(&v), Vec::<String>::new(), "{}", me.display());
    // And the rules really are in it: the stored form is there, the text is not.
    assert!(RULE_FILES_Z.len() == RULE_FILES.len() && RULE_FILES.iter().all(|(_, s)| s.contains("rule")));
}

/// The sweep's memory keeps a verdict only while this tag is unchanged. It must carry a fingerprint
/// of the rule texts, lists and read method - not just two counts, which stayed equal across the
/// 29 Sep big-APK change and would have kept old "clean" answers for big apps.
#[test]
fn the_memory_tag_fingerprints_the_rules_and_the_method() {
    let t = tag().expect("rules compile");
    let c = rules().as_ref().unwrap();
    let (counts, print) = t.split_once('-').unwrap_or_else(|| panic!("no fingerprint in {t}"));
    let x = extra().as_ref().unwrap();
    assert_eq!(counts, format!("{}r{}f", c.count + x.count, c.files + x.files));
    assert!(print.len() == 12 && print.chars().all(|x| x.is_ascii_hexdigit()), "{t}");
    assert_eq!(tag().unwrap(), t);
}

#[test]
fn every_quiet_entry_names_a_real_rule_file() {
    // A renamed or moved file would make its QUIET entry silently skip nothing.
    for (q, why) in QUIET.iter() {
        assert!(RULE_FILES.iter().any(|f| f.0 == *q), "QUIET names a missing file: {q}");
        assert!(!why.is_empty());
    }
}

#[test]
fn a_known_pattern_is_caught_and_named() {
    // bartblaze OneNote_BuildPath: a UTF-16 build path seen in malicious OneNote files.
    let path = ["Z:", "\\bu", "ild\\one", "\\attach", "ment.hta"].concat();
    let mut bad = b"filler ".to_vec();
    bad.extend(utf16(&path));
    let v = scan(&tmp("sample.bin", &bad));
    assert_eq!(v["ran"], true, "{v}");
    let m = v["matches"].as_array().unwrap();
    assert_eq!(m.len(), 1, "{v}");
    assert_eq!(m[0]["rule"], "OneNote_BuildPath");
    assert_eq!(m[0]["set"], "bartblaze");
    assert_eq!(m[0]["file"], "bartblaze/rules/generic/OneNote_BuildPath.yar"); assert_eq!(m[0]["weak"], true);
    assert!(m[0]["what"]["description"].as_str().unwrap().contains("OneNote"));

    // Clean twin: the same words in plain single-byte text do not match.
    let mut ok = b"filler ".to_vec();
    ok.extend(path.as_bytes());
    let v = scan(&tmp("twin.bin", &ok));
    assert_eq!(v["ran"], true);
    assert!(rule_names(&v).is_empty(), "{v}");
}

#[test]
fn clean_windows_programs_stay_quiet() {
    let win = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let notepad = std::path::Path::new(&win).join("System32").join("notepad.exe");
    let v = scan(&notepad);
    assert_eq!(v["ran"], true, "{v}");
    assert!(rule_names(&v).is_empty(), "{v}");
    assert!(v["ms"].is_u64());
}

#[test]
fn the_quiet_list_really_silences_the_browser_engine_false_alarm() {
    // Avaddon (QUIET) fired on chrome.dll in the 25 Sep measurement. If Chrome is installed,
    // it must be quiet now; if not, say so rather than pass silently.
    let base = std::path::Path::new(r"C:\Program Files\Google\Chrome\Application");
    let dll = std::fs::read_dir(base).ok().and_then(|rd| {
        rd.flatten().map(|e| e.path().join("chrome.dll")).find(|p| p.exists())
    });
    match dll {
        None => eprintln!("SKIPPED: no chrome.dll on this machine"),
        Some(p) => {
            // chrome.dll is ~300 MB: 25 s against scan()'s 30 s limit on a quiet laptop (31 Oct 2026),
            // so it timed out once when the page suites ran beside it. A timeout is "couldn't judge",
            // not "the quiet list failed": retry once, and a second timeout still fails.
            let mut v = scan(&p);
            if v["reason"] == "timeout" {
                eprintln!("chrome.dll scan timed out once (machine busy?) - retrying");
                v = scan(&p);
            }
            assert_eq!(v["ran"], true, "{v}");
            assert!(rule_names(&v).is_empty(), "{} -> {v}", p.display());
            eprintln!("chrome.dll: {} ms, rules compiled in {} ms", v["ms"], v["compileMs"]);
        }
    }
}

#[test]
fn a_missing_file_says_it_did_not_run() {
    let v = scan(std::path::Path::new(r"C:\no\such\file.exe"));
    assert_eq!(v["ran"], false);
    assert!(v["reason"].as_str().is_some_and(|r| !r.is_empty()));
}

// The phone's crash guard (25 Sep evening). A start that dies mid-compile is simulated by a
// compile closure that returns without the guard's clean-up running - i.e. by writing the
// count the way a dead start leaves it.
fn guard_dir(tag: &str) -> super::testdir::TestDir {
    super::testdir::TestDir::absent(&format!("guard-{tag}"))
}

#[test]
fn guard_counts_a_start_while_compiling_and_clears_after() {
    let d = guard_dir("count");
    let seen = guarded(&d, || Ok(std::fs::read_to_string(d.join(GUARD_FILE)).unwrap()));
    assert_eq!(seen.unwrap(), "1", "the count must be on disk WHILE compiling");
    assert!(!d.join(GUARD_FILE).exists(), "a finished compile clears the count");
    // A clean error is not a crash: cleared too.
    let e: Result<(), String> = guarded(&d, || Err("broken rule".into()));
    assert_eq!(e.unwrap_err(), "broken rule");
    assert!(!d.join(GUARD_FILE).exists());
}

#[test]
fn guard_switches_off_after_max_died_and_not_before() {
    let d = guard_dir("off");
    std::fs::create_dir_all(&d).unwrap();
    // MAX_DIED - 1 earlier starts died: this start still tries, and a success resets the count.
    std::fs::write(d.join(GUARD_FILE), (MAX_DIED - 1).to_string()).unwrap();
    let mut ran = false;
    assert!(guarded(&d, || { ran = true; Ok(()) }).is_ok());
    assert!(ran && !d.join(GUARD_FILE).exists());
    // MAX_DIED starts died: switched off, the compile is NOT attempted, the count stays.
    std::fs::write(d.join(GUARD_FILE), MAX_DIED.to_string()).unwrap();
    let mut ran = false;
    let r: Result<(), String> = guarded(&d, || { ran = true; Ok(()) });
    assert_eq!(r.unwrap_err(), OFF_HERE);
    assert!(!ran, "must not compile once switched off");
    assert!(d.join(GUARD_FILE).exists(), "switched off stays off");
}

#[test]
fn guard_never_compiles_unguarded() {
    // The guard folder is a FILE, so the count cannot be written: refuse, don't compile.
    let d = guard_dir("blocked");
    std::fs::create_dir_all(d.parent().unwrap()).unwrap();
    std::fs::write(&d, b"x").unwrap();
    let mut ran = false;
    let r: Result<(), String> = guarded(&d, || { ran = true; Ok(()) });
    assert!(r.is_err() && !ran, "{r:?}");
    let _ = std::fs::remove_file(&d);
}

/// Loose patterns vs strong ones (26 Sep 2026 - his own shortcuts were called harmful).
#[test]
fn loose_rules_are_weak_and_implants_are_not() {
    use super::yara::{weak_file, weak_rule};
    assert!(weak_rule("bartblaze", "Script_in_LNK"));
    assert!(weak_rule("bartblaze", "Download_in_LNK"));
    assert!(weak_rule("bartblaze", "AutoIT_Script"));
    // Glued: this test binary is scanned by vigils_own_program_matches_none_of_its_rules.
    assert!(weak_rule("bartblaze", &unrev("pmudsndidAprahS")));
    assert!(!weak_rule("bartblaze", "HiddenVNC"));
    assert!(!weak_rule("bartblaze", "Script_in_LN"), "a prefix of a weak rule's name is not that rule");
    assert!(!weak_rule("bartblaze", "No_Such_Rule"), "unknown means strong, never quieter");
    assert!(!weak_rule("ReversingLabs", "Script_in_LNK"), "the set must match too");
    assert!(weak_file("rl/yara/pua/Anything.yara"));
    assert!(!weak_file("rl/yara/ransomware/Win32.Ransomware.X.yara"));
    // every file named in WEAK exists, so a typo cannot silently leave a rule strong
    for w in super::yara::WEAK.iter().filter(|w| !w.ends_with('/')) {
        assert!(super::yara::rule_file_exists(w), "WEAK names a file that is not embedded: {w}");
    }
}

/// 29 Sep 2026: YARAhub rules are taken one file at a time, only CC0 / CC BY 4.0 and only
/// TLP:WHITE. Read from the EMBEDDED files, so a file dropped in by hand later is checked too.
#[test]
fn every_yarahub_rule_is_free_to_ship() {
    let lic = regex::Regex::new(r#"yarahub_license\s*=\s*"([^"]*)""#).unwrap();
    let tlp = regex::Regex::new(r#"yarahub_rule_sharing_tlp\s*=\s*"([^"]*)""#).unwrap();
    let mut n = 0;
    for (rel, src) in super::yara::RULE_FILES.iter().filter(|(r, _)| r.starts_with("yarahub/") || r.starts_with("yarahub-win/")) {
        n += 1;
        let rules = regex::Regex::new(r"(?m)^\s*rule\s").unwrap().find_iter(src).count();
        let l: Vec<&str> = lic.captures_iter(src).map(|c| c.get(1).unwrap().as_str()).collect();
        let t: Vec<&str> = tlp.captures_iter(src).map(|c| c.get(1).unwrap().as_str()).collect();
        assert!(rules >= 1 && l.len() == rules && t.len() == rules, "{rel}: {rules} rules, {} licences, {} TLP", l.len(), t.len());
        assert!(l.iter().all(|x| *x == "CC0 1.0" || *x == "CC BY 4.0"), "{rel}: licence {l:?}");
        assert!(t.iter().all(|x| *x == "TLP:WHITE"), "{rel}: sharing {t:?}");
    }
    assert!(n >= 1000, "only {n} YARAhub files embedded");
}

/// A zip in memory: (name, bytes, compressed?).
fn zip_bytes(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes, deflate) in members {
        let m = if *deflate { zip::CompressionMethod::Deflated } else { zip::CompressionMethod::Stored };
        w.start_file(*name, zip::write::SimpleFileOptions::default().compression_method(m)).unwrap();
        std::io::Write::write_all(&mut w, bytes).unwrap();
    }
    w.finish().unwrap().into_inner()
}
fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// An APK's code is compressed, so rules could not see it (29 Sep 2026). The view is the raw file
/// followed by the decompressed code members; a plain zip is not expanded; a zip bomb stops at 64 MB.
#[test]
fn apk_code_is_seen_decompressed_and_capped() {
    let marker = b"VV_MARKER_classes_dex_7f3a9c".repeat(50);
    let apk = zip_bytes(&[("AndroidManifest.xml", b"manifest", true), ("classes.dex", &marker, true), ("res/a.png", &marker, true)]);
    assert!(!has(&apk, b"VV_MARKER_classes_dex_7f3a9c"), "the raw zip must hide it, or this test proves nothing");
    let f = tmp("app.apk", &apk);
    let (view, members) = apk_view(&*f).expect("an APK is expanded");
    assert!(view.starts_with(b"PK\x03\x04"), "rules that check the zip header still see it");
    assert!(has(&view, b"VV_MARKER_classes_dex_7f3a9c"));
    assert_eq!(members, 2, "classes.dex and the manifest; a picture is not code");
    // A plain zip (no classes.dex) is scanned as it is.
    let f2 = tmp("photos.zip", &zip_bytes(&[("a.dex.txt", &marker, true)]));
    assert!(apk_view(&*f2).is_none());
    // 200 MB of zeros compresses to ~200 KB; the view must stop at 64 MB.
    let bomb = zip_bytes(&[("classes.dex", &vec![0u8; 200 << 20], true)]);
    let f3 = tmp("bomb.apk", &bomb);
    let (v3, _) = apk_view(&*f3).unwrap();
    assert!(v3.len() <= 64 << 20, "view {} bytes", v3.len());
}

/// End to end, with a real YARAhub rule: its strings inside a compressed classes.dex are found
/// through the APK view - and that rule is only "worth a look" (the genuine app matches it too).
#[test]
fn a_rule_finds_strings_inside_an_apks_compressed_code() {
    // Glued at run time: this test binary is itself scanned (vigils_own_program_matches_none_of_its_rules).
    let pkg = unrev("redrawrof.sms.ymrodi.moc");
    let dex = format!("dex\n035\0 {pkg} ... {} ... ", unrev("redrawroFsmS")).into_bytes().repeat(20);
    let apk = zip_bytes(&[("classes.dex", &dex, true)]);
    assert!(!has(&apk, pkg.as_bytes()));
    let f = tmp("fwd.apk", &apk);
    let v = scan(&*f);
    assert_eq!(v["ran"], true, "{v}");
    let m = v["matches"].as_array().unwrap();
    let hit = m.iter().find(|x| x["file"] == "yarahub/Jeevan_SMS_Forwarder_APK.yar").unwrap_or_else(|| panic!("{v}"));
    assert_eq!(hit["set"], "YARAhub");
    assert_eq!(hit["weak"], true);
    assert_eq!(v["apkMembers"], 1);
}

/// Not a test: every rule over a real folder, run by hand to count false alarms
/// (`VV_YARA_DIR=<folder> cargo test --lib real_rules_over_folder -- --ignored --nocapture`).
/// Prints one HIT line per matching file (rule, set, weak) and a TOTAL line; nothing else.
#[test]
#[ignore]
fn real_rules_over_folder() {
    let root = std::path::PathBuf::from(std::env::var("VV_YARA_DIR").expect("set VV_YARA_DIR"));
    let (mut files, mut apks, mut hits, mut strong, mut failed) = (0, 0, 0, 0, 0);
    let mut stack = vec![root];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            files += 1;
            let v = scan(&p);
            if v["ran"] != true {
                failed += 1;
                println!("FAIL {} {}", p.display(), v["reason"]);
                continue;
            }
            if v["apkMembers"].is_number() {
                apks += 1;
            }
            let m = v["matches"].as_array().unwrap();
            if !m.is_empty() {
                hits += 1;
                if m.iter().any(|x| x["weak"] != true) {
                    strong += 1;
                }
                let names: Vec<String> = m.iter().map(|x| format!("{}[{}{}]", x["rule"].as_str().unwrap_or(""), x["set"].as_str().unwrap_or(""), if x["weak"] == true { ",weak" } else { "" })).collect();
                println!("HIT {} {}", p.display(), names.join(" "));
            }
        }
    }
    println!("TOTAL files={files} apkViews={apks} filesHit={hits} filesWithStrong={strong} failed={failed}");
}

/// 29 Sep 2026: an APK over 32 MB was never expanded, so the Android rules never saw a big app's
/// code (8 of 17 popular open-source apps; WhatsApp, banking and UPI apps are that size too).
/// A big APK must be seen BOTH ways: its compressed code, and a pattern that sits only in the raw
/// file far past the start (a stored member after 34 MB of filler).
#[test]
fn a_big_apk_is_seen_in_its_code_and_in_its_raw_file() {
    let mut x: u32 = 7;
    let filler: Vec<u8> = (0..34 << 20).map(|_| { x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223); (x >> 24) as u8 }).collect();
    let marker = format!(" {} ... {} ... ", unrev("redrawrof.sms.ymrodi.moc"), unrev("redrawroFsmS")).into_bytes().repeat(20);
    let find = |v: &Value| v["matches"].as_array().unwrap().iter().any(|m| m["file"] == "yarahub/Jeevan_SMS_Forwarder_APK.yar");

    // In the code: compressed inside classes.dex.
    let dex = [b"dex\n035\0".to_vec(), marker.clone()].concat();
    let a = zip_bytes(&[("classes.dex", &dex, true), ("assets/filler.bin", &filler, false)]);
    assert!(a.len() > 32 << 20 && !has(&a, &marker[..20]));
    let fa = tmp("big-code.apk", &a);
    let va = scan(&*fa);
    assert_eq!(va["apkMembers"], 1, "{va}");
    assert!(find(&va), "big APK's compressed code not seen: {va}");

    // Only in the raw file, stored after the filler (far past the view's 64 KB of raw).
    let b = zip_bytes(&[("classes.dex", b"dex\n035\0 nothing here", true), ("assets/filler.bin", &filler, false), ("assets/z.txt", &marker, false)]);
    let fb = tmp("big-raw.apk", &b);
    let vb = scan(&*fb);
    assert!(find(&vb), "big APK's raw tail not seen: {vb}");

    // And the clean twin stays quiet.
    let c = zip_bytes(&[("classes.dex", b"dex\n035\0 nothing here", true), ("assets/filler.bin", &filler, false)]);
    let fc = tmp("big-clean.apk", &c);
    assert!(!find(&scan(&*fc)));
}

/// 2 Nov 2026: the second set runs on a small file and says so; on a file over EXTRA_MAX it says it
/// did not run, and the main set's answer is unchanged by it.
#[test]
fn the_laptop_second_set_runs_on_small_files_and_says_when_it_did_not() {
    let small = scan(&tmp("small.bin", b"just some ordinary bytes"));
    assert_eq!(small["ran"], true, "{small}");
    assert_eq!(small["extra"]["ran"], true, "{small}");
    assert!(small["rules"].as_u64().unwrap() > small["mainRules"].as_u64().unwrap(), "{small}");
    let mut big = vec![b'a'; (EXTRA_MAX + 1) as usize];
    big[..5].copy_from_slice(b"hello");
    let v = scan(&tmp("big.bin", &big));
    assert_eq!(v["ran"], true, "{v}");
    assert_eq!(v["extra"]["ran"], false, "{v}");
    assert_eq!(v["rules"], v["mainRules"], "{v}");
}
