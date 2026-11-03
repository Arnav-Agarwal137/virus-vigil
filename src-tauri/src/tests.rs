//! Tests for the file checker. The APK expectations are NOT typed here: they are read
//! from tests/fixtures/*.aapt-*.txt, which were produced by Android's own `aapt dump`
//! on the real apps (F-Droid 1.x from f-droid.org, and the owner's Sound 0.1.2 build).
//! The fixtures are those apps' real binary manifests, rezipped on their own.

use super::*;
use std::io::Write;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

/// QR pictures (B8): expectations are read from qr-cases.json, written by make_qr.py from the
/// text it ENCODED with segno - not from what the decoder under test returns.
#[test]
fn qr_codes_in_pictures_are_read() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fixture("qr-cases.json")).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(cases.len() >= 6, "fixture list shrank");
    for c in cases {
        let file = c["file"].as_str().unwrap();
        let r = qr::read(&fixture(file));
        if c["unreadable"] == true {
            assert_eq!(r["read"], false, "{file}: a broken picture must say so, not 'no code': {r}");
            continue;
        }
        assert_eq!(r["read"], true, "{file}: {r}");
        let mut got: Vec<&str> = r["codes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        let mut want: Vec<&str> = c["codes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "{file}");
    }
}

fn lines(name: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_to_string(fixture(name))
        .expect("fixture list missing")
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    v.sort();
    v
}

fn strings(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_array().expect("array").iter().map(|s| s.as_str().unwrap().to_string()).collect();
    out.sort();
    out
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join("virus-vigil-tests");
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

#[test]
fn apk_manifest_matches_aapt_for_real_apps() {
    for app in ["fdroid", "sound"] {
        let v = apk_permissions(&fixture(&format!("{app}.apk"))).unwrap();
        assert_eq!(v["method"], "parsed", "{app}: parser fell back");
        assert_eq!(strings(&v["requested"]), lines(&format!("{app}.aapt-requested.txt")), "{app}: requested");
        assert_eq!(strings(&v["offers"]), lines(&format!("{app}.aapt-services.txt")), "{app}: offered services");
        assert_eq!(v["package"].as_str().map(String::from), lines(&format!("{app}.aapt-package.txt")).pop(), "{app}: package");
        // DUMP only guards a receiver in both apps; it is never asked for.
        assert!(!strings(&v["permissions"]).contains(&"android.permission.DUMP".to_string()), "{app}: DUMP leaked in");
    }
}

#[test]
fn sound_app_notification_listener_is_reported_as_offered() {
    let v = apk_permissions(&fixture("sound.apk")).unwrap();
    let perms = strings(&v["permissions"]);
    assert!(perms.contains(&"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".to_string()));
    assert!(perms.contains(&"android.permission.RECORD_AUDIO".to_string()));
}

#[test]
fn broken_manifest_falls_back_and_still_reports() {
    // What malware does: a manifest the parser cannot walk. We must not say "asks for nothing".
    let p = scratch("broken.apk");
    let f = std::fs::File::create(&p).unwrap();
    let mut z = zip::ZipWriter::new(f);
    z.start_file("AndroidManifest.xml", zip::write::SimpleFileOptions::default()).unwrap();
    z.write_all(b"\x03\x00\x08\x00garbage android.permission.READ_SMS more garbage").unwrap();
    z.finish().unwrap();
    let v = apk_permissions(&p).unwrap();
    assert_eq!(v["method"], "fallback");
    assert_eq!(strings(&v["permissions"]), vec!["android.permission.READ_SMS".to_string()]);
}

#[test]
fn text_file_named_apk_is_refused_not_read_as_empty() {
    let p = scratch("not-really.apk");
    std::fs::write(&p, "hello, I am a text file").unwrap();
    let r = check_file_blocking(p.to_str().unwrap()).unwrap();
    assert_eq!(r["apk"]["read"], false);
    assert!(r["apk"]["error"].as_str().unwrap().contains("does not open"));
}

#[test]
fn folder_is_refused() {
    let d = scratch("a-folder");
    std::fs::create_dir_all(&d).unwrap();
    assert!(check_file_blocking(d.to_str().unwrap()).unwrap_err().contains("folder"));
}

#[test]
fn clean_file_hash_and_defender_verdict() {
    let p = scratch("clean.txt");
    std::fs::write(&p, "abc").unwrap();
    let r = check_file_blocking(p.to_str().unwrap()).unwrap();
    // SHA-256("abc"), the FIPS 180-2 test vector - not a value this code produced.
    assert_eq!(r["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(r["size"], 3);
    assert_eq!(r["defender"]["ran"], true, "Defender scan did not run: {}", r["defender"]);
    assert_eq!(r["defender"]["found"], false);
    assert_eq!(r["stillThere"], true);
}

#[test]
fn real_apk_through_the_whole_checker() {
    let r = check_file_blocking(fixture("sound.apk").to_str().unwrap()).unwrap();
    assert_eq!(r["ext"], "apk");
    assert_eq!(r["apk"]["method"], "parsed");
    assert_eq!(r["defender"]["found"], false, "{}", r["defender"]);
}

#[test]
fn obfuscated_manifest_is_read_by_resource_id() {
    // tests/make_obfuscated.py blanked the attribute NAMES; aapt still reads it (checked).
    let v = apk_permissions(&fixture("sound-obfuscated.apk")).unwrap();
    assert_eq!(v["method"], "parsed");
    assert_eq!(strings(&v["requested"]), lines("sound.aapt-requested.txt"));
    assert_eq!(strings(&v["offers"]), lines("sound.aapt-services.txt"));
    assert_eq!(v["package"].as_str().map(String::from), lines("sound.aapt-package.txt").pop());
}

#[test]
fn scan_carries_the_deeper_checks() {
    let r = run_json_script("scan-test.ps1", &scan_script().unwrap()).unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["extraError"].is_null(), "deeper checks failed: {}", r["extraError"]);
    let x = &r["extra"];
    assert!(x.is_object(), "no extra block in the scan: {r}");
    // Keys the page reads (main.js deeperDoses). Values may be null (unreadable), keys may not vanish.
    for k in ["otherAv", "guestEnabled", "noPasswordAccounts", "smb1", "rdpDeny", "remoteAssist",
              "hideExt", "hostsRead", "hostsEntries", "proxy", "updatesPausedUntil", "rebootPending",
              "cloud", "memoryIntegrity", "lsaPpl", "driverBlocklist", "secureBoot", "cfa", "backup"] {
        assert!(x.get(k).is_some(), "extra.{k} missing: {x}");
    }
    let b = &x["backup"];
    for k in ["folders", "oneDriveAccounts", "oneDriveRoots", "oneDriveRunning", "fileHistory"] {
        assert!(b.get(k).is_some(), "extra.backup.{k} missing: {b}");
    }
    // Arrays must stay arrays even with 0 or 1 entries (PowerShell unrolls one-item arrays).
    assert!(b["oneDriveAccounts"].is_array() && b["oneDriveRoots"].is_array(), "backup lists not arrays: {b}");
    // The main scan is still whole.
    for k in ["defender", "firewall", "browsers", "threatCount"] {
        assert!(r.get(k).is_some(), "main scan lost {k}: {r}");
    }
}

#[test]
fn a_broken_deeper_check_does_not_break_the_scan() {
    let s = join_scan(SCAN_PS, "throw 'deeper-boom'").unwrap();
    let r = run_json_script("scan-broken.ps1", &s).unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["extraError"].as_str().unwrap_or("").contains("deeper-boom"), "{}", r["extraError"]);
}

#[test]
fn join_refuses_a_scan_without_its_json_line() {
    assert!(join_scan("$out = 1", "x").is_err());
}

/// startup.ps1's command-line reader, fed the fixture's command lines (the owner's real task
/// shapes plus hostile ones). Expectations live in the fixture, not here.
#[test]
fn startup_command_lines_are_read_right() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fixture("startup-cases.json")).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    let cmds: Vec<&Value> = cases.iter().map(|c| &c["cmd"]).collect();
    let input = scratch("startup-cases-in.json");
    std::fs::write(&input, serde_json::to_string(&cmds).unwrap()).unwrap();
    let script = write_script("startup-test.ps1", STARTUP_PS).unwrap();
    let out = powershell().arg("-File").arg(&script).env("VV_PARSE_CASES", &input).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let got: Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)));
    let got = got.as_array().unwrap();
    assert_eq!(got.len(), cases.len());
    for (want, g) in cases.iter().zip(got) {
        for k in ["target", "encoded", "web", "tempPlace", "program"] {
            if want.get(k).is_some() {
                assert_eq!(g[k], want[k], "{k} for {}", want["cmd"]);
            }
        }
    }
}

#[test]
fn startup_list_reads_this_laptop() {
    let r = run_json_script("startup-live.ps1", STARTUP_PS).unwrap();
    assert_eq!(r["ok"], true);
    let items = r["items"].as_array().expect("items");
    assert!(!items.is_empty(), "every Windows starts something (SecurityHealth at least)");
    for i in items {
        for k in ["name", "source", "path", "exists", "signature", "enabled", "launcher", "encoded", "web", "tempPlace"] {
            assert!(i.get(k).is_some(), "{k} missing in {i}");
        }
    }
}

/// A fake browser folder: LOCALAPPDATA/APPDATA point at a scratch folder for the child only.
fn fake_browser_home(tag: &str, list: &str) -> PathBuf {
    let home = scratch(&format!("ext-home-{tag}"));
    let _ = std::fs::remove_dir_all(&home);
    let prof = home.join("Google").join("Chrome").join("User Data").join("Default");
    let bad = "abcdefghijklmnopabcdefghijklmnop"; // on the planted list
    let good = "ponmlkjihgfedcbaponmlkjihgfedcba";
    for (id, manifest) in [
        (bad, r#"{"manifest_version":3,"name":"__MSG_appName__","default_locale":"en","version":"1.0","host_permissions":["<all_urls>"],"permissions":["cookies","scripting"]}"#),
        (good, r#"{"manifest_version":3,"name":"Plain Helper","version":"2.1","permissions":["storage"]}"#),
    ] {
        let d = prof.join("Extensions").join(id).join("1.0_0");
        std::fs::create_dir_all(d.join("_locales").join("en")).unwrap();
        std::fs::write(d.join("manifest.json"), manifest).unwrap();
        std::fs::write(d.join("_locales").join("en").join("messages.json"), r#"{"APPNAME":{"message":"Coupon Finder"}}"#).unwrap();
    }
    std::fs::write(prof.join("Secure Preferences"), format!(
        r#"{{"extensions":{{"settings":{{"{bad}":{{"location":1,"from_webstore":true}},"{good}":{{"location":1,"from_webstore":true,"disable_reasons":[1]}}}}}}}}"#)).unwrap();
    std::fs::write(prof.parent().unwrap().join("Local State"), r#"{"profile":{"info_cache":{"Default":{"name":"Test Person"}}}}"#).unwrap();
    let lists = home.join("VirusVigil").join("lists");
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(lists.join("chrome-mal-ids.txt"), list).unwrap();
    std::fs::create_dir_all(home.join("roaming")).unwrap();
    home
}

fn planted_list(total_line: usize) -> String {
    // 1000+ valid ids (a-p only) including the planted one; "Total:" as given.
    let mut ids = vec!["abcdefghijklmnopabcdefghijklmnop".to_string()];
    let a: Vec<char> = "abcdefghijklmnop".chars().collect();
    for n in 0..1200usize {
        let mut s = String::new();
        let mut x = n + 1;
        for _ in 0..32 { s.push(a[x % 16]); x = x / 16 + 7; }
        ids.push(s);
    }
    ids.sort();
    ids.dedup();
    let total = if total_line == 0 { ids.len() } else { total_line };
    format!("# test list\n# Generated: 2026-09-24 00:00 UTC\n# Total: {total}\n{}\n", ids.join("\n"))
}

fn run_extensions(home: &PathBuf) -> Value {
    let script = write_script("ext-test.ps1", EXTENSIONS_PS).unwrap();
    let out = powershell().arg("-File").arg(&script)
        .env("LOCALAPPDATA", home).env("APPDATA", home.join("roaming")).env("VV_NO_NETWORK", "1")
        .output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn extension_on_the_list_is_found_and_described() {
    let r = run_extensions(&fake_browser_home("good", &planted_list(0)));
    assert!(r["list"]["error"].is_null(), "{}", r["list"]);
    assert!(r["list"]["count"].as_u64().unwrap() > 1000);
    let ex = r["extensions"].as_array().unwrap();
    assert_eq!(ex.len(), 2, "{r}");
    let bad = ex.iter().find(|e| e["id"] == "abcdefghijklmnopabcdefghijklmnop").unwrap();
    assert_eq!(bad["known"], true);
    assert_eq!(bad["name"], "Coupon Finder", "__MSG_ name, key matched case-insensitively");
    assert_eq!(bad["enabled"], true);
    assert_eq!(bad["profile"], "Test Person");
    assert!(bad["hosts"].as_array().unwrap().iter().any(|h| h == "<all_urls>"));
    let good = ex.iter().find(|e| e["name"] == "Plain Helper").unwrap();
    assert_eq!(good["known"], false);
    assert_eq!(good["enabled"], false, "disable_reasons [1] = off");
}

/// Firefox profiles (B9): profiles.ini with a relative and an absolute profile, one without
/// extensions.json. Field names and meanings from Mozilla's XPIDatabase / AddonManager source.
#[test]
fn firefox_addons_are_read_and_builtins_skipped() {
    let home = fake_browser_home("firefox", &planted_list(0));
    let ff = home.join("roaming").join("Mozilla").join("Firefox");
    let rel = ff.join("Profiles").join("abcd.default-release");
    let abs = home.join("elsewhere").join("work-profile");
    let empty = ff.join("Profiles").join("zzzz.empty");
    for d in [&rel, &abs, &empty] { std::fs::create_dir_all(d).unwrap(); }
    std::fs::write(ff.join("profiles.ini"), format!(
        "[General]\r\nStartWithLastProfile=1\r\n\r\n[Profile0]\r\nName=default-release\r\nIsRelative=1\r\nPath=Profiles/abcd.default-release\r\n\r\n[Profile1]\r\nName=Work\r\nIsRelative=0\r\nPath={}\r\n\r\n[Profile2]\r\nName=Empty\r\nIsRelative=1\r\nPath=Profiles/zzzz.empty\r\n",
        abs.display())).unwrap();
    // Profile 0: store add-on on every site, a switched-off one, a theme, a built-in, a system add-on,
    // an add-on another program put in through the registry, and an unsigned one.
    std::fs::write(rel.join("extensions.json"), r#"{"schemaVersion":36,"addons":[
      {"id":"uBlock0@raymondhill.net","type":"extension","location":"app-profile","active":true,"userDisabled":false,"version":"1.60.0","defaultLocale":{"name":"uBlock Origin"},"signedState":2,"userPermissions":{"permissions":["storage","tabs"],"origins":["<all_urls>"]},"foreignInstall":false,"sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/ublock.xpi"},
      {"id":"sleepy@example.org","type":"extension","location":"app-profile","active":false,"userDisabled":true,"version":"2.0","defaultLocale":{"name":"Sleepy Tab"},"signedState":2,"userPermissions":{"permissions":["storage"],"origins":[]},"foreignInstall":false,"sourceURI":"https://example.org/downloads/sleepy.xpi"},
      {"id":"dark@mozilla.org","type":"theme","location":"app-builtin","active":true,"version":"1.3","defaultLocale":{"name":"Dark"},"signedState":null},
      {"id":"sunset@themes.example","type":"theme","location":"app-profile","active":true,"version":"1.0","defaultLocale":{"name":"Sunset Theme"},"signedState":2,"foreignInstall":false},
      {"id":"formautofill@mozilla.org","type":"extension","location":"app-builtin-addons","active":true,"version":"1.0","defaultLocale":{"name":"Form Autofill"},"signedState":3},
      {"id":"pictureinpicture@mozilla.org","type":"extension","location":"app-system-addons","active":true,"version":"1.0","defaultLocale":{"name":"PiP"},"signedState":4},
      {"id":"toolbar@shady.example","type":"extension","location":"winreg-app-global","active":true,"version":"9.9","defaultLocale":{"name":"Shopping Toolbar"},"signedState":2,"userPermissions":{"permissions":["cookies"],"origins":["*://*/*"]},"foreignInstall":true},
      {"id":"raw@example.org","type":"extension","location":"app-profile","active":true,"version":"0.1","defaultLocale":{"name":"Raw Helper"},"signedState":0,"userPermissions":{"permissions":[],"origins":["https://example.org/*"]},"foreignInstall":false}
    ]}"#).unwrap();
    // Profile 1 (absolute path): exactly ONE add-on - PowerShell must not unroll it into a non-array.
    std::fs::write(abs.join("extensions.json"), r#"{"schemaVersion":36,"addons":[
      {"id":"solo@example.org","type":"extension","location":"app-profile","active":true,"version":"3.0","defaultLocale":{"name":"Solo"},"signedState":2,"userPermissions":{"permissions":["storage"],"origins":[]},"foreignInstall":false}
    ]}"#).unwrap();

    let r = run_extensions(&home);
    let ex: Vec<&Value> = r["extensions"].as_array().unwrap().iter().filter(|e| e["browser"] == "firefox").collect();
    let names: Vec<&str> = ex.iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["uBlock Origin", "Sleepy Tab", "Shopping Toolbar", "Raw Helper", "Solo"], "{r}");
    let by = |n: &str| *ex.iter().find(|e| e["name"] == n).unwrap();
    assert_eq!(by("uBlock Origin")["fromStore"], true);
    assert_eq!(by("uBlock Origin")["foreign"], false);
    assert!(by("uBlock Origin")["hosts"].as_array().unwrap().iter().any(|h| h == "<all_urls>"));
    assert_eq!(by("uBlock Origin")["profile"], "default-release");
    assert_eq!(by("Sleepy Tab")["enabled"], false);
    assert!(by("Sleepy Tab")["fromStore"].is_null(), "a download address outside addons.mozilla.org = unknown, never false");
    assert_eq!(by("Shopping Toolbar")["foreign"], true);
    assert_eq!(by("Raw Helper")["signedState"], 0);
    assert_eq!(by("Solo")["profile"], "Work");
    assert!(by("Solo")["permissions"].is_array() && by("Solo")["hosts"].is_array());
    assert!(ex.iter().all(|e| e["known"] == false), "the list covers Chrome ids only");
    // Chrome profile (1) + two Firefox profiles with a database; the empty one is not counted.
    assert_eq!(r["profilesRead"], 3, "{r}");
}

#[test]
fn damaged_list_says_not_checked_instead_of_clean() {
    let r = run_extensions(&fake_browser_home("damaged", &planted_list(99999)));
    assert_eq!(r["list"]["error"], "saved list is damaged", "{}", r["list"]);
    assert_eq!(r["list"]["count"], 0);
    // The page must read count 0 as "not checked", never as "none are bad".
    assert!(r["extensions"].as_array().unwrap().iter().all(|e| e["known"] == false));
}

#[test]
fn phishing_lookup_is_exact_and_says_when_it_could_not_check() {
    let p = scratch("phish-list.txt");
    std::fs::write(&p, "# comment\nevil-login.web.app\nsbi-kyc-update.xyz\n\nSITES.GOOGLE.COM\n").unwrap();
    let names = vec!["sbi-kyc-update.xyz".to_string(), "EVIL-LOGIN.web.app".into(), "web.app".into(), "kyc-update.xyz".into(), "sites.google.com".into()];
    let r = phish::lookup_in(&p, &names);
    assert_eq!(r["count"], 3);
    assert!(r["error"].is_null());
    let found: Vec<String> = r["found"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    // Exact names only (any case); a parent or a longer name is not a match.
    assert_eq!(found, vec!["sbi-kyc-update.xyz", "EVIL-LOGIN.web.app", "sites.google.com"]);
    // The file changing on disk is picked up (cache keyed on modified time).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&p, "kyc-update.xyz\n").unwrap();
    let r = phish::lookup_in(&p, &names);
    assert_eq!(r["found"], serde_json::json!(["kyc-update.xyz"]));
    let missing = phish::lookup_in(&scratch("no-such-list.txt"), &names);
    assert_eq!(missing["count"], 0);
    assert!(missing["error"].is_string());
}

// 31 Oct 2026: the list's makers stopped on 2 Oct while our download time said "today". The makers'
// own date is kept beside the list; unknown stays unknown (null), never "fresh".
#[test]
fn phishing_list_reports_its_makers_date_not_our_download_time() {
    assert_eq!(phish::parse_iso_utc("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(phish::parse_iso_utc("2026-10-02T15:30:28Z"), Some(1_790_955_028));
    assert_eq!(phish::parse_iso_utc("2024-02-29T00:00:00Z"), Some(1_709_164_800));
    for bad in ["2026-10-02 15:30:28Z", "2026-13-02T15:30:28Z", "2026-10-02T15:30:28", "", "2026-10-02T15:30:28+05:30"] {
        assert_eq!(phish::parse_iso_utc(bad), None, "{bad}");
    }
    let p = scratch("phish-since.txt");
    std::fs::write(&p, "evil-login.web.app\n").unwrap();
    let names = vec!["x.example".to_string()];
    let _ = std::fs::remove_file(phish::since_path(&p));
    assert!(phish::lookup_in(&p, &names)["sourceDays"].is_null(), "no sidecar = unknown");
    let ten_days_ago = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 10 * 86400 - 60;
    std::fs::write(phish::since_path(&p), ten_days_ago.to_string()).unwrap();
    assert_eq!(phish::lookup_in(&p, &names)["sourceDays"], 10);
    // A good download with an unreadable date removes the old note, so it never describes a newer list.
    phish::write_since(&p, Some("not a date"));
    assert!(!phish::since_path(&p).exists());
    assert!(phish::lookup_in(&p, &names)["sourceDays"].is_null());
    phish::write_since(&p, Some("2026-10-02T15:30:28Z"));
    assert_eq!(std::fs::read_to_string(phish::since_path(&p)).unwrap(), "1790955028");
}

fn run_phish_update(home: &PathBuf, src: &PathBuf) -> Value {
    run_phish_update2(home, src, src)
}

/// Both lists from local files, so the test never reaches the real list servers.
fn run_phish_update2(home: &PathBuf, src: &PathBuf, cert: &PathBuf) -> Value {
    let script = write_script("phish-update-test.ps1", PHISH_UPDATE_PS).unwrap();
    let url = |p: &PathBuf| format!("file:///{}", p.to_string_lossy().replace('\\', "/"));
    let out = powershell().arg("-File").arg(&script)
        .env("LOCALAPPDATA", home).env("VV_PHISH_URL", url(src)).env("VV_PHISH_MIN", "3")
        .env("VV_CERTPL_URL", url(cert)).env("VV_CERTPL_MIN", "3")
        // An unreachable address: the makers' date must then be unknown, never invented.
        .env("VV_PHISH_API", "http://127.0.0.1:9/none")
        .output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn phishing_update_keeps_the_old_list_when_a_download_is_bad() {
    let home = scratch("phish-home");
    let _ = std::fs::remove_dir_all(&home);
    let good = scratch("phish-good.txt");
    std::fs::write(&good, "a-bad.example\nb-bad.example\nc-bad.example\n").unwrap();
    let r = run_phish_update(&home, &good);
    assert_eq!(r["updated"], true, "{r}");
    let dest = home.join("VirusVigil").join("lists").join("phishing-domains.txt");
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "a-bad.example\nb-bad.example\nc-bad.example\n");
    // Fresh copy: a second run does not download.
    assert_eq!(run_phish_update(&home, &good)["skipped"], true);
    // Make it old, then offer garbage: refused, old copy untouched.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
    std::fs::File::options().write(true).open(&dest).unwrap().set_modified(old).unwrap();
    let junk = scratch("phish-junk.txt");
    std::fs::write(&junk, "<html>\n<body>rate limited</body>\n</html>\nnot a host name!\n").unwrap();
    let r = run_phish_update(&home, &junk);
    assert_eq!(r["updated"], false, "{r}");
    assert!(r["error"].as_str().unwrap_or("").contains("failed its checks"), "{r}");
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "a-bad.example\nb-bad.example\nc-bad.example\n");
}

// 2 Nov 2026: CERT Polska's list is a second file with its own answer; a bad CERT download must
// not touch either list, and the first list's answer stays at the top as before.
#[test]
fn phishing_update_fetches_cert_polska_beside_the_first_list() {
    let home = scratch("phish-home2");
    let _ = std::fs::remove_dir_all(&home);
    let good = scratch("phish-good2.txt");
    std::fs::write(&good, "a-bad.example\nb-bad.example\nc-bad.example\n").unwrap();
    let cert = scratch("phish-cert.txt");
    std::fs::write(&cert, "x-pl.example\ny-pl.example\nz-pl.example\nw-pl.example\n").unwrap();
    let r = run_phish_update2(&home, &good, &cert);
    assert_eq!(r["updated"], true, "{r}");
    assert_eq!(r["certpl"]["updated"], true, "{r}");
    assert_eq!(r["certpl"]["lines"], 4, "{r}");
    let lists = home.join("VirusVigil").join("lists");
    assert_eq!(std::fs::read_to_string(lists.join("phishing-certpl.txt")).unwrap(), "x-pl.example\ny-pl.example\nz-pl.example\nw-pl.example\n");
    // No date could be read (file:// has no Last-Modified, the API is unreachable): no sidecar at all.
    assert!(!lists.join("phishing-certpl.since").exists());
    assert!(!lists.join("phishing-domains.since").exists());
    // Both fresh: nothing downloaded. Then CERT made 7 h old (its limit is 6) and offered junk.
    let r = run_phish_update2(&home, &good, &cert);
    assert_eq!((r["skipped"].clone(), r["certpl"]["skipped"].clone()), (json!(true), json!(true)), "{r}");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 3600);
    std::fs::File::options().write(true).open(lists.join("phishing-certpl.txt")).unwrap().set_modified(old).unwrap();
    let junk = scratch("phish-junk2.txt");
    std::fs::write(&junk, "<html>\n<body>busy</body>\n</html>\nnot a host!\n").unwrap();
    let r = run_phish_update2(&home, &good, &junk);
    assert_eq!(r["skipped"], true, "the first list is still under a day old: {r}");
    assert_eq!(r["certpl"]["updated"], false, "{r}");
    assert!(r["certpl"]["error"].as_str().unwrap_or("").contains("failed its checks"), "{r}");
    assert_eq!(std::fs::read_to_string(lists.join("phishing-certpl.txt")).unwrap(), "x-pl.example\ny-pl.example\nz-pl.example\nw-pl.example\n");
}

// 2 Nov 2026: a link is checked against every list; the answer says WHICH list named it, and one
// list missing is still a check (by the other), while no list at all is NOT a check.
#[test]
fn phishing_lookup_asks_every_list_and_names_the_one_that_found_it() {
    let d = scratch("phish-many");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let names = vec!["only-pdb.example".to_string(), "both.example".into(), "only-cert.example".into(), "clean.example".into()];
    let none = phish::lookup_many(&d, &names);
    assert_eq!(none["count"], 0);
    assert!(none["error"].is_string(), "no list = not checked: {none}");
    std::fs::write(d.join(phish::SOURCES[1].1), "only-cert.example\nBOTH.example\n").unwrap();
    let one = phish::lookup_many(&d, &names);
    assert!(one["error"].is_null(), "{one}");
    assert_eq!(one["count"], 2);
    assert_eq!(one["found"], json!(["both.example", "only-cert.example"]));
    assert_eq!(one["lists"][0]["count"], 0);
    assert!(one["lists"][0]["error"].is_string(), "the missing list says so: {one}");
    std::fs::write(d.join(phish::SOURCES[0].1), "only-pdb.example\nboth.example\nx.example\n").unwrap();
    let ten_days_ago = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 10 * 86400 - 60;
    std::fs::write(phish::since_path(&d.join(phish::SOURCES[0].1)), ten_days_ago.to_string()).unwrap();
    let both = phish::lookup_many(&d, &names);
    assert_eq!(both["count"], 5);
    assert_eq!(both["found"], json!(["only-pdb.example", "both.example", "only-cert.example"]));
    assert_eq!(both["foundBy"]["only-pdb.example"], json!(["Phishing.Database"]));
    assert_eq!(both["foundBy"]["both.example"], json!(["Phishing.Database", "CERT Polska"]));
    assert_eq!(both["foundBy"]["only-cert.example"], json!(["CERT Polska"]));
    assert!(both["foundBy"].get("clean.example").is_none());
    assert_eq!(both["lists"][0]["sourceDays"], 10);
    assert!(both["lists"][1]["sourceDays"].is_null(), "no date beside CERT's copy = unknown");
    assert_eq!(both["sourceDays"], 10, "the only known makers' date");
    // The two lists are cached side by side: asking again (no file changed) gives the same answer.
    assert_eq!(phish::lookup_many(&d, &names)["found"], both["found"]);
}

#[test]
fn only_a_five_character_hash_prefix_may_leave() {
    for ok in ["5BAA6", "00000", "FFFFF"] { assert!(valid_prefix(ok), "{ok}"); }
    for bad in ["5baa6", "5BAA", "5BAA61", "5BAG6", "", "passw", "5BAA6 ", "../..", "5BA\u{0}6"] {
        assert!(!valid_prefix(bad), "{bad:?} must be refused");
    }
}

#[test]
fn leaked_password_range_lookup_works_live() {
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, the textbook example.
    let r = pwned_laptop("5BAA6").unwrap();
    assert_eq!(r["ok"], true, "{r}");
    let body = r["body"].as_str().unwrap();
    let line = body.lines().find(|l| l.starts_with("1E4C9B93F3F0682250B6CF8331B7EE68FD8:")).expect("textbook hash missing");
    let count: u64 = line.split(':').nth(1).unwrap().trim().parse().unwrap();
    assert!(count > 1000, "{line}");
    assert!(pwned_laptop("password").is_err());
}

#[test]
fn local_ai_probe_names_a_vetted_model_or_says_why_not() {
    let r = tauri::async_runtime::block_on(ask_local_ai(String::new())).unwrap();
    if r["ok"] == true {
        assert!(["qwen3:14b", "qwen3:8b"].contains(&r["model"].as_str().unwrap()), "{r}");
        assert!(r["answer"].is_null(), "an empty question must not generate anything: {r}");
    } else {
        assert!(["no-ollama", "no-model"].contains(&r["error"].as_str().unwrap_or("")), "{r}");
    }
}

fn cards_db(name: &str, rows: Option<usize>) -> PathBuf {
    let p = scratch(name);
    let _ = std::fs::remove_file(&p);
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE autofill (name TEXT);").unwrap();
    if let Some(n) = rows {
        c.execute_batch("CREATE TABLE credit_cards (guid TEXT, name_on_card TEXT);").unwrap();
        for i in 0..n {
            c.execute("INSERT INTO credit_cards VALUES (?1, 'X')", [format!("g{i}")]).unwrap();
        }
    }
    drop(c);
    p
}

#[test]
fn saved_cards_counted_without_reading_them() {
    assert_eq!(cards::count_chromium(&cards_db("wd-two", Some(2))).unwrap(), 2);
    assert_eq!(cards::count_chromium(&cards_db("wd-zero", Some(0))).unwrap(), 0);
    // no known table = the layout changed: an error, not a reassuring zero
    assert!(cards::count_chromium(&cards_db("wd-notable", None)).is_err());
    // unreadable is an error, never a quiet "0 cards"
    let junk = scratch("wd-junk");
    std::fs::write(&junk, b"this is not a database at all, just text padding it out").unwrap();
    assert!(cards::count_chromium(&junk).is_err());
    assert!(cards::count_chromium(&scratch("wd-missing-file")).is_err());
    assert_eq!(cards::count_firefox(r#"{"version":3,"addresses":[],"creditCards":[{"guid":"a"},{"guid":"b"},{"guid":"c"}]}"#).unwrap(), 3);
    assert_eq!(cards::count_firefox(r#"{"version":3,"addresses":[]}"#).unwrap(), 0);
    assert!(cards::count_firefox("not json").is_err());
}

/// software.ps1's judging, fed the fixture's names and versions. Expectations (which rule
/// matches, old or not, or "cannot tell" = null) live in the fixture, not here.
#[test]
fn old_attack_prone_programs_are_judged_right() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fixture("software-cases.json")).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    let script = write_script("software-test.ps1", SOFTWARE_PS).unwrap();
    let out = powershell().arg("-File").arg(&script).env("VV_SOFTWARE_CASES", fixture("software-cases.json")).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let got: Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(got["ok"], true, "{got}");
    assert_eq!(got["read"], cases.len());
    let items = got["items"].as_array().unwrap();
    for want in cases {
        let hit = items.iter().find(|i| i["name"] == want["name"]);
        if want["id"].is_null() {
            assert!(hit.is_none(), "{} should match no rule", want["name"]);
            continue;
        }
        let hit = hit.unwrap_or_else(|| panic!("{} matched no rule", want["name"]));
        assert_eq!(hit["id"], want["id"], "rule for {}", want["name"]);
        assert_eq!(hit["old"], want["old"], "old for {}", want["name"]);
    }
    assert_eq!(items.len(), cases.iter().filter(|c| !c["id"].is_null()).count());
}

#[test]
fn old_program_check_reads_this_laptop_and_rides_with_the_scan() {
    let r = run_json_script("software-live.ps1", SOFTWARE_PS).unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert!(r["read"].as_u64().unwrap() > 20, "a real Windows lists many programs: {r}");
}

/// Windows' camera/microphone record: both devices reported, each app with a start time,
/// and "in use" is a yes/no (never missing). What the page says about it is checked in the window.
#[test]
fn camera_and_microphone_record_reads_this_laptop() {
    let r = run_json_script("camera-live.ps1", CAMERA_PS).unwrap();
    assert_eq!(r["ok"], true, "{r}");
    let devs = r["devices"].as_array().unwrap();
    let names: Vec<&str> = devs.iter().map(|d| d["device"].as_str().unwrap()).collect();
    assert_eq!(names, ["webcam", "microphone"]);
    for d in devs {
        for a in d["apps"].as_array().unwrap() {
            assert!(a["lastStart"].is_string(), "{a}");
            assert!(a["inUse"].is_boolean(), "{a}");
        }
    }
}

/// camera.ps1's judging, fed raw registry-style records from the fixture (expectations there):
/// Stop = 0 or Stop before Start means "in use now"; never-used apps are left out; a program
/// whose path is gone says so rather than being called unsigned.
#[test]
fn camera_records_are_judged_right() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fixture("camera-cases.json")).unwrap()).unwrap();
    let script = write_script("camera-test.ps1", CAMERA_PS).unwrap();
    let out = powershell().arg("-File").arg(&script).env("VV_CAMERA_CASES", fixture("camera-cases.json")).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let got: Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(got["ok"], true, "{got}");
    for (i, dev) in ["webcam", "microphone"].iter().enumerate() {
        let d = &got["devices"][i];
        assert_eq!(d["device"], *dev);
        assert_eq!(d["allowedForApps"], cases["masters"][dev]);
        let apps = d["apps"].as_array().unwrap();
        let mut listed = 0;
        for c in cases[dev].as_array().unwrap() {
            let key = c["key"].as_str().unwrap();
            let name = if c["packaged"] == true { key.to_string() } else { key.rsplit('#').next().unwrap().to_string() };
            let hit = apps.iter().find(|a| a["name"] == name.as_str());
            let want = &c["want"];
            assert_eq!(hit.is_some(), want["listed"] == true, "listed for {key}");
            let Some(hit) = hit else { continue };
            listed += 1;
            for k in ["inUse", "exists", "signature"] {
                if want.get(k).is_some() {
                    assert_eq!(hit[k], want[k], "{k} for {key}");
                }
            }
        }
        assert_eq!(apps.len(), listed, "{dev}: nothing extra");
    }
}

/// Remote-control programs (B7): expectations are the "want" field of each fixture case.
#[test]
fn remote_control_programs_are_named_and_lookalikes_ignored() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fixture("remote-cases.json")).unwrap()).unwrap();
    let script = write_script("remote-test.ps1", REMOTE_PS).unwrap();
    let out = powershell().arg("-File").arg(&script).env("VV_REMOTE_CASES", fixture("remote-cases.json")).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let got: Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .unwrap_or_else(|e| panic!("{e}: {text} / {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(got["ok"], true, "{got}");
    let cases = cases.as_array().unwrap();
    assert_eq!(got["checked"].as_u64().unwrap() as usize, cases.len());
    let want: Vec<&str> = cases.iter().filter_map(|c| c["want"].as_str()).collect();
    let running: Vec<&str> = got["running"].as_array().unwrap().iter().map(|r| r["tool"].as_str().unwrap()).collect();
    assert_eq!(running, want, "{got}");
}

/// The live list reads this laptop without failing (whatever happens to be running).
#[test]
fn remote_control_check_reads_this_laptop() {
    let got = run_json_script("remote-live.ps1", REMOTE_PS).unwrap();
    assert_eq!(got["ok"], true, "{got}");
    assert!(got["checked"].as_u64().unwrap() > 20, "{got}");
}

/// Windows' own "this file has a virus" refusals (225, 226) are Defender's verdict; other open
/// errors stay errors. 225 is what the EICAR test file produced on this laptop, 24 Sep 2026.
#[test]
fn a_file_defender_locked_is_reported_as_a_threat() {
    assert!(defender_blocked(&std::io::Error::from_raw_os_error(225)));
    assert!(defender_blocked(&std::io::Error::from_raw_os_error(226)));
    assert!(!defender_blocked(&std::io::Error::from_raw_os_error(5)), "access denied is not a verdict");
    assert!(!defender_blocked(&std::io::Error::from_raw_os_error(32)), "file in use is not a verdict");
    let v = blocked_by_defender(&fixture("qr-none.png"), "x.com", "com", 68);
    assert_eq!(v["defender"]["found"], true);
    assert_eq!(v["defender"]["blocked"], true);
    assert!(v["sha256"].is_null());
    assert_eq!(v["stillThere"], true);
}

/// MpCmdRun exits 2 for "threat found" AND for "the scan failed". The failure text below was
/// captured from this laptop on 24 Sep 2026 (a forward-slash path made the scan fail); before
/// the fix the app called that file a threat and said "delete it".
#[test]
fn a_failed_defender_scan_is_never_a_threat() {
    let failed = "Scan starting...\r\nCmdTool: Failed with hr = 0x80508023. Check C:\\Users\\x\\AppData\\Local\\Temp\\MpCmdRun.log for more information";
    let v = defender_verdict(2, failed, None);
    assert_eq!(v["found"], false);
    assert_eq!(v["ran"], false);
    assert!(v["reason"].as_str().unwrap().contains("0x80508023"));
    let clean = "Scan starting...\r\nScan finished.\r\nScanning R:\\f.png found no threats.";
    assert_eq!(defender_verdict(0, clean, None)["found"], false);
    assert_eq!(defender_verdict(0, clean, None)["ran"], true);
    assert_eq!(defender_verdict(2, "Scan starting...\r\nThreat : Virus:DOS/EICAR_Test_File", None)["found"], true);
}

/// The same path written with forward slashes must scan clean end to end (it failed before).
#[test]
fn forward_slash_paths_scan_clean() {
    let p = fixture("qr-broken.png").to_string_lossy().replace('\\', "/");
    let r = check_file_blocking(&p).unwrap();
    assert_eq!(r["defender"]["found"], false, "{}", r["defender"]);
    assert_eq!(r["defender"]["ran"], true, "{}", r["defender"]);
}

/// The phone's phishing-list check must accept exactly what ps/phish-update.ps1 accepts.
/// Cases chosen at the pattern's edges; expectations are PowerShell's own -match answers
/// (run 24 Sep 2026 against '^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$').
#[test]
fn phone_phish_lines_match_the_laptop_rule() {
    for (line, ok) in [
        ("example.com", true), ("a", true), ("_", true), ("_dmarc.x.org", true), ("EXAMPLE.COM", true),
        ("x-", false), ("x.", false), ("-x", false), (".x", false), ("a b.com", false), ("", false), ("xn--80ak6aa92e.com", true),
    ] {
        assert_eq!(phish::looks_like_host(line), ok, "line {line:?}");
    }
}

#[test]
fn phone_phish_download_is_swapped_in_only_when_whole() {
    let dir = std::env::temp_dir().join("vv-phish-accept-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("list.txt");
    std::fs::write(&dest, "old.example\n").unwrap();

    // Too short: refused, download deleted, old list untouched.
    let tmp = dir.join("list.txt.download");
    std::fs::write(&tmp, "# header\na.com\nb.com\n").unwrap();
    assert!(phish::accept_download(&tmp, &dest, 3).is_err());
    assert!(!tmp.exists());
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "old.example\n");

    // Whole: swapped in, count excludes comments and blanks.
    let body: String = (0..200).map(|i| format!("site{i}.example\r\n")).collect::<String>() + "#c\n\n";
    std::fs::write(&tmp, &body).unwrap();
    assert_eq!(phish::accept_download(&tmp, &dest, 200), Ok(200));
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), body);

    // 2 bad lines in 100 = 98% valid: refused.
    let bad: String = (0..98).map(|i| format!("s{i}.example\n")).collect::<String>() + "bad line\nx-\n";
    std::fs::write(&tmp, &bad).unwrap();
    assert!(phish::accept_download(&tmp, &dest, 10).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Online AI (his 19:45 rule): what must NOT leave the device, and what must survive so the
/// question still makes sense. Each case: input, strings that must be gone, strings that must stay.
#[test]
fn personal_details_are_stripped_before_a_question_goes_online() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        ("My number is +91 98765 43210, someone is calling me", &["98765", "43210"], &["someone is calling me"]),
        ("they called from 9876543210 and asked for OTP", &["9876543210"], &["asked for OTP"]),
        ("I gave my OTP 482913 to the caller, what now?", &["482913"], &["I gave my OTP", "to the caller"]),
        ("my card 4111 1111 1111 1111 was charged", &["4111"], &["was charged"]),
        ("aadhaar 1234 5678 9012 misuse?", &["1234", "9012"], &["misuse"]),
        ("mail me at someone.test@example.com please", &["someone.test", "example.com"], &["mail me at"]),
        ("I paid to scammer@ybl on UPI", &["scammer@ybl"], &["on UPI"]),
        ("is https://bit.ly/3xYz safe? also check sbi-kyc-update.xyz/login", &["bit.ly", "3xYz", "sbi-kyc", "/login"], &["safe"]),
        ("my password is Tiger@123 and I think it leaked", &["Tiger@123"], &["password", "leaked"]),
        ("upi pin: 4321 was typed on a fake page", &["4321"], &["was typed on a fake page"]),
        ("PAN ABCDE1234F and IFSC SBIN0001234 were asked", &["ABCDE1234F", "SBIN0001234"], &["were asked"]),
        ("Hi, I am Arnav Agarwal and my phone is slow", &["Arnav", "Agarwal"], &["my phone is slow"]),
        ("my name is priya sharma, my Instagram got hacked", &["priya", "sharma"], &["my Instagram got hacked"]),
        ("Mr Rakesh Kumar from the bank called me", &["Rakesh", "Kumar"], &["from the bank called me"]),
        ("my brother Rohan clicked a link", &["Rohan"], &["my brother", "clicked a link"]),
        ("the anydesk code was 123 456 789", &["123 456 789", "456"], &["anydesk code"]),
        // Must survive untouched:
        ("I am worried, I lost Rs 25000 on UPI 3 days ago", &[], &["I am worried", "Rs 25000", "3 days"]),
        ("I lost 50000 rupees in 2024, can I get it back?", &[], &["50000 rupees", "2024"]),
        ("should I call 1930 or the bank first?", &[], &["1930"]),
        ("I am Not sure if my laptop has a virus", &[], &["I am Not sure"]),
        ("what is SIM swap and how do I stop it?", &[], &["what is SIM swap and how do I stop it?"]),
        ("₹5000 was debited", &[], &["₹5000"]),
    ];
    for (input, gone, kept) in cases {
        let r = redact::redact(input);
        for g in *gone {
            assert!(!r.text.contains(g), "{input:?}: {g:?} leaked -> {:?}", r.text);
        }
        for k in *kept {
            assert!(r.text.contains(k), "{input:?}: {k:?} was stripped -> {:?}", r.text);
        }
        if gone.is_empty() {
            assert!(r.removed.is_empty(), "{input:?}: nothing personal, but removed {:?} -> {:?}", r.removed, r.text);
        } else {
            assert!(!r.removed.is_empty(), "{input:?}: removed-list empty");
        }
    }
    // The removed list names kinds in words the page shows.
    let r = redact::redact("call 9876543210 or mail a@example.com");
    assert_eq!(r.removed, vec!["email", "number"]);
}

/// The online AI's reply, read from the transport's {status, body, error}. The 200 body shape is
/// Groq's real reply (captured 24 Sep 2026 from api.groq.com with curl), trimmed to the fields read.
#[test]
fn online_ai_replies_are_read_and_failures_named() {
    let ok = json!({"status": 200, "error": null,
        "body": r#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":" Call 1930 now. ","reasoning":"..."},"finish_reason":"stop"}]}"#});
    assert_eq!(online_reply(&ok), (Some("Call 1930 now.".to_string()), None));
    let empty = json!({"status": 200, "error": null, "body": r#"{"choices":[{"message":{"content":""}}]}"#});
    assert!(online_reply(&empty).0.is_none() && online_reply(&empty).1.is_some());
    assert_eq!(online_reply(&json!({"status": 429, "error": null, "body": "{}"})).1.as_deref(), Some("busy"));
    assert_eq!(online_reply(&json!({"status": 401, "error": null, "body": "{}"})).1.as_deref(), Some("no-key"));
    assert_eq!(online_reply(&json!({"status": 0, "error": "no-key", "body": ""})).1.as_deref(), Some("no-key"));
    let off = online_reply(&json!({"status": 0, "error": "Unable to resolve host", "body": ""}));
    assert!(off.0.is_none() && off.1.unwrap().starts_with("no connection"));
    let s500 = online_reply(&json!({"status": 500, "error": null, "body": "oops"}));
    assert!(s500.1.unwrap().contains("500"));
}

/// Only the stripped question goes into the request, and nothing else from the caller.
#[test]
fn online_request_carries_only_the_stripped_question() {
    let q = "I am Arnav, my number 9876543210, OTP 482913 given to scammer@ybl";
    let r = redact::redact(q);
    let body = online_body(&r.text, "phone");
    let s = body.to_string();
    for leak in ["Arnav", "9876543210", "482913", "scammer@ybl"] {
        assert!(!s.contains(leak), "{leak} in the request");
    }
    assert_eq!(body["messages"][1]["content"], json!(r.text));
    assert_eq!(body["messages"].as_array().unwrap().len(), 2);
    assert!(body["messages"][0]["content"].as_str().unwrap().contains("on a phone"));
    assert!(online_body("x", "laptop")["messages"][0]["content"].as_str().unwrap().contains("on a laptop"));
}

/// Only numbers / names typed: after stripping nothing is left to ask, so nothing is sent
/// (the live run on 24 Sep sent "[number]" before this existed - the placeholder word counted).
#[test]
fn a_message_of_only_personal_details_is_not_sent() {
    // A bare name with no "I am" / "my name is" cannot be found by rules - the page shows the
    // exact text and asks before sending; that is the guard for it, not this check.
    for q in ["9876543210 482913", "I am Arnav Agarwal 9876543210", "scammer@ybl", "https://bit.ly/x", "OTP: 482913"] {
        let r = redact::redact(q);
        assert!(!has_question(&r.text), "{q:?} -> {:?} would be sent", r.text);
    }
    for q in ["is it safe?", "what is a VPN", "9876543210 called me, is it a scam?"] {
        assert!(has_question(&redact::redact(q).text), "{q:?} is a real question");
    }
}

/// The full-sweep follower: a pid counts as "still scanning" only while that pid is MpCmdRun.
#[test]
fn tasklist_pid_and_name_both_needed() {
    let rows = "\"MpCmdRun.exe\",\"4242\",\"Console\",\"1\",\"9,000 K\"\n\"notepad.exe\",\"77\",\"Console\",\"1\",\"12,000 K\"\n";
    assert!(tasklist_has(rows, 4242, "mpcmdrun.exe"));
    assert!(!tasklist_has(rows, 77, "mpcmdrun.exe"), "a reused pid running another program is not the scan");
    assert!(!tasklist_has(rows, 424, "mpcmdrun.exe"), "a pid that is a prefix of another is not it");
    assert!(!tasklist_has("INFO: No tasks are running which match the specified criteria.\n", 4242, "mpcmdrun.exe"));
}
