//! Vigil's own deep look, run on every file the sweep pattern-reads (29 Sep 2026, his exam: 17
//! harmless test files copying malware's tricks, and the sweep caught 0 of 15). The sweep only
//! fingerprinted files and ran the pattern rules on their raw bytes, so it never:
//!   - opened an archive (a zip, a zip in a zip, a .tar.gz, an app file's inner files),
//!   - knew the antivirus industry's test file (EICAR),
//!   - read what an app file ASKS for (SMS + screen control + no icon is how banking theft looks),
//!   - ran the file-shape checks the single-file "Is this safe?" check already had (sniff.rs).
//! Premium antivirus apps do all four. This does them, offline, on bytes only.
//!
//! Output: hits named `Vigil/<Rule>`, which the sweep stores and shows like any pattern hit.
//! Each rule is strong ("harmful") or weak ("worth a look") by `is_weak`, and worded by `words`.
//! Also returns the SHA-256 of every file found inside an archive, so the sweep can look those up
//! in the known-malware list: samples usually travel zipped, and the list holds the unzipped file.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Deepest archive-in-archive opened. Past it: said, never silently passed.
const MAX_DEPTH: u8 = 5;
/// Most bytes expanded out of one file in all (a zip bomb stops here).
const MAX_EXPANDED: usize = 128 << 20;
/// Biggest single inner file read.
const MAX_MEMBER: u64 = 32 << 20;
/// Most inner files looked at in one file.
const MAX_MEMBERS: usize = 20_000;

/// The EICAR test file's fixed start, stored reversed so this program itself is not "a test virus"
/// (a scanner reading Vigil's own library would otherwise see it - the 29 Sep self-match lesson).
pub(crate) fn eicar() -> Vec<u8> {
    "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".bytes().rev().collect()
}

/// The standard says: the file starts with the 68-byte string, may be followed by whitespace only,
/// and is at most 128 bytes. Every major antivirus reports it; nothing else looks like it.
pub fn is_test_file(b: &[u8]) -> bool {
    let h = eicar();
    b.len() <= 128 && b.starts_with(&h) && b[h.len()..].iter().all(|c| c.is_ascii_whitespace() || *c == 0x1a)
}

/// Rules Vigil writes itself. (name, weak, plain words for the page).
pub const RULES: &[(&str, bool, &str)] = &[
    ("TestFile", false, "It is the antivirus TEST file (EICAR) - harmless on purpose, made so people can check their scanner works. Vigil treats it like a real virus, as every good scanner does."),
    ("TestFileInside", false, "The antivirus TEST file (EICAR) is hidden inside it (an archive or app file). Harmless on purpose - but this is exactly how real malware is hidden, and Vigil opened it and found it."),
    ("ListedInside", false, "A file inside it is on MalwareBazaar's public list of real malware samples. Malware is usually sent zipped for exactly this reason."),
    ("KnownMaliciousOnline", false, "A free public checker (CIRCL hashlookup) was asked about this file's fingerprint - never the file - and it knows it as real malware, reported by a malware collection."),
    ("RulesInside", false, "A file inside it matches rules written to recognise known malware."),
    ("AppHidesAndSteals", false, "It is an Android app that hides its icon AND asks to read your text messages AND to control your screen (accessibility). That is how OTP-stealing banking malware is built."),
    ("AppDisguised", false, "It is an Android app file dressed up with another name (like a PDF or a photo). Real apps never do this - it is a trick to get you to open it."),
    ("AppInArchiveDisguised", false, "It holds an Android app whose name pretends to be something else (like photo.jpg.apk)."),
    ("AppBankerShape", true, "It is an Android app that asks to read your text messages AND to control your screen (accessibility). Some honest automation apps ask for this too; banking malware always does."),
    ("AppHidden", true, "It is an Android app with no icon - once installed you would not see it in your app list."),
    ("AppFromChat", true, "It is an Android app file that arrived through a chat app. Fake \"KYC update\", \"bill\" and \"wedding card\" apps are sent this way."),
    ("ArchiveLocked", true, "It is locked with a password, so no scanner can look inside. Sending malware in a password zip, with the password in the message, is a known trick. Fine if you locked it yourself."),
    ("ArchiveTooDeep", true, "It holds archives inside archives more than 5 levels deep - Vigil stopped there. Real files almost never do this; zip bombs and hidden malware do."),
    ("PasswordFormElsewhere", true, "It is a saved web page with a password box that sends what you type to a web address. Fake bank and login pages arrive as attachments like this."),
    ("MacroDocument", true, "It is an Office document with macros (small programs inside). Most are harmless; macro documents from strangers are a classic way in."),
    // 29 Sep 2026 evening, his "improve all these faults": the hard cases.
    ("AppStalkerware", false, "It is a known stalkerware app (spying software, named in brackets): someone installs it on another person's phone to read their messages, listen to calls and track where they go. Matched on the app's name or its maker's signing key, from the Echap stalkerware list."),
    ("AppHiddenInstaller", false, "It is an Android app with no icon that can install other apps AND reads your text messages or controls your screen. That is a 'dropper': it looks harmless, then installs the real banking malware later."),
    ("AppDropperShape", true, "It is an Android app that can install other apps AND reads your text messages or controls your screen. A few honest tools ask for this; 'dropper' malware, which installs the real harmful app later, always does."),
    ("AppHiddenCanInstall", true, "It is an Android app with no icon that can install other apps. Droppers look like this before they fetch the real malware."),
    ("AppPacked", true, "Its code is wrapped in a 'protector' (a tool that scrambles an app's code; named in brackets). Banks and games use them against copying; malware uses them so scanners cannot read its code. Vigil could not read what is inside the wrapping."),
    ("ArchiveOpenedWithCommonPassword", true, "It is locked with a password, but a guessable one (like \"infected\", or a word or number from its own name). Vigil opened it and looked inside. Malware is often sent this way, with the password in the message."),
    ("ArchiveNotFullyOpened", true, "It holds more than Vigil reads out of one file (over 20,000 files inside, over 128 MB unpacked, or one inner file over 32 MB), so part of it was NOT looked inside. Big backups do this; so do zip bombs."),
];

pub fn is_weak(rule: &str) -> Option<bool> {
    if let Some(r) = RULES.iter().find(|r| r.0 == rule) {
        return Some(r.1);
    }
    // "Shape_<code>": a "danger" sign from the file-shape checks (sniff.rs). In a sweep of every
    // file only the plain deceptions are harmful; download-and-run, a zip holding one program, a
    // shortcut starting a script are also how his own install scripts and shortcuts look (26 Sep).
    rule.strip_prefix("Shape_").map(|c| !STRONG_SHAPES.contains(&c))
}

/// Shape signs that are a deception whatever the file is for: nothing honest dresses up like this.
const STRONG_SHAPES: &[&str] = &["disguised-program", "disguised-shortcut", "archive-name-trick", "double-ending",
    "hidden-ending", "name-reversed", "pdf-launch", "remote-template"];

pub fn words(rule: &str) -> String {
    if let Some(r) = RULES.iter().find(|r| r.0 == rule) {
        return r.2.to_string();
    }
    match rule.trim_start_matches("Shape_") {
        "disguised-program" => "It is a Windows program pretending to be another kind of file.".into(),
        "double-ending" | "name-reversed" | "hidden-ending" => "Its name hides what it really is (like invoice.pdf.exe).".into(),
        "download-and-run" => "It is a script that downloads something from the internet and runs it - how most infections start.".into(),
        "hidden-and-run" => "It is a script that runs hidden, scrambled code.".into(),
        "turns-off-defender" => "It is a script that switches off Windows' virus protection.".into(),
        "deletes-backups" => "It deletes Windows' backup copies - what ransomware does before locking files.".into(),
        "web-runner" => "It uses a Windows tool to run code straight from the internet.".into(),
        "shortcut-runs-command" | "disguised-shortcut" => "It is a shortcut that starts a command tool instead of opening a file.".into(),
        "remote-template" => "It is an Office document that fetches code from the internet when opened.".into(),
        "pdf-launch" | "pdf-code" => "It is a PDF that tries to run something when opened.".into(),
        "disguised-script" => "It is a script or web page pretending to be a harmless file.".into(),
        "archive-name-trick" => "It is an archive holding a program with a name trick.".into(),
        "archive-single-program" => "It is an archive holding just one program - a common way to deliver malware, and also how some honest downloads come.".into(),
        c => format!("A strong warning sign in its shape ({c})."),
    }
}

struct Budget {
    expanded: usize,
    members: usize,
    /// Something was left unread because of a cap - said as ArchiveNotFullyOpened, never silent.
    capped: bool,
}

/// Passwords tried on a locked zip before calling it unreadable. Malware and malware samples are
/// sent with these (the industry's "infected", and the easy ones a victim is told to type); the
/// words and numbers in the zip's own name are tried too ("Invoice_pw_4471.zip").
const COMMON_PASSWORDS: &[&str] = &["infected", "malware", "virus", "password", "Password", "1234", "12345",
    "123456", "12345678", "0000", "1111", "abc123", "pass", "qwerty", "2024", "2025", "2026"];

fn password_guesses(name: &str) -> Vec<Vec<u8>> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = base.rsplit_once('.').map_or(base, |(s, _)| s);
    let mut out: Vec<Vec<u8>> = COMMON_PASSWORDS.iter().map(|p| p.as_bytes().to_vec()).collect();
    let mut add = |s: &str| {
        if (3..=24).contains(&s.len()) && !out.iter().any(|o| o == s.as_bytes()) {
            out.push(s.as_bytes().to_vec());
        }
    };
    add(stem);
    for t in stem.split(|c: char| !c.is_ascii_alphanumeric()) {
        add(t);
        add(&t.to_lowercase());
    }
    out
}

/// Library and file names that app protectors ("packers") leave inside the apps they wrap:
/// (name, protector, where the name comes from). A name with "/" is a path start; otherwise a
/// file name. Sources (29 Sep 2026; quotes in LEGAL-CHECK.md), every name is a bare fact, no rule text:
///   die        Detect It Easy db/APK, github.com/horsicq/Detect-It-Easy (MIT)
///   lcr        LibChecker-Rules native-libs, github.com/LibChecker/LibChecker-Rules (Apache-2.0)
///   mhook      mHook PackerDetector.java, github.com/xiamiya/mHook (Apache-2.0)
///   vb2014     Yu, "Android packers: facing challenges, building solutions", Virus Bulletin 2014
///   caro2014   Apvrille & Nigam, Fortinet, CARO 2014 ("Obfuscation in Android malware")
///   blog       "Android Apk加固厂商特征" packer-feature blog, 2017 (CSDN / Tencent Cloud mirrors)
///   (apkid-fact names were dropped for the public release, 3 Nov 2026; the test keeps the count at 0)
/// Left out on purpose: SDKs that are not packers (Approov, Kony, freeRASP, face/anti-cheat SDKs)
/// and generic names (libmd.so, libexec.so, assets/crash) that honest apps also carry.
const PACKERS: &[(&str, &str, &str)] = &[
    ("assets/appguard0.jar", "AppGuard", "die"), ("libappguard-x86.so", "AppGuard", "die"),
    ("libdxbase.so", "DxShield", "die"),
    ("libdexhelper.so", "SecNeo / Bangcle", "die"),
    ("libdexjni.so", "SecNeo", "die"), ("assets/dp.arm.so.dat", "DexProtector", "die"),
    ("assets/classes.dex.dat", "DexProtector", "die"), ("assets/dp.mp3", "DexProtector", "die"),
    ("libapkprotect.so", "APKProtect", "die"),
    ("libsecexe.so", "Bangcle", "die"), ("libsecmain.so", "Bangcle", "caro2014"),
    ("assets/bangcleplugin/", "Bangcle", "vb2014"), ("libsecshell.so", "Bangcle SecShell", "die"),
    ("assets/secdata0.jar", "Bangcle SecShell", "die"), ("libkiroro.so", "Kiro", "die"),
    ("libprotectclass.so", "Qihoo 360", "die"), ("libjiagu.so", "Qihoo 360 Jiagu", "die"),
    ("libjiagu_art.so", "Qihoo 360 Jiagu", "blog"), ("assets/jiagu_data.bin", "Jiagu (ApkToolPlus)", "blog"),
    ("libapktoolplus_jiagu.so", "Jiagu (ApkToolPlus)", "die"), ("assets/qdbh", "qdbh", "die"),
    ("liapp.ini", "LIAPP", "mhook"), ("libnsaferonly.so", "Tongfudun", "blog"),
    ("libnqshield.so", "NQ Shield", "die"), ("mix.dex", "Tencent", "die"),
    ("assets/tosversion", "Tencent Legu", "die"),
    ("assets/ijiami.dat", "Ijiami", "die"), ("assets/ijm_lib/", "Ijiami", "die"),
    ("libijmdataencryption.so", "Ijiami", "die"), ("libchaosvmp.so", "Naga", "lcr"),
    ("libxloader.so", "Naga", "lcr"), ("libmobisec.so", "Alibaba", "die"),
    ("libbaiduprotect.so", "Baidu", "die"), ("libnsecure.so", "Pangxie", "die"),
    ("libnesec.so", "Yidun (NetEase)", "die"), ("assets/nedata.db", "Yidun (NetEase)", "die"),
    ("lib/armeabi/libhdus.so", "Chornclickers", "die"),
    ("libv++.so", "Virbox", "die"),
    ("assets/appdefence_xml", "AppDefence", "die"),
    ("license.tak", "Build38", "die"),
    ("assets/ali_sec.dat", "Alibaba", "mhook"),
    ("libdexprotector.so", "DexProtector", "die"), ("assets/dp.arm-v7.so.dat", "DexProtector", "die"),
    ("assets/dp.arm-v8.so.dat", "DexProtector", "die"), ("assets/dp.x86.so.dat", "DexProtector", "die"),
    ("assets/dp.x86_64.so.dat", "DexProtector", "die"), ("assets/dexprotect/", "DexProtector", "die"),
    ("assets/dp-lib/", "DexProtector", "die"), ("libdexhelper-x86.so", "SecNeo / Bangcle", "die"),
    ("libdexhelper-x86_64.so", "SecNeo / Bangcle", "die"), ("libsecshell-x86.so", "Bangcle SecShell", "die"),
    ("libjiagu_a64.so", "Qihoo 360 Jiagu", "die"), ("libjiagu_x64.so", "Qihoo 360 Jiagu", "die"),
    ("libjiagu_x86.so", "Qihoo 360 Jiagu", "die"), ("libjiagu_ls.so", "Qihoo 360 Jiagu", "die"),
    ("assets/baiduprotect.jar", "Baidu", "die"), ("libbaiduprotect_x86.so", "Baidu", "die"),
    ("libnqshieldx86.so", "NQ Shield", "die"), ("libappguard.so", "AppGuard", "die"),
    ("assets/appguard.dgc", "AppGuard", "die"), ("assets/ap.src/apkprotect", "APKProtector", "die"),
    ("assets/ap.others/apkprotect.bin", "APKProtector", "die"), ("assets/liappclient.sc", "LIAPP", "die"),
    ("assets/liappclient_x86.sc", "LIAPP", "die"), ("assets/liappegg.sc", "LIAPP", "die"),
    ("assets/liappegg_x86.sc", "LIAPP", "die"), ("libkwprotectsdk.so", "Kiwi", "die"),
    ("libkwsdataenc.so", "Kiwi", "die"), ("assets/kwpt.lincense", "Kiwi", "die"),
    ("libexecmain.so", "Ijiami", "die"), ("assets/ijiami.ajm", "Ijiami", "die"),
    ("libijmdataencryption_arm64.so", "Ijiami", "die"), ("libijmdataencryption_x86.so", "Ijiami", "die"),
    ("libijm-emulator.so", "Ijiami", "die"), ("libshell-super.2019.so", "Tencent Legu", "die"),
    ("libshellx-super.2019.so", "Tencent Legu", "die"), ("libshell-superv.2019.so", "Tencent Legu", "die"),
    ("libshell-supervbasic.2019.so", "Tencent Legu", "die"),
    ("libtprt.so", "Tencent TP (game protection)", "die"),
    ("libtersafe.so", "Tencent TP (game protection)", "die"),
    ("libtersafe2.so", "Tencent TP (game protection)", "die"), ("libvdog.so", "Naga (VDog)", "die"),
    ("libvdog-x86.so", "Naga (VDog)", "die"), ("libhdog.so", "Naga (VDog)", "die"),
    ("libhdog-x86.so", "Naga (VDog)", "die"), ("libddog.so", "Naga", "die"), ("libfdog.so", "Naga", "die"),
    ("libmtprotect.so", "OLLVM-TTL", "die"), ("libegis.so", "Tongfudun", "die"),
    ("lib/armeabi/libwjus.so", "Hdus-Wjus", "die"), ("__license.tak", "Build38", "die"),
    ("libv++_64.so", "Virbox", "die"), ("libnesec-x86.so", "Yidun (NetEase)", "die"),
    ("libedog.so", "Naga", "lcr"), ("libjiagu_vip.so", "Qihoo 360 Jiagu", "lcr"),
    ("libjiagu_vip_x64.so", "Qihoo 360 Jiagu", "lcr"), ("libbaiduprotect_art.so", "Baidu", "lcr"),
    ("libbaiduprotect_dump.so", "Baidu", "lcr"), ("libbasec.so", "CFCA", "lcr"),
    ("libbasec_x86.so", "CFCA", "lcr"), ("libsecenh.so", "CFCA", "lcr"), ("libsecenh_a64.so", "CFCA", "lcr"),
    ("libsecenh_x86.so", "CFCA", "lcr"), ("libexecoat.so", "Ijiami", "lcr"),
    ("libexecoat_x86.so", "Ijiami", "lcr"), ("libexecmain_x86.so", "Ijiami", "lcr"),
    ("libijm_linker.so", "Ijiami", "lcr"), ("libijiami_ijm.so", "Ijiami", "lcr"),
    ("libijiami_release01.so", "Ijiami", "lcr"), ("libijmdataencryption_x86_64.so", "Ijiami", "lcr"),
    ("libx3g.so", "DingXiang", "lcr"), ("assets/aliprotect.dat", "Alibaba", "mhook"),
];

#[cfg(test)]
pub(crate) fn packer_list() -> &'static [(&'static str, &'static str, &'static str)] {
    PACKERS
}

/// The protector an inner file name belongs to (lower-cased name).
fn packer_of(ln: &str) -> Option<&'static str> {
    PACKERS.iter().find(|(m, _, _)| {
        if m.contains('/') { ln.starts_with(m) } else { ln == *m || ln.ends_with(&format!("/{m}")) }
    }).map(|p| p.1)
}

#[derive(Default)]
pub struct Found {
    /// (rule, where: "backup.zip > old.zip > readme.com")
    pub hits: Vec<(String, String)>,
    pub member_shas: Vec<String>,
    /// Pattern-rule matches inside archives: "set/rule".
    pub member_rules: Vec<String>,
}

impl Found {
    fn hit(&mut self, rule: &str, at: &str) {
        if !self.hits.iter().any(|h| h.0 == rule) {
            self.hits.push((rule.to_string(), at.to_string()));
        }
    }
}

fn ext_of(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if base.contains('.') { base.rsplit('.').next().unwrap_or("").to_lowercase() } else { String::new() }
}

// "ap_" = the resource package Android's build tools write (29 Sep 2026: a developer's own build
// folder on his laptop was called "an app dressed up with another name").
const APP_EXTS: &[&str] = &["apk", "apks", "xapk", "apkm", "aab", "zip", "jar", "ap_"];

/// What an app's manifest says, and whether that is the shape of trouble.
fn manifest_of<R: Read + std::io::Seek>(z: &mut zip::ZipArchive<R>) -> Option<Vec<u8>> {
    let m = z.by_name("AndroidManifest.xml").ok()?;
    let mut b = Vec::new();
    m.take(4 << 20).read_to_end(&mut b).ok()?;
    Some(b)
}

fn app_check(b: &[u8], name: &str, path_hint: &str, at: &str, inside: bool, certs: &[String], f: &mut Found) {
    let ext = ext_of(name);
    if !APP_EXTS.contains(&ext.as_str()) {
        f.hit(if inside { "AppInArchiveDisguised" } else { "AppDisguised" }, at);
    } else if inside && name.to_lowercase().trim_end_matches(".apk").rsplit('.').next().map_or(false, |e| ["jpg", "jpeg", "png", "pdf", "mp4", "doc", "docx"].contains(&e)) {
        f.hit("AppInArchiveDisguised", at);
    }
    let man = crate::axml::parse(b);
    // The signing key identifies a stalkerware maker even when the manifest cannot be read.
    if let Some(app) = crate::stalker::app_for(man.as_ref().and_then(|m| m.package.as_deref()), certs) {
        f.hit("AppStalkerware", &format!("{at} ({app})"));
    }
    let Some(man) = man else { return };
    let has = |p: &str| man.requested.iter().any(|r| r == p);
    let sms = man.sms_listener || has("android.permission.RECEIVE_SMS") || has("android.permission.READ_SMS");
    let screen = man.offers.iter().any(|o| o == "android.permission.BIND_ACCESSIBILITY_SERVICE");
    if sms && screen && !man.launcher {
        f.hit("AppHidesAndSteals", at);
    } else if sms && screen {
        f.hit("AppBankerShape", at);
    } else if !man.launcher && (sms || screen) {
        f.hit("AppHidden", at);
    }
    // Droppers (29 Sep 2026): harmless-looking at first, they install the real malware later, so
    // the power to install apps is the thing to see in the file itself.
    let installs = has("android.permission.REQUEST_INSTALL_PACKAGES");
    if installs && (sms || screen) {
        f.hit(if man.launcher { "AppDropperShape" } else { "AppHiddenInstaller" }, at);
    } else if installs && !man.launcher {
        f.hit("AppHiddenCanInstall", at);
    }
    let p = path_hint.to_lowercase().replace('\\', "/");
    if !inside && ["/whatsapp/", "/telegram/", "/com.whatsapp", "/org.telegram"].iter().any(|c| p.contains(c)) {
        f.hit("AppFromChat", at);
    }
}

fn is_zip(b: &[u8]) -> bool { b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") }
fn is_gzip(b: &[u8]) -> bool { b.starts_with(b"\x1f\x8b") }
fn is_tar(b: &[u8]) -> bool { b.len() > 262 && &b[257..262] == b"ustar" }

/// One file's bytes, at some depth inside the file on disk. `yara` pattern-reads inner files.
fn look_bytes(name: &str, b: &[u8], at: &str, depth: u8, path_hint: &str, budget: &mut Budget, yara: &dyn Fn(&[u8]) -> Vec<String>, f: &mut Found) {
    let inside = depth > 0;
    if is_test_file(b) {
        f.hit(if inside { "TestFileInside" } else { "TestFile" }, at);
        return;
    }
    if inside {
        f.member_shas.push(Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect());
        for r in yara(b) {
            if !f.member_rules.contains(&r) {
                f.member_rules.push(r);
            }
        }
    }
    let ext = ext_of(name);
    // The file-shape checks, on the file itself and on every inner file.
    let s = crate::sniff::sniff_bytes(name.rsplit(['/', '\\']).next().unwrap_or(name), &ext, b);
    for fl in s["flags"].as_array().into_iter().flatten() {
        let code = fl["code"].as_str().unwrap_or("");
        match (fl["level"].as_str(), code) {
            (Some("danger"), c) => f.hit(&format!("Shape_{c}"), at),
            (_, "locked-archive") => f.hit("ArchiveLocked", at),
            (_, "macros") => f.hit("MacroDocument", at),
            _ => {}
        }
    }
    if ["html", "htm", "shtml", "xhtml", "mht"].contains(&ext.as_str()) {
        let t = String::from_utf8_lossy(&b[..b.len().min(1 << 20)]).to_lowercase();
        let pw = t.contains("type=password") || t.contains("type=\"password\"") || t.contains("type='password'");
        if pw && regex_form_to_web(&t) {
            f.hit("PasswordFormElsewhere", at);
        }
    }
    if depth >= MAX_DEPTH {
        if is_zip(b) || is_gzip(b) || is_tar(b) {
            f.hit("ArchiveTooDeep", at);
        }
        return;
    }
    if is_zip(b) {
        let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(b)) else { return };
        walk_zip(&mut z, name, at, depth, path_hint, &|| crate::apksig::cert_sha1s(&mut std::io::Cursor::new(b)), budget, yara, f);
    } else if is_gzip(b) {
        walk_gzip(b, name, at, depth, path_hint, budget, yara, f);
    } else if is_tar(b) {
        walk_tar(b, at, depth, path_hint, budget, yara, f);
    }
}

fn walk_gzip<R: Read>(r: R, name: &str, at: &str, depth: u8, path_hint: &str, budget: &mut Budget, yara: &dyn Fn(&[u8]) -> Vec<String>, f: &mut Found) {
    let mut v = Vec::new();
    let room = MAX_EXPANDED.saturating_sub(budget.expanded).min(MAX_MEMBER as usize) as u64;
    let mut d = flate2::read::GzDecoder::new(r).take(room);
    if d.read_to_end(&mut v).is_err() && v.is_empty() {
        return;
    }
    // Filled the room and there is more: the rest was never read.
    if v.len() as u64 == room && d.into_inner().read(&mut [0u8; 1]).map_or(false, |n| n > 0) {
        budget.capped = true;
    }
    budget.expanded += v.len();
    let inner = name.trim_end_matches(".gz").trim_end_matches(".tgz").to_string();
    look_bytes(&inner, &v, &format!("{at} > (unpacked)"), depth + 1, path_hint, budget, yara, f);
}

fn walk_tar<R: Read>(r: R, at: &str, depth: u8, path_hint: &str, budget: &mut Budget, yara: &dyn Fn(&[u8]) -> Vec<String>, f: &mut Found) {
    let mut t = tar::Archive::new(r);
    let Ok(entries) = t.entries() else { return };
    for e in entries.flatten() {
        if !e.header().entry_type().is_file() {
            continue;
        }
        if budget.members >= MAX_MEMBERS || budget.expanded >= MAX_EXPANDED || e.size() > MAX_MEMBER {
            budget.capped = true;
            if e.size() > MAX_MEMBER {
                continue;
            }
            return;
        }
        let n = e.path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        budget.members += 1;
        let mut v = Vec::new();
        // Inside the room left, like a zip entry (29 Sep: tar read a full 32 MB whatever was left,
        // so the total could pass 128 MB and the next gzip's `MAX_EXPANDED - expanded` went below
        // zero - a crash in a debug build).
        let size = e.size();
        let room = ((MAX_EXPANDED - budget.expanded) as u64).min(MAX_MEMBER);
        if e.take(room).read_to_end(&mut v).is_err() {
            continue;
        }
        if (v.len() as u64) < size {
            budget.capped = true;
        }
        budget.expanded += v.len();
        look_bytes(&n, &v, &format!("{at} > {n}"), depth + 1, path_hint, budget, yara, f);
    }
}

/// Read one zip entry, with `pw` if the zip is locked. Err = it did not open (or not with pw).
fn read_entry<R: Read + std::io::Seek>(z: &mut zip::ZipArchive<R>, i: usize, pw: Option<&[u8]>, limit: u64) -> Result<Vec<u8>, ()> {
    let e = match pw {
        Some(p) => z.by_index_decrypt(i, p),
        None => z.by_index(i),
    };
    let e = e.map_err(|_| ())?;
    let mut v = Vec::with_capacity(e.size().min(1 << 20) as usize);
    // A wrong password passes ZipCrypto's one-byte check 1 time in 256; the checksum at the end
    // of the entry (or AES's authentication code) is what rejects it.
    e.take(limit).read_to_end(&mut v).map_err(|_| ())?;
    Ok(v)
}

/// Every entry of a zip (from memory or straight from a big file on disk).
fn walk_zip<R: Read + std::io::Seek>(z: &mut zip::ZipArchive<R>, name: &str, at: &str, depth: u8, path_hint: &str,
    certs: &dyn Fn() -> Vec<String>, budget: &mut Budget, yara: &dyn Fn(&[u8]) -> Vec<String>, f: &mut Found) {
    let inside = depth > 0;
    let app = manifest_of(z);
    if let Some(m) = &app {
        app_check(m, name, path_hint, at, inside, &certs(), f);
    }
    let office = z.file_names().any(|n| n.starts_with("word/") || n.starts_with("xl/") || n.starts_with("ppt/"));
    // None = not locked (or not yet met a locked entry); Some(None) = locked, no guess opened it.
    let mut pw: Option<Option<Vec<u8>>> = None;
    for i in 0..z.len() {
        let Ok((n, is_dir, size, encrypted)) = z.by_index_raw(i).map(|e| (e.name().to_string(), e.is_dir(), e.size(), e.encrypted())) else { continue };
        if is_dir {
            continue;
        }
        let ln = n.to_lowercase();
        if app.is_some() {
            if let Some(p) = packer_of(&ln) {
                f.hit("AppPacked", &format!("{at} > {n} ({p})"));
            }
        }
        // An app's own code and resources are the pattern rules' job (yara::apk_view); an
        // Office file's parts are XML. Only what could be a hidden file is opened here.
        if office && (ln.ends_with(".xml") || ln.ends_with(".rels")) {
            continue;
        }
        if ln.ends_with(".dex") || ln.starts_with("res/") || ln == "resources.arsc" || ln == "androidmanifest.xml" || ln.starts_with("meta-inf/") {
            continue;
        }
        if size > MAX_MEMBER {
            // A big inner file of an APP is its media or native code (the pattern rules read the
            // app's code); in any other archive it is a file Vigil did not look at.
            if app.is_none() {
                budget.capped = true;
            }
            continue;
        }
        if budget.members >= MAX_MEMBERS || budget.expanded >= MAX_EXPANDED {
            budget.capped = true;
            break;
        }
        let limit = ((MAX_EXPANDED - budget.expanded) as u64).min(MAX_MEMBER);
        let v = if encrypted {
            if pw.is_none() {
                // First locked entry: try the guessable passwords once for this zip.
                let found = password_guesses(name).into_iter().find(|g| read_entry(z, i, Some(g), limit).is_ok());
                if found.is_some() {
                    // The shape check (sniff) already said "locked, not looked inside" for this
                    // zip; Vigil did look inside, so that sentence would now be false.
                    f.hits.retain(|h| !(h.0 == "ArchiveLocked" && h.1 == at));
                    f.hit("ArchiveOpenedWithCommonPassword", at);
                } else {
                    f.hit("ArchiveLocked", at);
                }
                pw = Some(found);
            }
            match pw.as_ref().and_then(|p| p.as_deref()) {
                Some(p) => read_entry(z, i, Some(p), limit),
                None => continue,
            }
        } else {
            read_entry(z, i, None, limit)
        };
        let Ok(v) = v else { continue };
        // Cut short by the 128 MB room: its end was never read (29 Sep: this was silent when it
        // happened to the LAST inner file, as nothing came after it to trip the cap check).
        if (v.len() as u64) < size {
            budget.capped = true;
        }
        budget.members += 1;
        budget.expanded += v.len();
        look_bytes(&n, &v, &format!("{at} > {n}"), depth + 1, path_hint, budget, yara, f);
    }
}

fn regex_form_to_web(t: &str) -> bool {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"<form[^>]*action\s*=\s*["']?https?://"#).unwrap()).is_match(t)
}

/// Look at one file on disk. Reads at most MAX_MEMBER bytes of it (an app file is opened from
/// the file, so a big one is still looked into).
pub fn look(path: &Path, yara: &dyn Fn(&[u8]) -> Vec<String>) -> Found {
    let mut f = Found::default();
    let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let Ok(mut file) = std::fs::File::open(path) else { return f };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len > MAX_MEMBER {
        // Too big to hold (29 Sep 2026: used to read only a big app's manifest, so a 40 MB zip of
        // anything was never opened). Archives are walked straight from the file, inside the same
        // caps; the file itself is not held, only one inner file at a time.
        let mut head = [0u8; 262];
        let n = file.read(&mut head).unwrap_or(0);
        let head = &head[..n];
        let hint = path.to_string_lossy();
        let mut budget = Budget { expanded: 0, members: 0, capped: false };
        let reopen = || std::fs::File::open(path).ok();
        if head.starts_with(b"PK\x03\x04") {
            if let Some(mut z) = reopen().and_then(|fh| zip::ZipArchive::new(fh).ok()) {
                let certs = || reopen().map(|mut fh| crate::apksig::cert_sha1s(&mut fh)).unwrap_or_default();
                walk_zip(&mut z, &name, &name, 0, &hint, &certs, &mut budget, yara, &mut f);
            }
        } else if is_gzip(head) {
            if let Some(fh) = reopen() {
                walk_gzip(std::io::BufReader::new(fh), &name, &name, 0, &hint, &mut budget, yara, &mut f);
            }
        } else if is_tar(&[head, &[0u8; 1]].concat()) {
            if let Some(fh) = reopen() {
                walk_tar(std::io::BufReader::new(fh), &name, 0, &hint, &mut budget, yara, &mut f);
            }
        }
        if budget.capped {
            f.hit("ArchiveNotFullyOpened", &name);
        }
        return f;
    }
    let mut b = Vec::with_capacity(len as usize);
    if file.read_to_end(&mut b).is_err() {
        return f;
    }
    look_in_memory(&path.to_string_lossy(), &b, yara)
}

/// The same look on bytes in memory, `path` only naming where they sit. Tests use it so no test
/// virus is ever written to the laptop's disk (Defender would take it, and the test with it).
pub fn look_in_memory(path: &str, b: &[u8], yara: &dyn Fn(&[u8]) -> Vec<String>) -> Found {
    let mut f = Found::default();
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path).to_string();
    let mut budget = Budget { expanded: 0, members: 0, capped: false };
    look_bytes(&name, b, &name, 0, path, &mut budget, yara, &mut f);
    if budget.capped {
        f.hit("ArchiveNotFullyOpened", &name);
    }
    f
}
