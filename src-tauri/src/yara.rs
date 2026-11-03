// Layer 2 of the file check (his rule 25 Sep 00:55 "better at checking viruses of all sorts"):
// YARA-X (VirusTotal's engine, BSD-3) with two MIT rule sets - ReversingLabs and bartblaze -
// embedded by build.rs from yara/. The rules are compiled once, in the background at start
// (warm), so a file check never waits ~2 s for them. Laptop and phone (phone behind `guarded`).
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

include!(concat!(env!("OUT_DIR"), "/yara_rules.rs"));

/// Every rule file as (path under yara/, text). build.rs stores them deflated so that Vigil's own
/// exe and APK never carry a rule's strings in the clear (29 Sep 2026: stored as text, Vigil's APK
/// matched 78 rules itself); they are inflated here once, in memory, on first use.
pub static RULE_FILES: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    RULE_FILES_Z
        .iter()
        .map(|z| inflate(z).split_once('\n').expect("embedded rule file: path line"))
        .collect()
});

fn inflate(z: &[u8]) -> &'static str {
    use std::io::Read;
    let mut s = String::new();
    flate2::read::DeflateDecoder::new(z).read_to_string(&mut s).expect("embedded rule data");
    Box::leak(s.into_boxed_str())
}

/// yara/policy.txt, inflated: `quiet <path> | <why>` and `weak <path>` lines (# = comment).
fn policy(kind: &str) -> impl Iterator<Item = &'static str> + '_ {
    static TEXT: LazyLock<&'static str> = LazyLock::new(|| inflate(POLICY_Z));
    TEXT.lines().filter_map(move |l| l.trim().strip_prefix(kind)?.strip_prefix(' ')).map(str::trim)
}

/// Rule files left out, each for a MEASURED false alarm (the measurements are in yara/policy.txt).
pub static QUIET: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    policy("quiet").map(|l| l.split_once(" | ").map(|(p, w)| (p.trim(), w.trim())).unwrap_or((l, ""))).collect()
});

/// Rule files whose match is a LOOSE pattern - "worth a look", never "delete it" (reasons in
/// yara/policy.txt). A path ending in / = a whole folder.
pub static WEAK: LazyLock<Vec<&'static str>> = LazyLock::new(|| policy("weak").collect());

pub struct Compiled {
    rules: yara_x::Rules,
    pub files: usize,
    pub count: usize,
    pub failed: Vec<String>,
    pub ms: u64,
}

static RULES: OnceLock<Result<Compiled, String>> = OnceLock::new();


#[cfg(test)]
pub fn rule_file_exists(rel: &str) -> bool {
    RULE_FILES.iter().any(|(r, _)| *r == rel)
}

pub fn weak_file(rel: &str) -> bool {
    WEAK.iter().any(|w| if w.ends_with('/') { rel.starts_with(w) } else { rel == *w })
}

/// For a hit remembered as "set/rule" (no file): weak only if EVERY rule file of that set that
/// defines a rule of this name is weak, and at least one does. Unknown -> strong (never quieter).
pub fn weak_rule(set: &str, rule: &str) -> bool {
    if set == "Vigil" {
        return crate::deeplook::is_weak(rule).unwrap_or(false);
    }
    let mut any = false;
    for (rel, src) in RULE_FILES.iter() {
        if set_name(rel) != set || !defines(src, rule) {
            continue;
        }
        if !weak_file(rel) {
            return false;
        }
        any = true;
    }
    any
}

fn defines(src: &str, rule: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    src.match_indices(rule).any(|(i, _)| {
        let before = src[..i].trim_end();
        let after = src[i + rule.len()..].chars().next();
        before.ends_with("rule") && !before[..before.len() - 4].ends_with(ident) && !after.map_or(false, ident)
    })
}

/// Which rule set a file under yara/ belongs to, in words for the page.
pub fn set_name(rel: &str) -> &'static str {
    if rel.starts_with("rl/") { "ReversingLabs" } else if rel.starts_with("bartblaze/") { "bartblaze" } else if rel.starts_with("yarahub/") || rel.starts_with("yarahub-win/") { "YARAhub" } else { "other" }
}

/// 2 Nov 2026: the YARAhub LAPTOP set (yarahub-win/, ~1,500 community rules) is compiled as its
/// own set. Together with the main set it doubled the time per file (measured on 815 drivers: 46 s
/// main, 49 s this set), which pushed a ~300 MB file past the 30 s limit and would have cost such
/// files the MAIN check too. So: the main set exactly as before, then this set as a second pass on
/// files up to EXTRA_MAX only, laptop only. Its timeout or error never touches the main answer.
pub fn is_extra(rel: &str) -> bool {
    rel.starts_with("yarahub-win/")
}
pub const EXTRA_MAX: u64 = 32 << 20;
static EXTRA: OnceLock<Result<Compiled, String>> = OnceLock::new();

/// The laptop-only second set. On the phone: never compiled.
pub fn extra() -> &'static Result<Compiled, String> {
    EXTRA.get_or_init(|| if cfg!(target_os = "android") { Err("laptop only".into()) } else { compile_where(is_extra) })
}

fn compile() -> Result<Compiled, String> {
    compile_where(|rel| !is_extra(rel))
}

fn compile_where(pick: impl Fn(&str) -> bool) -> Result<Compiled, String> {
    let t = std::time::Instant::now();
    let mut c = yara_x::Compiler::new();
    let mut failed = Vec::new();
    let mut ok = 0;
    for (i, (rel, src)) in RULE_FILES.iter().enumerate() {
        if QUIET.iter().any(|q| q.0 == *rel) {
            continue;
        }
        if !pick(rel) {
            continue;
        }
        // One namespace per file: two sets may reuse a rule name without clashing.
        c.new_namespace(&format!("f{i}"));
        match c.add_source(*src) {
            Ok(_) => ok += 1,
            Err(e) => failed.push(format!("{rel}: {}", e.to_string().lines().next().unwrap_or(""))),
        }
    }
    if ok == 0 {
        return Err(format!("no rule file compiled ({} failed)", failed.len()));
    }
    let rules = c.build();
    let count = rules.iter().count();
    Ok(Compiled { rules, files: ok, count, failed, ms: t.elapsed().as_millis() as u64 })
}

/// Compiling the rules makes machine code at run time (wasmtime). A phone may refuse that, and
/// the release build aborts on a panic - so one refusal would end the app on EVERY start. On the
/// phone the compile is therefore wrapped: a count is written before it and removed after it.
/// A start that died mid-compile leaves the count behind; after MAX_DIED such starts the check
/// is switched off on that phone (answer OFF_HERE, said in words by the page) instead of crashing
/// for ever. A clean error is not a crash and clears the count like a success.
pub const GUARD_FILE: &str = "yara-compiling";
pub const MAX_DIED: u32 = 3;
pub const OFF_HERE: &str = "off-here";

pub fn guarded<T>(dir: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let g = dir.join(GUARD_FILE);
    let died: u32 = std::fs::read_to_string(&g).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    if died >= MAX_DIED {
        return Err(OFF_HERE.into());
    }
    // Never compile unguarded: if the count can't be written, a crash could not be counted.
    std::fs::create_dir_all(dir).map_err(|e| format!("couldn't prepare the pattern check ({e})"))?;
    std::fs::write(&g, (died + 1).to_string()).map_err(|e| format!("couldn't prepare the pattern check ({e})"))?;
    let r = f();
    let _ = std::fs::remove_file(&g);
    r
}

/// The phone's folder for the guard count (the app's own lists folder), set by phone.rs.
static GUARD_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_guard_dir(p: PathBuf) {
    let _ = GUARD_DIR.set(p);
}

pub fn rules() -> &'static Result<Compiled, String> {
    if cfg!(target_os = "android") {
        // Not before the folder is known: an early "no folder" answer would be cached for good.
        if GUARD_DIR.get().is_none() && RULES.get().is_none() {
            static NOT_YET: OnceLock<Result<Compiled, String>> = OnceLock::new();
            return NOT_YET.get_or_init(|| Err("the pattern check is still getting ready".into()));
        }
        return RULES.get_or_init(|| match GUARD_DIR.get() {
            Some(d) => guarded(d, compile),
            None => Err("the pattern check is still getting ready".into()),
        });
    }
    RULES.get_or_init(compile)
}

/// Start compiling in the background so the first file check doesn't wait for it. On the phone
/// call it only after set_guard_dir (update_hash_list and check_file do).
pub fn warm() {
    if !RULE_FILES.is_empty() {
        std::thread::spawn(|| { let _ = rules(); let _ = extra(); });
    }
}

/// An APK is a zip, and its code (classes*.dex), manifest and native libraries are almost always
/// deflate-compressed - so a rule's strings never appear in the raw file, and every Android rule
/// was blind to real apps (found 29 Sep 2026 while adding YARAhub's Android rules; the older sets
/// had the same blind spot). For a zip holding classes.dex this returns the raw file FOLLOWED by
/// those members decompressed: a rule still sees "PK" at offset 0 (many check it), and now the
/// code as well. Capped at 64 MB in all (four sweep threads on a phone), members checked by their
/// real decompressed size, so a zip bomb stops at the cap. None = not an APK. A big APK (is_big) gets only the first 64 KB
/// of its raw file here, followed by its code; scan() then reads the raw file on its own as well.
pub(crate) fn apk_view(path: &Path) -> Option<(Vec<u8>, usize)> {
    const CAP: usize = 64 << 20;
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let mut head = [0u8; 4];
    file.read_exact(&mut head).ok().filter(|_| &head == b"PK\x03\x04")?;
    // Read from the file itself, never all of it into memory first: a BIG app (over 32 MB -
    // WhatsApp, banking and UPI apps; 8 of 17 popular open-source apps, 29 Sep 2026) used to be
    // left unexpanded, so the Android rules never saw its code. Now its code is expanded too, after
    // only the first 64 KB of the raw file; scan() reads the raw file separately for those (is_big).
    let mut z = zip::ZipArchive::new(file).ok()?;
    let names: Vec<String> = z.file_names().map(String::from).collect();
    let code = |n: &str| (n.starts_with("classes") && n.ends_with(".dex") && !n.contains('/'))
        || n == "AndroidManifest.xml" || (n.starts_with("lib/") && n.ends_with(".so"));
    if !names.iter().any(|n| n == "classes.dex") {
        return None;
    }
    let mut out = Vec::new();
    std::fs::File::open(path).ok()?.take(if is_big(len) { 64 << 10 } else { len }).read_to_end(&mut out).ok()?;
    let mut added = 0;
    for n in names.iter().filter(|n| code(n)) {
        let Ok(f) = z.by_name(n) else { continue };
        let room = CAP.saturating_sub(out.len());
        if room == 0 {
            break;
        }
        let before = out.len();
        if f.take(room as u64).read_to_end(&mut out).is_ok() && out.len() > before {
            added += 1;
        } else {
            out.truncate(before);
        }
    }
    Some((out, added))
}

/// Scan one file. {ran, rules, files, matches:[{rule, set, file, what}], ms} or {ran:false, reason}.
/// A match is a pattern known from malware written into the file - evidence, not proof.
pub fn scan(path: &std::path::Path) -> Value {
    let c = match rules() {
        Ok(c) => c,
        Err(e) => return json!({"ran": false, "reason": e}),
    };
    let t = std::time::Instant::now();
    let mut s = yara_x::Scanner::new(&c.rules);
    s.set_timeout(std::time::Duration::from_secs(30));
    let view = apk_view(path);
    let apk_members = view.as_ref().map(|v| v.1);
    // A big APK's view holds only the start of the raw file, so the raw file is read on its own too.
    let big = view.is_some() && std::fs::metadata(path).map_or(false, |m| is_big(m.len()));
    let mut matches: Vec<Value> = Vec::new();
    let passes: Vec<Option<&[u8]>> = match &view {
        Some((bytes, _)) if big => vec![Some(bytes), None],
        Some((bytes, _)) => vec![Some(bytes)],
        None => vec![None],
    };
    for pass in passes {
        let res = match pass {
            Some(bytes) => s.scan(bytes),
            None => s.scan_file(path),
        };
        let r = match res {
            Err(e) => return json!({"ran": false, "reason": e.to_string(), "rules": c.count}),
            Ok(r) => r,
        };
        for m in match_list(r.matching_rules()) {
            if !matches.iter().any(|x| x["rule"] == m["rule"] && x["file"] == m["file"]) {
                matches.push(m);
            }
        }
    }
    // The laptop's second set (see is_extra), on files up to EXTRA_MAX. Said in "extra", never silent.
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(u64::MAX);
    let extra_note = match extra() {
        Err(e) => json!({"ran": false, "reason": e}),
        Ok(_) if size > EXTRA_MAX => json!({"ran": false, "reason": "too big for the extra patterns"}),
        Ok(x) => {
            let mut s2 = yara_x::Scanner::new(&x.rules);
            s2.set_timeout(std::time::Duration::from_secs(30));
            let res = match &view { Some((bytes, _)) if !big => s2.scan(bytes), _ => s2.scan_file(path) };
            match res {
                Err(e) => json!({"ran": false, "reason": e.to_string(), "rules": x.count}),
                Ok(r) => {
                    for m in match_list(r.matching_rules()) {
                        if !matches.iter().any(|y| y["rule"] == m["rule"] && y["file"] == m["file"]) {
                            matches.push(m);
                        }
                    }
                    json!({"ran": true, "rules": x.count, "files": x.files})
                }
            }
        }
    };
    let extra_rules = extra_note["rules"].as_u64().filter(|_| extra_note["ran"] == true).unwrap_or(0) as usize;
    // Vigil's own deep look: archives opened, the test file, what an app asks for, file shapes.
    let d = crate::deeplook::look(path, &|b| scan_bytes(&c.rules, b));
    for (rule, at) in &d.hits {
        let weak = crate::deeplook::is_weak(rule).unwrap_or(false);
        matches.push(json!({"rule": rule, "set": "Vigil", "file": "", "at": at,
                            "what": {"description": crate::deeplook::words(rule)}, "weak": weak}));
    }
    for sr in &d.member_rules {
        let (set, rule) = sr.split_once('/').unwrap_or(("", sr));
        if !matches.iter().any(|x| x["rule"] == rule && x["set"] == set) {
            matches.push(json!({"rule": rule, "set": set, "file": "", "at": "inside", "what": {}, "weak": weak_rule(set, rule)}));
        }
    }
    json!({"ran": true, "rules": c.count + extra_rules, "mainRules": c.count, "extra": extra_note, "files": c.files, "failed": c.failed, "compileMs": c.ms,
           "matches": matches, "apkMembers": apk_members, "memberShas": d.member_shas, "ms": t.elapsed().as_millis() as u64})
}

/// The rules over bytes already in memory (a file found inside an archive): "set/rule" each.
fn scan_bytes(rules: &yara_x::Rules, b: &[u8]) -> Vec<String> {
    let mut s = yara_x::Scanner::new(rules);
    s.set_timeout(std::time::Duration::from_secs(10));
    match s.scan(b) {
        Ok(r) => match_list(r.matching_rules()).iter().map(|m| format!("{}/{}", m["set"].as_str().unwrap_or(""), m["rule"].as_str().unwrap_or(""))).collect(),
        Err(_) => Vec::new(),
    }
}

/// How scan() reads a file. Raise it whenever that changes, so remembered verdicts are read again.
/// 2 = APK code expanded, big APKs too (29 Sep 2026). 3 = the sweep reads APKs over 64 MB too (29 Sep 14:40).
/// 4 = Vigil's deep look added (archives opened, test file, app manifests, file shapes; 29 Sep 16:30).
/// 5 = locked zips tried with common passwords, big zips opened from the file, caps said, app
/// protectors named, stalkerware app files, hidden installers (29 Sep 19:30).
/// 6 = the laptop's second set (YARAhub laptop rules) on files up to 32 MB (2 Nov 2026).
const METHOD: u32 = 6;

/// The name a remembered verdict is kept under: rule count + file count + a fingerprint of every
/// rule text, the quiet/weak lists and METHOD. It used to be the two counts only (29 Sep 2026), so
/// a change in HOW files are read, or a rule edited in place, left old "clean" answers standing.
/// None = the rules are not available.
pub fn tag() -> Option<String> {
    use sha2::{Digest, Sha256};
    let c = rules().as_ref().ok()?;
    static PRINT: LazyLock<String> = LazyLock::new(|| {
        let mut h = Sha256::new();
        for z in RULE_FILES_Z {
            h.update(z);
        }
        h.update(POLICY_Z);
        h.update(crate::stalker::STALKER_Z);
        h.update(METHOD.to_le_bytes());
        h.finalize().iter().take(6).map(|b| format!("{b:02x}")).collect()
    });
    let x = extra().as_ref().map(|x| (x.count, x.files)).unwrap_or((0, 0));
    Some(format!("{}r{}f-{}", c.count + x.0, c.files + x.1, *PRINT))
}

/// Over 32 MB: too big to hold whole in an APK view (four sweep threads on a phone).
fn is_big(len: u64) -> bool {
    len > 32 << 20
}

fn match_list<'a, 'r: 'a>(it: impl Iterator<Item = yara_x::Rule<'a, 'r>>) -> Vec<Value> {
    it.map(|m| {
        let idx: usize = m.namespace().trim_start_matches('f').parse().unwrap_or(usize::MAX);
        let rel = RULE_FILES.get(idx).map(|x| x.0).unwrap_or("");
        let mut what = serde_json::Map::new();
        for (k, v) in m.metadata() {
            if let yara_x::MetaValue::String(s) = v {
                if matches!(k, "description" | "malware" | "malware_family" | "malware_type" | "category" | "author" | "reference") {
                    what.insert(k.to_string(), json!(s));
                }
            }
        }
        json!({"rule": m.identifier(), "set": set_name(rel), "file": rel, "what": what, "weak": weak_file(rel)})
    })
    .collect()
}
