//! Vigil's own look inside a file - no engine, no internet, nothing uploaded.
//! It does not know malware by name (that is Defender's job); it catches the SHAPES malware
//! arrives in: a program dressed as a PDF, a name trick, a zip hiding a script, an Office file
//! with macros or a remote template, a PDF that runs code, a shortcut that runs PowerShell, a
//! script that downloads and runs something or switches Defender off.
//! Output: {kind, flags:[{level, code, detail}]}. The page words each code; levels are
//! "danger" (strong sign), "careful" (common in attacks, also in normal files), "info".

use regex::bytes::Regex as BRegex;
use regex::Regex;
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

/// Files that can run code by themselves when double-clicked (Windows).
pub const RUNS_ITSELF: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "msi", "msc", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "ps1", "psm1", "lnk", "jar", "reg", "appx", "msix", "application", "url", "chm",
];
/// Files Windows can carry a maker's signature on.
pub const SIGNABLE: &[&str] = &["exe", "dll", "msi", "sys", "scr", "cpl", "ocx", "ps1", "psm1", "cab", "appx", "msix", "cat"];
/// Disk images: open like a folder and have been used to slip past download warnings.
const CONTAINERS: &[&str] = &["iso", "img", "vhd", "vhdx"];
/// Extensions people treat as harmless.
const LOOKS_HARMLESS: &[&str] = &[
    "pdf", "jpg", "jpeg", "png", "gif", "webp", "bmp", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "mp3", "mp4", "mov", "avi", "mkv", "wav", "csv", "rtf", "odt", "heic",
];
const SCRIPT_EXTS: &[&str] = &["bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sh"];

/// How much of a file is read for the content checks.
const READ_CAP: u64 = 24 << 20;

fn flag(out: &mut Vec<Value>, level: &str, code: &str, detail: impl Into<String>) {
    let d: String = detail.into();
    if !out.iter().any(|f| f["code"] == code) {
        out.push(json!({"level": level, "code": code, "detail": d}));
    }
}

/// What the first bytes say the file really is, whatever its name claims.
pub fn real_kind(head: &[u8], whole: &[u8]) -> &'static str {
    let s = |m: &[u8]| head.starts_with(m);
    if s(b"MZ") { "program" }
    else if s(b"PK\x03\x04") || s(b"PK\x05\x06") { "zip" }
    else if s(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") { "ole" }
    else if s(b"%PDF") { "pdf" }
    else if s(b"L\x00\x00\x00\x01\x14\x02\x00") { "shortcut" }
    else if s(b"\x7FELF") { "linux-program" }
    else if s(b"dex\n") { "android-code" }
    else if s(b"Rar!\x1A\x07") || s(b"7z\xBC\xAF\x27\x1C") || s(b"\x1F\x8B") { "archive" }
    else if s(b"\x89PNG") || s(b"\xFF\xD8\xFF") || s(b"GIF8") || s(b"BM") || (s(b"RIFF") && head.get(8..12) == Some(b"WEBP")) { "picture" }
    else if whole.len() > 0x8006 && &whole[0x8001..0x8006] == b"CD001" { "disk-image" }
    else if looks_text(head) { "text" }
    else { "other" }
}

fn looks_text(b: &[u8]) -> bool {
    if b.is_empty() { return false; }
    if b.starts_with(b"\xFF\xFE") || b.starts_with(b"\xFE\xFF") || b.starts_with(b"\xEF\xBB\xBF") { return true; }
    let odd = b.iter().filter(|&&c| c < 0x09 || (c > 0x0D && c < 0x20)).count();
    odd * 100 < b.len()
}

/// Text of a script, UTF-16 or UTF-8.
fn as_text(b: &[u8]) -> String {
    if b.starts_with(b"\xFF\xFE") || (b.len() > 3 && b[1] == 0 && b[3] == 0) {
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u);
    }
    String::from_utf8_lossy(b).into_owned()
}

/// Name tricks: an extension hidden by a right-to-left mark, "invoice.pdf.exe", or a run of
/// spaces pushing the real ending out of sight.
fn name_tricks(name: &str, ext: &str, out: &mut Vec<Value>) {
    if name.contains('\u{202E}') || name.contains('\u{202D}') || name.contains('\u{200F}') {
        flag(out, "danger", "name-reversed", name.replace('\u{202E}', "[reverse]"));
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 3 && RUNS_ITSELF.contains(&ext) {
        let before = parts[parts.len() - 2].trim().to_lowercase();
        if LOOKS_HARMLESS.contains(&before.as_str()) {
            flag(out, "danger", "double-ending", format!(".{before}.{ext}"));
        }
    }
    if RUNS_ITSELF.contains(&ext) && name.contains("     ") {
        flag(out, "danger", "hidden-ending", format!(".{ext}"));
    }
}

/// Returns what it looked at: ("office" | "android" | "archive" | "unreadable", entries read).
fn zip_check(bytes: &[u8], ext: &str, out: &mut Vec<Value>) -> (&'static str, usize) {
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        flag(out, "info", "zip-unreadable", "");
        return ("unreadable", 0);
    };
    let mut names = Vec::new();
    let mut encrypted = 0;
    for i in 0..z.len() {
        if let Ok(f) = z.by_index_raw(i) {
            if f.encrypted() { encrypted += 1; }
            names.push(f.name().to_string());
        }
    }
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let office = lower.iter().any(|n| n.starts_with("word/") || n.starts_with("xl/") || n.starts_with("ppt/"));
    let android = lower.iter().any(|n| n == "androidmanifest.xml" || n.ends_with(".dex"));
    if office {
        if lower.iter().any(|n| n.ends_with("vbaproject.bin")) {
            flag(out, "careful", "macros", "");
        }
        // A document that fetches a "template" from the internet when opened: a known way in.
        for rel in ["word/_rels/settings.xml.rels", "word/_rels/document.xml.rels", "xl/_rels/workbook.xml.rels"] {
            if let Ok(mut f) = z.by_name(rel) {
                let mut s = String::new();
                let _ = f.by_ref().take(1 << 20).read_to_string(&mut s);
                if let Some(u) = remote_template(&s) { flag(out, "danger", "remote-template", u); }
            }
        }
        if lower.iter().any(|n| n.ends_with(".bin") && n.contains("oleobject")) {
            flag(out, "careful", "embedded-object", "");
        }
    } else if !android {
        if encrypted > 0 {
            flag(out, "careful", "locked-archive", format!("{encrypted}"));
        }
        let risky: Vec<&String> = names.iter().filter(|n| {
            let e = n.rsplit('.').next().unwrap_or("").to_lowercase();
            RUNS_ITSELF.contains(&e.as_str()) || CONTAINERS.contains(&e.as_str())
        }).collect();
        if !risky.is_empty() {
            let shown: Vec<&str> = risky.iter().take(5).map(|s| s.as_str()).collect();
            flag(out, "careful", "archive-has-program", shown.join(", "));
            for n in &risky {
                let base = n.rsplit('/').next().unwrap_or(n);
                let e = base.rsplit('.').next().unwrap_or("").to_lowercase();
                let mut sub = Vec::new();
                name_tricks(base, &e, &mut sub);
                if !sub.is_empty() { flag(out, "danger", "archive-name-trick", base.to_string()); }
            }
        }
        if names.len() == 1 && risky.len() == 1 && !RUNS_ITSELF.contains(&ext) {
            flag(out, "danger", "archive-single-program", names[0].clone());
        }
    }
    (if office { "office" } else if android { "android" } else { "archive" }, names.len())
}

fn remote_template(rels: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)<Relationship\b[^>]*\bTarget="((?:https?|file)://[^"]+)"[^>]*\bTargetMode="External"|<Relationship\b[^>]*\bTargetMode="External"[^>]*\bTarget="((?:https?|file)://[^"]+)""#).unwrap());
    for c in re.captures_iter(rels) {
        let whole = c.get(0).unwrap().as_str().to_lowercase();
        // Hyperlinks inside a document are normal; only a template/frame/object that is FETCHED is the trick.
        if whole.contains("/attachedtemplate") || whole.contains("/frame") || whole.contains("/oleobject") || whole.contains("/subdocument") {
            let u = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str().to_string()).unwrap_or_default();
            // 29 Sep 2026: Word saves the AUTHOR's own template as file:///C:\... - on anyone else's
            // machine it is simply missing. Only an address on ANOTHER machine is fetched: http(s),
            // or file://server/share (which also leaks the Windows sign-in to that server).
            if is_local_drive_path(&u) {
                continue;
            }
            return Some(u);
        }
    }
    None
}

/// file:///C:/..., file:///C:\..., file:///C|/... - a path on this machine's own drive.
fn is_local_drive_path(u: &str) -> bool {
    let b = u.as_bytes();
    u.len() >= 10 && u[..8].eq_ignore_ascii_case("file:///") && b[8].is_ascii_alphabetic() && (b[9] == b':' || b[9] == b'|')
}

/// PDF /Launch: harmful when what it launches is a program or a command tool. 29 Sep 2026, his
/// laptop: government reports (NCRB, NFHS) use /Launch for links to other PDFs and to e-mail
/// addresses. If no target can be read at all, it cannot be cleared, so it stays harmful.
fn launch_runs_something(d: &[u8]) -> bool {
    static T: OnceLock<BRegex> = OnceLock::new();
    let t = T.get_or_init(|| BRegex::new(r"/(?:F|P|DL)\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)").unwrap());
    let mut read_any = false;
    for c in t.captures_iter(d) {
        let raw = c.get(1).unwrap().as_bytes();
        let s: Vec<u8> = if raw[0] == b'<' {
            let h: Vec<u8> = raw.iter().copied().filter(|x| x.is_ascii_hexdigit()).collect();
            h.chunks(2).filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect()
        } else {
            raw[1..raw.len() - 1].to_vec()
        };
        // Compressed page data can contain "/F(" by chance; a real target is printable text.
        if s.is_empty() || !s.iter().all(|c| (0x20..0x7f).contains(c)) {
            continue;
        }
        let s = String::from_utf8_lossy(&s).to_lowercase();
        let s = s.trim().trim_start_matches("mailto:");
        if s.is_empty() {
            continue;
        }
        read_any = true;
        // An e-mail address (NFHS: an address like survey.desk@example.com) ends in ".com" like an old program does.
        if s.contains('@') && !s.contains(['/', '\\', ' ']) {
            continue;
        }
        let last = s.rsplit(['/', '\\']).next().unwrap_or(s);
        let ext = last.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
        let runner = ["cmd", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "bitsadmin", "certutil", "msiexec", "bash", "sh"]
            .iter().any(|r| last == *r || last.starts_with(&format!("{r}.")) || last.starts_with(&format!("{r} ")));
        if runner || ["exe", "com", "scr", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "msi", "lnk", "cpl", "jar", "reg"].contains(&ext) {
            return true;
        }
    }
    !read_any
}

fn utf16(s: &str) -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() }

fn contains(hay: &[u8], needle: &[u8]) -> bool { hay.windows(needle.len()).any(|w| w == needle) }

/// PDF: undo "#xx" escapes in names (/J#61vaScript is /JavaScript) before looking.
fn pdf_check(b: &[u8], out: &mut Vec<Value>) {
    let mut d = Vec::with_capacity(b.len());
    let hex = |c: u8| (c as char).to_digit(16);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'#' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                d.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        d.push(b[i]);
        i += 1;
    }
    static JS: OnceLock<BRegex> = OnceLock::new();
    let js = JS.get_or_init(|| BRegex::new(r"/(JavaScript|JS)\b[^A-Za-z]").unwrap());
    let has_js = js.is_match(&d);
    let auto = contains(&d, b"/OpenAction") || contains(&d, b"/AA");
    if contains(&d, b"/Launch") {
        if launch_runs_something(&d) { flag(out, "danger", "pdf-launch", ""); } else { flag(out, "careful", "pdf-opens-file", ""); }
    }
    if has_js { flag(out, if auto { "danger" } else { "careful" }, "pdf-code", if auto { "runs on opening" } else { "" }); }
    if contains(&d, b"/EmbeddedFile") { flag(out, "careful", "pdf-attachment", ""); }
    if contains(&d, b"/XFA") && has_js { flag(out, "careful", "pdf-form-code", ""); }
}

/// Tools a shortcut or script has no business starting, and what each means.
const LAUNCHERS: &[&str] = &["powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "bitsadmin", "certutil", "msiexec", "curl.exe", "conhost"];

fn shortcut_check(b: &[u8], out: &mut Vec<Value>) {
    // Strings in a .lnk are UTF-16 (or ANSI in old ones): look in both.
    let wide: String = {
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u).to_lowercase()
    };
    let narrow = String::from_utf8_lossy(b).to_lowercase();
    let odd: String = {
        let u: Vec<u16> = b.get(1..).unwrap_or(&[]).chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u).to_lowercase()
    };
    for t in [&wide, &odd, &narrow] {
        if let Some(l) = LAUNCHERS.iter().find(|l| t.contains(*l)) {
            flag(out, "danger", "shortcut-runs-command", l.to_string());
            return;
        }
    }
    if [&wide, &odd, &narrow].iter().any(|t| t.contains("http://") || t.contains("https://")) {
        flag(out, "careful", "shortcut-web", "");
    }
}

struct Pat { code: &'static str, level: &'static str, re: &'static str }

/// Script signs, read by a person in plain words on the page. Each has a normal use somewhere,
/// so most are "careful"; the combinations below raise them.
const SCRIPT_PATS: &[Pat] = &[
    Pat { code: "hidden-code", level: "careful", re: r"(?i)(?:\s-e(?:nc?|ncodedcommand)?\s+[A-Za-z0-9+/=]{60,}|FromBase64String|\[char\]\s*0x[0-9a-f]+\s*\+|chrw?\(\s*\d+\s*\)\s*&\s*chrw?\()" },
    Pat { code: "downloads", level: "careful", re: r"(?i)(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\s|Invoke-RestMethod|\birm\s|Net\.WebClient|Start-BitsTransfer|bitsadmin\s+/transfer|certutil[^\n]{0,40}-urlcache|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|\bcurl(?:\.exe)?\s+[^\n]*https?://|\bwget\s+https?://)" },
    Pat { code: "runs-text-as-code", level: "careful", re: r"(?i)(?:\bIEX\b|Invoke-Expression|\beval\s*\(|ExecuteGlobal|\bExecute\s*\(|new\s+Function\s*\()" },
    Pat { code: "starts-programs", level: "info", re: r"(?i)(?:WScript\.Shell|Shell\.Application|Start-Process|\.ShellExecute|\bcmd(?:\.exe)?\s+/c\b|powershell(?:\.exe)?\s+-)" },
    Pat { code: "hidden-window", level: "careful", re: r"(?i)(?:-w(?:indowstyle)?\s+h(?:idden)?\b|-nop(?:rofile)?\b[^\n]{0,40}-w\s*h|\.Run\s*\([^,\n]+,\s*0\s*[,)])" },
    Pat { code: "turns-off-defender", level: "danger", re: r"(?i)(?:Set-MpPreference[^\n]{0,80}-Disable|Add-MpPreference[^\n]{0,40}-Exclusion|DisableRealtimeMonitoring|DisableAntiSpyware|sc(?:\.exe)?\s+(?:stop|config)\s+WinDefend)" },
    Pat { code: "deletes-backups", level: "danger", re: r"(?i)(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete|bcdedit[^\n]{0,40}recoveryenabled\s+no)" },
    Pat { code: "starts-itself", level: "careful", re: r"(?i)(?:schtasks(?:\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask|CurrentVersion\\Run\b|\\Startup\\)" },
    Pat { code: "web-runner", level: "danger", re: r"(?i)(?:mshta(?:\.exe)?\s+[\x22']?(?:https?|vbscript|javascript):|regsvr32[^\n]{0,60}/i:\s*https?:|rundll32[^\n]{0,60}(?:javascript:|https?://))" },
    Pat { code: "clears-tracks", level: "careful", re: r"(?i)(?:wevtutil(?:\.exe)?\s+cl\b|Clear-EventLog|Remove-Item[^\n]{0,80}ConsoleHost_history)" },
];

fn script_check(text: &str, out: &mut Vec<Value>) {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    let res = RES.get_or_init(|| SCRIPT_PATS.iter().map(|p| Regex::new(p.re).unwrap()).collect());
    let mut hit = Vec::new();
    for (p, re) in SCRIPT_PATS.iter().zip(res) {
        if let Some(m) = re.find(text) {
            let s: String = m.as_str().chars().take(80).collect();
            hit.push(p.code);
            flag(out, p.level, p.code, s.trim().to_string());
        }
    }
    // The classic dropper: fetch something and run it, or run text that was hidden.
    let has = |c: &str| hit.contains(&c);
    if has("downloads") && (has("runs-text-as-code") || has("starts-programs") || has("hidden-window")) {
        flag(out, "danger", "download-and-run", "");
    }
    if has("hidden-code") && (has("runs-text-as-code") || has("hidden-window")) {
        flag(out, "danger", "hidden-and-run", "");
    }
}

/// Everything above, on bytes (so tests need no files on disk - a test file holding a real
/// dropper line would itself be caught by Defender).
pub fn sniff_bytes(name: &str, ext: &str, bytes: &[u8]) -> Value {
    let head = &bytes[..bytes.len().min(4096)];
    let kind = real_kind(head, bytes);
    let mut flags = Vec::new();
    // What was actually looked at, so the page can show it (his rule 25 Sep: a scan must show
    // what it checked). Every entry is pushed where the check runs, never listed up front.
    let mut checked: Vec<Value> = vec![json!({"code": "type", "n": head.len()}), json!({"code": "name"})];
    name_tricks(name, ext, &mut flags);

    // Disguise: the content is a program, the name says something harmless.
    match kind {
        // The trick is a program wearing a name people open without thinking (a PDF, a photo, a
        // video). 29 Sep 2026, his laptop: installers keep real programs as .tmp, and Microsoft's
        // own Visual Studio packages as .psdsxs - 38 "harmful" calls; an odd name is only a note.
        "program" if LOOKS_HARMLESS.contains(&ext) || ext.is_empty() =>
            flag(&mut flags, "danger", "disguised-program", format!(".{ext}")),
        "program" if !["exe", "dll", "scr", "com", "sys", "cpl", "ocx", "efi", "msi", "mui", "pif", "drv", "node", "pyd", "winmd", "ax"].contains(&ext) =>
            flag(&mut flags, "careful", "program-odd-name", format!(".{ext}")),
        "shortcut" if ext != "lnk" => flag(&mut flags, "danger", "disguised-shortcut", format!(".{ext}")),
        "zip" | "archive" if LOOKS_HARMLESS.contains(&ext) && !["docx", "xlsx", "pptx", "odt"].contains(&ext) =>
            flag(&mut flags, "careful", "disguised-archive", format!(".{ext}")),
        "text" if LOOKS_HARMLESS.contains(&ext) && ext != "txt" && ext != "csv" && ext != "rtf" => {
            checked.push(json!({"code": "hidden-page"}));
            let t = as_text(&bytes[..bytes.len().min(1 << 20)]).to_lowercase();
            if t.contains("<script") || t.contains("<html") || t.contains("wscript") || t.contains("powershell") {
                flag(&mut flags, "danger", "disguised-script", format!(".{ext}"));
            }
        }
        _ => {}
    }
    if RUNS_ITSELF.contains(&ext) { flag(&mut flags, "info", "can-run", format!(".{ext}")); }
    if CONTAINERS.contains(&ext) || kind == "disk-image" { flag(&mut flags, "careful", "disk-image", format!(".{ext}")); }

    match kind {
        "zip" => {
            let (what, n) = zip_check(bytes, ext, &mut flags);
            checked.push(json!({"code": format!("zip-{what}"), "n": n}));
        }
        "ole" => {
            checked.push(json!({"code": "ole"}));
            if contains(bytes, &utf16("_VBA_PROJECT")) || contains(bytes, &utf16("Macros")) && contains(bytes, &utf16("VBA")) {
                flag(&mut flags, "careful", "macros", "");
            }
        }
        "pdf" => { checked.push(json!({"code": "pdf"})); pdf_check(bytes, &mut flags) }
        "shortcut" => { checked.push(json!({"code": "shortcut"})); shortcut_check(bytes, &mut flags) }
        _ => {}
    }
    let scripty = SCRIPT_EXTS.contains(&ext) || (kind == "text" && ["html", "htm", "svg", "xml", "txt"].contains(&ext));
    if scripty || flags.iter().any(|f| f["code"] == "disguised-script") {
        let text = as_text(bytes);
        checked.push(json!({"code": "script", "n": SCRIPT_PATS.len(), "lines": text.lines().count()}));
        script_check(&text, &mut flags);
    }
    json!({"read": true, "kind": kind, "flags": flags, "readBytes": bytes.len(), "checked": checked})
}

pub fn sniff(path: &Path, name: &str, ext: &str) -> Value {
    let mut b = Vec::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            if let Err(e) = f.take(READ_CAP).read_to_end(&mut b) {
                return json!({"read": false, "error": e.to_string()});
            }
        }
        Err(e) => return json!({"read": false, "error": e.to_string()}),
    }
    let mut v = sniff_bytes(name, ext, &b);
    if let Ok(m) = std::fs::metadata(path) {
        if m.len() > READ_CAP { v["partial"] = json!(true); }
    }
    v
}

/// Windows only: where the file was downloaded from, from the "Mark of the Web" Windows keeps
/// beside a downloaded file. Nothing leaves the computer.
pub fn downloaded_from(path: &Path) -> Value {
    if !cfg!(windows) { return Value::Null; }
    let ads = format!("{}:Zone.Identifier", path.to_string_lossy());
    let Ok(s) = std::fs::read_to_string(&ads) else { return json!({"marked": false}) };
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()));
    json!({"marked": true, "zone": get("ZoneId=").and_then(|z| z.parse::<i64>().ok()), "host": get("HostUrl="), "referrer": get("ReferrerUrl=")})
}
