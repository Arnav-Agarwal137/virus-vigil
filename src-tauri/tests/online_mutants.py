"""Rust mutants for the online look-up. Full `cargo test --lib` per mutant (never a name filter,
7b.5). Byte-for-byte restore with a hash check; a pattern that does not match once = SKIPPED;
a mutant that does not compile = SKIPPED (counted apart)."""
import hashlib, subprocess, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # src-tauri/
M = [
    ("sendable lets any letter through", "src/hashonline.rs", "(b'a'..=b'f').contains(&b)", "(b'a'..=b'z').contains(&b)"),
    ("any 404 read as never-seen", "src/hashonline.rs", '404 if body.contains("Non existing") => Ok(Said::Unknown),', "404 => Ok(Said::Unknown),"),
    ("200 without a file read as known", "src/hashonline.rs", 'if !v.is_object() || (v.get("SHA-256").is_none() && v.get("SHA-1").is_none()) {', "if !v.is_object() {"),
    ("memory never expires", "src/hashonline.rs", "if now.saturating_sub(t) > KEEP_SECS || t > now + 3600 {", "if t > now + 3600 {"),
    ("no cap", "src/hashonline.rs", "    todo.truncate(MAX_ASK);\n", "\n"),
    ("a missing reply read as never-seen", "src/hashonline.rs", 'let got = by.get(s.as_str()).map_or(Err("no reply for it".to_string()), |(st, b)| read_answer(*st, b));',
     'let got = by.get(s.as_str()).map_or(Ok(Said::Unknown), |(st, b)| read_answer(*st, b));'),
    ("strong finds asked too", "src/hashonline.rs", '.filter(|f| f["weak"] == true)', ".filter(|_| true)"),
    ("named weak find stays weak", "src/hashonline.rs", '            f["weak"] = json!(false);\n            f["online"] = json!(src);', '            f["online"] = json!(src);'),
    ("unknown apps not added as rows", "src/hashonline.rs", "            found.push(row);\n", "\n"),
    ("maker apps asked too", "src/apkcheck.rs", "} else if !a.maker && unknown_apps.len()", "} else if unknown_apps.len()"),
    ("not answered reads as never-seen", "src/hashonline.rs", "None => (Value::Null, Value::Null),", 'None => (json!("unknown"), Value::Null),'),
    ("sweep stops collecting app files", "src/folderscan.rs", "} else if is_apk(&e.path) {", "} else if false {"),
]

def run():
    os.chdir(ROOT)
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "src"], capture_output=True, text=True).stdout
    print("dirty before (expected: my own uncommitted work):", dirty.strip().replace("\n", " | "))
    res = []
    for name, f, a, b in M:
        raw = open(f, "rb").read()
        h0 = hashlib.sha256(raw).hexdigest()
        t = raw.decode("utf-8")
        crlf = "\r\n" in t
        tt = t.replace("\r\n", "\n")
        if tt.count(a) != 1:
            res.append((name, "SKIPPED (pattern x%d)" % tt.count(a))); continue
        tt = tt.replace(a, b)
        if crlf:
            tt = tt.replace("\n", "\r\n")
        open(f, "wb").write(tt.encode("utf-8"))
        try:
            p = subprocess.run(["cargo", "test", "--lib"], capture_output=True, text=True)
            out = p.stdout + p.stderr
            if "could not compile" in out or "error[E" in out:
                verdict = "SKIPPED (does not compile)"
            elif p.returncode != 0:
                verdict = "RED"
            else:
                verdict = "SURVIVED"
        finally:
            open(f, "wb").write(raw)
            assert hashlib.sha256(open(f, "rb").read()).hexdigest() == h0, "restore failed " + f
        res.append((name, verdict))
        print(name, "->", verdict, flush=True)
    print("SUMMARY", sum(v == "RED" for _, v in res), "red of", len(res))
    for n, v in res:
        print(" ", v, "-", n)

run()
