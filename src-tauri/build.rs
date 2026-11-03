fn main() {
    yara_index();
    tauri_build::build()
}

// Every YARA rule file under yara/ becomes an entry in $OUT_DIR/yara_rules.rs, embedded in the
// exe and the phone library alike (compiled once by src/yara.rs; on the phone behind a crash guard).
fn yara_index() {
    use std::path::{Path, PathBuf};
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).expect("yara/ folder").flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if matches!(p.extension().and_then(|x| x.to_str()), Some("yar") | Some("yara")) {
                out.push(p);
            }
        }
    }
    println!("cargo:rerun-if-changed=yara");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("yara");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    // Stored DEFLATED, never as text (29 Sep 2026): as text, Vigil's own exe and APK carried every
    // rule's strings, and once APK code was read decompressed Vigil matched 78 rules itself.
    // src/yara.rs inflates them once, in memory.
    use std::io::Write;
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let zdir = out_dir.join("yara-z");
    let _ = std::fs::remove_dir_all(&zdir);
    std::fs::create_dir_all(&zdir).unwrap();
    // The PATH goes inside the blob too ("<path>\n<text>"): a path such as .../SharpHostInfo.yar is
    // itself a string some rules look for. Same for policy.txt, the quiet/weak lists.
    let deflate = |bytes: &[u8], name: &str| -> String {
        let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        z.write_all(bytes).unwrap();
        let zp = zdir.join(name);
        std::fs::write(&zp, z.finish().unwrap()).unwrap();
        format!("include_bytes!({:?})", zp.to_string_lossy())
    };
    let mut s = String::from("pub static RULE_FILES_Z: &[&[u8]] = &[\n");
    for (i, f) in files.iter().enumerate() {
        let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        println!("cargo:rerun-if-changed={}", f.display());
        let text = std::fs::read(f).unwrap();
        std::str::from_utf8(&text).unwrap_or_else(|_| panic!("rule file is not UTF-8: {rel}"));
        let mut blob = format!("{rel}\n").into_bytes();
        blob.extend_from_slice(&text);
        s.push_str(&format!("    {},\n", deflate(&blob, &format!("{i}.z"))));
    }
    s.push_str("];\n");
    let policy = root.join("policy.txt");
    println!("cargo:rerun-if-changed={}", policy.display());
    s.push_str(&format!("pub static POLICY_Z: &[u8] = {};\n", deflate(&std::fs::read(&policy).expect("yara/policy.txt"), "policy.z")));
    std::fs::write(out_dir.join("yara_rules.rs"), s).unwrap();

    // The stalkerware list (29 Sep 2026, src/stalker.rs), deflated for the same reason.
    let sw = Path::new(env!("CARGO_MANIFEST_DIR")).join("data").join("stalkerware.tsv");
    println!("cargo:rerun-if-changed={}", sw.display());
    let z = deflate(&std::fs::read(&sw).expect("data/stalkerware.tsv (tools/stalkerware.py)"), "stalker.z");
    std::fs::write(out_dir.join("stalker.rs"), format!("pub static STALKER_Z: &[u8] = {z};\n")).unwrap();
}
