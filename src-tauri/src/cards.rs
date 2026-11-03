//! How many bank cards each browser keeps on this laptop - a COUNT, never a number, name or date.
//! Password stealers take these, so a card saved in a browser is a card at risk.
//! Chromium keeps full cards in the `credit_cards` table of each profile's "Web Data" (SQLite);
//! Firefox keeps them in autofill-profiles.json. Files are opened read-only and immutable,
//! so the browser (which may be running) is never locked or written to.

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Full cards in one Chromium "Web Data" file. Err = could not read it (not "no cards").
pub fn count_chromium(web_data: &Path) -> Result<u64, String> {
    let uri = format!("file:{}?immutable=1", web_data.to_string_lossy().replace('\\', "/").replace('?', "%3f").replace('#', "%23"));
    let conn = Connection::open_with_flags(&uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| e.to_string())?;
    let mut total = 0u64;
    let mut seen = 0;
    for table in CARD_TABLES {
        let has: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1", [table], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if has == 0 {
            continue;
        }
        seen += 1;
        let n: i64 = conn.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| r.get(0)).map_err(|e| e.to_string())?;
        total += n.max(0) as u64;
    }
    // No known table at all means the browser changed its layout: say so, never "0 cards".
    if seen == 0 {
        return Err("no card table found (browser layout changed?)".into());
    }
    Ok(total)
}

/// Tables holding full card or bank-account numbers on this laptop (seen in real Chrome, Edge
/// and Brave files, 24 Sep 2026). "masked_*" hold only the last 4 digits, so they are left out.
const CARD_TABLES: [&str; 3] = ["credit_cards", "unmasked_credit_cards", "local_ibans"];

/// Cards in one Firefox autofill-profiles.json.
pub fn count_firefox(text: &str) -> Result<u64, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    Ok(v.get("creditCards").and_then(|c| c.as_array()).map(|a| a.len() as u64).unwrap_or(0))
}

fn subdirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// Every installed browser's profiles: { browsers: [{id, name, profiles, cards, unreadable}] }.
/// `cards` is null when no profile could be read, so the page shows no row rather than a false "0".
pub fn saved_cards() -> Value {
    let lad = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let mut list = Vec::new();
    for (id, name, root) in [
        ("chrome", "Google Chrome", format!(r"{lad}\Google\Chrome\User Data")),
        ("edge", "Microsoft Edge", format!(r"{lad}\Microsoft\Edge\User Data")),
        ("brave", "Brave", format!(r"{lad}\BraveSoftware\Brave-Browser\User Data")),
    ] {
        let files: Vec<PathBuf> = subdirs(Path::new(&root)).into_iter().map(|p| p.join("Web Data")).filter(|p| p.is_file()).collect();
        if files.is_empty() {
            continue;
        }
        let (mut cards, mut read, mut errors) = (0u64, 0u64, Vec::new());
        for f in &files {
            match count_chromium(f) {
                Ok(n) => { cards += n; read += 1; }
                Err(e) => errors.push(e),
            }
        }
        list.push(json!({ "id": id, "name": name, "profiles": files.len(), "read": read,
            "cards": if read > 0 { json!(cards) } else { Value::Null }, "errors": errors }));
    }
    let ff: Vec<PathBuf> = subdirs(&Path::new(&appdata).join(r"Mozilla\Firefox\Profiles"))
        .into_iter().map(|p| p.join("autofill-profiles.json")).filter(|p| p.is_file()).collect();
    if !ff.is_empty() {
        let (mut cards, mut read, mut errors) = (0u64, 0u64, Vec::new());
        for f in &ff {
            match std::fs::read_to_string(f).map_err(|e| e.to_string()).and_then(|t| count_firefox(&t)) {
                Ok(n) => { cards += n; read += 1; }
                Err(e) => errors.push(e),
            }
        }
        list.push(json!({ "id": "firefox", "name": "Firefox", "profiles": ff.len(), "read": read,
            "cards": if read > 0 { json!(cards) } else { Value::Null }, "errors": errors }));
    }
    json!({ "browsers": list })
}
