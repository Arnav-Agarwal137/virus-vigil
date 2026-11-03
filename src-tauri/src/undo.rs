// The browser fixer's undo record. fix.ps1 reports, for every value it writes, what was there
// before; this keeps those in %LOCALAPPDATA%\VirusVigil\undo.json so "Undo" can put them back.
//
// The FIRST "before" for a setting always wins: if the fixer runs twice, the second run's
// "before" is the fixer's own value, and keeping that would make undo restore our change
// instead of the person's original (e.g. the 16 Sep hardening policies on the owner's laptop).

use serde_json::{json, Value};
use std::path::PathBuf;

/// Where the record lives. VV_UNDO_FILE lets the tests use a scratch file instead.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("VV_UNDO_FILE") {
        return PathBuf::from(p);
    }
    let base = std::env::var("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    base.join("VirusVigil").join("undo.json")
}

pub fn load() -> Option<Value> {
    let text = std::fs::read_to_string(path()).ok()?;
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let has = v["registry"].as_array().is_some_and(|a| !a.is_empty()) || !v["firefox"].is_null();
    has.then_some(v)
}

pub fn save(v: &Value) -> Result<(), String> {
    let p = path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }
    std::fs::write(&p, v.to_string()).map_err(|e| format!("cannot save the undo record: {e}"))
}

pub fn clear() {
    let _ = std::fs::remove_file(path());
}

/// Fold one apply result into the record. Only settings that were actually written (ok) are
/// recorded; a setting already in the record keeps its older "before".
pub fn merge(existing: Option<Value>, result: &Value) -> Value {
    let mut registry: Vec<Value> = existing.as_ref().and_then(|e| e["registry"].as_array().cloned()).unwrap_or_default();
    let key = |v: &Value| format!("{}|{}", v["where"].as_str().unwrap_or(""), v["name"].as_str().unwrap_or(""));
    for c in result["changes"].as_array().into_iter().flatten() {
        if c["before"].is_null() || c["ok"] != true {
            continue; // Firefox rows and failed writes carry no registry "before"
        }
        let k = key(c);
        if registry.iter().any(|r| key(r) == k) {
            continue;
        }
        registry.push(json!({"where": c["where"], "name": c["name"], "before": c["before"]}));
    }
    let firefox = match existing.as_ref().map(|e| &e["firefox"]) {
        Some(f) if !f.is_null() => f.clone(),
        _ => result["firefoxBefore"].clone(),
    };
    json!({"registry": registry, "firefox": firefox})
}

/// What the page needs to offer the button: how many settings, and which browsers.
pub fn summary(v: &Option<Value>) -> Value {
    let Some(v) = v else { return json!({"available": false}) };
    let reg = v["registry"].as_array().cloned().unwrap_or_default();
    let mut browsers: Vec<&str> = Vec::new();
    for r in &reg {
        let b = match r["where"].as_str() {
            Some("Google\\Chrome") => "Chrome",
            Some("BraveSoftware\\Brave") => "Brave",
            Some("Microsoft\\Edge") => "Edge",
            Some("Defender ASR") => "Defender rules",
            Some("System") => "Windows settings",
            _ => continue,
        };
        if !browsers.contains(&b) {
            browsers.push(b);
        }
    }
    if !v["firefox"].is_null() {
        browsers.push("Firefox");
    }
    json!({"available": true, "settings": reg.len() + usize::from(!v["firefox"].is_null()), "browsers": browsers})
}
