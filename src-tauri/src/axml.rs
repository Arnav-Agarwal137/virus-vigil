//! Reads an Android app's binary AndroidManifest.xml well enough to say two things:
//! which permissions it ASKS for (<uses-permission>), and which special services it
//! OFFERS to the system (a <service> or <receiver> guarded by a BIND_* permission -
//! e.g. an accessibility service can see and tap the screen, a notification listener
//! reads every notification). A plain text search cannot tell those apart, and it also
//! picks up permissions that merely guard a component (like DUMP), which the app never
//! asks for. Checked against Android's own `aapt dump` on real apps (tests/).
//!
//! Every read is bounds-checked: malware ships deliberately broken manifests to crash
//! scanners, so any malformed input returns None and the caller falls back.

use std::collections::BTreeSet;

const RES_STRING_POOL: u16 = 0x0001;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const ATTR_NAME: u32 = 0x0101_0003; // android:name
const ATTR_PERMISSION: u32 = 0x0101_0006; // android:permission
const TYPE_STRING: u8 = 0x03;

#[derive(Debug, Default, PartialEq)]
pub struct Manifest {
    pub requested: Vec<String>,
    pub offers: Vec<String>,
    /// The app id (`<manifest package=...>`), None when the manifest does not carry one.
    pub package: Option<String>,
    /// Some activity is listed in the app drawer (category LAUNCHER). Malware that hides its icon has none.
    pub launcher: bool,
    /// Some receiver listens for incoming text messages (SMS_RECEIVED): where OTPs are stolen.
    pub sms_listener: bool,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn string_pool(b: &[u8], start: usize) -> Option<Vec<String>> {
    let header = u16_at(b, start + 2)? as usize;
    let count = u32_at(b, start + 8)? as usize;
    let flags = u32_at(b, start + 16)?;
    let strings_start = start + u32_at(b, start + 20)? as usize;
    if count > 1_000_000 {
        return None;
    }
    let utf8 = flags & (1 << 8) != 0;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut p = strings_start + u32_at(b, start + header + 4 * i)? as usize;
        let s = if utf8 {
            // char count (1-2 bytes, skipped), then byte count (1-2 bytes), then bytes
            p += if *b.get(p)? & 0x80 != 0 { 2 } else { 1 };
            let first = *b.get(p)? as usize;
            let n = if first & 0x80 != 0 {
                let n = ((first & 0x7f) << 8) | *b.get(p + 1)? as usize;
                p += 2;
                n
            } else {
                p += 1;
                first
            };
            String::from_utf8_lossy(b.get(p..p + n)?).into_owned()
        } else {
            let first = u16_at(b, p)? as usize;
            p += 2;
            let n = if first & 0x8000 != 0 {
                let n = ((first & 0x7fff) << 16) | u16_at(b, p)? as usize;
                p += 2;
                n
            } else {
                first
            };
            let units: Vec<u16> = b.get(p..p + 2 * n)?.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Some(out)
}

/// Parse a binary manifest. None = not a manifest we can read (caller must fall back).
pub fn parse(b: &[u8]) -> Option<Manifest> {
    if u16_at(b, 0)? != 0x0003 {
        return None;
    }
    let total = (u32_at(b, 4)? as usize).min(b.len());
    let mut pool: Vec<String> = Vec::new();
    let mut res_ids: Vec<u32> = Vec::new();
    let mut requested = BTreeSet::new();
    let mut offers = BTreeSet::new();
    let mut package: Option<String> = None;
    let (mut launcher, mut sms_listener) = (false, false);
    let mut saw_element = false;

    let mut pos = u16_at(b, 2)? as usize;
    while pos + 8 <= total {
        let typ = u16_at(b, pos)?;
        let header = u16_at(b, pos + 2)? as usize;
        let size = u32_at(b, pos + 4)? as usize;
        if size < 8 || pos + size > total {
            return None;
        }
        match typ {
            RES_STRING_POOL if pool.is_empty() => pool = string_pool(b, pos)?,
            RES_XML_RESOURCE_MAP => {
                res_ids = (0..(size - header) / 4).filter_map(|i| u32_at(b, pos + header + 4 * i)).collect();
            }
            RES_XML_START_ELEMENT => {
                saw_element = true;
                let ext = pos + header;
                let name = pool.get(u32_at(b, ext + 4)? as usize).map(String::as_str).unwrap_or("");
                let attr_start = u16_at(b, ext + 8)? as usize;
                let attr_size = u16_at(b, ext + 10)? as usize;
                let attr_count = u16_at(b, ext + 12)? as usize;
                if attr_size < 20 {
                    return None;
                }
                let (mut a_name, mut a_perm, mut a_package) = (None, None, None);
                for i in 0..attr_count {
                    let a = ext + attr_start + i * attr_size;
                    let name_idx = u32_at(b, a + 4)? as usize;
                    let raw = u32_at(b, a + 8)?;
                    let data_type = *b.get(a + 15)?;
                    let data = u32_at(b, a + 16)?;
                    // Match by resource id first: obfuscated apps blank the attribute's text name.
                    let id = res_ids.get(name_idx).copied();
                    let text = pool.get(name_idx).map(String::as_str).unwrap_or("");
                    let value_idx = if raw != u32::MAX { Some(raw) } else if data_type == TYPE_STRING { Some(data) } else { None };
                    let value = value_idx.and_then(|v| pool.get(v as usize)).cloned();
                    if id == Some(ATTR_NAME) || (id.is_none() && text == "name") {
                        a_name = value;
                    } else if id == Some(ATTR_PERMISSION) || (id.is_none() && text == "permission") {
                        a_perm = value;
                    } else if id.is_none() && text == "package" {
                        // "package" has no android: namespace and no resource id - its text name is all there is.
                        a_package = value;
                    }
                }
                match name {
                    "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                        if let Some(n) = a_name {
                            requested.insert(n);
                        }
                    }
                    "manifest" if package.is_none() => package = a_package.filter(|p| !p.is_empty()),
                    "service" | "receiver" => {
                        if let Some(p) = a_perm.filter(|p| p.starts_with("android.permission.BIND_")) {
                            offers.insert(p);
                        }
                    }
                    "category" if a_name.as_deref() == Some("android.intent.category.LAUNCHER") => launcher = true,
                    "action" if a_name.as_deref() == Some("android.provider.Telephony.SMS_RECEIVED") => sms_listener = true,
                    _ => {}
                }
            }
            _ => {}
        }
        pos += size;
    }
    if !saw_element {
        return None;
    }
    Some(Manifest { requested: requested.into_iter().collect(), offers: offers.into_iter().collect(), package, launcher, sms_listener })
}
