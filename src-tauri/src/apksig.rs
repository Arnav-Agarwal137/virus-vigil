//! The signing certificates of an Android app FILE, as SHA-1 (uppercase hex) - the same value
//! Android reports for an installed app and the stalkerware list records (29 Sep 2026). A
//! stalkerware maker renames the package often; changing the signing key is much rarer.
//!
//! Two places a certificate lives:
//!   - the APK Signing Block (scheme v2/v3), just before the zip's central directory;
//!   - META-INF/*.RSA|DSA|EC (scheme v1), a PKCS#7 blob.
//! Both are read; unreadable or unsigned -> an empty list (never an error the sweep has to carry).

use sha1::{Digest, Sha1};
use std::io::{Read, Seek, SeekFrom};

const V2: u32 = 0x7109_871a;
const V3: u32 = 0xf053_68c0;
const V31: u32 = 0x1b93_ad61;
/// Biggest signing block read (real ones are a few KB).
const MAX_BLOCK: u64 = 4 << 20;

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02X}")).collect()
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()))
}

/// One length-prefixed (u32 LE) item at `*at`, advancing past it.
fn item<'a>(b: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let n = u32le(b, *at)? as usize;
    let s = b.get(*at + 4..(*at + 4).checked_add(n)?)?;
    *at += 4 + n;
    Some(s)
}

/// Certificates in one v2/v3 value: signers[ signer{ signed_data{ digests, certificates[..] } } ].
fn certs_in_scheme(v: &[u8], out: &mut Vec<Vec<u8>>) -> Option<()> {
    let mut at = 0;
    let signers = item(v, &mut at)?;
    let mut s_at = 0;
    while s_at < signers.len() {
        let signer = item(signers, &mut s_at)?;
        let mut g = 0;
        let signed = item(signer, &mut g)?;
        let mut d = 0;
        item(signed, &mut d)?; // digests
        let certs = item(signed, &mut d)?;
        let mut c = 0;
        while c < certs.len() {
            out.push(item(certs, &mut c)?.to_vec());
        }
    }
    Some(())
}

/// The APK Signing Block's certificates, from the file.
fn block_certs<R: Read + Seek>(r: &mut R) -> Option<Vec<Vec<u8>>> {
    let len = r.seek(SeekFrom::End(0)).ok()?;
    // End of central directory: in the last 64 KB + 22 bytes.
    let tail_len = len.min(65_557);
    r.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    r.read_exact(&mut tail).ok()?;
    let eocd = tail.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    let cd = u32le(&tail, eocd + 16)? as u64;
    if cd < 32 {
        return None;
    }
    r.seek(SeekFrom::Start(cd - 24)).ok()?;
    let mut foot = [0u8; 24];
    r.read_exact(&mut foot).ok()?;
    if &foot[8..] != b"APK Sig Block 42" {
        return None;
    }
    let size = u64::from_le_bytes(foot[..8].try_into().unwrap());
    if size < 24 || size > MAX_BLOCK || size + 8 > cd {
        return None;
    }
    let start = cd - size - 8;
    r.seek(SeekFrom::Start(start + 8)).ok()?;
    let mut pairs = vec![0u8; (size - 24) as usize];
    r.read_exact(&mut pairs).ok()?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 12 <= pairs.len() {
        let n = u64::from_le_bytes(pairs[at..at + 8].try_into().unwrap()) as usize;
        let Some(end) = (at + 8).checked_add(n).filter(|e| *e <= pairs.len()) else { break };
        if n >= 4 {
            let id = u32le(&pairs, at + 8)?;
            if id == V2 || id == V3 || id == V31 {
                certs_in_scheme(&pairs[at + 12..end], &mut out);
            }
        }
        at = end;
    }
    Some(out)
}

/// One DER element at `*at`: (tag, contents), advancing past it.
fn der<'a>(b: &'a [u8], at: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *b.get(*at)?;
    let l0 = *b.get(*at + 1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let k = l0 & 0x7f;
        if k == 0 || k > 4 {
            return None;
        }
        let mut n = 0usize;
        for i in 0..k {
            n = (n << 8) | *b.get(*at + 2 + i)? as usize;
        }
        (n, 2 + k)
    };
    let s = b.get(*at + hdr..(*at + hdr).checked_add(len)?)?;
    *at += hdr + len;
    Some((tag, s))
}

/// The whole DER encoding (header included) of the element at `*at`.
fn der_whole<'a>(b: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let from = *at;
    der(b, at)?;
    b.get(from..*at)
}

/// Certificates in a v1 PKCS#7 SignedData: ContentInfo{ oid, [0]{ SignedData{ version,
/// digestAlgorithms, contentInfo, [0] IMPLICIT certificates{ Certificate... }, ... } } }.
pub(crate) fn pkcs7_certs(b: &[u8]) -> Vec<Vec<u8>> {
    let run = || -> Option<Vec<Vec<u8>>> {
        let mut at = 0;
        let (_, ci) = der(b, &mut at)?;
        let mut i = 0;
        der(ci, &mut i)?; // contentType OID
        let (_, explicit) = der(ci, &mut i)?;
        let mut j = 0;
        let (_, sd) = der(explicit, &mut j)?;
        let mut k = 0;
        der(sd, &mut k)?; // version
        der(sd, &mut k)?; // digestAlgorithms
        der(sd, &mut k)?; // encapContentInfo
        let mut out = Vec::new();
        while k < sd.len() {
            let tag = sd[k];
            let (_, body) = der(sd, &mut k)?;
            if tag == 0xa0 {
                let mut m = 0;
                while m < body.len() {
                    out.push(der_whole(body, &mut m)?.to_vec());
                }
            }
        }
        Some(out)
    };
    run().unwrap_or_default()
}

/// Every signing certificate of the app file, as uppercase SHA-1 hex, deduplicated.
pub fn cert_sha1s<R: Read + Seek>(r: &mut R) -> Vec<String> {
    let mut ders = block_certs(r).unwrap_or_default();
    if r.seek(SeekFrom::Start(0)).is_ok() {
        if let Ok(mut z) = zip::ZipArchive::new(&mut *r) {
            let names: Vec<String> = z.file_names()
                .filter(|n| {
                    let u = n.to_ascii_uppercase();
                    u.starts_with("META-INF/") && [".RSA", ".DSA", ".EC"].iter().any(|e| u.ends_with(e))
                })
                .map(String::from)
                .collect();
            for n in names {
                let mut b = Vec::new();
                if let Ok(e) = z.by_name(&n) {
                    if e.take(1 << 20).read_to_end(&mut b).is_ok() {
                        ders.extend(pkcs7_certs(&b));
                    }
                }
            }
        }
    }
    let mut out: Vec<String> = ders.iter().map(|d| hex(&Sha1::digest(d))).collect();
    out.sort();
    out.dedup();
    out
}
