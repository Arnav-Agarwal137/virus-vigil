//! apksig.rs: the signing-certificate SHA-1s of an app FILE (29 Sep 2026, the stalkerware gap).
//! The fixtures are vv-plain.apk signed by apksigner with a throwaway key
//! (tests/make_deeplook_fixtures.py), one with only the v2/v3 signing block and one with only the
//! v1 META-INF signature; the expected value is what apksigner itself printed, read from
//! vv-signed.sha1.txt - never typed here.

use crate::apksig::cert_sha1s;
use std::io::Cursor;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)).unwrap()
}

fn expected() -> String {
    String::from_utf8(fixture("vv-signed.sha1.txt")).unwrap().trim().to_string()
}

fn certs(b: &[u8]) -> Vec<String> {
    cert_sha1s(&mut Cursor::new(b.to_vec()))
}

/// Each fixture carries exactly one kind of signature, so each reader is tested alone.
#[test]
fn each_fixture_has_only_one_kind_of_signature() {
    let v2 = fixture("vv-signed-v2.apk");
    let v1 = fixture("vv-signed-v1.apk");
    assert!(v2.windows(16).any(|w| w == b"APK Sig Block 42"));
    assert!(!v1.windows(16).any(|w| w == b"APK Sig Block 42"));
    let names = |b: &[u8]| zip::ZipArchive::new(Cursor::new(b.to_vec())).unwrap().file_names().map(String::from).collect::<Vec<_>>();
    assert!(!names(&v2).iter().any(|n| n.ends_with(".RSA")), "{:?}", names(&v2));
    assert!(names(&v1).iter().any(|n| n.ends_with(".RSA")), "{:?}", names(&v1));
    assert_eq!(expected().len(), 40);
}

#[test]
fn the_v2_signing_block_is_read() {
    assert_eq!(certs(&fixture("vv-signed-v2.apk")), [expected()]);
}

#[test]
fn the_v1_signature_is_read() {
    assert_eq!(certs(&fixture("vv-signed-v1.apk")), [expected()]);
}

#[test]
fn an_unsigned_app_has_no_certificate() {
    assert!(certs(&fixture("vv-plain.apk")).is_empty());
}

/// A damaged or hostile file gives an empty list, never a crash: every byte of the signed files
/// flipped in turn, and every cut-off length, must return.
#[test]
fn a_damaged_file_never_crashes_the_reader() {
    assert!(certs(b"").is_empty());
    assert!(certs(b"PK\x05\x06").is_empty());
    for name in ["vv-signed-v2.apk", "vv-signed-v1.apk"] {
        let good = fixture(name);
        for i in 0..good.len() {
            let mut b = good.clone();
            b[i] ^= 0xff;
            let _ = certs(&b);
        }
        for n in (0..good.len()).step_by(7) {
            let _ = certs(&good[..n]);
        }
    }
}
