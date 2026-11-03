//! Every test's scratch folder, deleted when the test ends (26 Sep: the tests had left ~1,100
//! folders in Temp, 62 of them holding the YARA-positive OneNote sample, which the laptop folder
//! sweep then reported as harmful files - a test suite writing into the very folder the app sweeps).
//! A test gets a per-run folder ONLY from here; `no_test_makes_its_own_temp_folder` refuses any other.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static N: AtomicUsize = AtomicUsize::new(0);

pub struct TestDir(PathBuf);

impl TestDir {
    fn path_for(tag: &str) -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("vv-test-{}-{n}-{tag}", std::process::id()))
    }
    /// An empty folder that exists now and is deleted with this value.
    pub fn new(tag: &str) -> TestDir {
        let d = Self::path_for(tag);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        TestDir(d)
    }
    /// A path that does NOT exist yet (for code that must create it itself); deleted if it appears.
    pub fn absent(tag: &str) -> TestDir {
        let d = Self::path_for(tag);
        let _ = std::fs::remove_dir_all(&d);
        TestDir(d)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for TestDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One file in its own folder; the folder goes when this value does.
pub struct TestFile {
    _dir: TestDir,
    path: PathBuf,
}

impl TestFile {
    pub fn new(tag: &str, name: &str, bytes: &[u8]) -> TestFile {
        let dir = TestDir::new(tag);
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        TestFile { _dir: dir, path }
    }
}

impl std::ops::Deref for TestFile {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TestFile {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

/// The folders really go: made, used, dropped -> gone (a Drop that silently failed would look
/// exactly like a clean suite).
#[test]
fn a_test_folder_is_gone_when_the_test_ends() {
    let (p, f) = {
        let d = TestDir::new("drop");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub").join("x.bin"), b"x").unwrap();
        let t = TestFile::new("dropfile", "s.bin", b"y");
        assert!(d.join("sub").join("x.bin").exists() && t.exists());
        (d.path().to_path_buf(), t.parent().unwrap().to_path_buf())
    };
    assert!(!p.exists(), "{} left behind", p.display());
    assert!(!f.exists(), "{} left behind", f.display());
}

/// The wire: a test file that builds its own per-run folder in Temp (a name carrying the process id)
/// leaves one more folder behind on every run. Fixed-name folders, reused and overwritten each run,
/// do not pile up and are allowed.
#[test]
fn no_test_makes_its_own_temp_folder() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    for e in std::fs::read_dir(&src).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with("tests") || !name.ends_with(".rs") {
            continue;
        }
        let text = std::fs::read_to_string(e.path()).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.contains("temp_dir()") && line.contains("process::id()") {
                bad.push(format!("{name}:{}", i + 1));
            }
        }
    }
    assert!(bad.is_empty(), "per-run Temp folders outside testdir.rs (use TestDir): {bad:?}");
}
