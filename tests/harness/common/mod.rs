//! Helpers shared by the ignored Rust harness test binaries.
//!
//! [`tests/harness/real_daemon.rs`](../../tests/harness/real_daemon.rs) and
//! the private-broker proofs include this module for the common environment
//! contract, disposable-secret generation, and the fail-closed retained
//! artifact scan. Files here are compiled only as modules of the declared
//! `[[test]]` targets; Cargo does not discover them as separate tests.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use zeroize::Zeroizing;

/// Nesting marker exported by every harness profile.
pub const ACTIVE_MARKER: &str = "GMELL_HARNESS_ACTIVE";
/// Caller opt-in that retains a successful run's scratch tree.
pub const KEEP_SUCCESS_MARKER: &str = "GMELL_HARNESS_KEEP_SUCCESS";
/// The only approved scratch location for harness roots.
pub const APPROVED_TEMP_ROOT: &str = "/home/rektide/tmp-opencode";

pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn relay(output: &Output) {
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}

pub fn require_command<I, S>(program: impl AsRef<OsStr>, arguments: I, remedy: &str)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let display = program.as_ref().to_string_lossy();
    let result = Command::new(program.as_ref()).args(arguments).output();
    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "harness prerequisite `{display}` failed with {}; {remedy}",
            output.status
        ),
        Err(error) => {
            panic!("harness prerequisite `{display}` is unavailable: {error}; {remedy}")
        }
    }
}

pub fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("the active harness did not export {name}"))
}

pub fn assert_beneath(path: &Path, root: &Path) {
    assert!(
        path.starts_with(root),
        "harness path {} escaped expected root {}",
        path.display(),
        root.display()
    );
}

pub fn read_urandom(buffer: &mut [u8]) {
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(buffer))
        .expect("preflighted /dev/urandom should remain readable");
}

pub fn random_password() -> Zeroizing<Vec<u8>> {
    let mut random = [0_u8; 32];
    read_urandom(&mut random);
    Zeroizing::new(random.into_iter().map(|byte| byte % 94 + 33).collect())
}

pub fn distinct_password(others: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    loop {
        let candidate = random_password();
        if others.iter().all(|other| candidate.as_slice() != *other) {
            return candidate;
        }
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Record the redacted observation, then scan the retained harness artifacts
/// for every generated secret before reporting success (or re-raising an
/// earlier assertion failure). The scan covers exactly what exists beneath the
/// harness root at scan time: every regular file is read and checked, and any
/// symlink fails the proof instead of being skipped, so no unscanned path can
/// point outside the scratch root. `cleanup.json` is outside this scope by
/// construction: the supervisor writes it after the command exits, and it
/// records metadata only (command status, handled signal, per-child teardown),
/// never command data.
pub fn finish_case(
    root: &Path,
    observation_file: &str,
    header: &str,
    secrets: &[&[u8]],
    outcome: std::thread::Result<()>,
) {
    let observation = root.join(observation_file);
    let record = |scan: &str| {
        fs::write(&observation, format!("{header}\nartifact_scan={scan}\n"))
            .expect("write redacted Rust proof evidence")
    };

    record("pending");
    scan_directory(root, secrets);
    record("passed");

    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

pub fn scan_directory(directory: &Path, secrets: &[&[u8]]) {
    for entry in fs::read_dir(directory).expect("scan harness artifacts") {
        let entry = entry.expect("read harness artifact entry");
        let file_type = entry.file_type().expect("inspect harness artifact type");
        // Fail closed: a symlink skipped by a regular-file scan would be an
        // unscanned gap that could point outside the scratch root, so its
        // presence is proof failure. The scan never follows links.
        assert!(
            !file_type.is_symlink(),
            "symlink {} inside the retained harness root; the artifact scan refuses to skip it",
            entry.path().display()
        );
        if file_type.is_dir() {
            scan_directory(&entry.path(), secrets);
        } else if file_type.is_file() {
            let contents =
                fs::read(entry.path()).expect("read harness artifact for redaction scan");
            assert!(secrets.iter().all(|secret| !secret.is_empty()));
            assert!(
                secrets.iter().all(|secret| !contains(&contents, secret)),
                "generated password appeared in retained harness artifact {}",
                entry.path().display()
            );
        }
        // Live Unix sockets (the private bus and control sockets) are the only
        // other entries the retained root holds while the command runs; they
        // carry no readable retained bytes and are deliberately outside the
        // scan scope.
    }
}
