//! Opt-in tests of the maintained Rust transport against an isolated daemon.
//!
//! Each ignored outer test invokes the executable lifecycle contract, which
//! starts a fresh daemon and re-runs only that test inside the isolated command
//! environment. Pure codec and fake-socket tests do not depend on this file's
//! external prerequisites.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(target_os = "linux")]
use gmellon::control::{DaemonResult, SyncClient};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

const ACTIVE_MARKER: &str = "GMELL_HARNESS_ACTIVE";
const KEEP_SUCCESS_MARKER: &str = "GMELL_HARNESS_KEEP_SUCCESS";
const UNLOCK_TEST: &str = "real_daemon_unlock_uses_the_reviewed_transport";
const CHANGE_TEST: &str = "real_daemon_change_uses_the_reviewed_transport";

#[test]
#[ignore = "requires explicit real-daemon harness run; see doc/harness/README.md"]
fn real_daemon_unlock_uses_the_reviewed_transport() {
    run_isolated(UNLOCK_TEST, || {
        #[cfg(target_os = "linux")]
        {
            let password = random_password();
            let wrong_password = distinct_password(&[&password]);
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                let client = isolated_client();

                require_result(client.unlock(&password), DaemonResult::Ok, "fresh UNLOCK");
                require_login_files();
                require_result(
                    client.unlock(&password),
                    DaemonResult::Ok,
                    "subsequent correct UNLOCK",
                );
                require_result(
                    client.unlock(&wrong_password),
                    DaemonResult::Denied,
                    "wrong UNLOCK",
                );
            }));

            finish_case("unlock", &[&password, &wrong_password], outcome);
        }
    });
}

#[test]
#[ignore = "requires explicit real-daemon harness run; see doc/harness/README.md"]
fn real_daemon_change_uses_the_reviewed_transport() {
    run_isolated(CHANGE_TEST, || {
        #[cfg(target_os = "linux")]
        {
            let original_password = random_password();
            let new_password = distinct_password(&[&original_password]);
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                let client = isolated_client();

                require_result(
                    client.unlock(&original_password),
                    DaemonResult::Ok,
                    "fixture UNLOCK",
                );
                require_login_files();
                require_result(
                    client.change(&original_password, &new_password),
                    DaemonResult::Ok,
                    "CHANGE A-to-B",
                );
                require_result(client.unlock(&new_password), DaemonResult::Ok, "UNLOCK B");
                require_result(
                    client.unlock(&original_password),
                    DaemonResult::Denied,
                    "UNLOCK former A",
                );
            }));

            finish_case("change", &[&original_password, &new_password], outcome);
        }
    });
}

fn run_isolated(test_name: &str, test: impl FnOnce()) {
    if env::var_os(ACTIVE_MARKER).is_some() {
        #[cfg(not(target_os = "linux"))]
        panic!("real-daemon transport tests require Linux Unix-socket peer credentials");

        test();
        return;
    }

    require_outer_prerequisites();
    let lifecycle = repository_root().join("dev/harness/lifecycle.py");
    let current_test = env::current_exe().unwrap_or_else(|error| {
        panic!("real-daemon test could not locate its test executable: {error}")
    });
    let mut command = Command::new(&lifecycle);
    if env::var_os(KEEP_SUCCESS_MARKER).as_deref() == Some(OsStr::new("1")) {
        command.arg("--keep-success");
    }
    let output = command
        .arg("--")
        .arg(current_test)
        .args(["--ignored", "--exact", test_name, "--nocapture"])
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "explicit real-daemon run could not execute {}: {error}; ensure python3 is installed and the lifecycle script is executable",
                lifecycle.display()
            )
        });
    relay(&output);
    assert!(
        output.status.success(),
        "executable real-daemon lifecycle failed with {}; diagnostics are printed above and any allocated failure scratch was retained",
        output.status
    );
}

fn require_outer_prerequisites() {
    #[cfg(not(target_os = "linux"))]
    panic!("real-daemon transport tests require Linux Unix-socket peer credentials");

    let lifecycle = repository_root().join("dev/harness/lifecycle.py");
    let metadata = fs::metadata(&lifecycle).unwrap_or_else(|error| {
        panic!(
            "real-daemon test requires executable {}: {error}",
            lifecycle.display()
        )
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            metadata.permissions().mode() & 0o111 != 0,
            "real-daemon test requires executable {}; restore its executable mode",
            lifecycle.display()
        );
    }

    require_command(
        "python3",
        ["--version"],
        "install Python 3 and make `python3` available on PATH",
    );
    let daemon = [
        Path::new("/usr/bin/gnome-keyring-daemon"),
        Path::new("/bin/gnome-keyring-daemon"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .unwrap_or_else(|| {
        panic!(
            "real-daemon test requires gnome-keyring-daemon in /usr/bin or /bin; install the system GNOME Keyring daemon package"
        )
    });
    require_command(
        daemon.as_os_str(),
        ["--version"],
        "install a runnable system GNOME Keyring daemon package",
    );
    File::open("/dev/urandom").unwrap_or_else(|error| {
        panic!("real-daemon test requires readable /dev/urandom for disposable passwords: {error}")
    });
}

fn require_command<I, S>(program: impl AsRef<OsStr>, arguments: I, remedy: &str)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let display = program.as_ref().to_string_lossy();
    let result = Command::new(program.as_ref()).args(arguments).output();
    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "real-daemon prerequisite `{display}` failed with {}; {remedy}",
            output.status
        ),
        Err(error) => {
            panic!("real-daemon prerequisite `{display}` is unavailable: {error}; {remedy}")
        }
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn relay(output: &Output) {
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}

#[cfg(target_os = "linux")]
fn isolated_client() -> SyncClient {
    let root = harness_root();
    let control_directory = required_path("GMELL_HARNESS_CONTROL_DIR");
    let control_socket = required_path("GMELL_HARNESS_CONTROL_SOCKET");
    assert_beneath(&control_directory, &root);
    assert_beneath(&control_socket, &root);
    assert_eq!(control_socket, control_directory.join("control"));
    assert_eq!(
        env::var_os("GNOME_KEYRING_CONTROL"),
        Some(control_directory.clone().into_os_string())
    );
    assert_eq!(
        env::var_os("DBUS_SESSION_BUS_ADDRESS"),
        Some(format!("unix:path={}/missing-session-bus", root.display()).into())
    );
    assert_eq!(
        env::var_os("DBUS_SYSTEM_BUS_ADDRESS"),
        Some(format!("unix:path={}/missing-system-bus", root.display()).into())
    );
    for name in [
        "HOME",
        "TMPDIR",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "GMELL_HARNESS_DAEMON_STDOUT",
        "GMELL_HARNESS_DAEMON_STDERR",
        "GMELL_HARNESS_EVIDENCE",
        "GMELL_HARNESS_CLEANUP",
    ] {
        assert_beneath(&required_path(name), &root);
    }
    for absent in ["SSH_AUTH_SOCK", "NOTIFY_SOCKET", "DBUS_STARTER_ADDRESS"] {
        assert!(
            env::var_os(absent).is_none(),
            "isolated command inherited {absent}"
        );
    }

    SyncClient::new(control_directory)
}

#[cfg(target_os = "linux")]
fn harness_root() -> PathBuf {
    let root = required_path("GMELL_HARNESS_ROOT");
    let approved = Path::new("/home/rektide/tmp-opencode");
    assert_beneath(&root, approved);
    let metadata = fs::metadata(&root).expect("harness root should exist");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    root
}

#[cfg(target_os = "linux")]
fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("executable lifecycle did not export {name}"))
}

#[cfg(target_os = "linux")]
fn assert_beneath(path: &Path, root: &Path) {
    assert!(
        path.starts_with(root),
        "harness path {} escaped expected root {}",
        path.display(),
        root.display()
    );
}

#[cfg(target_os = "linux")]
fn random_password() -> Zeroizing<Vec<u8>> {
    let mut random = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .expect("preflighted /dev/urandom should remain readable");
    Zeroizing::new(random.into_iter().map(|byte| byte % 94 + 33).collect())
}

#[cfg(target_os = "linux")]
fn distinct_password(others: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    loop {
        let candidate = random_password();
        if others.iter().all(|other| candidate.as_slice() != *other) {
            return candidate;
        }
    }
}

#[cfg(target_os = "linux")]
fn require_result(
    actual: Result<DaemonResult, gmellon::control::ControlError>,
    expected: DaemonResult,
    operation: &str,
) {
    match actual {
        Ok(result) => assert_eq!(
            result, expected,
            "{operation} returned an unexpected result"
        ),
        Err(error) => panic!("{operation} transport failed: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn require_login_files() {
    let root = harness_root();
    let keyring_directory = required_path("XDG_DATA_HOME").join("keyrings");
    for name in ["login.keyring", "user.keystore"] {
        let path = keyring_directory.join(name);
        assert!(path.is_file(), "real daemon did not create {name}");
        assert_beneath(&path, &root);
    }
}

#[cfg(target_os = "linux")]
fn record_and_scan(path_name: &str, secrets: &[&[u8]]) {
    let root = harness_root();
    let observation = root.join("rust-integration.txt");
    fs::write(
        &observation,
        format!(
            "path={path_name}\ntransport=gmellon::control::SyncClient\nsecret_values={}\nartifact_scan=pending\n",
            secrets.len()
        ),
    )
    .expect("write redacted Rust integration evidence");

    scan_directory(&root, secrets);
    fs::write(
        observation,
        format!(
            "path={path_name}\ntransport=gmellon::control::SyncClient\nsecret_values={}\nartifact_scan=passed\n",
            secrets.len()
        ),
    )
    .expect("mark successful artifact scan");
}

#[cfg(target_os = "linux")]
fn finish_case(path_name: &str, secrets: &[&[u8]], outcome: std::thread::Result<()>) {
    record_and_scan(path_name, secrets);
    if let Err(payload) = outcome {
        panic::resume_unwind(payload);
    }
}

#[cfg(target_os = "linux")]
fn scan_directory(directory: &Path, secrets: &[&[u8]]) {
    for entry in fs::read_dir(directory).expect("scan harness artifacts") {
        let entry = entry.expect("read harness artifact entry");
        let file_type = entry.file_type().expect("inspect harness artifact type");
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
    }
}

#[cfg(target_os = "linux")]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
