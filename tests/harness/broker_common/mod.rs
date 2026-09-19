//! Shared machinery for the private-broker Rust proofs.
//!
//! Both the collection-client proof
//! ([`tests/harness/broker_collections.rs`](../broker_collections.rs)) and the
//! CLI binary proof ([`tests/harness/broker_cli.rs`](../broker_cli.rs))
//! run inside [`broker.py`](../../../dev/harness/broker.py) against one
//! isolated private bus and daemon. They share this module for the validated
//! environment contract, the fixture connection that performs the only
//! permitted mutation setup (private `CreateWithMasterPassword` plus counted
//! standard `Lock` calls), the match-filtered method-call monitors (standard
//! `Service.Lock` for fixture-attributed locking, plus the password-bearing
//! private `ChangeWithMasterPassword` rule whose stdout is consumed by a
//! streaming reader that retains only header-derived facts and never writes
//! a raw log to disk), disposable proof secrets, and the outer isolated
//! runner. Include `mod common;` and
//! `mod broker_common;` together: this module builds on [`common`].
//!
//! Layout: [`fixture`] (harness environment contract and the fixture service
//! proxies), [`monitor`] (method-call monitors plus the busctl spawn/stop
//! plumbing), [`scanner`] (the streaming header/body parsers and their owned
//! reader threads), [`body`] (the body-verdict monitor), and [`secrets`]
//! (disposable proof secrets); this file keeps the outer prerequisites and
//! the isolated runner.
//!
//! The streaming header parser [`HeaderCallParser`] is pinned against the
//! installed busctl monitor shape by the ordinary positive-control tests in
//! [`tests/harness/redaction_scan.rs`](../redaction_scan.rs).
//!
//! This module is compiled only as a module of the declared `[[test]]`
//! targets; Cargo does not discover it as a separate test.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::Path;
use std::process::Command;

mod body;
mod fixture;
mod monitor;
mod scanner;
mod secrets;

// Re-export exactly the surface the proof targets import, under the same
// flat `broker_common::` paths as before the directory split. Every target
// compiles this module separately and consumes a different subset, so the
// shared surface needs the allow: one target's unused re-export is another
// target's required import.
#[allow(unused_imports)]
mod reexports {
    pub use super::body::BodyMonitor;
    pub use super::fixture::{
        BusEnvironment, Fixture, LOGIN_LABEL, expected_collection_id, validated_harness_environment,
    };
    pub use super::monitor::MethodMonitor;
    pub use super::scanner::{BodyMode, BodyScanner, DH_ALGORITHM_LINE, HeaderCallParser};
    pub use super::secrets::ProofSecrets;
}
pub use reexports::*;

use super::common;
use monitor::{BUSCTL, STDBUF};

/// Outer-mode prerequisite preflight shared by every private-broker Rust
/// proof. Mirrors `broker.py`'s host-dependency probe plus the monitor tools.
pub fn require_outer_prerequisites() {
    #[cfg(not(target_os = "linux"))]
    panic!("private-broker proofs require Linux Unix-socket peer credentials");

    let broker = common::repository_root().join("dev/harness/broker.py");
    let metadata = fs::metadata(&broker).unwrap_or_else(|error| {
        panic!(
            "private-broker proof requires executable {}: {error}",
            broker.display()
        )
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            metadata.permissions().mode() & 0o111 != 0,
            "private-broker proof requires executable {}; restore its executable mode",
            broker.display()
        );
    }

    common::require_command("python3", ["--version"], "install Python 3");
    let daemon = ["/usr/bin/gnome-keyring-daemon", "/bin/gnome-keyring-daemon"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or_else(|| {
            panic!("private-broker proof requires gnome-keyring-daemon in /usr/bin or /bin")
        });
    common::require_command(
        daemon,
        ["--version"],
        "install a runnable system GNOME Keyring daemon package",
    );
    for tool in ["systemd-socket-activate", "dbus-broker-launch", "gdbus"] {
        require_fixed_tool(tool, "install the private-broker host dependencies");
    }
    common::require_command(
        BUSCTL,
        ["--version"],
        "install systemd's busctl for the lock-call monitor",
    );
    assert!(
        Path::new(STDBUF).is_file(),
        "private-broker proof requires {STDBUF} for line-buffered monitor output"
    );

    for socket in ["/run/systemd/journal/socket", "/run/dbus/system_bus_socket"] {
        let path = Path::new(socket);
        let metadata = fs::metadata(path)
            .unwrap_or_else(|error| panic!("private-broker proof requires {socket}: {error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            assert!(
                metadata.file_type().is_socket(),
                "private-broker host dependency is not a socket: {socket}"
            );
        }
    }
    assert!(
        Path::new("/run/systemd/system").is_dir(),
        "private-broker proof requires a running host systemd runtime"
    );
    File::open("/dev/urandom").unwrap_or_else(|error| {
        panic!("private-broker proof requires readable /dev/urandom: {error}")
    });
}

pub fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("the harness did not export {name}"))
}

/// Mirror broker.py's host-dependency probe: presence and executability in
/// the fixed /usr/bin:/bin set, without executing the tool (gdbus and the
/// launcher have no safe --version probe).
fn require_fixed_tool(name: &str, remedy: &str) {
    let found = ["/usr/bin", "/bin"].into_iter().any(|directory| {
        let path = Path::new(directory).join(name);
        fs::metadata(path)
            .map(|metadata| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    metadata.is_file()
                }
            })
            .unwrap_or(false)
    });
    assert!(
        found,
        "private-broker proof requires {name} in /usr/bin or /bin; {remedy}"
    );
}

/// Outer-mode runner: re-run exactly `test_name` inside `broker.py`, honoring
/// the caller's `--keep-success` opt-in, and require a clean harness exit.
pub fn run_broker_isolated(test_name: &str, context: &str) {
    require_outer_prerequisites();
    let broker = common::repository_root().join("dev/harness/broker.py");
    let current_test = env::current_exe()
        .unwrap_or_else(|error| panic!("{context} could not locate its test executable: {error}"));
    let mut command = Command::new(&broker);
    if env::var_os(common::KEEP_SUCCESS_MARKER).as_deref() == Some(OsStr::new("1")) {
        command.arg("--keep-success");
    }
    let output = command
        .arg("--")
        .arg(current_test)
        .args(["--ignored", "--exact", test_name, "--nocapture"])
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "explicit {context} run could not execute {}: {error}; ensure python3 is installed and the broker script is executable",
                broker.display()
            )
        });
    common::relay(&output);
    assert!(
        output.status.success(),
        "executable {context} failed with {}; diagnostics are printed above and any allocated failure scratch was retained",
        output.status
    );
}
