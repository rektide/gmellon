//! Opt-in binary-level proof of the collection CLI against an isolated
//! private dbus-broker daemon.
//!
//! The ignored outer test invokes the executable broker harness contract,
//! which starts a private bus, manually launches `gnome-keyring-daemon`, and
//! re-runs only this test inside the isolated command environment. The inner
//! proof is maintained Rust: a zbus fixture performs the *only* permitted
//! mutation setup (creating disposable collections through GNOME's private
//! `CreateWithMasterPassword` and returning them to the locked state with the
//! standard `Lock` method), and every observed behavior belongs to the actual
//! compiled `gmellon` binary located through the Cargo-provided
//! `CARGO_BIN_EXE_gmellon` path — never a hosted bus, store, or in-process
//! client call. The Python harness stays lifecycle/check wiring only.
//!
//! Covered binary contract: `gmellon list` determinism and exact login row;
//! default and explicit `unlock --stdin` exit codes and messages; wrong,
//! cross, and correct passwords; the already-unlocked early return proven
//! with stdin that is guaranteed to fail if read; missing-collection exit 1;
//! captured stdout/stderr and retained artifacts scanned for generated
//! passwords; and a match-filtered monitor attributing every standard Lock
//! call to the fixture (ordinary CLI paths never lock or relock).
//!
//! Ordinary `cargo test` and `cargo nextest run` visibly skip this proof. The
//! maintained explicit entry point is `dev/harness/check rust-cli`.

mod broker_common;
mod common;

use std::env;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use broker_common::{
    Fixture, LOGIN_LABEL, LockMonitor, ProofSecrets, expected_collection_id, run_broker_isolated,
    validated_harness_environment,
};
use common::{contains, required_path};
use zeroize::Zeroizing;

const PROOF_TEST: &str = "private_broker_cli_binary_proof";
const MISSING_ID: &str = "gmellon-cli-missing";
static INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[test]
#[ignore = "requires explicit private-broker harness run; see doc/harness/README.md"]
fn private_broker_cli_binary_proof() {
    if env::var_os(common::ACTIVE_MARKER).is_some() {
        #[cfg(not(target_os = "linux"))]
        panic!("private-broker CLI proof requires Linux Unix-socket peer credentials");

        let secrets = ProofSecrets::generate();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_proof(&secrets);
        }));
        finish_case(&secrets.all_slices(), outcome);
        return;
    }

    run_broker_isolated(PROOF_TEST, "private-broker CLI proof");
}

/// One row of `gmellon list` output after strict parsing.
#[derive(Debug, Eq, PartialEq)]
struct ListedCollection {
    id: String,
    locked: bool,
    label: String,
}

/// What the proof pipes into the binary's standard input.
enum CliStdin {
    /// One password line, newline-terminated, as the `--stdin` contract
    /// requires.
    Password(Zeroizing<Vec<u8>>),
    /// Standard input is `/dev/null`: any read returns end of input, which
    /// the `--stdin` reader rejects as unterminated, so a successful
    /// invocation proves no secret was read at all.
    FailIfRead,
}

/// Everything the inner proof asserts, in one command inside `broker.py`.
fn run_proof(secrets: &ProofSecrets) {
    let bus = validated_harness_environment();

    // The compiled product binary, located through Cargo's integration-test
    // variable. The path is absolute, so the fixed PATH of the harness
    // environment cannot substitute another gmellon.
    let binary = Path::new(env!("CARGO_BIN_EXE_gmellon"));
    assert!(
        binary.is_file(),
        "CARGO_BIN_EXE_gmellon does not point at a built binary: {}",
        binary.display()
    );

    // The lock-call monitor must be armed before any fixture traffic so the
    // count is exhaustive; readiness is proven by its banner, not a sleep.
    let monitor = LockMonitor::start(&bus.address, &bus.root);

    // Fixture connection: separate D-Bus unique name from the product binary,
    // so every observed Lock call can be attributed to a sender.
    let mut fixture = Fixture::connect(&bus.address).expect("fixture plain session");
    let fixture_sender = fixture.unique_name();

    let label_second = format!("gmellon-cli-second-{}", secrets.run_tag);

    // Fixture setup: persistent disposable collections with distinct
    // passwords, both returned to the locked state. This is the only code
    // permitted to create or lock. One collection is labeled exactly `login`.
    let login_path = fixture
        .create(LOGIN_LABEL, &secrets.login)
        .expect("fixture CreateWithMasterPassword login");
    let second_path = fixture
        .create(&label_second, &secrets.second)
        .expect("fixture CreateWithMasterPassword second");
    assert_ne!(login_path, second_path);
    fixture.lock(&login_path).expect("fixture Lock login");
    fixture.lock(&second_path).expect("fixture Lock second");

    // --- `gmellon list`: deterministic rows for both fixtures -------------
    let first = list_raw(secrets, "list first");
    let repeat = list_raw(secrets, "list repeat");
    assert_eq!(
        first.stdout, repeat.stdout,
        "gmellon list output was not byte-deterministic across invocations"
    );
    let rows = parse_list(&String::from_utf8_lossy(&first.stdout), "list first");
    let login_row = find_row(&rows, LOGIN_LABEL, "initial listing");
    // The exact-login requirement: the collection labeled `login` must be
    // listed under the exact stable ID `login`, locked.
    assert_eq!(login_row.label, LOGIN_LABEL);
    assert!(
        login_row.locked,
        "login must be listed locked after fixture lock"
    );

    // Discover the second collection's stable ID from the listing itself (by
    // label), then cross-check the observed escaped-label form: the tagged
    // label deterministically maps to the `_2d` escaping seen on daemon 48.0.
    let second_row = rows
        .iter()
        .find(|row| row.label == label_second)
        .unwrap_or_else(|| panic!("gmellon list omitted the labeled second collection"));
    let second_id = second_row.id.clone();
    assert_eq!(
        second_id,
        expected_collection_id(&label_second),
        "the returned second-collection ID is not the escaped-label form"
    );
    assert!(
        second_row.locked,
        "second must be listed locked after fixture lock"
    );

    // The client sorts rows by stable ID; the escaped second ID sorts before
    // `login`, and both must appear in that relative order.
    let login_index = rows.iter().position(|row| row.id == LOGIN_LABEL);
    let second_index = rows.iter().position(|row| row.id == second_id);
    assert!(
        second_index.is_some_and(|second| login_index.is_some_and(|login| second < login)),
        "gmellon list did not present the second collection before login in ID order"
    );

    // --- explicit unlock of the locked second collection ------------------
    // A wrong password is denied with exit 2 and leaves it locked.
    let denied = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.wrong)),
        secrets,
        "unlock second with the wrong password",
    );
    assert_eq!(
        exit_code(&denied),
        Some(2),
        "wrong password must exit 2, not {:?}",
        exit_code(&denied)
    );
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("denied"),
        "denied unlock must explain the denial on stderr"
    );
    assert_listed_locked(secrets, &second_id, true, "second after wrong password");

    // The login password is wrong for the second collection (cross password).
    let cross = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.login)),
        secrets,
        "unlock second with the login (cross) password",
    );
    assert_eq!(exit_code(&cross), Some(2), "cross password must exit 2");
    assert_listed_locked(secrets, &second_id, true, "second after cross password");

    // The correct distinct password unlocks the second collection only.
    let unlocked = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second)),
        secrets,
        "unlock second with its password",
    );
    assert_eq!(exit_code(&unlocked), Some(0));
    assert!(
        String::from_utf8_lossy(&unlocked.stdout)
            .contains(&format!("unlocked collection {second_id}")),
        "successful unlock must report the unlocked collection"
    );
    assert_listed_locked(secrets, &second_id, false, "second after correct password");
    assert_listed_locked(
        secrets,
        LOGIN_LABEL,
        true,
        "login untouched by second unlock",
    );

    // --- default unlock of the locked login collection --------------------
    // No collection argument: selection defaults to login.
    let login_unlock = run_gmellon(
        &["unlock", "--stdin"],
        CliStdin::Password(password_line(&secrets.login)),
        secrets,
        "default unlock login",
    );
    assert_eq!(exit_code(&login_unlock), Some(0));
    assert!(
        String::from_utf8_lossy(&login_unlock.stdout).contains("unlocked collection login"),
        "default unlock must report the unlocked login collection"
    );
    assert_listed_locked(secrets, LOGIN_LABEL, false, "login after default unlock");
    assert_listed_locked(
        secrets,
        &second_id,
        false,
        "second untouched by login unlock",
    );

    // --- already-unlocked: success without reading any secret -------------
    // Both the default selection and the explicit second ID must exit 0 with
    // the not-checked message while stdin is /dev/null: a read would fail the
    // --stdin line contract and exit 1, so exit 0 proves the pre-resolved
    // lock state was trusted and no password was consumed.
    for (arguments, id) in [
        (vec!["unlock", "--stdin"], LOGIN_LABEL),
        (vec!["unlock", &second_id, "--stdin"], second_id.as_str()),
    ] {
        let already = run_gmellon(
            &arguments,
            CliStdin::FailIfRead,
            secrets,
            "already unlocked",
        );
        assert_eq!(
            exit_code(&already),
            Some(0),
            "already-unlocked unlock of {id} must exit 0"
        );
        let stdout = String::from_utf8_lossy(&already.stdout);
        assert!(
            stdout.contains(&format!("collection {id} is already unlocked")),
            "already-unlocked unlock of {id} must say so"
        );
        assert!(
            stdout.contains("password was not checked"),
            "already-unlocked unlock of {id} must state the password was not checked"
        );
    }
    assert_listed_locked(
        secrets,
        LOGIN_LABEL,
        false,
        "login after already-unlocked path",
    );
    assert_listed_locked(
        secrets,
        &second_id,
        false,
        "second after already-unlocked path",
    );

    // --- missing collection: actionable exit 1 before any password use ----
    let missing = run_gmellon(
        &["unlock", MISSING_ID, "--stdin"],
        CliStdin::Password(password_line(&secrets.login)),
        secrets,
        "unlock a missing collection",
    );
    assert_eq!(
        exit_code(&missing),
        Some(1),
        "missing collection must exit 1"
    );
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("collection ID does not exist"),
        "missing collection must be reported actionably on stderr"
    );
    assert!(
        stderr.contains(MISSING_ID),
        "the missing-collection diagnostic must name the requested ID"
    );
    assert!(
        missing.stdout.is_empty(),
        "the missing-collection failure must not write stdout"
    );

    // --- wire evidence: no CLI path locked or relocked anything -----------
    let observed = monitor.finish(&fixture_sender, fixture.lock_calls(), secrets);
    assert!(
        observed.lock_calls >= 1,
        "the monitor observed no Lock traffic although the fixture locked collections"
    );
    assert_eq!(
        observed.lock_calls,
        fixture.lock_calls(),
        "observed Service.Lock calls must equal the fixture's deliberate calls"
    );
    assert!(
        observed.senders_match_fixture,
        "every observed Service.Lock call must come from the fixture connection"
    );
}

/// Run `gmellon list`, require success, and reject control-protocol
/// artifacts in either stream.
fn list_raw(secrets: &ProofSecrets, stage: &str) -> Output {
    let output = run_gmellon(&["list"], CliStdin::FailIfRead, secrets, stage);
    assert_eq!(
        exit_code(&output),
        Some(0),
        "gmellon list must exit 0 (stage {stage})"
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !contains(stream, b"control"),
            "gmellon list must not emit control-protocol artifacts (stage {stage})"
        );
    }
    output
}

/// Run `gmellon list` and strictly parse the documented rendering: one header
/// line, then one ID<TAB>LOCKED<TAB>LABEL row per collection.
fn list(secrets: &ProofSecrets, stage: &str) -> Vec<ListedCollection> {
    let output = list_raw(secrets, stage);
    parse_list(&String::from_utf8_lossy(&output.stdout), stage)
}

/// Parse the documented rendering: one header line, then one
/// ID<TAB>LOCKED<TAB>LABEL row per collection.
fn parse_list(stdout: &str, stage: &str) -> Vec<ListedCollection> {
    let mut lines = stdout.lines();
    let header = lines
        .next()
        .unwrap_or_else(|| panic!("gmellon list printed nothing (stage {stage})"));
    assert_eq!(
        header, "ID\tLOCKED\tLABEL",
        "unexpected gmellon list header (stage {stage})"
    );
    lines
        .enumerate()
        .map(|(index, line)| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                3,
                "gmellon list row {index} is not three tab-separated fields (stage {stage}): {line:?}"
            );
            let locked = match fields[1] {
                "yes" => true,
                "no" => false,
                other => panic!("unexpected locked state {other:?} (stage {stage})"),
            };
            ListedCollection {
                id: fields[0].to_owned(),
                locked,
                label: fields[2].to_owned(),
            }
        })
        .collect()
}

fn find_row<'a>(rows: &'a [ListedCollection], id: &str, stage: &str) -> &'a ListedCollection {
    rows.iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("gmellon list did not include collection {id} (stage {stage})"))
}

/// Assert one collection's lock state through the binary's own listing.
fn assert_listed_locked(secrets: &ProofSecrets, id: &str, locked: bool, stage: &str) {
    let rows = list(secrets, stage);
    let row = find_row(&rows, id, stage);
    assert_eq!(row.locked, locked, "unexpected lock state at stage {stage}");
}

/// One newline-terminated secret line, zeroized when dropped.
fn password_line(secret: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut line = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
    line.extend_from_slice(secret);
    line.push(b'\n');
    line
}

/// Spawn the compiled gmellon binary with the harness-inherited environment,
/// feed the chosen stdin, capture both streams, and scan the captured bytes
/// for every generated password before the caller inspects the result.
fn run_gmellon(arguments: &[&str], stdin: CliStdin, secrets: &ProofSecrets, stage: &str) -> Output {
    INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let mut command = Command::new(env!("CARGO_BIN_EXE_gmellon"));
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(match stdin {
            CliStdin::Password(_) => Stdio::piped(),
            CliStdin::FailIfRead => Stdio::null(),
        });
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn the gmellon binary for `{stage}`: {error}"));
    if let CliStdin::Password(line) = stdin
        && let Some(mut handle) = child.stdin.take()
    {
        // A broken pipe is expected when the binary exits before reading
        // (for example the missing-collection rejection); the exit-code
        // and message assertions surface any unexpected early exit.
        let _ = handle.write_all(&line);
    }
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("wait for the gmellon binary for `{stage}`: {error}"));

    for (name, secret) in secrets.named() {
        assert!(
            !contains(&output.stdout, secret),
            "gmellon `{stage}` stdout leaked the generated {name} password"
        );
        assert!(
            !contains(&output.stderr, secret),
            "gmellon `{stage}` stderr leaked the generated {name} password"
        );
    }
    output
}

fn exit_code(output: &Output) -> Option<i32> {
    output.status.code()
}

fn finish_case(secrets: &[&[u8]], outcome: std::thread::Result<()>) {
    let root = required_path("GMELL_HARNESS_ROOT");
    let header = format!(
        "path=private_broker_cli\nbinary={}\ninvocations={}\nsecret_values={}",
        env!("CARGO_BIN_EXE_gmellon"),
        INVOCATIONS.load(Ordering::Relaxed),
        secrets.len()
    );
    common::finish_case(&root, "rust-cli-proof.txt", &header, secrets, outcome);
}
