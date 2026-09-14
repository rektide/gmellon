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
//! and the `change --stdin` contract — mismatched confirmation and
//! unterminated input exit 1 while a private-method monitor proves the daemon
//! was never asked to change anything, wrong current password exits 2 with
//! the old password still valid, explicit second-collection A→B and default
//! login L→L2 changes exit 0 and rotate exactly the selected collection
//! (former password denied, new password accepted after fixture-only locks),
//! and a missing collection is rejected before stdin is read. Captured
//! stdout/stderr and retained artifacts are scanned for every generated
//! password, a match-filtered monitor attributes every standard Lock call to
//! the fixture (ordinary CLI paths never lock or relock), and the
//! password-bearing change monitor counts method-call headers streamed from
//! a pipe — its raw output never exists on disk.
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
    BodyMonitor, Fixture, LOGIN_LABEL, MethodMonitor, ProofSecrets, expected_collection_id,
    run_broker_isolated, validated_harness_environment,
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
    /// Several newline-terminated lines (the `change --stdin` contract):
    /// current, new, and confirmation in order. Unterminated-line variants
    /// are built by hand from the same zeroizing buffer.
    Lines(Zeroizing<Vec<u8>>),
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
    let monitor = MethodMonitor::lock(&bus.address, &bus.root);

    // The private change-call monitor is armed just as early so its count is
    // exhaustive over the whole run. Its match rule selects
    // password-bearing bodies, so its stdout is streamed from a pipe and
    // only header-derived facts are retained — raw output never reaches
    // disk in any form.
    let change_monitor = MethodMonitor::change_calls(&bus.address, &bus.root);

    // The encrypted-session wire evidence: every password-method body is
    // captured and scanned for the generated passwords, and every OpenSession
    // negotiation is checked for the encrypted algorithm. Streamed through
    // pipes; decoded bodies never touch disk.
    let password_monitor = BodyMonitor::password_methods(&bus.address, &bus.root, secrets);
    let negotiation_monitor = BodyMonitor::open_sessions(&bus.address, &bus.root, secrets);
    // The item-creation monitor: CreateItem is the only standard-API path a
    // passphrase can travel, so its bodies get the same encrypted-shape and
    // leak-scan treatment as the private password methods.
    let create_item_monitor = BodyMonitor::create_items(&bus.address, &bus.root, secrets);

    // Fixture connection: separate D-Bus unique name from the product binary,
    // so every observed Lock call can be attributed to a sender. The fixture
    // negotiates the same encrypted session the product binary does.
    let mut fixture = Fixture::connect(&bus.address).expect("fixture encrypted session");
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
    // Establish the default alias exactly as a real desktop session has it:
    // gcr-ssh-agent's libsecret lookup resolves through it. The private
    // creation path does not set aliases by itself.
    fixture
        .set_alias("default", &login_path)
        .expect("fixture SetAlias default -> login");
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

    // --- `gmellon status`: prompt-free capability and lock report ---------
    // Both collections are locked here, so the summary is fully determined.
    // stdin is /dev/null (FailIfRead): a successful status proves no secret
    // was read. The exact password-method counts asserted at the wire
    // evidence stage are unchanged by these invocations, proving status made
    // zero password-method calls.
    let status = run_gmellon(
        &["status"],
        CliStdin::FailIfRead,
        secrets,
        "status with both collections locked",
    );
    assert_eq!(
        exit_code(&status),
        Some(0),
        "status must exit 0 on a healthy service"
    );
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_text.contains("secret service: org.freedesktop.secrets (reachable)"),
        "status must report the reachable service: {status_text}"
    );
    assert!(
        status_text.contains("encrypted session: negotiated (dh-ietf1024-sha256-aes128-cbc-pkcs7)"),
        "status must report the negotiated encrypted session: {status_text}"
    );
    assert!(
        status_text.contains("private password interface: available"),
        "status must report the private password interface: {status_text}"
    );
    // The summary must agree with `list` exactly: the daemon also exposes
    // its ephemeral `session` collection here, so the counts are derived
    // from the parsed rows rather than hardcoded.
    let total = rows.len();
    let locked_count = rows.iter().filter(|row| row.locked).count();
    assert!(
        status_text.contains(&format!(
            "collections: {total} total, {locked_count} locked"
        )),
        "status lock summary must agree with list ({total} rows, {locked_count} locked): {status_text}"
    );
    for row in &rows {
        let state = if row.locked { "locked" } else { "unlocked" };
        let Some(line) = status_text
            .lines()
            .find(|line| line.starts_with("  ") && line.trim_start().starts_with(row.id.as_str()))
        else {
            panic!(
                "status must carry a per-collection line for {}: {status_text}",
                row.id
            )
        };
        assert!(
            line.ends_with(state),
            "status lock line for {} must end with its state: {line}",
            row.id
        );
    }
    assert!(
        status.stderr.is_empty(),
        "plain status must stay quiet on stderr"
    );

    // `-v` variants: stdout must be byte-identical to the plain run (the
    // subscriber writes to stderr only) while stderr positively carries the
    // operation events — a silent `-v` fails. The finish-stage stream scan
    // proves those events never contain secret bytes in any form.
    let status_verbose = run_gmellon(
        &["-v", "status"],
        CliStdin::FailIfRead,
        secrets,
        "status verbose with both collections locked",
    );
    assert_eq!(exit_code(&status_verbose), Some(0), "-v status must exit 0");
    assert_eq!(
        status_verbose.stdout, status.stdout,
        "-v must not alter status stdout"
    );
    let status_verbose_stderr = String::from_utf8_lossy(&status_verbose.stderr);
    assert!(
        status_verbose_stderr.contains("private password interface probed"),
        "-v status must emit the capability probe event: {status_verbose_stderr}"
    );

    let list_verbose = run_gmellon(
        &["-v", "list"],
        CliStdin::FailIfRead,
        secrets,
        "list verbose while both collections are locked",
    );
    assert_eq!(exit_code(&list_verbose), Some(0));
    assert_eq!(
        list_verbose.stdout, first.stdout,
        "-v must not alter list stdout"
    );

    // --- explicit unlock of the locked second collection ------------------
    // A wrong password is denied with exit 2 and leaves it locked. This run
    // carries `-v`: its stderr must positively classify the denial while the
    // stream scan proves the diagnostic events carry no secret bytes.
    let denied = run_gmellon(
        &["-v", "unlock", &second_id, "--stdin"],
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
    let denied_stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_stderr.contains("unlock outcome") && denied_stderr.contains("Denied"),
        "-v must positively classify the denial as an outcome event: {denied_stderr}"
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

    // --- `gmellon lock`: explicit, prompt-free state change ----------------
    // Entering this section both collections are unlocked (second still on
    // its original password; rotations come later). The lock invocations
    // never touch a password method, and the exact password-method counts
    // at the wire-evidence stage prove that. Two CLI Lock calls are made in
    // total (the flip and the rotation relock); the idempotent re-lock and
    // the missing-ID rejection must add none.
    let lock_missing = run_gmellon(
        &["lock", MISSING_ID],
        CliStdin::FailIfRead,
        secrets,
        "lock a missing collection",
    );
    assert_eq!(
        exit_code(&lock_missing),
        Some(1),
        "lock of a missing collection must exit 1"
    );
    let lock_missing_stderr = String::from_utf8_lossy(&lock_missing.stderr);
    assert!(
        lock_missing_stderr.contains("collection ID does not exist"),
        "lock of a missing collection must be reported actionably on stderr"
    );
    assert!(
        lock_missing_stderr.contains(MISSING_ID),
        "the missing-collection lock diagnostic must name the requested ID"
    );

    // The flip: locking the unlocked second collection changes its state.
    let locked_second = run_gmellon(
        &["lock", &second_id],
        CliStdin::FailIfRead,
        secrets,
        "lock the unlocked second collection",
    );
    assert_eq!(
        exit_code(&locked_second),
        Some(0),
        "locking an unlocked collection must exit 0"
    );
    assert!(
        String::from_utf8_lossy(&locked_second.stdout)
            .contains(&format!("locked collection {second_id}")),
        "a successful lock must name the collection"
    );
    assert_listed_locked(secrets, &second_id, true, "second after CLI lock");
    // The sibling is untouched: login stays unlocked.
    assert_listed_locked(secrets, LOGIN_LABEL, false, "login after second's CLI lock");

    // Idempotent: an already-locked collection is a no-op success that must
    // make no Lock call (the exact lock-count assertion below enforces it).
    let locked_again = run_gmellon(
        &["lock", &second_id],
        CliStdin::FailIfRead,
        secrets,
        "lock the already-locked second collection",
    );
    assert_eq!(
        exit_code(&locked_again),
        Some(0),
        "locking an already-locked collection must exit 0"
    );
    assert!(
        String::from_utf8_lossy(&locked_again.stdout).contains("already locked"),
        "the already-locked lock must say so"
    );
    assert_listed_locked(secrets, &second_id, true, "second after idempotent lock");

    // Rotation: unlock → lock → unlock, ending unlocked as the change
    // section expects. The wrong password never appears; the original
    // second password is still current (rotations come later).
    let rotated_unlock = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second)),
        secrets,
        "unlock second inside the lock rotation",
    );
    assert_eq!(
        exit_code(&rotated_unlock),
        Some(0),
        "the rotation unlock must succeed with the original password"
    );
    let rotated_lock = run_gmellon(
        &["lock", &second_id],
        CliStdin::FailIfRead,
        secrets,
        "relock second inside the lock rotation",
    );
    assert_eq!(exit_code(&rotated_lock), Some(0));
    let rotated_second_unlock = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second)),
        secrets,
        "unlock second to close the lock rotation",
    );
    assert_eq!(exit_code(&rotated_second_unlock), Some(0));
    assert_listed_locked(secrets, &second_id, false, "second after the lock rotation");

    // --- `gmellon ssh-add` / `items` / `ssh-list` / `ssh-remove` ---------
    // Entering this section both collections are unlocked; the harness's
    // default alias points at the exact-login fixture, which is where
    // gcr-ssh-agent's libsecret lookup goes. The proof's key passphrase is
    // a generated secret like the collection passwords: it must appear in
    // no stream, artifact, or bus body in the clear (the CreateItem body
    // monitor below enforces the wire side).
    let key_path = bus.root.join("proof-ssh-key");
    let key_generated = common::generate_encrypted_ssh_key(&key_path, secrets.key_pass.as_slice());
    assert!(
        key_generated.success(),
        "the proof's encrypted ssh key must generate"
    );
    let key_canonical = std::fs::canonicalize(&key_path).expect("canonical proof key path");
    let key_unique = format!("ssh-store:{}", key_canonical.display());

    let plain_key_path = bus.root.join("proof-plain-key");
    let plain_generated = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&plain_key_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("generate the unencrypted proof key");
    assert!(
        plain_generated.success(),
        "the plain proof key must generate"
    );

    let ssh_list = |stage: &str| -> std::process::Output {
        run_gmellon(&["ssh-list"], CliStdin::FailIfRead, secrets, stage)
    };
    let ssh_list_key_rows = |output: &std::process::Output| -> usize {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .filter(|line| line.starts_with(&format!("{}\t", key_canonical.display())))
            .count()
    };

    // Before storing: no rows anywhere, and the fresh login collection
    // holds no items at all.
    let before = ssh_list("ssh-list before any store");
    assert_eq!(exit_code(&before), Some(0));
    assert_eq!(ssh_list_key_rows(&before), 0, "nothing is stored yet");
    let items_before = run_gmellon(
        &["items", "login"],
        CliStdin::FailIfRead,
        secrets,
        "items login before any store",
    );
    assert_eq!(exit_code(&items_before), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&items_before.stdout)
            .lines()
            .count(),
        1,
        "a fresh login collection lists only the header"
    );

    // A wrong passphrase is refused with exit 2 and stores nothing.
    let wrong_add = run_gmellon(
        &["ssh-add", key_canonical.to_str().unwrap(), "--stdin"],
        CliStdin::Password(password_line(&secrets.wrong)),
        secrets,
        "ssh-add with the wrong passphrase",
    );
    assert_eq!(
        exit_code(&wrong_add),
        Some(2),
        "a wrong key passphrase must exit 2"
    );
    assert!(
        String::from_utf8_lossy(&wrong_add.stderr).contains("WRONG"),
        "the wrong-passphrase refusal must say so"
    );
    assert!(
        wrong_add.stdout.is_empty(),
        "a refused ssh-add must not write stdout"
    );
    let after_wrong = ssh_list("ssh-list after the refused store");
    assert_eq!(ssh_list_key_rows(&after_wrong), 0, "nothing was stored");

    // An unencrypted key has nothing to store: exit 1.
    let plain_add = run_gmellon(
        &["ssh-add", plain_key_path.to_str().unwrap(), "--stdin"],
        CliStdin::Password(password_line(&secrets.key_pass)),
        secrets,
        "ssh-add against an unencrypted key",
    );
    assert_eq!(
        exit_code(&plain_add),
        Some(1),
        "an unencrypted key must be refused with exit 1"
    );
    assert!(
        String::from_utf8_lossy(&plain_add.stderr).contains("not passphrase-protected"),
        "the unencrypted refusal must say what it found"
    );

    // The verified store: exit 0, stored exactly where gcr looks.
    let stored = run_gmellon(
        &["ssh-add", key_canonical.to_str().unwrap(), "--stdin"],
        CliStdin::Password(password_line(&secrets.key_pass)),
        secrets,
        "ssh-add with the verified passphrase",
    );
    assert_eq!(
        exit_code(&stored),
        Some(0),
        "a verified passphrase must store successfully"
    );
    let stored_stdout = String::from_utf8_lossy(&stored.stdout);
    assert!(
        stored_stdout.contains("stored in collection login & verified against the key"),
        "the successful store must say where and that it verified: {stored_stdout}"
    );

    let listed = ssh_list("ssh-list after the verified store");
    assert_eq!(exit_code(&listed), Some(0));
    assert_eq!(
        ssh_list_key_rows(&listed),
        1,
        "exactly one stored passphrase row must exist"
    );
    assert!(
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|line| line == format!("{}\tlogin\tno", key_canonical.display())),
        "the stored row must name the key, the login collection, and the unlocked state"
    );

    let items_after = run_gmellon(
        &["items", "login"],
        CliStdin::FailIfRead,
        secrets,
        "items login after the verified store",
    );
    assert_eq!(exit_code(&items_after), Some(0));
    let items_text = String::from_utf8_lossy(&items_after.stdout);
    let expected_attributes =
        format!("unique={key_unique},xdg:schema=org.freedesktop.Secret.Generic");
    assert!(
        items_text.lines().any(
            |line| line.starts_with("Unlock password for: proof-ssh-key\tno\t")
                && line.ends_with(&expected_attributes)
        ),
        "the item row must carry the gcr label and attributes: {items_text}"
    );

    // Storing again replaces rather than duplicates.
    let stored_again = run_gmellon(
        &["ssh-add", key_canonical.to_str().unwrap(), "--stdin"],
        CliStdin::Password(password_line(&secrets.key_pass)),
        secrets,
        "ssh-add replacing the stored passphrase",
    );
    assert_eq!(exit_code(&stored_again), Some(0));
    let after_replace = ssh_list("ssh-list after the replacing store");
    assert_eq!(
        ssh_list_key_rows(&after_replace),
        1,
        "replace=true must rotate the item, not duplicate it"
    );

    // The stored secret is exactly the passphrase the proof fed in, read
    // back the way gcr-ssh-agent reads it: GetSecret under an encrypted
    // session, decrypted with the reading side's session key.
    let readback = fixture
        .read_item_secret_by_unique(&login_path, &key_unique)
        .expect("fixture reads the stored item back");
    assert_eq!(
        readback.as_slice(),
        secrets.key_pass.as_slice(),
        "the stored item secret must equal the verified passphrase"
    );

    // Removal: exactly the matching item, and a second removal finds
    // nothing.
    let removed = run_gmellon(
        &["ssh-remove", key_canonical.to_str().unwrap()],
        CliStdin::FailIfRead,
        secrets,
        "ssh-remove the stored passphrase",
    );
    assert_eq!(
        exit_code(&removed),
        Some(0),
        "removing the stored passphrase must exit 0"
    );
    assert!(
        String::from_utf8_lossy(&removed.stdout).contains(&format!(
            "removed stored passphrase for {}",
            key_canonical.display()
        )),
        "the removal must name the key"
    );
    let after_remove = ssh_list("ssh-list after removal");
    assert_eq!(
        ssh_list_key_rows(&after_remove),
        0,
        "the stored passphrase must be gone"
    );
    let removed_again = run_gmellon(
        &["ssh-remove", key_canonical.to_str().unwrap()],
        CliStdin::FailIfRead,
        secrets,
        "ssh-remove with nothing stored",
    );
    assert_eq!(
        exit_code(&removed_again),
        Some(1),
        "removing a missing stored passphrase must exit 1"
    );
    assert!(
        String::from_utf8_lossy(&removed_again.stderr).contains("no stored passphrase"),
        "the missing-store removal must say so"
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

    // --- `gmellon change`: three-line stdin contract on the second fixture --
    // State entering this section: both collections unlocked. Every
    // fixture-only Lock below is counted and attributed by the monitor; the
    // CLI itself must never lock or relock.

    // Mismatched confirmation is rejected client-side: exit 1, and — proven
    // at the change monitor below — no private ChangeWithMasterPassword call
    // ever reaches the daemon. Fixture-lock first so "password unchanged" is
    // observable as a successful unlock with the original password.
    fixture
        .lock(&second_path)
        .expect("fixture Lock second before mismatch");
    assert_listed_locked(secrets, &second_id, true, "second before mismatch");
    let mismatch = run_gmellon(
        &["change", &second_id, "--stdin"],
        CliStdin::Lines(change_stdin([
            secrets.second.as_slice(),
            secrets.second_two.as_slice(),
            secrets.wrong.as_slice(),
        ])),
        secrets,
        "change second with mismatched confirmation",
    );
    assert_eq!(
        exit_code(&mismatch),
        Some(1),
        "mismatched confirmation must exit 1"
    );
    let mismatch_stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        mismatch_stderr.contains("do not match"),
        "the mismatch diagnostic must explain the confirmation mismatch"
    );
    assert!(
        mismatch.stdout.is_empty(),
        "the mismatch rejection must not write stdout"
    );
    assert_listed_locked(secrets, &second_id, true, "second after mismatch");
    // The old password still unlocks, so the mismatch changed nothing.
    let old_still_valid = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second)),
        secrets,
        "unlock second with the original password after mismatch",
    );
    assert_eq!(
        exit_code(&old_still_valid),
        Some(0),
        "the original password must remain valid after a rejected mismatch"
    );

    // Wrong current password with matching new+confirmation: the daemon is
    // asked (one private call) and denies; exit 2 with the old password
    // still valid. This run carries `-v` so a change with two live secrets
    // transits the diagnostics path under the stream scan.
    fixture
        .lock(&second_path)
        .expect("fixture Lock second before denied change");
    let denied_change = run_gmellon(
        &["-v", "change", &second_id, "--stdin"],
        CliStdin::Lines(change_stdin([
            secrets.wrong.as_slice(),
            secrets.second_two.as_slice(),
            secrets.second_two.as_slice(),
        ])),
        secrets,
        "change second with the wrong current password",
    );
    assert_eq!(
        exit_code(&denied_change),
        Some(2),
        "wrong current password must exit 2"
    );
    let denied_change_stderr = String::from_utf8_lossy(&denied_change.stderr);
    assert!(
        denied_change_stderr.contains("denied"),
        "the denied change must explain the denial on stderr"
    );
    assert!(
        denied_change_stderr.contains("change outcome") && denied_change_stderr.contains("Denied"),
        "-v must positively classify the denied change as an outcome event: {denied_change_stderr}"
    );
    assert_listed_locked(secrets, &second_id, true, "second after denied change");
    let old_after_denial = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second)),
        secrets,
        "unlock second with the original password after denied change",
    );
    assert_eq!(
        exit_code(&old_after_denial),
        Some(0),
        "the original password must remain valid after a denied change"
    );

    // Successful explicit second-collection change A to B.
    fixture
        .lock(&second_path)
        .expect("fixture Lock second before successful change");
    let changed = run_gmellon(
        &["change", &second_id, "--stdin"],
        CliStdin::Lines(change_stdin([
            secrets.second.as_slice(),
            secrets.second_two.as_slice(),
            secrets.second_two.as_slice(),
        ])),
        secrets,
        "change second A to B",
    );
    assert_eq!(exit_code(&changed), Some(0), "a correct change must exit 0");
    assert!(
        String::from_utf8_lossy(&changed.stdout)
            .contains(&format!("changed password for collection {second_id}")),
        "successful change must report the changed collection"
    );
    // Observed daemon 48.0 behavior: a change on a locked collection
    // succeeds without unlocking it.
    assert_listed_locked(secrets, &second_id, true, "second after change");

    // After the rotation the former password is denied and the new one
    // unlocks; no fixture lock is needed because the change kept it locked.
    let former_denied = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second)),
        secrets,
        "unlock second with the former password after change",
    );
    assert_eq!(
        exit_code(&former_denied),
        Some(2),
        "the former password must be denied after the change"
    );
    assert_listed_locked(
        secrets,
        &second_id,
        true,
        "second still locked after former-password denial",
    );
    let new_unlocks = run_gmellon(
        &["unlock", &second_id, "--stdin"],
        CliStdin::Password(password_line(&secrets.second_two)),
        secrets,
        "unlock second with the new password after change",
    );
    assert_eq!(
        exit_code(&new_unlocks),
        Some(0),
        "the new password must unlock after the change"
    );

    // Sibling isolation: rotating the second collection left login's
    // password untouched.
    fixture
        .lock(&login_path)
        .expect("fixture Lock login before sibling check");
    let sibling = run_gmellon(
        &["unlock", "--stdin"],
        CliStdin::Password(password_line(&secrets.login)),
        secrets,
        "unlock login with its original password after second's change",
    );
    assert_eq!(
        exit_code(&sibling),
        Some(0),
        "login's original password must still work after second's change"
    );

    // Omitted collection defaults to login: L to L2.
    fixture
        .lock(&login_path)
        .expect("fixture Lock login before default change");
    let default_change = run_gmellon(
        &["change", "--stdin"],
        CliStdin::Lines(change_stdin([
            secrets.login.as_slice(),
            secrets.login_two.as_slice(),
            secrets.login_two.as_slice(),
        ])),
        secrets,
        "change default login L to L2",
    );
    assert_eq!(
        exit_code(&default_change),
        Some(0),
        "the default-selection change must exit 0"
    );
    assert!(
        String::from_utf8_lossy(&default_change.stdout)
            .contains("changed password for collection login"),
        "the default-selection change must report the login collection"
    );
    assert_listed_locked(secrets, LOGIN_LABEL, true, "login after default change");
    let login_former_denied = run_gmellon(
        &["unlock", "--stdin"],
        CliStdin::Password(password_line(&secrets.login)),
        secrets,
        "unlock default login with the former password after change",
    );
    assert_eq!(
        exit_code(&login_former_denied),
        Some(2),
        "login's former password must be denied after the default change"
    );
    let login_new_unlocks = run_gmellon(
        &["unlock", "--stdin"],
        CliStdin::Password(password_line(&secrets.login_two)),
        secrets,
        "unlock default login with the new password after change",
    );
    assert_eq!(
        exit_code(&login_new_unlocks),
        Some(0),
        "login's new password must unlock after the default change"
    );

    // Missing collection: rejected before stdin is read. `/dev/null` stdin
    // makes any read fail the `--stdin` contract with an unterminated-input
    // diagnostic, so the not-found diagnostic on stderr proves the
    // collection was resolved before any input was consumed.
    let change_missing = run_gmellon(
        &["change", MISSING_ID, "--stdin"],
        CliStdin::FailIfRead,
        secrets,
        "change a missing collection",
    );
    assert_eq!(
        exit_code(&change_missing),
        Some(1),
        "change of a missing collection must exit 1"
    );
    let change_missing_stderr = String::from_utf8_lossy(&change_missing.stderr);
    assert!(
        change_missing_stderr.contains("collection ID does not exist"),
        "change of a missing collection must be reported actionably on stderr"
    );
    assert!(
        change_missing_stderr.contains(MISSING_ID),
        "the missing-collection change diagnostic must name the requested ID"
    );
    assert!(
        !change_missing_stderr.contains("without a newline"),
        "the missing-collection change must fail before reading stdin, not on input"
    );
    assert!(
        change_missing.stdout.is_empty(),
        "the missing-collection change failure must not write stdout"
    );

    // Fewer than three terminated lines map to exit 1 — the collection
    // exists, so reaching the input contract at all is expected — and, per
    // the change monitor below, none of these sends a private change call.
    let truncated_variants: [(&str, Zeroizing<Vec<u8>>); 3] = [
        ("change second from empty stdin", Zeroizing::new(Vec::new())),
        (
            "change second with two terminated lines",
            lines_stdin(&[&secrets.second, &secrets.second_two]),
        ),
        ("change second with an unterminated confirmation", {
            let mut bytes = lines_stdin(&[&secrets.second, &secrets.second_two]);
            bytes.extend_from_slice(secrets.second_two.as_slice());
            bytes
        }),
    ];
    for (stage, stdin_bytes) in truncated_variants {
        let truncated = run_gmellon(
            &["change", &second_id, "--stdin"],
            CliStdin::Lines(stdin_bytes),
            secrets,
            stage,
        );
        assert_eq!(
            exit_code(&truncated),
            Some(1),
            "truncated change input must exit 1 ({stage})"
        );
        assert!(
            String::from_utf8_lossy(&truncated.stderr).contains("without a newline"),
            "truncated change input must report unterminated input ({stage})"
        );
        assert!(
            truncated.stdout.is_empty(),
            "truncated change input must not write stdout ({stage})"
        );
    }

    // --- wire evidence: the only Lock calls are deliberate -----------------
    // The fixture's setup locks plus exactly the two legitimate CLI lock
    // calls (the initial flip and the rotation relock). The idempotent
    // re-lock and the missing-ID rejection must reach the daemon not at
    // all — exact counts prove it. Every non-fixture Lock call must come
    // from a CLI connection, and the fixture's count must match its own
    // tally exactly.
    let observed = monitor.finish(&fixture_sender, fixture.lock_calls(), secrets);
    assert!(
        observed.calls >= 1,
        "the monitor observed no Lock traffic although the fixture locked collections"
    );
    assert_eq!(
        observed.calls,
        fixture.lock_calls() + 2,
        "observed Service.Lock calls must equal the fixture's deliberate calls plus \
         exactly the two legitimate CLI locks (flip and rotation relock)"
    );
    assert_eq!(
        observed.fixture_calls,
        fixture.lock_calls(),
        "the fixture's Lock tally must match its deliberate calls exactly"
    );
    assert_eq!(
        observed.senders.len() - observed.fixture_calls,
        2,
        "exactly two Lock calls must come from CLI connections"
    );
    assert!(
        !observed.senders_match_fixture,
        "with legitimate CLI locks, not every Lock sender is the fixture"
    );

    // --- wire evidence: exactly the legitimate private change calls --------
    // The change section made exactly three legitimate private
    // ChangeWithMasterPassword calls — the denied wrong-current attempt and
    // the two successful rotations — each from a fresh CLI connection. Any
    // input-rejected invocation (mismatch, truncated lines, missing ID)
    // reaching the daemon would raise the count; a broken monitor would
    // lower it; a fixture call would appear in observed_fixture_calls.
    let observed_changes = change_monitor.finish(&fixture_sender, 0, secrets);
    assert_eq!(
        observed_changes.calls, 3,
        "expected exactly the three legitimate private change calls (denied attempt plus two rotations)"
    );
    assert_eq!(
        observed_changes.fixture_calls, 0,
        "the fixture never performs a private change call"
    );
    assert!(
        observed_changes
            .senders
            .iter()
            .all(|sender| sender != &fixture_sender),
        "every private change call must come from a CLI connection, not the fixture"
    );

    // --- encrypted-session wire evidence -------------------------------------
    // Absence was asserted inside the monitor: any generated password seen
    // in any captured body — line bytes, hex, or a decoded ay run — fails
    // the proof. Presence is asserted here: exactly the expected
    // password-method calls were captured, every one in the encrypted shape
    // (a plain secret's empty IV array would fail the shape verdict), and
    // one encrypted OpenSession per CLI invocation plus the fixture's own.
    let bodies = password_monitor.finish(secrets);
    assert_eq!(
        bodies.messages_of("CreateWithMasterPassword").len(),
        2,
        "exactly the fixture's two creations must be captured"
    );
    assert_eq!(
        bodies.messages_of("UnlockWithMasterPassword").len(),
        13,
        "exactly the thirteen binary unlock calls that reached the daemon must be captured \
         (eleven prior plus the two lock-rotation unlocks); lock invocations never appear here"
    );
    let observed_change_bodies = bodies.messages_of("ChangeWithMasterPassword").len();
    assert_eq!(
        observed_change_bodies, 3,
        "the body monitor must see the same three change calls as the header monitor"
    );
    for member in [
        "CreateWithMasterPassword",
        "UnlockWithMasterPassword",
        "ChangeWithMasterPassword",
    ] {
        assert!(
            bodies.all_encrypted(member),
            "every captured {member} body must carry well-formed encrypted secrets"
        );
    }

    // The CreateItem wire evidence: exactly the two legitimate stores (the
    // verified store and the replacing store) reached the daemon, every one
    // with an encrypted Secret. The finish call itself fails closed on any
    // leak of the key passphrase into a captured body, and the refused and
    // unencrypted attempts never got here to be counted.
    let created = create_item_monitor.finish(secrets);
    assert_eq!(
        created.messages.len(),
        2,
        "exactly the verified store and the replacing store may create items"
    );
    assert!(
        created
            .messages
            .iter()
            .all(|message| message.encrypted_secrets),
        "every CreateItem body must carry a well-formed encrypted secret"
    );

    // The wrong-passphrase and unencrypted-key ssh-add refusals verify the
    // key before ever connecting, so those invocations negotiate nothing.
    let verify_refused_invocations = 2_usize;

    let negotiations = negotiation_monitor.finish(secrets);
    assert_eq!(
        negotiations.messages.len(),
        INVOCATIONS.load(Ordering::Relaxed) + 1 - verify_refused_invocations,
        "one encrypted OpenSession per CLI invocation (every invocation constructs the \
         client) plus the fixture's own negotiation must be captured"
    );
    assert!(
        negotiations
            .messages
            .iter()
            .all(|message| message.dh_algorithm),
        "every captured OpenSession must negotiate the encrypted-session algorithm"
    );
    assert_eq!(
        negotiations
            .messages
            .iter()
            .filter(|message| message.sender == fixture_sender)
            .count(),
        1,
        "exactly one negotiation must belong to the fixture connection"
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

/// Newline-terminated lines, zeroized when dropped; the base for both the
/// three-line `change` input and its truncated variants.
fn lines_stdin(lines: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let capacity = lines.iter().map(|line| line.len() + 1).sum::<usize>();
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    for line in lines {
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
    }
    bytes
}

/// Exactly three newline-terminated lines — current, new, confirmation — as
/// the `change --stdin` contract requires.
fn change_stdin(lines: [&[u8]; 3]) -> Zeroizing<Vec<u8>> {
    lines_stdin(&lines)
}

/// Spawn the compiled gmellon binary with the harness-inherited environment,
/// feed the chosen stdin, capture both streams, and scan the captured bytes
/// for every generated password — literal bytes and the reversible encodings
/// a diagnostic dump could carry — before the caller inspects the result.
fn run_gmellon(arguments: &[&str], stdin: CliStdin, secrets: &ProofSecrets, stage: &str) -> Output {
    INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let mut command = Command::new(env!("CARGO_BIN_EXE_gmellon"));
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(match stdin {
            CliStdin::Password(_) | CliStdin::Lines(_) => Stdio::piped(),
            CliStdin::FailIfRead => Stdio::null(),
        });
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn the gmellon binary for `{stage}`: {error}"));
    let piped_stdin = match stdin {
        CliStdin::Password(line) => Some(line),
        CliStdin::Lines(bytes) => Some(bytes),
        CliStdin::FailIfRead => None,
    };
    if let Some(bytes) = piped_stdin
        && let Some(mut handle) = child.stdin.take()
    {
        // A broken pipe is expected when the binary exits before reading
        // (for example the missing-collection rejection); the exit-code
        // and message assertions surface any unexpected early exit.
        let _ = handle.write_all(&bytes);
    }
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("wait for the gmellon binary for `{stage}`: {error}"));

    for (name, secret) in secrets.named() {
        for (stream, label) in [(&output.stdout, "stdout"), (&output.stderr, "stderr")] {
            common::assert_secret_absent(
                stream,
                secret,
                &format!("gmellon `{stage}` {label} (generated {name} password)"),
            );
        }
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
