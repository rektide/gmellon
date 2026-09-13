//! Opt-in proof of the committed Rust Secret Service client against an
//! isolated private dbus-broker daemon.
//!
//! The ignored outer test invokes the executable broker harness contract,
//! which starts a private bus, manually launches `gnome-keyring-daemon`, and
//! re-runs only this test inside the isolated command environment. The inner
//! proof is maintained Rust: a zbus test fixture performs the *only* permitted
//! mutation setup — creating disposable collections through GNOME's private
//! `CreateWithMasterPassword` (one labeled exactly `login`, satisfying the
//! parent acceptance's literal login-plus-second requirement, plus a second
//! distinguishable collection) and returning them to the locked state with the
//! standard `Lock` method — and every observed behavior is asserted through
//! the public `gmellon::secret_service::BlockingClient`.
//!
//! Ordinary `cargo test` and `cargo nextest run` visibly skip this proof. The
//! maintained explicit entry point is `dev/harness/check rust-broker`.

// The change-call monitor and its summary fields serve the CLI proof's
// change coverage; this proof compiles the shared module without using them.
#[allow(dead_code)]
mod broker_common;
mod common;

use std::env;

use broker_common::{
    BodyMonitor, BusEnvironment, Fixture, LOGIN_LABEL, MethodMonitor, ProofSecrets,
    expected_collection_id, run_broker_isolated, validated_harness_environment,
};
use common::required_path;
use gmellon::secret_service::{BlockingClient, CollectionId, Error, UnlockOutcome};

const PROOF_TEST: &str = "private_broker_collections_client_proof";

#[test]
#[ignore = "requires explicit private-broker harness run; see doc/harness/README.md"]
fn private_broker_collections_client_proof() {
    if env::var_os(common::ACTIVE_MARKER).is_some() {
        #[cfg(not(target_os = "linux"))]
        panic!("private-broker collection proof requires Linux Unix-socket peer credentials");

        let secrets = ProofSecrets::generate();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_proof(&secrets);
        }));
        finish_case("private_broker_collections", &secrets.all_slices(), outcome);
        return;
    }

    run_broker_isolated(PROOF_TEST, "private-broker collection proof");
}

/// Everything the inner proof asserts, in one command inside `broker.py`.
fn run_proof(secrets: &ProofSecrets) {
    let bus = validated_harness_environment();

    // The lock-call monitor must be armed before any fixture traffic so the
    // count is exhaustive; readiness is proven by its banner, not a sleep.
    let monitor = MethodMonitor::lock(&bus.address, &bus.root);

    // The encrypted-session wire evidence is armed just as early so it is
    // exhaustive over the whole run: every password-method body is captured
    // and scanned for the generated passwords, and every OpenSession
    // negotiation is checked for the encrypted algorithm. Both monitors
    // stream through pipes; decoded bodies never touch disk.
    let password_monitor = BodyMonitor::password_methods(&bus.address, &bus.root, secrets);
    let negotiation_monitor = BodyMonitor::open_sessions(&bus.address, &bus.root, secrets);

    // Fixture connection: separate D-Bus unique name from the product client,
    // so every observed Lock call can be attributed to a sender. The fixture
    // negotiates the same encrypted session the product client does.
    let mut fixture = Fixture::connect(&bus.address).expect("fixture encrypted session");
    let fixture_sender = fixture.unique_name();

    let label_second = format!("gmellon-proof-second-{}", secrets.run_tag);

    // Fixture setup: persistent disposable collections with distinct
    // passwords. This is the only code permitted to create or lock. One
    // collection is labeled exactly `login`; the second carries a per-run tag
    // so its escaped-label ID is distinguishable from any other run's.
    let login_path = fixture
        .create(LOGIN_LABEL, &secrets.login)
        .expect("fixture CreateWithMasterPassword login");
    let second_path = fixture
        .create(&label_second, &secrets.second)
        .expect("fixture CreateWithMasterPassword second");
    assert_ne!(login_path, second_path);

    // One product client, as a CLI process would own it. It resolves its own
    // connection from the exported DBUS_SESSION_BUS_ADDRESS.
    let client = BlockingClient::session().expect("BlockingClient::session");

    // Discovery is by label only to learn the stable IDs; every later
    // operation addresses the returned CollectionId values, never a hardcoded
    // object path or label.
    let login_id = collection_id_by_label(&client, LOGIN_LABEL);
    let second_id = collection_id_by_label(&client, &label_second);
    assert_ne!(login_id, second_id);

    // The parent acceptance literally requires the `login` collection: the
    // discovered stable ID must be exactly `login` (observed daemon 48.0
    // behavior — the label needs no escaping), not a login-shaped run-tagged
    // approximation.
    assert_eq!(
        login_id.as_str(),
        LOGIN_LABEL,
        "the collection labeled {LOGIN_LABEL} must expose the exact stable ID `{LOGIN_LABEL}`"
    );

    // A just-created collection holds its master-password credential, so it
    // starts unlocked; the daemon persists token collections immediately.
    assert_lock_state(&client, &login_id, false, "login after fixture create");
    assert_lock_state(&client, &second_id, false, "second after fixture create");
    assert_persisted(&bus, LOGIN_LABEL, &login_id);
    assert_persisted(&bus, &label_second, &second_id);

    // Fixture-only locking: standard Lock, counted and attributed.
    fixture.lock(&login_path).expect("fixture Lock login");
    fixture.lock(&second_path).expect("fixture Lock second");
    assert_lock_state(&client, &login_id, true, "login after fixture lock");
    assert_lock_state(&client, &second_id, true, "second after fixture lock");

    // Wrong password while genuinely locked: denied, and the denial must not
    // change lock state.
    assert!(
        matches!(
            client.unlock(&login_id, &secrets.wrong),
            Err(Error::PasswordDenied)
        ),
        "wrong password while login locked must be PasswordDenied"
    );
    assert_lock_state(&client, &login_id, true, "login after denied attempt");

    // Cross password: login's password is wrong for second.
    assert!(
        matches!(
            client.unlock(&second_id, &secrets.login),
            Err(Error::PasswordDenied)
        ),
        "login's password on locked second must be PasswordDenied"
    );

    // Each correct password unlocks only its own collection.
    assert_eq!(
        client
            .unlock(&login_id, &secrets.login)
            .expect("unlock login with its password"),
        UnlockOutcome::Unlocked
    );
    assert_lock_state(&client, &login_id, false, "login after unlock");
    assert_lock_state(
        &client,
        &second_id,
        true,
        "second untouched by login unlock",
    );

    assert_eq!(
        client
            .unlock(&second_id, &secrets.second)
            .expect("unlock second with its password"),
        UnlockOutcome::Unlocked
    );
    assert_lock_state(
        &client,
        &login_id,
        false,
        "login untouched by second unlock",
    );

    // Already-unlocked: the committed client returns AlreadyUnlocked from its
    // lock-state guard in `blocking.rs` before any password method is sent,
    // so no password method is invoked on this path (established by the
    // committed early return plus this outcome — the monitor's match rule is
    // deliberately password-excluding and proves only the no-Lock claim).
    // Upstream's private method would short-circuit anyway, which is exactly
    // why the client's guard, not the daemon, carries the no-verification
    // behavior. Both a wrong and the correct password return AlreadyUnlocked
    // and the collection stays unlocked.
    assert_eq!(
        client
            .unlock(&login_id, &secrets.wrong)
            .expect("already-unlocked login with wrong password"),
        UnlockOutcome::AlreadyUnlocked
    );
    assert_lock_state(
        &client,
        &login_id,
        false,
        "login after already-unlocked path",
    );
    assert_eq!(
        client
            .unlock(&login_id, &secrets.login)
            .expect("already-unlocked login with its password"),
        UnlockOutcome::AlreadyUnlocked
    );

    // Missing collection: discovery reports it before any password method.
    let missing = CollectionId::new("gmellon-proof-missing").expect("nonempty id");
    assert!(
        matches!(
            client.unlock(&missing, &secrets.login),
            Err(Error::CollectionNotFound { .. })
        ),
        "unlock of a missing collection must be CollectionNotFound"
    );
    assert!(
        matches!(
            client.change_password(&missing, &secrets.login, &secrets.login_two),
            Err(Error::CollectionNotFound { .. })
        ),
        "change_password of a missing collection must be CollectionNotFound"
    );

    // Password change on the unlocked login, then fixture-only relock: the
    // former password is denied while locked, the new one unlocks.
    client
        .change_password(&login_id, &secrets.login, &secrets.login_two)
        .expect("change_password login L to L2");
    assert_lock_state(&client, &login_id, false, "login after change_password");

    fixture
        .lock(&login_path)
        .expect("fixture Lock login after change");
    assert_lock_state(&client, &login_id, true, "login after fixture relock");

    assert!(
        matches!(
            client.unlock(&login_id, &secrets.login),
            Err(Error::PasswordDenied)
        ),
        "former password while login relocked must be PasswordDenied"
    );
    assert_eq!(
        client
            .unlock(&login_id, &secrets.login_two)
            .expect("unlock login with the changed password"),
        UnlockOutcome::Unlocked
    );

    // Wire evidence: ordinary product unlock/change never emitted a standard
    // Lock method call. Every observed Lock belongs to the fixture sender,
    // and the total equals only the fixture's deliberate calls. The count is
    // positive, so a silently broken monitor cannot pass vacuously.
    let observed = monitor.finish(&fixture_sender, fixture.lock_calls(), secrets);
    assert!(
        observed.calls >= 1,
        "the monitor observed no Lock traffic although the fixture locked collections"
    );
    assert_eq!(
        observed.calls,
        fixture.lock_calls(),
        "observed Service.Lock calls must equal the fixture's deliberate calls"
    );
    assert!(
        observed.senders_match_fixture,
        "every observed Service.Lock call must come from the fixture connection"
    );

    // --- encrypted-session wire evidence ------------------------------------
    // Absence was already asserted inside the monitor (any generated
    // password found in any captured body, as line bytes, hex, or a decoded
    // ay run, fails the proof). Presence is asserted here so a blind
    // monitor cannot pass vacuously: exactly the expected password-method
    // calls were captured, every one in the encrypted shape (16-byte IV
    // array plus non-empty 16-multiple ciphertext per Secret — a plain
    // secret's empty parameters would fail the shape), and exactly the two
    // expected OpenSession negotiations (fixture and product client), both
    // for the encrypted algorithm.
    let bodies = password_monitor.finish(secrets);
    assert_eq!(
        bodies.messages_of("CreateWithMasterPassword").len(),
        2,
        "exactly the fixture's two creations must be captured"
    );
    assert_eq!(
        bodies.messages_of("UnlockWithMasterPassword").len(),
        6,
        "exactly the six product unlock calls must be captured (denied, cross, \
         two successful, former-password denial, changed-password unlock)"
    );
    assert_eq!(
        bodies.messages_of("ChangeWithMasterPassword").len(),
        1,
        "exactly the one product change call must be captured"
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
    let fixture_creates = bodies
        .messages_of("CreateWithMasterPassword")
        .iter()
        .filter(|message| message.sender == fixture_sender)
        .count();
    assert_eq!(
        fixture_creates, 2,
        "both creations must come from the fixture connection"
    );

    let negotiations = negotiation_monitor.finish(secrets);
    assert_eq!(
        negotiations.messages.len(),
        2,
        "exactly the fixture and product-client OpenSession calls must be captured"
    );
    assert!(
        negotiations
            .messages
            .iter()
            .all(|message| message.dh_algorithm),
        "every captured OpenSession must negotiate the encrypted-session algorithm"
    );
    assert!(
        negotiations
            .messages
            .iter()
            .any(|message| message.sender == fixture_sender)
            && negotiations
                .messages
                .iter()
                .any(|message| message.sender != fixture_sender),
        "one negotiation must belong to the fixture and one to the product client"
    );
}

fn collection_id_by_label(client: &BlockingClient, label: &str) -> CollectionId {
    let collections = client.collections().expect("BlockingClient::collections");
    let found = collections
        .iter()
        .find(|collection| collection.label == label)
        .unwrap_or_else(|| panic!("collection labeled {label} was not listed"));
    assert_eq!(found.label, label);
    found.id.clone()
}

fn assert_lock_state(client: &BlockingClient, id: &CollectionId, locked: bool, stage: &str) {
    let collections = client
        .collections()
        .expect("list collections for lock state");
    let found = collections
        .iter()
        .find(|collection| &collection.id == id)
        .unwrap_or_else(|| panic!("collection {id} missing at stage {stage}"));
    assert_eq!(found.locked, locked, "unexpected lock state at {stage}");
}

/// Observed daemon-48.0 persistence contract for token collections, asserted
/// per fixture: the store file stem is the raw label, and the D-Bus ID is the
/// escaped-label form. The escaped form is asserted, not guessed: the exact
/// `login` ID for the untagged label, and the deterministic `-` to `_2d`
/// escaping for the tagged second label.
fn assert_persisted(bus: &BusEnvironment, label: &str, id: &CollectionId) {
    let keyrings = required_path("XDG_DATA_HOME").join("keyrings");
    let file = keyrings.join(format!("{label}.keyring"));
    assert!(
        file.is_file(),
        "token collection {id} was not persisted at {}",
        file.display()
    );
    common::assert_beneath(&file, &bus.root);
    let expected_id = expected_collection_id(label);
    assert_eq!(
        id.as_str(),
        expected_id,
        "collection ID for label {label} is not the observed escaped-label form"
    );
}

fn finish_case(path_name: &str, secrets: &[&[u8]], outcome: std::thread::Result<()>) {
    let root = required_path("GMELL_HARNESS_ROOT");
    let header = format!(
        "path={path_name}\nclient=gmellon::secret_service::BlockingClient\nsecret_values={}",
        secrets.len()
    );
    common::finish_case(&root, "rust-broker-proof.txt", &header, secrets, outcome);
}
