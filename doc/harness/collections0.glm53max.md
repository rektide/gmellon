---
type: Evidence
title: Multi-collection zbus client proof under the private broker harness
description: Installed-host evidence that gmellon's committed BlockingClient lists, unlocks, and re-keys multiple GNOME collections by stable ID through the private D-Bus interface, without ever locking or relocking as part of ordinary unlock.
resource: /doc/harness/collections0.glm53max.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, zbus, collections]
status: draft
generated: { by: model:zai/glm-5.3-max, at: 2026-09-12T01:30:00-04:00 }
verified: { by: model:zai/glm-5.3-max, at: 2026-09-11T21:45:00-04:00 }
stale_after: 2027-03-12
sources:
  - id: rust-proof
    resource: /tests/harness/broker_collections.rs
    title: Maintained opt-in Rust collection proof
  - id: broker-lifecycle
    resource: /dev/harness/broker.py
    title: Reusable private dbus-broker harness lifecycle
  - id: check-entry
    resource: /dev/harness/check
    title: Explicit rust-broker check mode
  - id: product-client
    resource: /src/secret_service/blocking.rs
    title: Committed BlockingClient under proof
  - id: gnome-private-interface
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/daemon/dbus/org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.xml
    title: GNOME Keyring private D-Bus interface declaration
  - id: gnome-service-methods
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/daemon/dbus/gkd-secret-service.c
    title: gkd-secret-service.c private method handlers
  - id: gnome-unlock-shortcut
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/daemon/dbus/gkd-secret-unlock.c
    title: gkd_secret_unlock_with_secret already-unlocked shortcut
  - id: gnome-change
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/daemon/dbus/gkd-secret-change.c
    title: gkd_secret_change_with_secrets credential swap
  - id: gnome-lock
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/daemon/dbus/gkd-secret-lock.c
    title: gkd_secret_lock credential destruction
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
  - id: installed-broker
    resource: package:dbus-broker@37
    title: Installed dbus-broker 37
  - id: installed-systemd
    resource: package:systemd@261
    title: Installed systemd 261 (busctl monitor, --match)
  - id: prior-broker-evidence
    resource: /doc/harness/broker0.gpt6a.md
    title: Private broker lifecycle and interface proof
---

# Multi-collection zbus client proof under the private broker harness

## Result

[`tests/harness/broker_collections.rs`](/tests/harness/broker_collections.rs)
is a maintained, opt-in Rust proof that runs as the command inside
[`dev/harness/broker.py`](/dev/harness/broker.py). The explicit entry point is
`dev/harness/check rust-broker`; ordinary `cargo test` / `cargo nextest run`
visibly skip the ignored test (61 passed, 3 skipped). No Python code implements
collection semantics — the harness only provides the bus/daemon/process
lifecycle it already owned.

The proof demonstrates, entirely through the committed public
`gmellon::secret_service::BlockingClient`
([`blocking.rs`](/src/secret_service/blocking.rs)):

1. one persistent disposable collection is labeled exactly `login`, and the
   discovered stable `CollectionId` is **exactly `login`** (observed daemon
   48.0 behavior: the label needs no escaping) with the token store persisted
   as `login.keyring` beneath the isolated root — the parent acceptance's
   literal login requirement — alongside a second persistent collection with a
   distinguishable tagged label; both are addressable by stable `CollectionId`
   after label discovery, never by a hardcoded object path or label;
2. a wrong password on a locked collection is `PasswordDenied`, and the denial
   does not change lock state;
3. each distinct password unlocks only its own collection — the sibling stays
   locked;
4. an already-unlocked collection returns `AlreadyUnlocked` with lock state
   left `false`, for a wrong *and* the right password, without relocking and
   without password verification;
5. a missing ID returns `CollectionNotFound` for both unlock and change;
6. `change_password` L→L2 succeeds, and after a fixture-only relock the former
   password L is denied while L2 unlocks;
7. on the wire, **ordinary product unlock/change never emits a standard
   `org.freedesktop.Secret.Service.Lock` method call** — a match-filtered bus
   monitor attributes every observed Lock call to the fixture connection.

## Observed host

```text
gnome-keyring-daemon 48.0
dbus-broker 37 (dbus-broker-launch 37, --scope=system)
systemd 261 (261.2-1): systemd-socket-activate, busctl monitor --match
python 3.14.6, rustc 1.96.0-nightly, cargo-nextest 0.9.122
host dependencies: /run/systemd/journal/socket, /run/dbus/system_bus_socket,
/run/systemd/system (unchanged from broker0; see its launcher-controller
boundary)
```

## Exact commands and results

2026-09-11/12 correction re-verification (after the GX review corrections):

```sh
dev/harness/check rust-broker          # PASS (and 4x more below)
cargo nextest run --test broker_collections --run-ignored ignored-only
# Summary: 1 test run: 1 passed, 0 skipped   (2x, both passed; 6 successful
# runs of the corrected proof in total this session)

cargo nextest run          # Summary: 61 tests run: 61 passed, 3 skipped
dev/harness/check broker   # 7/7 focused tests + interface smoke, PASS
dev/harness/check all
# exit 0: rust-nextest 2/2 real-daemon control tests, rust-broker 1/1 proof,
# python 10/10 focused + behavior matrix + smoke, broker 7/7 + probe
cargo fmt --all -- --check   # clean
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo doc --no-deps          # clean
PATH=/nonexistent dev/harness/check rust-broker
# HARNESS PREREQUISITE FAILURE: python3 was not found on PATH; exit 125
```

Retained successful run (`dev/harness/check --keep-success rust-broker`):
`/home/rektide/tmp-opencode/gmell-h-5g5tbiw8` — `rust-broker-proof.txt`
(`artifact_scan=passed`, `secret_values=4`), `lock-monitor.txt`
(`fixture_lock_calls=3 observed_lock_calls=3 senders_match_fixture=true`), and
the encrypted `login.keyring` plus `gmellon-proof-second-<tag>.keyring` fixture
stores; the root contains no symlinks.

Observed anomaly, recorded honestly: one direct (unkept) successful run at
2026-09-11 21:28 left a fully complete, clean, secret-free retained root
(`gmell-h-h46jz2me`, `command_return_code=0`, all children reaped) although
neither `--keep-success` nor any failure/signal was involved; it did not recur
across five subsequent unkept runs. Retention is the contract's safe direction,
so this is noted rather than chased; no action taken in this slice.

## Fixture and lock-state transitions

All state is observed through `BlockingClient::collections()`. Fixture calls
(private `CreateWithMasterPassword`, standard `Lock`) run on a separate zbus
connection whose unique bus name is the only permitted Lock sender. Passwords:
login's is L, the second collection's is S, `wrong` is a fourth random value,
and L2 is the changed login password.

| Step | login | second | Product call / fixture action | Result |
| --- | --- | --- | --- | --- |
| fixture create `login` (pw L), `second` (pw S) | unlocked | unlocked | — | persisted `login.keyring` (ID exactly `login`) and `gmellon-proof-second-<tag>.keyring`; second's D-Bus ID is the escaped label |
| fixture `Lock(login)`, `Lock(second)` | locked | locked | — | 2 counted fixture lock calls |
| `unlock(login, wrong)` | locked | locked | product | `Err(PasswordDenied)` |
| `unlock(second, L)` (cross password) | locked | locked | product | `Err(PasswordDenied)` |
| `unlock(login, L)` | unlocked | locked | product | `Ok(Unlocked)`; second untouched |
| `unlock(second, S)` | unlocked | unlocked | product | `Ok(Unlocked)` |
| `unlock(login, wrong)` | unlocked | unlocked | product | `Ok(AlreadyUnlocked)`; state stays false |
| `unlock(login, L)` | unlocked | unlocked | product | `Ok(AlreadyUnlocked)` |
| `unlock(missing, …)` / `change_password(missing, …)` | unlocked | unlocked | product | `Err(CollectionNotFound)` |
| `change_password(login, L→L2)` | unlocked | unlocked | product | `Ok(())` (credential swap leaves it unlocked) |
| fixture `Lock(login)` | locked | unlocked | — | 3rd counted fixture lock call |
| `unlock(login, L)` | locked | unlocked | product | `Err(PasswordDenied)` |
| `unlock(login, L2)` | unlocked | unlocked | product | `Ok(Unlocked)` |

## No-relock and no-verification evidence

Two distinct claims, with distinct evidence; neither is overstated:

**No standard Lock call (monitor-proven).**
`stdbuf -oL /usr/bin/busctl --address=<private bus> monitor
--match="interface='org.freedesktop.Secret.Service',member='Lock'"` is armed
before any fixture traffic; readiness is gated on the tool's
`Monitoring bus message stream.` banner (stderr), not a sleep. Because the
match rule delivers only `Service.Lock` method calls, no password-bearing
private-interface body can ever reach the monitor log.

Retained summary from the passing run:

```text
fixture_sender=:1.7
fixture_lock_calls=3
observed_lock_calls=3
senders_match_fixture=true
```

Any product-emitted Lock would break the exact count or the sender
attribution. This is what the monitor proves: ordinary product
unlock/change **never emits a standard `Service.Lock` method call**.

**No password method on the already-unlocked path (code-path plus outcome,
not the monitor).** The bus monitor is deliberately password-excluding, so it
*cannot* prove anything about password-method invocation, and this evidence
must not claim it does. That no password method is invoked when the
collection is already unlocked is established by the committed client's
early return — [`blocking.rs`](/src/secret_service/blocking.rs) checks the
listed lock state and returns `UnlockOutcome::AlreadyUnlocked` before any
`UnlockWithMasterPassword` call is constructed — together with the observed
outcome in result item 4 (both a wrong and the correct password return
`AlreadyUnlocked` with state still `false`). A lock-then-verify
implementation would additionally surface as `PasswordDenied` instead of
`AlreadyUnlocked` on the wrong-password already-unlocked step. The match rule
must not be widened to "prove" this: doing so would deliver password-bearing
bodies into the retained monitor log.

The daemon-side shortcut is real and worth knowing even though the client no
longer relies on it: upstream `gkd_secret_unlock_with_secret` returns success
*without checking the password* when the collection is unlocked, which is why
the committed client's lock-state guard (and this proof's password assertions,
which only run while locked) matter.

## Fixture semantics observed on daemon 48.0

- `CreateWithMasterPassword` with `{"org.freedesktop.Secret.Collection.Label":
  <string>}` creates a **token** collection that persists immediately as
  `~/.local/share/keyrings/<label>.keyring` (raw label as file stem), while
  the D-Bus object-path ID is the escaped label — observed
  `gmellon_2dproof_2dsecond_2d<tag>` for `gmellon-proof-second-<tag>`.
- A collection labeled exactly `login` persists as `login.keyring` and
  exposes the **exact stable ID `login`** (the label contains no escapable
  characters), which is how this proof satisfies the parent acceptance's
  literal login-plus-second requirement without touching any real store. The
  fresh isolated daemon starts with only the in-memory `session` collection,
  so no pre-existing `login` collection can collide.
- A just-created collection starts **unlocked** (it holds the master-password
  credential); the standard `Lock` destroys that credential.
- `ChangeWithMasterPassword` swaps the collection credential to the new
  password and leaves the collection unlocked (upstream
  `gck_object_set(CKA_G_CREDENTIAL, mcred)`); the old password stops working
  only in the locked state, which the fixture re-establishes.

## Error classification coverage

Live wire-level coverage exercised by this proof: `PasswordDenied`
(`org.gnome.keyring.Error.Denied` on wrong/cross/former passwords while
locked) and `CollectionNotFound` (client-side discovery of a missing ID for
unlock and change). `ServiceUnavailable` and `PrivateInterfaceUnavailable`
cannot be produced on this harness without killing the harness-owned daemon or
bus (a harness failure by contract), so their error-name → variant mapping
remains covered by the unit tests in
[`blocking.rs`](/src/secret_service/blocking.rs)
(`private_interface_error_names_are_recognized`). No product bug surfaced; no
product code changed in this proof.

## Secret handling and limits

- Four random 32-byte printable passwords (L, S, wrong, L2) are generated from
  `/dev/urandom` inside the test process, held in `Zeroizing` buffers, never
  printed, logged, passed through argv or environment, and never appear in
  harness-exported values.
- The raw monitor log and readiness log are scanned for all four values before
  the redacted `lock-monitor.txt` summary replaces them; then the retained
  root is scanned again before success.
- **Exact measured scan scope:** the final scan walks every directory beneath
  `GMELL_HARNESS_ROOT` and reads every **regular file present at scan time**
  — concretely `evidence.json`, `daemon.stdout.log`, `daemon.stderr.log`,
  `rust-broker-proof.txt`, `lock-monitor.txt`, `bus.conf`, the launcher logs,
  and the encrypted `login.keyring` / `gmellon-proof-second-<tag>.keyring`
  stores. The walk **fails closed on symlinks**: any symlink inside the root
  is proof failure, never a skip, so no unscanned path can point outside the
  scratch root. The live Unix sockets (private bus, control) are the only
  other entries; they carry no readable retained bytes and are outside the
  scope. `cleanup.json` is also outside the scope **by construction**: the
  supervisor writes it after the command exits, and it records metadata only
  (command status, handled signal, per-child teardown), never command data —
  verified against the retained run's `cleanup.json`.
- **Limit, stated honestly:** the plain Secret Service session sends secret
  values inside D-Bus message bodies in the clear over the private socket.
  zbus-owned serialization buffers and daemon-side copies cannot be zeroized
  by gmellon; only the test's own Rust buffers are. The exposure boundary is
  the mode-0700 harness root and the mode-0600 private bus socket, both owned
  by the invoking UID.
- Monitor matching, not redaction, is what keeps password bytes out of
  monitor output; this was verified by the match rule excluding an
  `OpenSession` body marker during development.

## Limitations

- Version-scoped to the installed daemon 48.0 / dbus-broker 37 / systemd 261;
  not an upstream promise.
- The proof rides the same host dependencies as `broker0` (journal socket,
  system bus for the launcher controller, systemd runtime); configuration and
  session isolation only, not host independence.
- The monitor observes the bus; it cannot see PKCS#11-internal credential
  operations, which is exactly the point: lock state transitions are only
  reachable through the D-Bus surface GNOME exposes.
- One daemon per run; the proof does not cover daemon restart persistence
  (that remains with `behavior.py`'s supervisor model).
- Maintainability follow-up, deliberately not taken in this correction slice:
  the outer-runner helper set (`repository_root`, `require_command`,
  `random_password`, `distinct_password`, `assert_beneath`, `finish_case`,
  `scan_directory`, `contains`, `relay`, `required_path` — roughly 200 lines)
  is duplicated between `tests/harness/broker_collections.rs` and
  `tests/harness/real_daemon.rs`. Extracting a shared harness-support module
  (behind a `#[path]` include or a shared crate) is a separate, reviewable
  change and must not be mixed into evidence corrections.

## What this enables and the next slice

With this proof, the collection-oriented backend claims of
`gmell-dbus-collections` are now demonstrated end-to-end against an isolated
real daemon: stable-ID addressing — including the literal `login` collection
plus a second — per-collection passwords, no-relock unlock, and headless
re-key. The natural next slice is CLI wiring (`gmell-unlock`,
`gmell-change`) over this client, plus extending the harness guide's fixture
story if restart persistence coverage is wanted. One product decision
remains open in the parent ticket: whether the product session should use a
Diffie-Hellman-encrypted Secret Service session instead of the plain session
this proof and the current client use (the plain-session D-Bus-copy limit
above is that decision's input).

## Correction log

- 2026-09-12 GX review corrections (applied to this document and
  [`tests/harness/broker_collections.rs`](/tests/harness/broker_collections.rs),
  verified the same day; earlier content preserved in version control):
  1. **Exact `login` fixture.** The proof now creates one persistent
     collection labeled exactly `login` (private `CreateWithMasterPassword`,
     no run tag) and asserts the listed stable ID is exactly `login` with the
     store persisted as `login.keyring`, alongside a second tagged collection
     — satisfying the parent acceptance's literal "login plus a second"
     wording. No real store is touched; the fallback to a control-only
     fixture was not needed.
  2. **Fail-closed artifact scan.** The retained-root scan now treats any
     symlink as proof failure instead of silently skipping it, and the
     evidence wording states the exact measured scope (every regular file
     present at scan time) plus the fact that `cleanup.json` is
     supervisor-written after the scan and metadata-only.
  3. **No-verification wording.** The no-relock section now separates the
     monitor-proven claim (no standard `Service.Lock` call) from the
     code-path-plus-outcome claim (no password method invoked on the
     already-unlocked path, established by the committed early return in
     `blocking.rs`, not by the password-excluding monitor); the monitor
     match rule is unchanged and must not be widened.
  4. **No helper dedupe** in this slice; recorded as a maintainability
     follow-up in Limitations.
