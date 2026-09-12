---
type: Evidence
title: Multi-collection zbus client proof under the private broker harness
description: Installed-host evidence that gmellon's committed BlockingClient lists, unlocks, and re-keys multiple GNOME collections by stable ID through the private D-Bus interface, without ever locking or relocking as part of ordinary unlock.
resource: /doc/harness/collections0.glm53max.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, zbus, collections]
status: draft
generated: { by: model:zai/glm-5.3-max, at: 2026-09-12T01:30:00-04:00 }
verified: { by: model:zai/glm-5.3-max, at: 2026-09-12T01:30:00-04:00 }
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

1. two persistent disposable collections with distinct random passwords are
   addressable by stable `CollectionId` after label discovery, never by a
   hardcoded object path or label;
2. a wrong password on a locked collection is `PasswordDenied`, and the denial
   does not change lock state;
3. each distinct password unlocks only its own collection — the sibling stays
   locked;
4. an already-unlocked collection returns `AlreadyUnlocked` with lock state
   left `false`, for a wrong *and* the right password, without relocking and
   without password verification;
5. a missing ID returns `CollectionNotFound` for both unlock and change;
6. `change_password` A→A2 succeeds, and after a fixture-only relock the former
   password A is denied while A2 unlocks;
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

```sh
dev/harness/check rust-broker
# Summary: 1 test run: 1 passed, 0 skipped
# broker.py: PASS: command completed in isolated private-broker harness

cargo nextest run --test broker_collections --run-ignored ignored-only
# Summary: 1 test run: 1 passed, 0 skipped   (run 4x, all passed)

cargo nextest run          # Summary: 61 tests run: 61 passed, 3 skipped
dev/harness/check broker   # 7/7 focused tests + interface smoke, PASS
dev/harness/check rust-nextest  # 2/2 control-path real-daemon tests, PASS
dev/harness/check python   # 10/10 focused + behavior matrix + smoke, PASS
cargo fmt --all -- --check   # clean
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo doc --no-deps          # clean
PATH=/nonexistent dev/harness/check rust-broker
# HARNESS PREREQUISITE FAILURE: python3 was not found on PATH; exit 125
```

Retained successful run (GMELL_HARNESS_KEEP_SUCCESS=1):
`/home/rektide/tmp-opencode/gmell-h-bz2zhy5v` — `rust-broker-proof.txt`
(`artifact_scan=passed`, `secret_values=4`), `lock-monitor.txt`, and both
encrypted `<label>.keyring` fixture stores.

## Fixture and lock-state transitions

All state is observed through `BlockingClient::collections()`. Fixture calls
(private `CreateWithMasterPassword`, standard `Lock`) run on a separate zbus
connection whose unique bus name is the only permitted Lock sender.

| Step | alpha | beta | Product call / fixture action | Result |
| --- | --- | --- | --- | --- |
| fixture create alpha (pw A), beta (pw B) | unlocked | unlocked | — | persisted `<label>.keyring`; D-Bus IDs are the escaped labels |
| fixture `Lock(alpha)`, `Lock(beta)` | locked | locked | — | 2 counted fixture lock calls |
| `unlock(alpha, wrong)` | locked | locked | product | `Err(PasswordDenied)` |
| `unlock(beta, A)` (cross password) | locked | locked | product | `Err(PasswordDenied)` |
| `unlock(alpha, A)` | unlocked | locked | product | `Ok(Unlocked)`; beta untouched |
| `unlock(beta, B)` | unlocked | unlocked | product | `Ok(Unlocked)` |
| `unlock(alpha, wrong)` | unlocked | unlocked | product | `Ok(AlreadyUnlocked)`; state stays false |
| `unlock(alpha, A)` | unlocked | unlocked | product | `Ok(AlreadyUnlocked)` |
| `unlock(missing, …)` / `change_password(missing, …)` | unlocked | unlocked | product | `Err(CollectionNotFound)` |
| `change_password(alpha, A→A2)` | unlocked | unlocked | product | `Ok(())` (credential swap leaves it unlocked) |
| fixture `Lock(alpha)` | locked | unlocked | — | 3rd counted fixture lock call |
| `unlock(alpha, A)` | locked | unlocked | product | `Err(PasswordDenied)` |
| `unlock(alpha, A2)` | unlocked | unlocked | product | `Ok(Unlocked)` |

## No-relock evidence

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
attribution; a lock-then-verify implementation would additionally surface as
`PasswordDenied` instead of `AlreadyUnlocked` in step 7. The daemon-side
shortcut is real: upstream `gkd_secret_unlock_with_secret` returns success
*without checking the password* when the collection is unlocked, which is why
the committed client's lock-state guard (and this proof's password assertions,
which only run while locked) matter.

## Fixture semantics observed on daemon 48.0

- `CreateWithMasterPassword` with `{"org.freedesktop.Secret.Collection.Label":
  <string>}` creates a **token** collection that persists immediately as
  `~/.local/share/keyrings/<label>.keyring` (raw label as file stem), while
  the D-Bus object-path ID is the escaped label — observed
  `gmellon_2dproof_2dalpha_2dc4f96eee` for `gmellon-proof-alpha-c4f96eee`.
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

- Four random 32-byte printable passwords (A, B, wrong, A2) are generated from
  `/dev/urandom` inside the test process, held in `Zeroizing` buffers, never
  printed, logged, passed through argv or environment, and never appear in
  harness-exported values.
- The raw monitor log and readiness log are scanned for all four values before
  the redacted `lock-monitor.txt` summary replaces them; then every regular
  file in the retained root (including `evidence.json`, daemon logs, and the
  encrypted `*.keyring` stores) is scanned again before success.
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

## What this enables and the next slice

With this proof, the collection-oriented backend claims of
`gmell-dbus-collections` are now demonstrated end-to-end against an isolated
real daemon: stable-ID addressing, per-collection passwords, no-relock unlock,
and headless re-key. The natural next slice is CLI wiring (`gmell-unlock`,
`gmell-change`) over this client, plus extending the harness guide's fixture
story if restart persistence coverage is wanted.
