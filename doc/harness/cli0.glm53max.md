---
type: Evidence
title: Collection CLI binary proof under the private broker harness
description: Installed-host evidence that the compiled gmellon binary's list and unlock subcommands behave per contract against isolated exact-login plus second fixtures — deterministic listing, stable exit codes, an already-unlocked path that reads no secret, and no lock or relock.
resource: /doc/harness/cli0.glm53max.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, cli, collections]
status: draft
generated: { by: model:zai/glm-5.3-max, at: 2026-09-12T02:57:00-04:00 }
verified: { by: model:zai/glm-5.3-max, at: 2026-09-12T02:57:00-04:00 }
stale_after: 2027-03-12
sources:
  - id: rust-proof
    resource: /tests/harness/broker_cli.rs
    title: Maintained opt-in Rust CLI binary proof
  - id: shared-machinery
    resource: /tests/harness/broker_common.rs
    title: Shared broker-proof fixture, monitor, secrets, and runner
  - id: cross-proof-helpers
    resource: /tests/harness/common/mod.rs
    title: Shared environment/secret/scan helpers
  - id: broker-lifecycle
    resource: /dev/harness/broker.py
    title: Reusable private dbus-broker harness lifecycle
  - id: check-entry
    resource: /dev/harness/check
    title: Explicit rust-cli check mode
  - id: product-cli
    resource: /src/cli/mod.rs
    title: Committed CLI under proof
  - id: collections-evidence
    resource: /doc/harness/collections0.glm53max.md
    title: Multi-collection BlockingClient proof this builds on
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
  - id: installed-broker
    resource: package:dbus-broker@37
    title: Installed dbus-broker 37
  - id: installed-systemd
    resource: package:systemd@261
    title: Installed systemd 261 (busctl monitor, --match)
---

# Collection CLI binary proof under the private broker harness

## Result

[`tests/harness/broker_cli.rs`](/tests/harness/broker_cli.rs) is a maintained,
opt-in Rust proof that runs as the command inside
[`dev/harness/broker.py`](/dev/harness/broker.py). The explicit entry point is
`dev/harness/check rust-cli`; ordinary `cargo test` / `cargo nextest run`
visibly skip the ignored test (64 passed, 4 skipped). The proof invokes the
actual compiled binary through the Cargo-provided `CARGO_BIN_EXE_gmellon`
integration-test path (observed `target/debug/gmellon`) — never a hosted bus,
store, or in-process client. Python remains lifecycle and check wiring only.

The fixture (shared with the collections proof through
[`broker_common.rs`](/tests/harness/broker_common.rs)) creates one persistent
collection labeled exactly `login` (observed stable ID exactly `login`) plus a
second tagged collection under distinct generated passwords, and returns both
to the locked state through two counted standard `Lock` calls. Everything the
fixture creates is disposable, inside the isolated scratch root.

Observed binary behavior (committed [`src/cli/mod.rs`](/src/cli/mod.rs),
checkpoint `04310fc8`):

1. `gmellon list` exits 0 and is **byte-deterministic** across consecutive
   invocations. The header is exactly `ID<TAB>LOCKED<TAB>LABEL`; each row is
   three tab-separated fields with `yes`/`no` lock state; the row labeled
   `login` carries the exact stable ID `login` while locked; the second
   collection's returned stable ID is the escaped-label form
   (`gmellon_2dcli_2dsecond_2d<tag>` for label `gmellon-cli-second-<tag>`),
   sorted before `login`. Neither stream mentions the control protocol.
2. Explicit `gmellon unlock <second-id> --stdin` on the locked second
   collection: a wrong password and the login (cross) password each **exit 2**
   with a `denied` diagnostic on stderr and leave the collection locked; the
   correct distinct password **exits 0**, reports `unlocked collection
   <second-id>`, unlocks only the second — `login` remains locked — and the
   persisted store shows both `.keyring` files.
3. Default `gmellon unlock --stdin` on the locked login collection (no
   collection argument) consumes `password\n` from the pipe, **exits 0**,
   reports `unlocked collection login`, and flips only the login row.
4. Already-unlocked — both the default selection and the explicit second ID:
   **exit 0** with `collection <id> is already unlocked; password was not
   checked` while stdin is `/dev/null`. This is a no-read proof: the `--stdin`
   reader rejects end-of-input as unterminated and would exit 1, so exit 0
   demonstrates the CLI trusted its pre-resolved lock state and consumed no
   secret. Lock state stays unlocked.
5. `gmellon unlock gmellon-cli-missing --stdin` **exits 1** with the
   actionable `collection ID does not exist: gmellon-cli-missing` diagnostic on
   stderr and empty stdout, and the login password supplied on stdin appears
   in neither stream.

One proof run performs 17 binary invocations (list determinism, per-stage
lock-state listings, and the unlock calls). Wire evidence: a match-filtered
`busctl monitor` observed exactly the fixture's two `Service.Lock` calls, both
attributed to the fixture connection's unique name — no CLI path emits a
standard Lock call, so nothing locks or relocks.

## Secret handling

Four passwords are generated per run (login, second, wrong, login-two) as
32-byte printable values, zeroized on drop. Every captured CLI stdout/stderr
is scanned for all four immediately after each invocation, and the final scan
reads every regular file present beneath the retained harness root —
including the redacted `rust-cli-proof.txt` and monitor summary — failing
closed on any symlink. Observed `artifact_scan=passed`.

## Limitations

- The plain Secret Service session remains the documented MVP limitation:
  password bytes cross the private bus without Secret Service encryption, and
  zbus/broker message copies are outside gmellon's zeroization control
  (`gmell-encrypted-session` tracks the release blocker).
- The already-unlocked no-read claim is established for the `--stdin` path by
  the guaranteed-failing stdin plus exit 0; the TTY path is covered by the
  `secret_input` seam's unit tests, not by a live terminal.
- Exit codes 3 (private interface unavailable) and 4 (service unavailable)
  are unit-covered in `src/cli/mod.rs` (`service_errors_map_to_stable_exit_codes`);
  this proof does not force those daemon-side conditions.
- No `change` coverage: the change subcommand is deliberately unimplemented
  (`gmell-change`) and this proof stops at list/unlock.

## Environment

Observed 2026-09-12 on the development host: gnome-keyring-daemon 48.0,
dbus-broker 37, systemd 261, rustc 1.96.0-nightly. Entry points verified:
`dev/harness/check rust-cli` (repeatedly), `dev/harness/check all`, ordinary
`cargo nextest run` (visible skip), `cargo fmt --all -- --check`, `cargo clippy
--all-targets --all-features -- -D warnings`, and `cargo doc --no-deps`.
Prerequisite failure exits 125 with actionable guidance (demonstrated by
removing `python3` from PATH).
