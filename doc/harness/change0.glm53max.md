---
type: Evidence
title: Collection change CLI binary proof under the private broker harness
description: Installed-host evidence that the compiled gmellon binary's change subcommand meets its contract against isolated exact-login plus second fixtures — three-line stdin semantics, exit 1 without any private change call on input rejection, exit 2 with the old password surviving, exact and default-collection rotations proven by former-denied/new-accepted transitions, and fixture-only locking.
resource: /doc/harness/change0.glm53max.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, cli, change]
status: draft
generated: { by: model:zai/glm-5.3-max, at: 2026-09-12T04:20:00-04:00 }
verified: { by: model:zai/glm-5.3-max, at: 2026-09-12T04:20:00-04:00 }
stale_after: 2027-03-12
sources:
  - id: rust-proof
    resource: /tests/harness/broker_cli.rs
    title: Maintained opt-in Rust CLI binary proof (list/unlock/change)
  - id: shared-machinery
    resource: /tests/harness/broker_common.rs
    title: Shared fixture, method monitors, secrets, and runner
  - id: cross-proof-helpers
    resource: /tests/harness/common/mod.rs
    title: Shared environment/secret/scan helpers with reversible-encoding checks
  - id: broker-lifecycle
    resource: /dev/harness/broker.py
    title: Reusable private dbus-broker harness lifecycle
  - id: check-entry
    resource: /dev/harness/check
    title: Explicit rust-cli check mode (unchanged by this proof)
  - id: product-cli
    resource: /src/cli/mod.rs
    title: Committed CLI under proof (collection change commits 3c5e6ca1/e5c35e51)
  - id: cli-evidence
    resource: /doc/harness/cli0.glm53max.md
    title: List/unlock CLI binary proof this extends
  - id: collections-evidence
    resource: /doc/harness/collections0.glm53max.md
    title: Multi-collection BlockingClient proof (unlocked-change precedent)
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

# Collection change CLI binary proof under the private broker harness

## Result

[`tests/harness/broker_cli.rs`](/tests/harness/broker_cli.rs) now covers the
`change` subcommand of the actual compiled binary (observed
`target/debug/gmellon`, located through `CARGO_BIN_EXE_gmellon`) inside
[`dev/harness/broker.py`](/dev/harness/broker.py). The explicit entry point
is unchanged — `dev/harness/check rust-cli` — and ordinary
`cargo test` / `cargo nextest run` visibly skip the ignored proof
(68 passed, 4 skipped). Python remains lifecycle and check wiring only; every
assertion is Rust against the binary.

The fixture (shared through
[`broker_common.rs`](/tests/harness/broker_common.rs)) creates the exact
`login` collection plus a tagged second collection under distinct generated
passwords and locks both. Five secrets are generated per run (login `L`,
second `A`, second-rotated `B`, wrong `W`, login-rotated `L2`), all
zeroized on drop.

Observed binary behavior (committed [`src/cli/mod.rs`](/src/cli/mod.rs),
change commits `3c5e6ca1` plus README `e5c35e51`):

1. **Mismatched confirmation** (`gmellon change <second-id> --stdin` with
   current `A`, new `B`, confirmation `W`): **exit 1**, stderr explains
   `the two entered secrets do not match`, stdout empty, collection still
   listed locked, and the original password still unlocks after a
   fixture-only lock — the mismatch changed nothing.
2. **No private call on input rejection** — wire evidence, see below:
   exactly three `ChangeWithMasterPassword` method calls were observed for
   the whole run, matching exactly the three legitimate ones; none of the
   rejected invocations (mismatch, truncated inputs, missing ID) reached
   the daemon.
3. **Wrong current password** (`W`/`B`/`B`): **exit 2** with a `denied`
   diagnostic, collection stays locked, and the original password still
   unlocks afterward.
4. **Successful explicit rotation** (`A`/`B`/`B`): **exit 0** with
   `changed password for collection <second-id>`. Observed daemon 48.0
   behavior: the change succeeds on the *locked* collection and leaves it
   locked. After that state, the former password `A` is denied (exit 2) and
   the new password `B` unlocks (exit 0). The sibling `login` collection
   still unlocks with its untouched original password `L`.
5. **Omitted collection defaults to login** (`gmellon change --stdin` with
   `L`/`L2`/`L2`): **exit 0** with `changed password for collection login`,
   stays locked, then `L` is denied (default-selection unlock, exit 2) and
   `L2` unlocks (exit 0).
6. **Missing collection before reading stdin**
   (`gmellon change gmellon-cli-missing --stdin` with `/dev/null` stdin):
   **exit 1**, stderr names `collection ID does not exist:
   gmellon-cli-missing`, stdout empty. Because any stdin read on
   `/dev/null` would fail the `--stdin` contract with an
   `without a newline` diagnostic and preempt the collection error, the
   observed not-found diagnostic proves resolution happened first and no
   input was consumed.
7. **Fewer than three terminated lines** — empty stdin, two terminated
   lines, and an unterminated confirmation each **exit 1** with the
   unterminated-input diagnostic on stderr, empty stdout, and (per the
   monitor count) no D-Bus change.

One proof run performs 38 binary invocations (list determinism, per-stage
lock-state listings, unlock and change calls).

## Wire evidence

Two match-filtered `busctl monitor` instances run for the whole proof, both
armed before any fixture traffic:

- The existing **Lock monitor** (`Service.Lock`, unchanged match rule that
  excludes every password-bearing body) observed exactly the fixture's 7
  `Lock` calls, every one attributed to the fixture connection's unique
  name — no CLI path locks or relocks, including around changes.
- The new **change-call monitor** matches only
  `ChangeWithMasterPassword` method calls. This rule necessarily selects
  password-bearing bodies (that is where the secrets travel), and on this
  host busctl renders matched bodies decoded — `ay` arrays as one decimal
  `BYTE <n>;` line per byte — so its raw log is password-bearing in a
  reversible encoding. The proof therefore retains only header-derived
  evidence (count and sender unique names), scans the raw and readiness
  logs for every secret in literal, hex, and byte-dump form, and deletes
  the raw log — including on failure paths, where the monitor's `Drop`
  removes it rather than retaining recoverable password dumps.

  The counting argument is closed: observed calls = 3, one per legitimate
  invocation (the denied wrong-current attempt is forced by its exit 2 plus
  `denied` reply source; each successful rotation is forced by the
  observed former-denied/new-accepted password transition), zero from the
  fixture connection. Any input-rejected invocation reaching the daemon
  would raise the count above 3; a silently broken monitor would read 0.

## Secret handling

Every captured CLI stdout/stderr is scanned after each invocation, and the
final scan reads every regular file present beneath the retained harness
root, for **all five** generated values in three forms each: literal bytes,
contiguous hex (either case), and reconstructed decimal byte dumps; any
symlink fails the proof. Observed `artifact_scan=passed` with the redacted
`rust-cli-proof.txt`, `lock-monitor.txt`, and `change-monitor.txt`
summaries retained and the raw change log absent.

## Limitations

- The plain Secret Service session remains the documented MVP limitation:
  password bytes cross the private bus without Secret Service encryption,
  and the change-call monitor transiently holds decoded copies in its raw
  log before deleting it (`gmell-encrypted-session` tracks the release
  blocker).
- The locked-change observation (succeeds while locked, stays locked) is
  daemon-48.0 evidence, recorded per this run; it must not be generalized
  into an unqualified upstream guarantee.
- The TTY prompting path for `change` is covered by the `secret_input`
  seam's unit tests, not by a live terminal; this proof drives `--stdin`
  only.
- Exit codes 3 (private interface unavailable) and 4 (service unavailable)
  remain unit-covered in `src/cli/mod.rs`; this proof does not force those
  daemon-side conditions.
- The change monitor cannot map its three observed sender unique names to
  individual invocations; the no-call claim rests on the closed counting
  argument above, not on per-invocation attribution.

## Environment

Observed 2026-09-12 on the development host: gnome-keyring-daemon 48.0,
dbus-broker 37, systemd 261 (busctl monitor), rustc 1.96.0-nightly. Entry
points verified: `dev/harness/check rust-cli` (five consecutive passes plus
one retained `--keep-success` run), `dev/harness/check rust-broker`
(regression for the shared monitor refactor), ordinary `cargo nextest run`
(visible skip), `cargo fmt --all -- --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, and `cargo doc --no-deps`. No product bug
was found: every observed exit, message, and lock-state transition matched
the committed implementation, so no `src/cli` or `secret_service` change
was needed.
