---
type: Evidence
title: Durable real-daemon test integration result
description: Executable-entry-point, opt-in, prerequisite, Rust transport, parallel-isolation, and retained-artifact evidence for the maintained GNOME Keyring harness.
resource: /doc/harness/integration0.gpt6a.md
tags: [gmellon, harness, gnome-keyring, rust, integration-test, nextest]
status: draft
generated: { by: model:openai/gpt-6-astra, at: 2026-09-11T19:40:41-04:00 }
verified: { by: model:openai/gpt-6-astra, at: 2026-09-11T19:41:13-04:00 }
stale_after: 2027-03-11
sources:
  - id: harness-contract
    resource: /doc/harness/prompt.md
    title: Isolated GNOME Keyring harness
  - id: lifecycle-contract
    resource: /dev/harness/lifecycle.py
    title: Executable isolated-daemon lifecycle
  - id: rust-transport
    resource: /src/control/sync.rs
    title: Synchronous GNOME Keyring control transport
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
---

# Durable real-daemon test integration result

## Result

[`tests/harness/real_daemon.rs`](/tests/harness/real_daemon.rs) adds two normal
Rust integration tests marked `#[ignore]`. When explicitly selected, each
outer test validates all external prerequisites, invokes the executable
[`dev/harness/lifecycle.py`](/dev/harness/lifecycle.py) interface, and re-runs
only itself as the lifecycle command. The inner invocation consumes exported
paths and exercises the public `gmellon::control::SyncClient`; no Rust code
imports Python names, starts the daemon, builds an alternate child environment,
or owns harness cleanup.

[`dev/harness/check`](/dev/harness/check) composes maintained `rust-cargo`,
`rust-nextest`, `python`, and `all` modes without duplicating lifecycle
orchestration. Explicit modes preflight tools and hard-fail with status 125;
direct Cargo/nextest selection makes a missing tool fail the selected Rust
test. Ordinary Rust workflows need none of those tools and visibly omit the
two ignored cases.

## Rust paths exercised

Two independent fresh-daemon cases run in parallel safely:

| Case | Public transport observations |
| --- | --- |
| `real_daemon_unlock_uses_the_reviewed_transport` | missing-store UNLOCK returns OK; private login files appear; repeated correct UNLOCK returns OK; wrong UNLOCK returns DENIED |
| `real_daemon_change_uses_the_reviewed_transport` | fixture UNLOCK returns OK; CHANGE A-to-B returns OK; B unlocks; former A is denied |

This is the coherent product-relevant seam before unlock/change CLI behavior
exists. The Rust adapter supplies the credential byte, frame codec, socket and
peer UID validation, fresh connection per operation, and response parsing.
Restart persistence and stopped/SIGSTOP behavior remain with `behavior.py`,
whose supervisor owns those transitions; the integration work did not add CLI
implementation or broker parity.

## Visible omission and requested-run failure

Normal Cargo output was:

```text
running 2 tests
test real_daemon_change_uses_the_reviewed_transport ... ignored, requires explicit real-daemon harness run; see doc/harness/README.md
test real_daemon_unlock_uses_the_reviewed_transport ... ignored, requires explicit real-daemon harness run; see doc/harness/README.md

test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
```

A narrowed normal nextest discovery reported `2 tests skipped`; the required
full ordinary run reports those same skips alongside pure tests. Selecting
only this ignored binary without `--run-ignored` returns nextest's expected
"no tests to run" status, so operators should use the documented full ordinary
command or explicit ignored-only command rather than treating that narrowed
selection as a passing suite.

The explicit nextest run was:

```text
Starting 2 tests across 1 binary
PASS gmellon::real_daemon real_daemon_unlock_uses_the_reviewed_transport
PASS gmellon::real_daemon real_daemon_change_uses_the_reviewed_transport
Summary 2 tests run: 2 passed, 0 skipped
```

The normal Cargo convention also ran both explicit cases with 2 passed and 0
ignored. A deterministic missing-Python simulation demonstrated the wrapper's
hard-failure classification:

```text
HARNESS PREREQUISITE FAILURE: python3 was not found on PATH; install Python 3 and make `python3` available
exit=125
```

The same preflight contains actionable branches for absent/non-runnable
`gnome-keyring-daemon`, lifecycle executable, Cargo, cargo-nextest, and
`/dev/urandom`. The Rust test independently validates runtime prerequisites so
direct conventional commands cannot bypass the hard-failure policy. There is
no unavailable-tool early return or dynamic ignore.

## Isolation, ownership, and redaction

A retained parallel nextest run produced two different mode-0700 roots and
daemon PIDs. In each root:

- both bus addresses named nonexistent sockets under that root;
- every HOME/XDG/control/log/evidence path consumed by Rust was beneath it;
- `SSH_AUTH_SOCK`, `NOTIFY_SOCKET`, and D-Bus starter state were absent;
- the login files were beneath private `XDG_DATA_HOME`;
- `rust-integration.txt` named only the operation path, public Rust transport,
  secret count, and `artifact_scan=passed`;
- generated 32-byte printable passwords lived in `Zeroizing<Vec<u8>>`, never
  crossed argv/environment/output, and were absent from every regular file in
  the retained root; and
- `cleanup.json` recorded the exact test command reaped at status 0 and the
  exact daemon TERM'd and reaped at status 0, with no KILL fallback.

Representative redacted evidence was:

```text
mode=700 /home/rektide/tmp-opencode/gmell-h-<unique>/
path=unlock
transport=gmellon::control::SyncClient
secret_values=2
artifact_scan=passed
isolation=configuration-and-session
children=[(command, reaped=true, status=0), (daemon, sent_term=true, sent_kill=false, reaped=true, status=0)]
```

The scan occurs before marking it passed. Lifecycle cleanup is written after
the inner process exits and contains process metadata only; lifecycle focused
tests separately enforce that evidence/cleanup/log artifacts omit explicit
passed values. As before, this is configuration/session isolation and
best-effort memory clearing, not filesystem confinement or a memory-erasure
proof.

## Commands and policy

The maintained commands are:

```sh
dev/harness/check rust-nextest
dev/harness/check rust-cargo
dev/harness/check python
dev/harness/check all
```

Direct equivalents, static checks, and complete verification are documented in
[`/doc/harness/README.md`](/doc/harness/README.md#running-harness-checks).
There is no tracked CI configuration. The documented policy therefore does not
claim a job exists: ordinary environments run pure tests with two visible
skips, while a separately provisioned Linux capability runs
`dev/harness/check all` and treats missing tools as setup failure.

At this checkpoint, both explicit Rust modes passed two tests; the Python mode
compiled five files, passed 10 focused tests, and passed both the complete
behavior matrix and smoke proof. `sh -n dev/harness/check`, rustfmt, and Clippy
over all targets/features with warnings denied passed. Full `cargo test` passed
54 unit/binary tests plus two doctests and visibly ignored the two integration
tests. Full `cargo nextest run` reported:

```text
Starting 54 tests across 3 binaries (2 tests skipped)
Summary 54 tests run: 54 passed, 2 skipped
```

## Unresolved risks and next slice

- The integration tests deliberately target Linux because `SyncClient` and
  daemon peer credentials are Linux-only. Ordinary non-Linux discovery remains
  visible through ignored test declarations; explicit selection fails.
- The executable test recursion relies on libtest-compatible arguments. It
  passed both Cargo and nextest at this revision, but custom future test
  harnesses must preserve that command contract or introduce a dedicated
  compiled probe binary.
- Success cleanup happens after the inner artifact scan. The cleanup record's
  schema and redaction remain lifecycle-owned and covered by focused Python
  tests rather than reparsed by Rust.
- Configuration/session isolation still permits cooperative test code to use
  the caller's filesystem authority; no namespace confinement was added.

The next coherent core ticket is `gmell-harness-docs`: reconcile and close the
core harness after parent acceptance, without pulling in optional broker parity
or product unlock/change implementation.

## Cross-references

- [`/doc/harness/lifecycle0.gpt6a.md`](/doc/harness/lifecycle0.gpt6a.md)
  establishes the executable environment, exact-child ownership, readiness,
  retention, and signal semantics reused rather than reimplemented here.
- [`/doc/harness/behavior0.gpt6a.md`](/doc/harness/behavior0.gpt6a.md) supplies
  broader installed-daemon restart, empty-password, and fault observations;
  those transitions intentionally remain outside the one-daemon lifecycle.
- [`/README.md`](/README.md) defines the eventual product paths. This ticket
  validates their reviewed Rust transport substrate but does not implement the
  unlock or change CLI.
