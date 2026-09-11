---
type: Evidence
title: Installed control-protocol behavior matrix
description: Version-scoped UNLOCK, CHANGE, restart-persistence, empty-password, and transport-fault observations from the isolated control-only harness.
resource: /doc/harness/behavior0.gpt6a.md
tags: [gmellon, harness, gnome-keyring, control-protocol, integration-test]
status: draft
generated: { by: model:openai/gpt-6-astra, at: 2026-09-11T19:19:46-04:00 }
verified: { by: model:openai/gpt-6-astra, at: 2026-09-11T19:19:46-04:00 }
stale_after: 2027-03-11
sources:
  - id: harness-contract
    resource: /doc/harness/prompt.md
    title: Isolated GNOME Keyring harness
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
  - id: behavior-probe
    resource: /dev/harness/behavior.py
    title: Reproducible control-only behavior probe
---

# Installed control-protocol behavior matrix

## Result

[`dev/harness/behavior.py`](/dev/harness/behavior.py) passed against installed
`gnome-keyring-daemon` 48.0 (`testing: enabled`) on Debian forky/sid,
Linux 7.1.0-debplus.1 x86-64 with glibc 2.43 and Python 3.14.6:

```text
PASS: installed control-protocol behavior matrix
  core-change: observed (2 daemon generations)
  missing-change: observed (2 daemon generations)
  empty-unlock: observed (3 daemon generations)
  transport-faults: observed (2 daemon generations)
  redaction: generated passwords and request frames absent from artifacts
  boundary: control socket only; no Secret Service calls
```

These results characterize this installed binary and platform. They are not an
unqualified promise about every GNOME Keyring version.

## Observed matrix

All result names below came from complete eight-byte control responses except
the two deliberately induced local transport outcomes.

| Initial store / transition | Operation | Observation |
| --- | --- | --- |
| Missing | `UNLOCK(A)` | `OK`; created `login.keyring` and `user.keystore` |
| Existing A, still live | `UNLOCK(A)` | `OK` |
| Existing A, still live | `UNLOCK(wrong)` | `DENIED` |
| Existing A | `CHANGE(A, empty)` | `DENIED`; A still unlocked successfully afterward |
| Existing A | `CHANGE(A, B)` | `OK` |
| Same private store, new owned daemon | `UNLOCK(B)` | `OK` |
| Same private store, new owned daemon | `UNLOCK(A)` | `DENIED` |
| Same private store, new owned daemon | `UNLOCK(empty)` | `DENIED` |
| Missing | `CHANGE(arbitrary-original, empty)` | `DENIED`; no login store was created |
| Still missing | `CHANGE(arbitrary-original, new)` | `OK`; created both login files |
| Same private store, new owned daemon | `UNLOCK(new)` | `OK` |
| Same private store, new owned daemon | `UNLOCK(arbitrary-original)` | `DENIED` |
| Missing | `UNLOCK(empty)` | `OK`; created both login files |
| Same empty-password store, new owned daemon | `UNLOCK(empty)` | `OK` |
| Empty-password store | `UNLOCK(nonempty)` | `DENIED` |
| Empty-password store | `CHANGE(empty, nonempty)` | `OK` |
| Same private store, new owned daemon | `UNLOCK(nonempty)` | `OK` |
| Re-keyed store | `UNLOCK(empty)` | `DENIED` |
| Supervisor has stopped and reaped daemon | Attempted `UNLOCK` | local `NO_DAEMON`; control socket absent |
| Exact daemon PID confirmed in SIGSTOP state | Attempted `UNLOCK` | local response timeout at 0.35 seconds |
| Exact daemon resumed | `UNLOCK(correct)` | `OK` |

The missing-store `CHANGE` result is especially important: for a nonempty new
password, this binary creates the login keyring and does not require the
supplied original value to match anything. A missing-store `CHANGE` with an
empty new password is denied and leaves the store absent.

## Evidence versus source corroboration

The matrix above is behavioral evidence from socket exchanges with the
installed binary. The local upstream checkout at commit
`5866520fa52c824c29e41b93153ef42b714a1716` independently explains, but did not
substitute for, those observations:

- [`daemon/control/gkd-control-server.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/control/gkd-control-server.c)
  maps successful login helpers to `OK` and other helper outcomes to `DENIED`.
- [`daemon/login/gkd-login.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/login/gkd-login.c)
  contains the unlock-or-create and change-or-create paths and rejects an empty
  new CHANGE password.
- [`egg/egg-unix-credentials.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/egg/egg-unix-credentials.c)
  consumes the separate credential NUL and retrieves peer credentials.
- [`daemon/gkd-main.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/gkd-main.c)
  removes the control socket during owned daemon shutdown and documents the
  initialization-stdout EOF signal reused by the harness.

The stopped and unresponsive labels are local product-transport
classifications, not daemon result codes: the stopped case fails before a
request can be sent, while the SIGSTOP case connects and sends but receives no
response before the probe deadline.

## Restart and fault topology

Each of the four scenarios receives its own unique mode-0700 sandbox and store.
Within a scenario, all daemon generations use exactly the same private HOME,
XDG data, runtime, control, and poisoned-bus paths. A restart is an explicit
behavior-owned supervisor transition:

1. verify the current exact child is still live;
2. send TERM to that PID;
3. apply the lifecycle's bounded TERM/KILL/reap machinery;
4. require evidence that TERM was supervisor-initiated and shutdown status was
   expected;
5. launch a new direct child over the unchanged private store; and
6. repeat initialization EOF, reported-path, liveness, socket-type, and socket
   owner readiness checks before probing again.

The lifecycle executable's public command contract did not gain root seeding,
root reuse, signals, or an RPC surface. Instead, the sibling behavior runner
uses a documented-as-internal readiness/owned-stop seam in
[`lifecycle.py`](/dev/harness/lifecycle.py). This keeps the transition close to
the only client that needs it and avoids making unstable Python names a public
integration contract. Product integration should continue to invoke
executables, not import these names.

For fault observations, the same behavior supervisor stops one exact daemon
generation and later starts another. It suspends the second generation using
SIGSTOP, positively observes `/proc/<pid>/status` enter the stopped state,
runs the bounded exchange, sends SIGCONT in `finally`, positively observes the
process leave the stopped state, and proves a correct UNLOCK succeeds. Cleanup
also resumes a suspended daemon before normal owned termination. Arbitrary
premature exit remains failure: the shared owned-stop validator still rejects
any daemon for which the supervisor did not send TERM.

## Isolation and secret handling

Every daemon environment is assembled from an empty map with private HOME,
XDG, runtime, temporary, and control paths. Session and system bus addresses
point to nonexistent sockets under the sandbox. No broker is launched and no
Secret Service call is made. Reported paths, expected login files, socket type,
socket UID, exact peer PID/UID, and an external sentinel are checked.

All nonempty passwords are fresh printable non-NUL values generated by
`os.urandom()` inside the narrow probe. They never cross argv or the
environment. The probe registers each generated password and complete
password-bearing request frame before exchange, emits only operation/result
labels, scans **every regular retained file** under each scenario root after
owned cleanup, and overwrites its mutable password/frame buffers before
return. `behavior.json` records the scan as pending until that scan succeeds,
then rewrites only the marker to `true`; a retained failed run therefore cannot
self-attest successful redaction. Five consecutive complete runs plus the
black-box retained-artifact test passed this scan. Python and allocator copies
remain best-effort rather than a memory-erasure guarantee.

## Reproduction and verification

```sh
python3 -m py_compile \
  dev/harness/behavior.py \
  dev/harness/lifecycle.py \
  dev/harness/tests/test_behavior.py \
  dev/harness/tests/test_lifecycle.py
python3 -m unittest -v \
  dev/harness/tests/test_behavior.py \
  dev/harness/tests/test_lifecycle.py
dev/harness/behavior.py
dev/harness/smoke.py
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run
```

At the recorded checkpoint, Python compilation passed; the combined behavior
and lifecycle suite ran 10 tests with 10 passed; the behavior matrix and
unchanged smoke probe passed; Rust formatting and Clippy with warnings denied
passed; and nextest ran 54 tests with 54 passed and no skips.

Use `dev/harness/behavior.py --keep-success` to retain four scenario roots.
Each contains `behavior.json`, `cleanup.json`, daemon logs, and its private
store. The black-box test checks the required matrix fields, installed context,
no-Secret-Service marker, artifact-scan marker, and reaping of every recorded
daemon generation, then removes only its exact retained roots.

## Unresolved risks and next slice

- The behavior runner's SIGSTOP confirmation uses Linux `/proc` and the control
  probe uses Linux `SO_PEERCRED`; this is intentionally consistent with the
  product's current Linux-only synchronous transport.
- The 0.35-second fault deadline characterizes a deliberately stopped local
  process, not a general production timeout recommendation. The Rust transport
  currently defaults to five seconds.
- Configuration/session isolation is not filesystem or process-namespace
  confinement; the external sentinel remains a regression tripwire rather
  than a sandbox boundary.
- Real-daemon coverage is still a developer command and Python test. The next
  coherent slice is `gmell-harness-integration`, which should expose explicit
  opt-in/missing-tool policy and connect the reviewed Rust transport/product
  tests to executable harness contracts without importing Python internals.

## Cross-references

- [`/doc/harness/README.md`](/doc/harness/README.md) is the durable operator and
  architecture guide for the lifecycle and this behavior runner.
- [`/doc/harness/lifecycle0.gpt6a.md`](/doc/harness/lifecycle0.gpt6a.md) records
  the predecessor readiness, isolation, signal, and teardown evidence reused
  here.
- [`/doc/harness/smoke0.gpt6a.md`](/doc/harness/smoke0.gpt6a.md) records the
  original fresh-UNLOCK and wrong-password observation now broadened by this
  matrix.
- [`/README.md`](/README.md) states the product behavior and safety consequences
  supported by these installed-binary observations.
