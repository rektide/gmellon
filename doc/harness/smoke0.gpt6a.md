---
type: Evidence
title: Isolated control-socket smoke result
description: Observed startup, isolation, protocol, and teardown behavior for the first real-daemon harness proof.
resource: /doc/harness/smoke0.gpt6a.md
tags: [gmellon, harness, gnome-keyring, integration-test]
status: draft
generated: { by: model:openai/gpt-6-astra, at: 2026-09-11T17:13:31-04:00 }
verified: { by: model:openai/gpt-6-astra, at: 2026-09-11T17:23:56-04:00 }
stale_after: 2027-03-11
sources:
  - id: harness-contract
    resource: /doc/harness/prompt.md
    title: Isolated GNOME Keyring harness
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
---

# Isolated control-socket smoke result

## Result

[`dev/harness/smoke.py`](/dev/harness/smoke.py) passed against the installed
`gnome-keyring-daemon` 48.0 on Linux 7.1.0-debplus.1 with Python 3.14.6.

```text
PASS: isolated control-socket smoke path
  readiness: stdout EOF + live child + owned Unix socket
  protocol: fresh UNLOCK OK; wrong UNLOCK DENIED
  isolation: configured paths under scratch; external sentinel unchanged
  lifecycle: owned process group terminated and reaped
```

The retained representative run used a unique mode-0700 root beneath
`/home/rektide/tmp-opencode`. The daemon reported only its selected private
control directory on stdout. Its stderr contained two expected failures to
connect to the deliberately nonexistent session-bus socket. It remained alive
and served the private control socket after those failures.

The first credential-prelude plus UNLOCK exchange created both
`data/keyrings/login.keyring` and `data/keyrings/user.keystore` beneath the
scratch root. A second connection using a different password returned DENIED.
The probe enumerated all observed scratch artifacts, resolved each path
beneath the scratch root, and validated every path-valued variable reported by
the daemon. It scanned stdout, stderr, evidence, and cleanup records for both
generated values and their complete request frames before declaring that no
password or frame had been retained.

One development rerun initially returned FAILED because the disposable probe
generated arbitrary bytes and occasionally included NUL, which is invalid in
the protocol's C-string representation. The probe now maps randomness into
printable non-NUL bytes and checks this invariant before sending. This was a
probe defect rather than nondeterministic daemon behavior.

After TERM, `cleanup.json` recorded daemon status 0, no KILL fallback, and the
absence of the complete process group; the launched PID was also absent from
`/proc`. A normal run without `--keep-success` left no new `gmell-h-*` scratch
root or `gmell-sentinel-*` file. The committed `--self-test-failure` mode
reproduced failure cleanup, retained both logs, and recorded the process group
as gone:

```text
retained scratch: /home/rektide/tmp-opencode/gmell-h-f_52dlyp
retained sentinel: /home/rektide/tmp-opencode/gmell-sentinel-lpzbpagm
FAIL: injected post-readiness failure
PASS: committed failure mode retained logs and reaped process group 715523
```

A separate live test sent SIGTERM to the harness after its control socket
appeared. The harness returned 143, retained both daemon logs, sent TERM to its
owned process group, verified that group disappeared, and reaped daemon PID
718184. Unexpected Python programming failures retain the same resources but
are not converted into terse expected-failure output; their traceback remains
visible.

## Isolation boundary

The daemon child received an environment constructed from an empty map. It
contained private `HOME`, `TMPDIR`, and XDG paths, explicit nonexistent
session and system bus addresses, locale settings, and a fixed executable
search path. Consequently, inherited `LISTEN_*`, `NOTIFY_SOCKET`,
`GNOME_KEYRING_CONTROL`, `SSH_AUTH_SOCK`, `DBUS_STARTER_*`, desktop-autostart,
and session identifiers were absent.

The run established **configuration and session isolation**, not filesystem
confinement. Known writable paths and observed artifacts stayed beneath the
scratch root, and an owned sentinel outside that root remained unchanged
before and after teardown. That sentinel is a regression tripwire, not proof
that arbitrary external filesystem writes are impossible.

The installed binary reports `testing: enabled`, but the probe did not set
`GNOME_KEYRING_TEST_PATH`; the successful storage redirection therefore used
the production XDG path selection needed by later `--allow-create` tests.

## Commands

```sh
python3 -m py_compile dev/harness/smoke.py
dev/harness/smoke.py --keep-success
dev/harness/smoke.py
dev/harness/smoke.py --self-test-failure
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run
```

The Python syntax check, retained and normal-cleanup invocations, five
consecutive smoke invocations, deterministic failure injection, and live
SIGTERM injection passed their expected outcomes. After concurrent
control-transport work settled, formatting and Clippy passed and nextest ran
28 tests successfully with no skips. The earlier transient Clippy compilation
failure was unrelated to the harness files and was not reproduced at the
ticket checkpoint.

## Cross-references

- [`/doc/harness/prompt.md`](/doc/harness/prompt.md) defines the safety
  invariants this run exercises and keeps reusable lifecycle work in the next
  ticket.
- [`/README.md`](/README.md) explains why the private control protocol is the
  product's required headless unlock path and why fresh UNLOCK creation needs
  an application-level guard.
- [GNOME Keyring `daemon/gkd-test.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/gkd-test.c)
  is the upstream precedent for treating initialization stdout EOF as a
  readiness signal.
- [GNOME Keyring `daemon/login/gkd-login.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/login/gkd-login.c)
  is the source-level precedent for unlock-or-create behavior; this run adds
  installed-binary evidence.
