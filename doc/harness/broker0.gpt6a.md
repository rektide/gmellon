---
type: Evidence
title: Private dbus-broker lifecycle and GNOME interface proof
description: Installed-host evidence for the reusable isolated bus, daemon name ownership, plain Secret Service session, measured collection lock-state stability, private interface, exact process teardown, and launcher controller constraints.
resource: /doc/harness/broker0.gpt6a.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, zbus]
status: draft
generated: { by: model:openai/gpt-6-astra, at: 2026-09-11T20:49:12-04:00 }
verified: { by: model:openai/gpt-6-astra, at: 2026-09-11T20:49:12-04:00 }
stale_after: 2027-03-11
sources:
  - id: broker-lifecycle
    resource: /dev/harness/broker.py
    title: Reusable private dbus-broker harness lifecycle
  - id: interface-probe
    resource: /dev/harness/private_bus_probe.py
    title: Plain Secret Service session and private-interface probe
  - id: harness-contract
    resource: /doc/harness/prompt.md
    title: Isolated GNOME Keyring harness
  - id: gnome-private-interface
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/daemon/dbus/org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.xml
    title: GNOME Keyring private D-Bus interface declaration
  - id: installed-broker
    resource: package:dbus-broker@37
    title: Installed dbus-broker-launch 37
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
  - id: dbus-broker-launcher
    resource: https://github.com/bus1/dbus-broker/blob/v37/src/launch/launcher.c
    title: dbus-broker 37 launcher.c (launcher_connect, launcher_subscribe, launcher_on_child_exit)
  - id: systemd-socket-activate
    resource: https://github.com/systemd/systemd/blob/v261/src/socket-activate/socket-activate.c
    title: systemd 261 socket-activate.c exec_process environment whitelist
  - id: systemd-sd-bus
    resource: https://github.com/systemd/systemd/blob/v261/src/libsystemd/sd-bus/sd-bus.c
    title: systemd 261 sd-bus.c bus_set_address_system
  - id: secret-service-spec
    resource: https://specifications.freedesktop.org/secret-service/latest/
    title: Secret Service API 0.2 draft (Service.Collections, Collection.Locked)
---

# Private dbus-broker lifecycle and GNOME interface proof

## Result

[`dev/harness/broker.py`](/dev/harness/broker.py) now provides a reusable
private-bus sibling to the control-only lifecycle. It creates a unique
mode-0700 root, starts a socket-activated `dbus-broker-launch --scope=system`
with a minimal config, manually launches `gnome-keyring-daemon`, proves the
private bus and daemon name ownership, and runs one command with an explicit
`DBUS_SESSION_BUS_ADDRESS=unix:path=<root>/bus`.

The delivered boundary is **configuration and session isolation**, not total
host independence. No command, daemon, or probe receives the real session-bus
address. The daemon and command receive an unreachable private system-bus
path. The bus config contains no service directories or includes, and
`ListActivatableNames` returned only `org.freedesktop.DBus`; the harness, not
D-Bus activation, starts the daemon. That pair — zero service directories plus
the `ListActivatableNames` result — is the entire measured proof that no host
D-Bus service activation exists.

The launcher itself is **not** isolated from host manager machinery, and the
harness no longer claims otherwise: `dbus-broker-launch` connects its
libsystemd controller to the real system bus and subscribes to the host
systemd manager (see [Launcher controller
boundary](#launcher-controller-boundary)). Launcher contact with host systemd,
journald, and the system bus is a required, preflight-checked host dependency
of this topology.

This is the lifecycle/private-interface checkpoint only. It does not create a
multi-collection fixture, call a password method, run product zbus behavior,
or implement a CLI.

## Observed host

The proof ran on:

```text
Linux 7.1.0-debplus.1 x86_64
Python 3.14.6
dbus-broker-launch 37
systemd-socket-activate 261 (systemd 261.2-1)
gnome-keyring-daemon 48.0 (testing enabled)
```

The host exposed `/run/systemd/journal/socket` and
`/run/dbus/system_bus_socket` as sockets and `/run/systemd/system` as a
directory. The maintained mode preflights all three and fails rather than
claiming portability when any launcher dependency is absent.

## Listener, launcher, and activation evidence

`dbus-broker-launch` does not create its listener. The successful composition
was:

```text
systemd-socket-activate --listen=<root>/bus \
  dbus-broker-launch --scope=system --config-file=<root>/bus.conf
```

The activator reported:

```text
Listening on <root>/bus as 3.
Communication attempt on fd 3.
Executing: /usr/bin/dbus-broker-launch --scope=system --config-file=<root>/bus.conf
```

On the first explicitly addressed bus call,
`systemd-socket-activate` exec'd `dbus-broker-launch` without changing PID.
The launcher then had exactly one child whose executable was
`/usr/bin/dbus-broker`. `/proc/net/unix` and exact `/proc/<pid>/fd` links showed
the same listener kernel inode at launcher FD 3 and broker FD 6. A retained
successful run recorded, with identifiers redacted here:

```text
root=<unique mode-0700 scratch>
bus=<root>/bus mode=0600 owner=<effective uid>
broker-launcher={pid=<launcher>, parent=<supervisor>, executable=/usr/bin/dbus-broker-launch}
broker={pid=<broker>, parent=<launcher>, executable=/usr/bin/dbus-broker}
listener_fd_holders={broker-launcher:[3], broker:[6]}
activatable_names=[org.freedesktop.DBus]
```

The listener initially appeared as 0644 on this installed
`systemd-socket-activate` despite the supervisor's umask. The harness tightens
it to 0600 before making the first connection; its parent directory is already
0700.

## Launcher controller boundary

The harness's `DBUS_SYSTEM_BUS_ADDRESS` **cannot** steer the launcher's
controller connection, and an earlier draft claim that the assessed composition
"redirected the selected system scope away from the real system bus" was
wrong. The verified chain on this host is:

1. The harness passes `DBUS_SYSTEM_BUS_ADDRESS` (unreachable scratch path) in
   the `systemd-socket-activate` environment. `exec_process()` in
   [systemd 261 socket-activate.c](https://github.com/systemd/systemd/blob/v261/src/socket-activate/socket-activate.c#L149-L170)
   builds a fresh environment for the activated service from a whitelist of
   `TERM`, `COLORTERM`, `NO_COLOR`, `PATH`, `USER`, `HOME`, plus `LISTEN_*`
   variables and explicit `--setenv` values; every other variable — including
   any D-Bus address — is stripped before `execvpe`.
2. `dbus-broker-launch --scope=system` then calls
   `sd_bus_open_system()` in
   [`launcher_connect`](https://github.com/bus1/dbus-broker/blob/v37/src/launch/launcher.c#L1268-L1281),
   which eagerly connects to the host system bus. This host's libsystemd does
   honor `DBUS_SYSTEM_BUS_ADDRESS` when present
   ([`bus_set_address_system`](https://github.com/systemd/systemd/blob/v261/src/libsystemd/sd-bus/sd-bus.c#L1312-L1324)),
   but per the previous point the variable never reaches the launcher, so the
   controller lands on `/run/dbus/system_bus_socket`.
3. [`launcher_subscribe`](https://github.com/bus1/dbus-broker/blob/v37/src/launch/launcher.c#L1283-L1316)
   then calls `org.freedesktop.systemd1.Manager.Subscribe` on that connection
   unconditionally, regardless of how many activatable services the config
   declares.

This was verified without `ss`/`strace` parsing, using two deterministic
observations and one library probe:

- running the same composition under `env -i` with
  `DBUS_SYSTEM_BUS_ADDRESS=unix:path=<missing>` still reached `Ready` and
  answered `ListNames` — impossible if libsystemd used the variable, since the
  address does not exist;
- an activated `/usr/bin/env` received `LISTEN_FDS/LISTEN_PID/LISTEN_PIDFDID`
  but **not** `DBUS_SYSTEM_BUS_ADDRESS`, demonstrating the whitelist directly;
- a ctypes call to `sd_bus_open_system` returned `-ENOENT` with the variable
  set to a missing path and `0` unset, confirming the library itself honors
  the variable and the stripping in point 1 is the operative mechanism.

The harness keeps the unreachable-scratch `DBUS_SYSTEM_BUS_ADDRESS` in the
passed environment (it never points anything at the real system bus) but
records in `evidence.json` that the variable does not reach
`dbus-broker-launch` (`dbus_system_bus_address_reaches_launcher: false`) and
that the launcher controller is an unisolated host dependency
(`isolation.launcher_controller`, `host_dependencies.launcher_controller_system_bus`).
The system bus socket is now part of `require_host_dependencies()`, the
`broker` check preflight, and the test suite's `available()` gate, each
requiring an actual socket.

## Scope and host-dependency constraints

The same isolated inherited-listener composition with `--scope=user` failed on
this host. The preserved spike diagnostic was:

```text
ERROR launcher_connect @ ../src/launch/launcher.c +1293: No medium found
      launcher_run @ ../src/launch/launcher.c +1440
      run @ ../src/launch/main.c +152
      main @ ../src/launch/main.c +178
Exiting due to fatal error: -123
```

The triggering private client then observed a closed connection. Error `-123`
is `ENOMEDIUM`. The maintained topology therefore uses the observed successful
`--scope=system`; it does not silently retry against user scope,
`dbus-daemon`, or a host bus.

The launcher manual says scope selects the systemd instance used for D-Bus
service activation and has no further effect when no activatable services are
declared. This config declares none, so no service activation is possible —
that is the measured no-activation proof above — but the launcher still
contacts host manager machinery by design (controller connection plus
unconditional `Manager.Subscribe`), logs through the host journal, and
requires socket activation. The mode therefore prevents host D-Bus service
activation while depending on host systemd, journald, and the system bus; it
does not and cannot isolate the launcher's controller with environment
variables under this composition.

## Daemon and bus-name readiness

After the broker answered `org.freedesktop.DBus.ListNames`, the harness manually
started:

```text
/usr/bin/gnome-keyring-daemon --foreground --components=secrets \
  --control-directory <root>/control
```

The daemon inherited private HOME and XDG runtime/data/config/cache/state/tmp
paths, the private session address, and an unreachable scratch system address.
The existing daemon readiness gate proved initialization stdout EOF, daemon
liveness, reported paths beneath scratch, and the private control socket's
type and owner.

The broker-specific gate then observed one unique owner for both names:

```text
org.gnome.keyring       -> :1.<private>
org.freedesktop.secrets -> :1.<private>
GetConnectionUnixProcessID(:1.<private>) -> <exact daemon PID>
```

Thus name presence did not merely prove that some service answered: the owner
was the exact manually launched disposable daemon.

## Plain session, measured lock state, and private interface

[`dev/harness/private_bus_probe.py`](/dev/harness/private_bus_probe.py) used
the explicit private address for every operation. Before any session work it
read the standard properties
[`org.freedesktop.Secret.Service.Collections`](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html)
and, for each advertised collection,
[`org.freedesktop.Secret.Collection.Locked`](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Collection.html)
— plain property reads, no mutation. It then called
`org.freedesktop.Secret.Service.OpenSession` with algorithm `plain` and an
empty string variant (matching GNOME Keyring's upstream `test-service.c`
setup), required a private session object path, introspected
`/org/freedesktop/secrets`, and re-read both properties. The probe fails
loudly if the collection set or any `Locked` value differs across the
operations, and its JSON record now contains only measured fields:

```text
collections_before=[/org/freedesktop/secrets/collection/session]
locked_before={/org/freedesktop/secrets/collection/session: false}
collections_after=[/org/freedesktop/secrets/collection/session]
locked_after={/org/freedesktop/secrets/collection/session: false}
collections_unchanged=true
locked_state_unchanged=true
```

A fresh daemon on this host consistently advertises exactly its in-memory
`session` collection, unlocked, before the first `OpenSession`; the empty
collection set would also be measured consistently. The probe made no
password call, did not create, lock, or unlock anything, and specifically did
not lock or relock an already-unlocked collection to simulate password
verification. The earlier unmeasurable constants
(`password_method_called`, `collection_lock_state_changed`) were removed; the
lock-state claim is now the before/after measurement above.

The introspection found:

```text
org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface
UnlockWithMasterPassword
ChangeWithMasterPassword
```

The upstream XML declares collection object-path and Secret tuple arguments
for those methods. This checkpoint verifies availability only.

## Exact teardown and retained failure evidence

The supervisor owns the command, daemon, and launcher as direct `Popen`
children. It identifies the launcher's exact broker child by parent PID,
executable, process start ticks, and an open pidfd. Teardown:

1. TERM's live command and daemon PIDs, waits under the existing shared
   deadline, KILLs only survivors, and reaps both directly;
2. signals the exact broker through its pidfd, waits, KILLs only if still live,
   and requires the launcher to reap the exited broker (see below);
3. TERM's the exact launcher if it did not exit after broker shutdown, uses the
   same bounded KILL fallback, and reaps it directly; and
4. records command, daemon, broker, and launcher identities in `cleanup.json`.

The reaping proof in step 2 is bounded against PID reuse: the pidfd already
proved the exact broker exited, and the launcher is required to reap it;
`/proc/<pid>` start ticks distinguish "same process, still a zombie" from "PID
recycled by an unrelated process", where recycling itself proves the original
was reaped. The check is one-directional: a stalled launcher fails loudly,
while a transient procfs disappearance (procfs can return `ESRCH` mid-vanish)
is treated as reaped rather than crashing cleanup.

When the broker dies by signal — either the harness's own KILL fallback or an
external mid-command kill — dbus-broker-launch's
[`launcher_on_child_exit`](https://github.com/bus1/dbus-broker/blob/v37/src/launch/launcher.c#L372-L385)
exits the event loop with `EXIT_FAILURE` (status 1) instead of propagating a
normal exit status. Teardown accepts status 1 exactly in those two
harness-supervised cases, after a short bounded grace for the launcher's
guaranteed self-exit, so a necessary SIGKILL fallback no longer masquerades as
an abnormal launcher failure and masks successful teardown. A broker that
exited cleanly still requires a normal launcher status.

If the broker dies under a running command, the harness fails the run (no
command completion against a dead bus); the daemon's own self-exit at status 0
after losing its bus is then recorded without turning into a second, masking
cleanup failure — the primary failure remains the actionable report, and a
TERMed daemon is still strictly status-checked.

Successful, command-failure, harness-SIGTERM, forced-SIGKILL-fallback
(broker job-control-stopped so TERM cannot act, deterministically exercising
the KILL path and the launcher's status-1 exit), external broker-death
mid-command, and parallel tests all required every recorded PID to be reaped
and absent. Parallel coverage ran two instances concurrently and observed
distinct roots, bus sockets, launcher PIDs, broker PIDs, and daemon PIDs.

A retained command-status-23 run contained the useful startup logs,
`evidence.json`, and `cleanup.json`; all four processes were reaped without a
KILL fallback. A separate focused failure test explicitly passed a synthetic
sensitive marker, retained the failure tree, and scanned every regular file to
prove that the value was omitted; retained evidence trees contain no synthetic
secret values. The harness does not record command argv or capture command
output. These checks preserve useful redacted evidence, but do not make
arbitrary daemon diagnostics generically safe for real passwords.

## Verification

The maintained broker check passed:

```text
$ sh -n dev/harness/check
$ dev/harness/check broker
Ran 7 tests ... OK
PASS: private bus opened a plain session and exposed the GNOME interface
PASS: command completed in isolated private-broker harness
```

The seven tests cover strict private environment, whitelist/controller
boundary and no-activation evidence, measured plain-session/lock-state
stability with private-interface introspection, retained redacted command
failure, parallel paths/processes, signal-time exact teardown, the
SIGKILL-fallback/launcher-status-1 path, and external broker-death mid-command
with full reaping.

The maintained aggregates also passed after the corrections:

```text
$ dev/harness/check python      # 10/10 control-only focused tests + behavior + smoke
$ dev/harness/check rust-nextest  # 2/2 real-daemon transport tests
```

## What this enables and what remains

It is now possible to run a zbus or other explicitly addressed command against
a fresh manually owned GNOME Secret Service without exposing the caller's
session bus or keyring store. Tests can rely on a proven plain session, the
GNOME private interface, both service names, exact daemon ownership, measured
collection/lock-state stability across session setup, and bounded topology
cleanup that survives a signal-killed broker.

It is not yet possible to claim product-level collection behavior. No fixture
collections or distinct passwords were created, daemon restart during fixture
setup was not added to the reusable mode, and the product zbus client was not
invoked in this track. The host must provide the assessed
systemd/journald/system-bus launcher facilities, and the launcher's controller
contact with host systemd remains unisolated by design of the composition (a
`--setenv`-based redirect was considered and deliberately not attempted — it
would at best point the controller's `Manager.Subscribe` at the private broker
and is out of scope for this checkpoint).

The proposed next slice is a disposable collection-fixture layer plus focused
product zbus tests: create at least login and one second collection with
different generated passwords, restart only harness-owned daemon generations
when setup requires it, and exercise list/unlock/change/error behavior by
stable ID. Ordinary unlock must first inspect lock state and return
already-unlocked without locking or password verification; only actually
locked fixture collections should receive a private password method call.

## Cross-references

- [`/doc/harness/lifecycle0.gpt6a.md`](/doc/harness/lifecycle0.gpt6a.md)
  supplies the environment, readiness, signal-latch, exit, retention, and
  exact-direct-child policy reused rather than replaced here.
- [`/doc/harness/integration0.gpt6a.md`](/doc/harness/integration0.gpt6a.md)
  records the older control-transport integration seam; broker mode is now the
  sibling substrate for collection-oriented product tests.
- [`/doc/harness/prompt.md`](/doc/harness/prompt.md) preserves the broker
  branch's original optional assessment and its promotion after the zbus-only
  architecture pivot.
