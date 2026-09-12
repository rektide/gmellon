---
type: Evidence
title: Private dbus-broker lifecycle and GNOME interface proof
description: Installed-host evidence for the reusable isolated bus, daemon name ownership, plain Secret Service session, private interface, exact process teardown, and launcher constraints.
resource: /doc/harness/broker0.gpt6a.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, zbus]
status: draft
generated: { by: model:openai/gpt-6-astra, at: 2026-09-11T20:11:47-04:00 }
verified: { by: model:openai/gpt-6-astra, at: 2026-09-11T20:11:47-04:00 }
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
D-Bus activation, starts the daemon.

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

The host exposed `/run/systemd/journal/socket` as a socket and
`/run/systemd/system` as a directory. The maintained mode preflights both and
fails rather than claiming portability when either launcher dependency is
absent.

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
declared. This config declares none, but the launcher remains built around
systemd socket activation and journal logging. Successful launcher/broker PIDs
emitted `Ready` and dispatch summaries to the host journal, corroborating the
existing assessment that `/run/systemd/journal/socket` is a runtime dependency.
The mode therefore prevents host D-Bus service activation but does not claim
independence from host systemd/journald facilities or prove that the launcher
never contacts host manager machinery.

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

## Plain session and private interface

[`dev/harness/private_bus_probe.py`](/dev/harness/private_bus_probe.py) used
the explicit private address for both operations. It called
`org.freedesktop.Secret.Service.OpenSession` with algorithm `plain` and an empty
string variant, then required a private session object path. This matches
GNOME Keyring's upstream test setup in
`daemon/dbus/test-service.c`, which opens a plain session before exercising the
service.

The probe then introspected `/org/freedesktop/secrets` and found:

```text
org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface
UnlockWithMasterPassword
ChangeWithMasterPassword
```

The upstream XML declares collection object-path and Secret tuple arguments
for those methods. This checkpoint verifies availability only. The probe made
no password call, changed no collection lock state, and specifically did not
lock or relock an already-unlocked collection to simulate password
verification.

## Exact teardown and retained failure evidence

The supervisor owns the command, daemon, and launcher as direct `Popen`
children. It identifies the launcher's exact broker child by parent PID,
executable, process start ticks, and an open pidfd. Teardown:

1. TERM's live command and daemon PIDs, waits under the existing shared
   deadline, KILLs only survivors, and reaps both directly;
2. signals the exact broker through its pidfd, waits, KILLs only if still live,
   and requires `/proc/<broker>` to disappear while its launcher can reap it;
3. TERM's the exact launcher if it did not exit after broker shutdown, uses the
   same bounded KILL fallback, and reaps it directly; and
4. records command, daemon, broker, and launcher identities in `cleanup.json`.

Successful, command-failure, and harness-SIGTERM tests all required the four
recorded PIDs to be absent. Parallel coverage ran two instances concurrently
and observed distinct roots, bus sockets, launcher PIDs, broker PIDs, and
daemon PIDs.

A retained command-status-23 run contained the useful startup logs,
`evidence.json`, and `cleanup.json`; all four processes were reaped without a
KILL fallback. A separate focused failure test explicitly passed a synthetic
sensitive marker, retained the failure tree, and scanned every regular file to
prove that the value was omitted. The harness does not record command argv or
capture command output. These checks preserve useful redacted evidence, but do
not make arbitrary daemon diagnostics generically safe for real passwords.

## Verification

The implementation checkpoint was committed as change `wpzzpsup`, Git commit
`471ab6bf`. The ticket promotion that preserves the old optional history was
committed separately as change `vkoymyxk`, Git commit `b7c7e688`.

The maintained broker check passed:

```text
$ sh -n dev/harness/check
$ dev/harness/check broker
Ran 5 tests ... OK
PASS: private bus opened a plain session and exposed the GNOME interface
PASS: command completed in isolated private-broker harness
```

The five tests cover strict private environment and no-activation evidence,
plain session/interface introspection, retained redacted command failure,
parallel paths/processes, and signal-time exact teardown.

## What this enables and what remains

It is now possible to run a zbus or other explicitly addressed command against
a fresh manually owned GNOME Secret Service without exposing the caller's
session bus or keyring store. Tests can rely on a proven plain session, the
GNOME private interface, both service names, exact daemon ownership, and
bounded topology cleanup.

It is not yet possible to claim product-level collection behavior. No fixture
collections or distinct passwords were created, daemon restart during fixture
setup was not added to the reusable mode, and the product zbus client was not
invoked in this track. The host also must provide the assessed
systemd/journald launcher facilities.

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
