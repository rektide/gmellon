# Sol handoff: isolated GNOME Keyring harness

Use this document as the working prompt for a fresh Sol session in the
`gmellon` repository.

## Total mission

`gmellon` is a small Rust CLI that unlocks or changes the password of the
GNOME **login** keyring by speaking `gnome-keyring-daemon`'s private Unix
control protocol. The product must be safe to use from a headless shell and
must be tested without touching the user's real keyring, session bus, or
socket-activated daemon. Read [`/README.md`](/README.md) for the provisional
product spec and inspect the Beads graph before acting.

Your track owns the reusable integration-test harness, not the Rust product
implementation. The required baseline is a hermetic process group containing:

1. one manually launched `gnome-keyring-daemon`,
2. a private mode-0700 home/runtime/data tree,
3. explicit unreachable scratch addresses for both session and system D-Bus,
   and
4. a command or test process that can safely exercise the daemon's control
   socket.

The user also wants a later private `dbus-broker` parity layer for Secret
Service observations. It must never inherit the real user bus, but it is not a
prerequisite for direct control-socket tests. Do not start
`gnome-settings-daemon`; the relevant process is `gnome-keyring-daemon`.

## How to run this work

You know the total mission, but **work one reviewed slice at a time**. At each
consequential checkpoint:

- summarize what became possible or impossible;
- explain the process topology and isolation boundary actually observed;
- cite source paths and commands that support the conclusion;
- identify unresolved risks or choices;
- propose exactly one next coherent slice; and
- stop for the human to review before continuing.

Do not accept a request to "do the harness" as permission to run every slice
unattended. Small investigation edits within the current slice are fine.
Commit each coherent, useful stage with `jj commit -m "..." <paths...>` before
asking for review. Preserve failed spikes in `.test-agent/harness/` when their
evidence is useful; do not overwrite unrelated or provisional work.

## Current state and known facts

- Stage 0 is complete: Cargo, a clap command skeleton, and three nextest tests
  exist. The harness should not need to restructure that code.
- The current `gmell-harness` ticket is provisional and too broad. It assumes
  a redirected daemon but does not fully specify bus isolation, activation,
  readiness, process ownership, or teardown.
- Installed tools presently include `dbus-broker-launch` 37,
  `systemd-socket-activate`, `dbus-run-session`, `dbus-daemon`,
  `gnome-keyring-daemon` 48.0, `gdbus`, and `secret-tool`.
- Direct control-socket operation does not require D-Bus. The daemon creates
  its control socket and initializes its internal PKCS#11 store before its
  non-fatal session-bus setup. The required first harness must therefore
  poison both bus addresses rather than introduce a broker immediately.
- `dbus-broker-launch` does **not** create its own listener. Its parent must
  pass exactly one socket using the systemd socket-activation protocol, and
  `<listen>` entries in a D-Bus config are ignored.
- `dbus-broker-launch` uses systemd for D-Bus service activation. The harness
  must not expose host service directories or permit activation of the real
  `org.freedesktop.secrets` service. Prefer a minimal custom bus config and
  manually launch the test daemon. The launcher also opens a controller
  connection to the selected host systemd instance; verify that the proposed
  topology cannot create or manipulate host units. If "no host systemd
  contact" is a hard boundary, surface that `dbus-broker-launch` may not meet
  it rather than hiding the caveat or silently falling back.
- An assessment spike succeeded with `systemd-socket-activate`, a minimal
  no-activation config, `--scope system`, and `DBUS_SYSTEM_BUS_ADDRESS`
  redirected to the private bus. On this host, `--scope user` failed with
  `ENOMEDIUM`, and the launcher also required `/run/systemd/journal/socket`.
  Reproduce and document these constraints; do not describe this composition
  as fully hermetic or portable.
- Upstream GNOME Keyring tests use GLib's `GTestDBus` (normally a private
  `dbus-daemon`) plus scratch directories and a manually launched daemon.
  Those tests are useful prior art, but they do not prove the broker topology.
- The daemon option is `--control-directory`, not `--control-dir`.
- On startup, the daemon initializes its internal PKCS#11 stack and attempts
  session-bus setup. Bus failure is currently non-fatal for the control
  socket; the `secrets` D-Bus API itself needs a functioning session bus.
- Do not pass `--components=`. An absent or empty value is replaced with the
  daemon's default component set.
- Upstream debug builds honor `GNOME_KEYRING_TEST_PATH`; this installed daemon
  reports `testing: enabled`. That variable is useful corroboration, but it is
  compile-time debug behavior and cannot be the only isolation mechanism.
  Redirect `HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`,
  `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, and preferably `TMPDIR` before spawning
  any child. Do not set `GNOME_KEYRING_TEST_PATH` in the final `gmellon`
  end-to-end tests: it bypasses the production XDG keyring path that
  `--allow-create` must inspect.
- A control connection begins with a separate NUL credential byte. The daemon
  consumes that byte, checks the peer UID, and only then reads the framed
  request. Any probe must model this transport prelude.
- Source says `CHANGE` creates a missing login keyring using the new password,
  and rejects an empty new password. Record what the installed binary does;
  do not let a source reading substitute for the behavioral test.
- Control-socket existence is not sufficient readiness. Upstream captures
  daemon stdout and waits for EOF, which occurs when late initialization
  redirects stdout to stderr. Combine that EOF with child-liveness and socket
  type/ownership checks, all under a deadline.

Primary local source is under `~/archive/GNOME/gnome-keyring/`; check it before
the web. Especially inspect:

- `daemon/control/gkd-control-server.c`
- `daemon/control/gkd-control-client.c`
- `egg/egg-unix-credentials.c`
- `daemon/gkd-main.c`
- `daemon/gkd-test.c`
- `daemon/test-startup.c`
- `daemon/dbus/test-service.c`
- `pam/test-pam.c`
- `pam/gkr-pam-client.c`
- `daemon/login/gkd-login.c`
- `pkcs11/gkm/gkm-util.c`

Also use the installed `dbus-broker-launch(1)`,
`systemd-socket-activate(1)`, and `gnome-keyring-daemon(1)` manuals as primary
documentation for the binaries actually under test.

## Safety invariants

Treat these as acceptance criteria, not aspirations:

- Create a short, unique scratch root under `/home/rektide/tmp-opencode` with
  `umask 077`; keep Unix socket path-length limits in mind.
- Every child receives an explicit environment assembled from the harness
  contract. Do not merely override two variables in the inherited session.
- Set `DBUS_SESSION_BUS_ADDRESS` and `DBUS_SYSTEM_BUS_ADDRESS` to explicit
  nonexistent sockets under the scratch root for the baseline harness;
  unsetting them is insufficient because GLib can rediscover host buses.
- Sanitize inherited `LISTEN_*`, `NOTIFY_SOCKET`, `GNOME_KEYRING_CONTROL`,
  `SSH_AUTH_SOCK`, `DBUS_STARTER_*`, `DESKTOP_AUTOSTART_ID`, and
  `XDG_SESSION_ID` before startup.
- The private bus config must not load standard or host service directories.
  Only the harness launches `gnome-keyring-daemon`.
- The test daemon's control socket and all keyring files must resolve beneath
  the scratch root. Record the daemon environment and selected paths as
  evidence.
- Establish readiness with bounded waits and positive checks. For the
  baseline, require initialization stdout EOF, child liveness, and the
  expected socket type and owner. For broker parity, additionally prove that
  the broker answers and the intended daemon owns its private bus names.
- Manage exact child PIDs or one dedicated process group. Never use broad
  `pkill`, `killall`, or name-based cleanup.
- On normal and signal exits, send TERM, wait with a deadline, then KILL only
  the remaining owned children. Reap them and report abnormal exits.
- Make instances parallel-safe. No fixed socket names, PIDs, or shared data
  directories.
- Preserve child logs on failure. Never print passwords or password-bearing
  frame bytes.
- Include an isolation regression check that fails if a sentinel outside the
  scratch root changes or if the daemon reports paths outside that root.

## Proposed slices

### Slice 0 — control-only sandbox and smoke test

This is the only slice authorized at kickoff.

1. Read the README, current source, Beads issues, recent `jj` history, upstream
   files listed above, and installed manuals.
2. Search for duplicate tickets, then make `gmell-harness` a clear umbrella
   with namespaced children for the control smoke test, lifecycle, behavior,
   durable integration, and optional broker parity. Preserve dependency
   direction and commit the exported Beads state separately.
3. Implement only a per-test scratch sandbox and one real-daemon smoke test.
   Spawn `gnome-keyring-daemon --foreground --components=secrets` with an
   explicit scratch control directory and poisoned session/system bus
   addresses.
4. Wait for initialization stdout EOF, then verify child liveness plus control
   socket type and ownership.
5. Send the credential NUL and one UNLOCK request. Observe first unlock OK and
   a subsequent wrong password DENIED without logging either password.
6. Verify `login.keyring` and every writable artifact remain under scratch.
   Terminate and reap the exact child with a bounded cleanup sequence.
7. Commit evidence and implementation, report, and stop. Do not add a broker,
   CLI commands, or the broader behavior matrix in this slice.

### Slice 1 — lifecycle interface

Turn the successful smoke-test spike into a composable "run this command
inside the harness" interface. Prefer a domain-grouped location such as
`dev/harness/` over scattered root scripts. Define exported environment
variables and exit semantics, implement signal-safe teardown and failure
artifact retention, and test nesting/parallel execution where practical.
Report and stop.

### Slice 2 — broader behavioral probes

Use a minimal disposable probe (Python, shell plus a purpose-built helper, or
the reviewed Rust transport if it exists by then) to send the credential byte
and protocol frames. Establish and record at least:

1. missing login keyring + UNLOCK creates it;
2. subsequent correct UNLOCK succeeds;
3. wrong UNLOCK returns DENIED;
4. CHANGE A→B makes B succeed and A fail after a daemon restart;
5. missing login keyring + CHANGE behavior;
6. empty-password behavior where relevant; and
7. stopped/unresponsive daemon behavior needed by product tests.

Use Secret Service calls only for observation that does not invoke a GUI
prompt. Keep passwords out of logs. Update factual behavior documentation
only after collecting evidence. Report and stop.

### Slice 3 — private broker parity

Make a broker-only experiment under `.test-agent/harness/`, reproducing the
known `systemd-socket-activate` composition before extending it. Demonstrate a
private socket, a minimal no-activation config, a successful bus method call,
bounded readiness, and clean shutdown. Then launch the daemon manually on the
private bus and prove ownership of `org.gnome.keyring` and
`org.freedesktop.secrets`. Document host systemd/journal dependencies and
exact process/FD ownership. Compare with `dbus-daemon` only as a diagnostic
baseline; do not silently replace the requested broker. Report and stop.

### Slice 4 — durable test integration

Promote only the useful pieces from the spike. Give Rust integration tests a
clear opt-in/tool-availability contract so a missing system daemon is a
visible skip or explicit prerequisite, not a false pass. Keep pure codec and
fake-socket transport tests independent of this external-binary harness.
Run the relevant format, clippy, nextest, shell/static checks, and harness
tests. Report and stop before closing tickets.

### Slice 5 — documentation and closure

Reconcile [`/README.md`](/README.md), harness documentation, and Beads
acceptance criteria with observed behavior. Include troubleshooting and a
process diagram if it clarifies ownership. Close only tickets whose acceptance
criteria are demonstrated. Commit the documentation/ticket checkpoint and
report remaining work back to the product track.

## Deliberate non-goals

- Do not implement `gmellon unlock` or `change` in this track.
- Do not use the real session bus "temporarily."
- Do not use a GUI prompter.
- Do not test against or rename the user's real keyrings.
- Do not add automatic cleanup of unrelated/stale processes or data.
- Do not make raw protocol hexdumps containing secrets.
- Do not turn broker-specific mechanics into Rust product dependencies.

Begin with Slice 0 only.
