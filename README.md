# gmellon

> *mellon* — "speak, friend, and enter."

`gmellon` is a small Rust CLI that speaks the gnome-keyring daemon's private
control protocol directly, so you can **unlock and re-key your login keyring
from any shell** — no GUI, no PAM, and no display server. A gnome-keyring
daemon must be listening on its control socket.

It exists because every other door is shut on a headless, SSH-only machine:

| Door | Why it's shut |
|---|---|
| GUI prompter (`gcr-prompter`) | needs X/Wayland; D-Bus activation fails without one |
| `gnome-keyring-daemon --unlock` | never forwards to a *running* daemon; tries to become its own daemon and collides with systemd's socket |
| `pam_gnome_keyring` | module not installed here; only fires on password logins; only works if keyring password == account password |
| `secret-tool` | has `lock`, has `search --unlock`, but **no `unlock` command** — unlocking is deliberately prompt-gated |
| Secret Service `Unlock()` D-Bus call | returns a *prompt object*; prompts are GUI |

The control socket is the one interface that accepts a password from any
client of yours, PAM or not. `pam_gnome_keyring` speaks it; `gmellon` is its
shell-native sibling.

## Usage (spec)

```
# unlock the login keyring; password prompted on the TTY, no echo
gmellon unlock

# scripting: read a single line (sans newline) from stdin
gmellon unlock --stdin < /dev/shm/pw

# rotate the login keyring password, headlessly (prompts for old + new + confirm)
gmellon change

# offline inventory: control socket present?, which keyring files exist
gmellon status

# speak to a private/test daemon instead of the session one
gmellon --control-dir ~/tmp-opencode/krtest unlock
```

**Password policy:** passwords are accepted only from the TTY (default) or a
single line on stdin (`--stdin`). They are never accepted as argv or flags —
argv is world-readable in `ps`. Password values and password-bearing request
buffers use best-effort zeroization when dropped; command paths drop them
promptly after each exchange. This cannot erase copies abandoned by dependency
internals or allocator behavior.

**`--stdin` contract:** exactly one line, terminated by LF or CRLF — input
ending without a newline is an error (an empty pipe included; an empty line is
a valid empty password). Input must be valid UTF-8 — invalid bytes error
rather than being replaced (the control protocol itself stays byte
transparent). Every byte before the terminator is literal password content:
no line editing is applied, so backspace and control bytes from a pipe are
data, not commands. Input is capped at 64 KiB. With no controlling terminal
the TTY prompt fails with an actionable error suggesting `--stdin`.

### Exit codes

| code | meaning |
|---|---|
| 0 | OK |
| 1 | usage / io / unexpected error |
| 2 | DENIED — wrong password |
| 3 | FAILED — daemon-side failure |
| 4 | NO_DAEMON — nothing listening on the control socket |

## The protocol (as reverse-engineered from source)

Transport: `AF_UNIX` `SOCK_STREAM` at `<control-dir>/control`,
default control dir `$XDG_RUNTIME_DIR/keyring`.

Immediately after connecting, the client writes one NUL credential byte. The
daemon consumes it separately from the frame and verifies that the peer UID
matches its own (on Linux via `SO_PEERCRED`). This byte is not included in the
frame length. A client should also verify that the socket and connected peer
belong to its effective UID before sending a password.

All integers are **u32 big-endian**. Strings are u32 BE length + raw bytes,
with no NUL terminator or interior NUL. GNOME's `EggBuffer` rejects string
lengths greater than or equal to `0x7fffffff`. The leading length field counts
the whole frame, including itself.

```
request:  [u32 total_len][u32 op][payload...]
response: [u32 total_len][u32 result]
```

| op | value | payload |
|---|---|---|
| INITIALIZE | 0 | stringv (env) — not used by gmellon |
| UNLOCK | 1 | string: password |
| CHANGE | 2 | string: original, string: new |
| QUIT | 3 | — |

| result | value |
|---|---|
| OK | 0 |
| DENIED | 1 |
| FAILED | 2 |
| NO_DAEMON | 3 |

Example: `unlock` with password `mellon` (after the credential byte):

```
send: 00 00 00 12  00 00 00 01  00 00 00 06  6d 65 6c 6c 6f 6e
      └len=18───── └op=UNLOCK── └strlen=6─── └"mellon"
recv: 00 00 00 08  00 00 00 00
      └len=8────── └OK
```

## Behavior notes (the sharp edges)

- **Only the `login` keyring is addressable.** Server-side `UNLOCK` runs
  `gkd_login_unlock()`, which only touches the keyring whose identity is
  `login` — and identity is literally the filename stem
  (`login.keyring`). A keyring with any other name is invisible to this
  protocol.
- **Unlock-or-create landmine:** if `login.keyring` does not exist, the
  daemon *creates one encrypted with whatever password you send*. `gmellon
  unlock` therefore checks for `~/.local/share/keyrings/login.keyring` first
  and refuses with an explanation unless `--allow-create` is passed
  (existence check is advisory; the daemon is the source of truth).
- **`CHANGE` also creates:** installed `gnome-keyring-daemon` 48.0 creates a
  missing login keyring with a nonempty new password, regardless of the
  supplied original password. An empty new password is denied and does not
  create the missing store. This is version-scoped harness evidence, so the
  product must treat CHANGE as create-capable rather than as a safe existence
  check.
- Empty-password behavior is asymmetric in the observed cases: fresh
  `UNLOCK(empty)` creates an empty-password login keyring, and
  `CHANGE(empty, nonempty)` succeeds. `CHANGE(A, empty)` on the existing A
  store and `CHANGE(arbitrary, empty)` with no store were both denied.
- No rate limiting or lockout exists server-side; a wrong password just
  returns DENIED.
- The socket lives in a 0700 runtime dir — any process of your uid may
  speak to it. Same trust boundary PAM already has.
- Works happily against the systemd socket-activated daemon (we are just
  another client connecting to `<dir>/control`).
- Password-bearing request frames must never be logged or hexdumped. Verbose
  diagnostics may report the operation, lengths, socket path, and result only.

## Development (readme-driven)

This README is the spec. Stages land in order; each is independently
committable and testable. Sizes are honest: the whole tool is ~300–500 LOC.
The staging exists to de-risk verification, not because the work is big.

### Stage 0 — scaffold
`cargo init`, clap v4 derive skeleton with stub subcommands, `.gitignore`,
clippy + rustfmt clean, nextest wired. `gmellon --help` prints the spec
above.

### Stage 1 — codec (pure, no I/O)
`protocol.rs`: op/result enums, frame + string encode/decode. Unit tests
with golden byte vectors — including the `mellon` example above — so the
wire format is locked by test before any socket is opened.

### Stage 1.5 — synchronous control transport
`control::sans_io` exposes the pure codec for alternate adapters. The
Linux-only `SyncClient` opens one connection per operation, validates the
socket metadata and connected peer UID, writes the credential NUL and
zeroizing frame, and reads the response under an absolute deadline. Unix
validation accepts `Metadata` and `AsFd` rather than depending directly on the
synchronous stream type. A future `TokioClient` can therefore reuse the codec
and security checks while replacing only connect/read/write scheduling; sync
and async are not forced through one trait.

### Stage 2 — test harness (complete)
Implemented under `dev/harness/`: the reusable
[`lifecycle.py`](/dev/harness/lifecycle.py) supervisor starts a throwaway
`gnome-keyring-daemon --foreground --components=secrets
--control-directory=<tmp>`, with `HOME` and all XDG directories redirected to
a mode-0700 scratch tree and both D-Bus addresses pointed at nonexistent
scratch sockets. It waits for the daemon's initialization EOF, verifies child
liveness and the control socket, and performs bounded teardown. This
control-only layer validates the transport and frame transcription without
touching the real store or buses. A private `dbus-broker` composition
(`gmell-harness-broker`, in progress) was promoted from optional parity to
required infrastructure for the zbus Secret Service product backend, but it
remains separate from — and no prerequisite for — this control-only layer and
its tests.

The reproducible behavior runner adds supervisor-owned restarts over the same
private store and explicit stopped/SIGSTOP fault transitions. Against installed
daemon 48.0 it proves missing/correct/wrong UNLOCK, persisted A→B CHANGE,
missing-store CHANGE creation, empty-password cases, stopped `NO_DAEMON`, and
bounded unresponsive behavior without logging generated passwords or frames.

The durable harness guide, runnable interface, isolation boundary, and evidence
map are in [`doc/harness/README.md`](/doc/harness/README.md). The underlying
acceptance constraints and ticket graph remain in
[`doc/harness/prompt.md`](/doc/harness/prompt.md).

### Stage 2.5 — secret input
`secret_input`: `Secret` owns a zeroized-on-drop UTF-8 string and exposes
only borrowed `as_bytes()` — no `Debug`, `Clone`, `Display`, or ownership
escape. Interactive prompts run through rpassword on the controlling TTY
(no echo, with rpassword's best-effort terminal-state restoration); the
`--stdin` path uses
its own bounded line-record reader because rpassword interprets DEL,
Ctrl-U, and Ctrl-W as editing commands even over pipes, where those bytes
are password bytes. LF/CRLF terminate a line, EOF before the newline
errors, an empty line passes, input is capped at 64 KiB, and invalid UTF-8
errors. ENXIO (no controlling terminal) maps to an actionable error
suggesting `--stdin`. A reusable two-prompt confirmation (single-shot
mismatch, zeroized temporaries) supports `change`.

### Stage 3 — `unlock`
Socket and peer ownership checks, connect, credential-byte handshake, send
UNLOCK, parse result, exit codes, TTY prompt (`rpassword`), `--stdin`, and the
`--allow-create` guard. Integration test via the Stage 2 harness: create →
unlock → wrong-password → DENIED.

### Stage 4 — `change`
Same frame machinery, two strings. Harness test: unlock with A, change A→B,
restart the daemon over the same private store, unlock with B, unlock with A →
DENIED. Guard missing-store CHANGE because the observed daemon creates with the
new password when it is absent.

### Stage 5 — polish
`status` (offline: socket stat, keyring dir inventory), redacted `-v`
diagnostics via `tracing`, `clap_complete` shell completions, and
manpage-grade `--help`.

### Stage 6 — stretch (only if wanted)
`lock` via the Secret Service D-Bus call (zbus) for symmetry; wrapper docs
for the zsh login hook; `env` (INITIALIZE) exposure.

### Crates

| crate | use |
|---|---|
| clap v4 (derive) + clap_complete | CLI + completions |
| rpassword | no-echo TTY prompts |
| zeroize | clear password and request buffers after use |
| rustix | effective and peer UID checks |
| anyhow | errors |
| tracing (optional, Stage 5) | redacted `-v` operation diagnostics |

Publishing: `cargo bump` + `jj commit` + `cargo publish` when it earns it.

## References

Upstream source (canonical, version-observed: gnome-keyring 48.0 / gcr
4.4.0.1; both trees unchanged on these paths through current main):

- [GNOME/gnome-keyring `daemon/control/gkd-control-codes.h`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/control/gkd-control-codes.h) — op/result enums
- [GNOME/gnome-keyring `daemon/control/gkd-control-client.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/control/gkd-control-client.c) — frame construction, `gkd_control_unlock` / `gkd_control_change_lock`
- [GNOME/gnome-keyring `daemon/control/gkd-control-server.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/control/gkd-control-server.c) — dispatch: `OP_UNLOCK → control_unlock_login → gkd_login_unlock`
- [GNOME/gnome-keyring `egg/egg-buffer.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/egg/egg-buffer.c) — big-endian u32, length-prefixed strings
- [GNOME/gnome-keyring `egg/egg-unix-credentials.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/egg/egg-unix-credentials.c) — the pre-frame credential byte and peer credential lookup
- [GNOME/gnome-keyring `pam/gkr-pam-client.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/pam/gkr-pam-client.c) — hardened client checks, handshake, frame I/O, and result mapping
- [GNOME/gnome-keyring `daemon/login/gkd-login.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/login/gkd-login.c) — `login` specialness, unlock-**or-create**
- [GNOME/gnome-keyring `pkcs11/secret-store/gkm-secret-module.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/pkcs11/secret-store/gkm-secret-module.c) — keyring identity = filename stem
- [GNOME/gnome-keyring `daemon/gkd-main.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/gkd-main.c) — why bare `--unlock` doesn't forward to a running daemon
- [GNOME/gcr `gcr/gcr-ssh-agent-service.c`](https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-ssh-agent-service.c) — the `unique=ssh-store:<path>` passphrase-item convention (why unlocking matters for ssh)

Local checkouts (same content, no network):

- `~/archive/GNOME/gnome-keyring/`
- `~/archive/GNOME/gcr/`

Context and docs:

- [Arch Wiki: GNOME/Keyring](https://wiki.archlinux.org/title/GNOME/Keyring) — PAM wiring, TTY patterns, troubleshooting
- [Secret Service API spec](https://specifications.freedesktop.org/secret-service-spec/latest/) — the D-Bus side (why `Unlock()` needs a prompt; stretch `lock`)
- [Debian `gnome-keyring` package](https://packages.debian.org/sid/gnome-keyring) / [Debian `libpam-gnome-keyring`](https://packages.debian.org/sid/libpam-gnome-keyring)
- JtR `gnome2john` — precedent that the on-disk keyring format is parseable offline (rescue path of last resort)
