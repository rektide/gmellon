# gmellon zsh module (zimfw)

A self-contained zsh module that exports a validated `SSH_AUTH_SOCK` in the
loading shell. It is shell-local environment setup and nothing else:
**loading never prompts for a password, never locks or unlocks anything, and
never invokes `systemctl`.** Unlocking is the `gmellon` CLI's job
([repo README](/README.md)); this module deliberately shares no code or
behavior with it.

## Install (one `zmodule` line)

Add one line to `~/.zimrc`:

```zsh
zmodule rektide/gmellon --root zimfw
```

or, for a local checkout that zimfw should never install or update
(zimfw treats absolute-path modules as externally managed):

```zsh
zmodule /path/to/gmellon/zimfw
```

The module's init file is `init.zsh` at the module root — zimfw's default
discovery name — so no `--source` is needed in either form. (Verified
against the real zimfw: the generated `${ZIM_HOME}/init.zsh` contains
`source <module>/init.zsh`.) Note that the real zimfw also `zcompile`s the
module files it initializes, leaving read-only `*.zwc` siblings; inside
`${ZIM_HOME}` that is expected, and for the absolute-path form the repo
ignores them (`.gitignore`).

## Selection policy

Evaluated by one code path, shared by module load and the opt-in publisher:

| priority | condition | result |
|---|---|---|
| 1 | `GMELLON_SSH_AUTH_SOCK` is set and validates | export it, report `(override GMELLON_SSH_AUTH_SOCK)` |
| 1' | `GMELLON_SSH_AUTH_SOCK` is set but invalid | actionable error on stderr; environment **unchanged** (no discovery); non-fatal |
| 2 | existing `SSH_AUTH_SOCK` is non-empty and validates | leave it untouched, silently (never clobber a working 1Password/gpg agent; makes repeated loads trivially stable) |
| 3 | `$XDG_RUNTIME_DIR/gcr/ssh` validates | export it, report `(discovered gcr/ssh)` |
| 3' | `$XDG_RUNTIME_DIR/keyring/ssh` validates | export it, report `(discovered keyring/ssh)` |
| 4 | nothing validates | actionable non-fatal message naming both expected paths, the agents to enable, and the override; `SSH_AUTH_SOCK` left unset/unchanged; the shell does not exit nonzero |

An existing `SSH_AUTH_SOCK` that does not validate (stale path, deleted
socket) does **not** stop discovery — discovery repairs it.

**Validation means `[[ -S ]]`: the path exists and is a unix socket.** It is
deliberately not a connect probe: a blocked connect on a full accept backlog
would hang shell startup. A stale socket file whose listener died therefore
still validates; the first real agent use fails loudly at that point.

## Opt-in systemd publishing

`gmellon-ssh-auth-sock-publish-systemd` — a function you call explicitly,
never run on load:

1. runs the same selection as load (override > existing > discovery);
2. reads `systemctl --user show-environment`;
3. only if `SSH_AUTH_SOCK` is absent there, sets it with
   `systemctl --user set-environment SSH_AUTH_SOCK=<selected>`;
4. if it is already present, preserves it exactly and reports the value;
5. if the user manager is unavailable (`systemctl` fails), reports and
   changes nothing (also never touches the shell environment).

Typical use: call it once from `.zshrc` or `.zprofile` *after* loading the
module, only on machines where systemd user services should see the agent.

## Files

| file | role |
|---|---|
| `init.zsh` | the module (zimfw default init file) |
| `functions/_gmellon` | zsh completion for the `gmellon` binary (auto-fpath'd by zimfw) |
| `test.zsh` | zsh test suite — run directly: `./test.zsh` |
| `socket-holder.zsh` | test fixture: holds a real AF_UNIX listening socket (`zsh/net/socket`) |

## Completions

Loading the module with a `gmellon` binary on `PATH` keeps
`functions/_gmellon` current: when the binary is newer than the file (or
the file is missing), the module regenerates it via
`gmellon completions zsh` and notes the regeneration on stderr. zimfw puts
the module's `functions/` directory on `fpath` automatically, so `compinit`
picks the completion up with no extra wiring. This block is guarded
independently of the SSH environment work: no binary means no completions
and a one-line skip, while `SSH_AUTH_SOCK` selection proceeds exactly as
above. Loading never prompts and never invokes `systemctl` either way.

## Tests

```sh
zimfw/test.zsh
```

Exercises unset→discovered (gcr and keyring order), already-set→preserved
(silently), override→wins, invalid override→error + unchanged environment,
missing socket (with and without `XDG_RUNTIME_DIR`)→actionable message +
nothing exported + exit 0, invalid existing value→discovery repairs,
repeated load→same value, load never invoking systemctl, and the publisher's
absent/present/unavailable/nothing-selected/invalid-override cases. Fixtures
are real AF_UNIX listening sockets; the only `systemctl` is a recording stub
earlier in PATH. Prints a pass/fail summary and exits nonzero on failure.
