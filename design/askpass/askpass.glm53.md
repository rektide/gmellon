---
type: Design
title: gmellon as an SSH_ASKPASS provider
description: Contract, threat model, and per-key opt-in design for answering OpenSSH passphrase prompts from gmellon-managed keyring storage.
resource: /design/askpass/askpass.glm53.md
tags: [gmellon, ssh-askpass, secret-service, security]
status: draft
generated: { by: model:zai-coding-plan/glm-5.3, at: 2026-09-17T00:00:00-04:00 }
sources:
  - id: openssh-readpass
    resource: https://github.com/openssh/openssh-portable/blob/master/readpass.c
    title: OpenSSH readpass.c (askpass invocation, master 2026)
  - id: gcr-ssh-agent-interaction
    resource: https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-ssh-agent-interaction.c
    title: gcr-ssh-agent passphrase lookup and fallback prompt (gcr 4.4, verified in ~/archive/GNOME/gcr)
  - id: ticket
    resource: beads:gmell-askpass-helper
    title: "gmell-askpass-helper: Explore gmellon as an SSH_ASKPASS provider backed by the keyring"
---

# gmellon as an SSH_ASKPASS provider

## What is going on

gmellon already stores SSH key passphrases exactly where gcr-ssh-agent finds
them (`unique=ssh-store:<absolute path>` in the default collection, verified
against the key before storing). The open ticket `gmell-askpass-helper` asks
whether gmellon should also serve as an `SSH_ASKPASS` provider, so OpenSSH
clients — `ssh`, `ssh-add`, `git` over ssh, headless automation — can pull
those same passphrases instead of prompting on a TTY. The ticket explicitly
gates implementation on this note: the exposure needs a threat model and the
interaction contract needs verification against real source.

**Decision (user, 2026-09-17):** proceed with implementation using a
**per-key opt-in attribute, default-deny**. Nothing is answerable until the
user marks the key; the oracle surface is exactly the set of keys explicitly
allowed.

## The contract, verified against source

### OpenSSH side: how ssh invokes an askpass

From `readpass.c` (upstream master, 2026) — `ssh_askpass()` and
`read_passphrase()`:

- **When**: askpass is allowed when `DISPLAY` or `WAYLAND_DISPLAY` is
  non-empty, or `SSH_ASKPASS_REQUIRE=force`. `SSH_ASKPASS_REQUIRE` is
  `force` (always, even with a TTY, even headless) / `prefer` (askpass when
  a display is set, else TTY) / `never` (disabled). Unset means legacy
  behavior: askpass only when there is no usable TTY.
- **Program**: `$SSH_ASKPASS` via `execlp`, so a bare name resolves through
  PATH; absolute paths win. Otherwise the compile-time default
  (`/usr/libexec/openssh/ssh-askpass` and kin).
- **Invocation**: `fork`; the child dup2s a pipe onto **stdout only**
  (stdin/stderr inherited) and execs with **exactly one argument**: the
  prompt text as `argv[1]`.
- **Answer protocol**: the parent reads until EOF or 1023 bytes, `waitpid`s,
  and requires **exit status 0** — a nonzero exit discards and zeroes the
  answer. The passphrase is everything before the first `\r` or `\n`, so a
  single line with optional trailing newline; 1023-byte cap.
- **Refusal channel**: exit nonzero (clean "don't know"), or print nothing
  and exit 0 (yields the empty passphrase — *not* a refusal).
- **Env hint**: `SSH_ASKPASS_PROMPT` is set to `confirm` when the askpass is
  being used for a yes/no **permission** question (`ask_permission()`), and
  `none` for pure notifications. It is **absent** for real passphrase
  prompts.

Prompt text formats differ by caller (this matters for parsing):

| Caller | Prompt | Path form |
|---|---|---|
| `ssh` | ``Enter passphrase for key '<path>': `` | single-quoted |
| `ssh-add`, `ssh-keygen -f` | ``Enter passphrase for <path>: `` | bare, `%.100s` truncated |
| `ssh-keygen -p` | `Enter old passphrase:` / `Enter new passphrase (empty for no passphrase):` | **no path** — unanswerable |
| permission questions | arbitrary yes/no text | `SSH_ASKPASS_PROMPT=confirm` |

Known limit: `ssh-add`'s `%.100s` truncates paths longer than 100 bytes, so
such prompts parse to a truncated path, miss the lookup, and are refused.
Safe failure; documented here rather than fixed.

### gcr side: the asymmetry

`gcr-ssh-agent` **never uses SSH_ASKPASS** (verified in
`gcr/gcr-ssh-agent-interaction.c`, gcr 4.4). When it needs a passphrase it
looks up the generic-schema item by attributes via `secret_password_lookupv`
(matching `unique=ssh-store:<abs path>`, superset attribute matching), and on
miss falls back to a GTK system prompt whose "Automatically unlock this key
whenever I'm logged in" checkbox stores the item back.

So `gmellon askpass` does not serve gcr — it serves **OpenSSH clients**. Both
sides read and write the same items, which is the point: `gmellon ssh add`
today, askpass tomorrow, keys unlock anywhere. Superset attribute matching
also means gmellon's extra opt-in attribute cannot break gcr's lookup; the
broker proof must demonstrate exactly that.

## Threat model

**The core exposure:** an askpass program is a passphrase oracle. Any local
process that can set `SSH_ASKPASS=gmellon-askpass` (or
`SSH_ASKPASS_REQUIRE=force` plus a wrapper) — or, more fundamentally, just
invoke the binary directly, which nothing can prevent — controls the prompt
string and can therefore request any key path it can name. There is no
authentication of the caller in the askpass contract; stdin/stdout pipes and
argv are the whole interface.

What an attacker gains without opt-in gating: any stored ssh-store secret on
demand. The same is true of gcr's own lookup path (any process can talk D-Bus
and search items), but gmellon should not *add* a second, more convenient
oracle on top.

### Mitigations considered

- **Per-key opt-in attribute (chosen):** only items carrying
  `gmellon:askpass=allow` are answerable. Default-deny; plain gcr-stored
  items stay silent; explicit `gmellon ssh allow KEY` (or `ssh add
  --askpass`) marks a key. No UI dependency; headless use stays headless.
- Confirmation prompt per invocation: strongest bound, but it defeats the
  headless/automation use case that motivates askpass.
- Answer-any-stored-item: maximum utility, oracle as wide as the keyring.
- Opt-in plus session-scoped confirm cache: agent-style remembered approval;
  more state (where does the session live?), deferred.

Not defenses, but honest boundaries to document: parsing rigor (only exact
prompt shapes parse), refusal of `SSH_ASKPASS_PROMPT=confirm`, and
never-prompting in askpass mode (a locked collection is a refusal, not a
hang). Parent-process identity checks are spoofable via `exec` chains and
are not adopted.

## Design

### Entry points

The askpass contract requires the program be invocable as `<prog> <prompt>`
— one argv element, no subcommand. Two entry points share one code path:

1. **Multicall binary**: `argv[0]` basename `gmellon-askpass` selects
   askpass mode before clap parsing (busybox-style; a symlink or copy named
   `gmellon-askpass` on PATH). Documented usage:
   `SSH_ASKPASS=gmellon-askpass SSH_ASKPASS_REQUIRE=force ssh …`.
2. **Hidden subcommand**: `gmellon __askpass <PROMPT>` for wrapper scripts
   (`exec gmellon __askpass "$1"`), hidden from help and completions.

The existing `GMELLON_ASKPASS` env-marker echo mode (self-verification
helper) is untouched: real callers never set the marker.

### Answer pipeline

`ssh::askpass_provider(prompt)`:

1. `SSH_ASKPASS_PROMPT` present and non-empty → refuse (permission and
   notification prompts are never passphrase prompts).
2. Parse the prompt: `Enter passphrase for key '<path>': …` or
   `Enter passphrase for <path>: …`; require an absolute path; canonicalize
   if the file exists (same path discipline as `ssh-remove`), else use the
   verbatim absolute path. Unparseable → refuse.
3. Open the encrypted-session client (refuse on any service error).
4. Look up the item by exact `unique` attribute across collections;
   exactly one match required; locked → refuse; **no TTY prompt, ever**.
5. Require the `gmellon:askpass=allow` attribute; else refuse.
6. `GetSecret` under the encrypted session, decrypt (`session::open`, the
   new counterpart to `seal`), write the bytes plus `\n` to stdout,
   zeroize, exit 0.

Refusals print **nothing to stdout** and exit 1, with at most one
secret-free stderr line. The success channel is stdout — the answer *is*
the secret; that is the contract, and the redaction stance below encodes it.

### CLI surface

- `gmellon ssh add KEY [--askpass]` — `--askpass` ends with the item
  carrying `gmellon:askpass=allow`.
- `gmellon ssh allow KEY` / `gmellon ssh deny KEY` — set/remove the opt-in
  attribute on the stored item (`deny` leaves the item itself in place for
  gcr), via `org.freedesktop.DBus.Properties.Set` on the item's attributes
  — the same mechanism libsecret's own attribute updates use.
- `gmellon ssh-list` gains an `ASKPASS` column (yes/no) — the grant is
  security state and belongs where keys are listed; `items` shows the raw
  attribute as always.

**Verified replace semantics (broker-proof correction).** gnome-keyring's
CreateItem-replace match is subset-on-the-new-fields
(`gkd-secret-objects.c` `collection_find_matching_item` →
`gkm_secret_fields_match`: every incoming field must already exist, equal,
on the item; extra item fields are fine), and a matched item has its
attributes set wholesale. Two consequences:

- a CreateItem carrying the grant **duplicates** an existing un-granted
  item instead of replacing it — the first broker run of this design
  failed exactly there;
- a plain re-store **wipes** an existing grant (attributes are replaced
  wholesale) — deliberate: the flags you pass are the state you get.

`create_ssh_key_item` therefore always replaces with the plain gcr
attribute set (subset-matches granted and un-granted items alike), then
merges the grant through the writable attributes property when
`--askpass` is given. Two bus calls in the granted case, one otherwise,
and exactly one item, always.

### Product read path

`BlockingClient::ssh_key_secret(key_path) -> Zeroizing<Vec<u8>>` — the one
place gmellon reads a secret back (shared future surface with the open
`gmell-ssh-verify` ticket). Refactor the exact-unique walk out of
`remove_ssh_key_item` so remove/read/allow share one lookup.

### Redaction stance

- Harness `run_gmellon` asserts secrets never appear in any stream; the
  askpass success case needs a dedicated runner asserting absence on
  **stderr only**, with the stdout equality in memory — mirroring the
  existing fixture `GetSecret` readback precedent.
- Retained artifacts keep the full scan: the passphrase must never reach
  disk. Logs (which askpass mode does not install) carry scalar fields
  only, per house style.

## Test plan

- **Unit** (`ssh.rs`): prompt parsing (both formats, quoted/unquoted,
  trailing colon-space, garbage, relative paths, >100-byte truncation),
  confirm-hint refusal, attribute-map logic.
- **Binary** (`tests/ssh_verify.rs`, no daemon): `__askpass` with
  unparseable prompt → exit 1, empty stdout; multicall dispatch via a
  renamed copy of the binary; confirm-env refusal.
- **Broker proof** (`broker_cli.rs`, ignored/dev-harness entry): after the
  existing store/readback section — allow, askpass answers exactly the
  stored passphrase, deny → refusal, unparseable → refusal, confirm-env →
  refusal, gcr-style fixture read-by-unique still finds the item with the
  extra attribute present (superset matching), ssh-list shows the grant.

## Open questions / future

- Packaging: nothing installs a `gmellon-askpass` symlink yet — the zimfw
  module or install docs need a line; the hidden subcommand works without
  it meanwhile.
- `gmell-ssh-verify` should reuse `ssh_key_secret` when it lands.
- A per-session confirm cache could later soften headless refusal of
  un-allowed keys without widening the standing oracle; not built now.

## Cross-references

- [`/doc/status.md`](/doc/status.md) — current product status; its Current
  CLI table and command notes now describe the askpass surface and point
  back here for the contract and threat model.
- [`/README.md`](/README.md) — the askpass helper usage section (multicall
  setup, grant commands, refusal invariants) is the user-facing rendering
  of this design.
- [`/doc/harness/README.md`](/doc/harness/README.md) — the harness guide;
  the private-broker CLI proof (implemented in
  [`tests/harness/broker_cli.rs`](/tests/harness/broker_cli.rs)) carries the
  full grant/answer/revoke lifecycle, the gcr-compat superset-matching
  readback, and the stdout-exempt redaction stance this note specifies.
- beads `gmell-askpass-helper` — the ticket this note gates; the
  subset-matching trap recorded above was caught by its proof run.
