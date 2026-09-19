---
type: Assessment
title: Code elegance and organization review — proposed refactor pass
description: Shape assessment of gmellon's CLI/service/ssh layering after the askpass and ssh-verify epics, with an ordered, independently committable refactor proposal.
resource: /design/elegance/elegance0.fx.md
tags: [architecture, refactoring, cli, secret-service, ssh]
status: draft
generated: { by: "agent:glm-5.3-flash-max (z.ai coding plan)", at: "2026-09-18" }
stale_after: 2027-01-01
sources:
  - id: working-tree
    resource: /src
    title: "gmellon working tree at change yuvopnly (post ssh-verify landing)"
    last_modified: 2026-09-18
---

# Elegance 0 — shape assessment and proposed refactor pass

Scope: the whole working tree read end to end for the core modules
([`src/cli/mod.rs`](/src/cli/mod.rs), [`src/secret_service/`](/src/secret_service),
[`src/ssh.rs`](/src/ssh.rs), [`src/secret_input/`](/src/secret_input),
[`src/main.rs`](/src/main.rs)) and structurally for the harness
([`tests/harness/`](/tests/harness)). `cargo fmt --check` was run and is
red, as briefed. No code was modified for this document.

This is an assessment and proposal only — a wave document, not an
implementation plan of record. Every proposed move names its verification
gate; the existing proof set is unusually strong, which is what makes these
moves cheap.

## 1. Snapshot of the current shape

Source is ~5,666 lines; the proof/harness layer is ~5,425 more.

| File | Lines | Role |
|---|---:|---|
| [`src/cli/mod.rs`](/src/cli/mod.rs) | 1,502 | clap enum + dispatch + all 13 handlers + all renderers + exit table + ~485 lines of inline tests |
| [`src/secret_service/blocking.rs`](/src/secret_service/blocking.rs) | 1,056 | model types (`CollectionId`, `Collection`, `Item`), `Error`, `BlockingClient` (collections, lock/unlock, change, SSH item CRUD, secret read-back), error classification |
| [`src/secret_service/session.rs`](/src/secret_service/session.rs) | 637 | sans-I/O DH + AES-128-CBC session crypto core, KAT-pinned |
| [`src/secret_input/mod.rs`](/src/secret_input/mod.rs) | 612 | TTY/stdin secret acquisition, `Secret`, zeroization |
| [`src/ssh.rs`](/src/ssh.rs) | 356 | passphrase verification primitive **and** the askpass provider pipeline |
| [`src/control/`](/src/control) (4 files) | 1,296 | legacy login-control backend behind the default-off `login-control` feature |
| [`src/main.rs`](/src/main.rs) | 45 | pre-clap dispatch: echo marker, `__askpass`, multicall argv[0] |
| [`tests/harness/broker_common.rs`](/tests/harness/broker_common.rs) | 1,821 | fixture service, busctl monitor machinery, body capture, `ProofSecrets`, prerequisites |
| [`tests/harness/broker_cli.rs`](/tests/harness/broker_cli.rs) | 1,762 | the CLI broker proof — `run_proof` is a single ~1,465-line narrative ([broker_cli.rs:103](/tests/harness/broker_cli.rs)–[1567](/tests/harness/broker_cli.rs)) |
| [`tests/harness/redaction_scan.rs`](/tests/harness/redaction_scan.rs) | 595 | positive controls for the redaction scanner + header parser |
| other tests | ~1,250 | `broker_collections` (384), `common` (288), `ssh_verify` (279), `real_daemon` (276), `completions` (99) |

Layering is actually clean top to bottom: `main.rs` → `cli` →
`secret_service::BlockingClient` → zbus proxies + sans-I/O `session`, with
`secret_input` and `ssh` as leaf capabilities. There are no cycles and the
CLI never touches zbus types except `OwnedObjectPath` in tests. The problems
below are about *width* inside files, not wrong dependency direction.

## 2. Strengths worth keeping (do not regress these)

1. **`session.rs` is the deepest module in the tree.** ~320 lines of product
   code behind four public items (`ClientKeypair`, `SessionKey`, `seal`,
   `open`, [`session.rs:138-314`](/src/secret_service/session.rs)) with zero
   I/O or zbus types, documented protocol derivation, and test vectors
   transcribed from upstream (`session.rs:322-364`). It was explicitly built
   for async reuse. Untouchable except by fmt.
2. **One `Error` enum with an exhaustive exit mapping.** `service_error_exit`
   matches every variant ([cli/mod.rs:949-969](/src/cli/mod.rs)); adding a
   variant forces an exit-code decision, and the table is pinned by
   `service_errors_map_to_stable_exit_codes`
   ([cli/mod.rs:1442-1476](/src/cli/mod.rs)). The 0–4 table documented in
   [`doc/status.md`](/doc/status.md) has survived three feature waves without
   gaining a code. Keep this shape.
3. **The enum "proliferation" is coherent layering, not accretion.**
   `RunOutcome` (process result, [ssh.rs:74-78](/src/ssh.rs)) → `Verdict`
   (crypto verdict, [ssh.rs:33-45](/src/ssh.rs)) → `VerifyOutcome`
   (storage + file + verdict composite,
   [cli/mod.rs:668-691](/src/cli/mod.rs)). Each layer maps forward only, no
   layer imports the one above, and the decrypted passphrase never reaches
   any of them. This is right; see §5 for why unifying them would be wrong.
4. **Secret hygiene is uniform and enforced.** `Zeroizing` everywhere, no
   `Debug`/`Clone`/`Display` on secret-bearing types
   ([session.rs:136-137](/src/secret_service/session.rs),
   [secret_input/mod.rs:62-65](/src/secret_input/mod.rs)), tracing fields
   are scalar-metadata-only, and [`tests/harness/redaction_scan.rs`](/tests/harness/redaction_scan.rs)
   positive-controls the scanner that polices it.
5. **The pre-clap dispatch in [`main.rs`](/src/main.rs)** is 45 lines, each
   branch documented with *why* it must precede clap (clap_complete advertises
   hidden subcommands — verified against 4.6.5,
   [main.rs:15-19](/src/main.rs)) and pinned by tests
   ([cli/mod.rs:1392-1413](/src/cli/mod.rs),
   [tests/ssh_verify.rs:225-279](/tests/ssh_verify.rs)).
6. **Async seams already exist.** The zbus macro generates async proxies
   alongside blocking ones, `decode_open_session_output` was made public
   "so test fixtures and a future async adapter share one decode step"
   ([blocking.rs:869-891](/src/secret_service/blocking.rs)), and the client
   doc-comment names the reuse path ([blocking.rs:287-295](/src/secret_service/blocking.rs)).

## 3. Tensions and smells, with evidence

### T1 — `cli/mod.rs` is a god file, and the drift is already visible

1,502 lines stack five layers: the clap grammar (29–228), dispatch
(230–254), handlers (268–851), renderers (853–1016), and tests (1018–1502).
Concrete accretion damage: the doc comment for `completions` ("Emit the
completion script… buffered and written once…") is stranded on `fn items`
([cli/mod.rs:459-461](/src/cli/mod.rs)) while `fn completions`
([cli/mod.rs:897](/src/cli/mod.rs)) has none — a merge/edit artifact that
rustdoc silently renders wrong. The ssh family (ssh-list/add/allow/deny/
remove/verify plus `VerifyOutcome` machinery) is ~370 of the ~585 handler
lines and every future ssh scope grows it further.

### T2 — the path discipline is stated in comments because it has no name

"Same path discipline as ssh-remove: canonicalize when present,
verbatim-absolute otherwise" appears at five call sites:
[cli/mod.rs:509-518](/src/cli/mod.rs) (`ssh_add`, strict flavor: hard error),
[cli/mod.rs:608-611](/src/cli/mod.rs) (`ssh_allow`),
[cli/mod.rs:643-646](/src/cli/mod.rs) (`ssh_remove`),
[cli/mod.rs:789-792](/src/cli/mod.rs) (`ssh_verify`), and
[ssh.rs:250-254](/src/ssh.rs) (`askpass_provider`). Two flavors exist and
the difference is load-bearing: `ssh_add` requires the key file to exist
(the canonical path is the storage key and the passphrase must be verified);
the lenient sites must match the stored attribute even when the file is
gone. A future edit that "unifies" them incorrectly is exactly the bug class
the unique-attribute join key punishes — the comment-referenced discipline
wants to be one tested function per flavor.

### T3 — the prompt-object refusal is hand-rolled three times

`!prompt.as_str().is_empty() && prompt.as_str() != "/"` with a
`LockPromptRequired` return appears at
[blocking.rs:500-502](/src/secret_service/blocking.rs) (`lock`),
[blocking.rs:641-644](/src/secret_service/blocking.rs)
(`create_ssh_key_item`), and
[blocking.rs:797-799](/src/secret_service/blocking.rs)
(`remove_ssh_key_item`). Small, but it is a protocol invariant (gmellon
never performs a prompt object) encoded as a duplicated expression.

### T4 — full-store walks are duplicated, and verify-all is quadratic over the bus

`ssh_key_items` ([blocking.rs:531-552](/src/secret_service/blocking.rs)) and
`find_exact_ssh_key_items` ([blocking.rs:683-696](/src/secret_service/blocking.rs))
both walk every collection × every item, three property reads per item
(`inspect_item`, [blocking.rs:662-677](/src/secret_service/blocking.rs)).
On top of that, `ssh-verify` in all mode enumerates via `ssh_key_items`
([cli/mod.rs:819-846](/src/cli/mod.rs)) and then calls
`verify_stored_passphrase` per key, which calls `ssh_key_item` →
`find_exact_ssh_key_items` — a *second* full walk per key
([cli/mod.rs:749-778](/src/cli/mod.rs)). That is
O(keys × collections × items) D-Bus property traffic; fine at a handful of
keys, quadratic in the store at hundreds of items. The fix must preserve one
semantic carefully: duplicate detection (`SshKeyItemsAmbiguous` → ERROR
line) currently comes from the re-walk, so a single-walk variant must derive
ambiguity from the enumerated set (duplicate `ssh_key_path` entries) instead.

### T5 — the CLI reaches past the client into the crypto module

`status` imports `secret_service::session` for `ALGORITHM`
([cli/mod.rs:9](/src/cli/mod.rs), [cli/mod.rs:305](/src/cli/mod.rs)). Tiny,
but it is the one place the CLI dips below `BlockingClient`; a re-export
from `secret_service` (or the client) closes it.

### T6 — `ssh.rs` serves two masters

The verification primitive (`verify_passphrase`, `Verdict`, `run_ssh_keygen`,
[ssh.rs:32-131](/src/ssh.rs)) is consumed by the `ssh-add`/`ssh-verify`
handlers; the askpass provider (`askpass_main`, `parse_askpass_prompt`,
`askpass_provider`, [ssh.rs:133-290](/src/ssh.rs)) is a *process entry
point* exec'd by ssh-keygen and OpenSSH. They share only the askpass-exec
mechanism. The file's own section banner
([ssh.rs:178-182](/src/ssh.rs)) marks the seam. Future per-collection ssh
scopes grow the provider half; the verifier half is stable.

### T7 — `cargo fmt --check` is red repo-wide

Verified: diffs in [`blocking.rs`](/src/secret_service/blocking.rs) (two
spots), [`ssh.rs:280+`](/src/ssh.rs), and an inline brace-drift in
[`cli/mod.rs:1080`](/src/cli/mod.rs)
(`fn completions_parse_every_advertised_shell_and_reject_others() {
        for shell in`). Askpass-wave drift, as briefed. This must be its own
first commit so refactor diffs carry no formatting noise.

### T8 — `broker_common.rs` is four files wearing a trenchcoat

1,821 lines comprise: harness-environment validation + the fixture service
proxy ([101-560ish](/tests/harness/broker_common.rs)), the header reader and
monitor spawn/stop plumbing ([532-713](/tests/harness/broker_common.rs)),
the streaming header/body scanners
([HeaderCallParser, 532-604](/tests/harness/broker_common.rs),
body capture 1082-1410), and the body monitors + `ProofSecrets` +
prerequisites (1415-1821). It is `#[path]`-included into four targets
([Cargo.toml:38-52](/Cargo.toml), [tests/ssh_verify.rs:11-13](/tests/ssh_verify.rs)
includes `common` similarly), which is fine — the structure inside is what
resists navigation. Note the `finish_case` trio
([common/mod.rs:164](/tests/harness/common/mod.rs),
[broker_cli.rs:1753](/tests/harness/broker_cli.rs),
[broker_collections.rs:377](/tests/harness/broker_collections.rs)) is *not*
duplication: thin per-proof wrappers delegating to `common::finish_case`
with per-proof evidence headers. Leave that shape alone.

### T9 — `login-control` is honest, dormant debt

~1,296 lines, default-off ([Cargo.toml:26-30](/Cargo.toml)), no CLI surface
(help exclusion is tested, [cli/mod.rs:1057-1058](/src/cli/mod.rs)), and its
doc-comment states its narrower semantics honestly
([control/mod.rs:1-14](/src/control/mod.rs)). But the only cross-module
coupling is two `secret_input` tests feeding the control codec
([secret_input/mod.rs:581-611](/src/secret_input/mod.rs)), and default
builds never compile it — so nothing in the ordinary check run notices if
it rots. Not dead (documented in the README's backend policy, proven by the
python harness), but unaudited by CI-as-run.

## 4. Proposed refactor pass (ordered; each move independently committable)

**Move 0 — fmt the tree, alone in its own commit.**
`cargo fmt`; commit nothing else in it. *Gate:* `cargo fmt --check` clean;
full default suite green. Risk: none. This makes every later diff reviewable.

**Move 1 — split `cli/mod.rs` per command family.**
Keep `Cli`, `Command`, and `run()` in `cli/mod.rs` (one grammar, one help
surface — see §5). Move into siblings:
- `cli/collections.rs` — `list`, `status`, `unlock`, `lock`, `change`,
  `items` + `read_change_stdin`/`read_change_tty`
- `cli/ssh.rs` — `ssh_list`, `ssh_add`, `ssh_allow`, `ssh_remove`,
  `ssh_verify`, `verify_stored_passphrase`, `VerifyOutcome` and its three
  total functions
- `cli/render.rs` — the four renderers + `private_interface_wording`
- `cli/report.rs` — `EXIT_*`, `service_error_exit`, `report_service_error`,
  `report_input_error`, `denied_wording`
- `cli/completions.rs` — the completions handler (and give it back its
  orphaned doc comment; fix `items`' while there)

Tests move with their subjects. Fold in T5: re-export `ALGORITHM` from
`secret_service` and drop the `session` import from the CLI. *Gate:*
`command_definition_is_consistent`, the help/completion/exit-table tests,
and the whole default suite; the compiled binary's behavior is unchanged, so
the broker CLI proof (opt-in) is the strong gate when next run. Risk: low —
pure motion; the one live hazard is `pub` visibility choices, which stay
`pub(crate)`.

**Move 2 — name the path discipline.**
Add one tested function, e.g. `pub fn canonical_or_absolute(path: &Path) ->
PathBuf` in the ssh module (it is needed by both the provider and the CLI),
and use it at the four lenient sites (T2). `ssh_add`'s strict flavor stays
an explicit `canonicalize` with its hard error — the asymmetry is policy,
not duplication, and should remain visible. *Gate:* new unit tests
(symlink resolution, missing-file verbatim-absolute, relative-path
absolutization) plus the existing ssh narratives in
[`broker_cli.rs`](/tests/harness/broker_cli.rs) (add/remove/allow/verify
against stored attributes) and [`tests/ssh_verify.rs`](/tests/ssh_verify.rs).
Risk: low-medium — this is the storage join key; the proofs pin it.

**Move 3 — collapse the prompt-object refusal.**
`fn ensure_no_prompt(prompt: &OwnedObjectPath) -> Result<(), Error>` in
`blocking.rs`, used by `lock`, `create_ssh_key_item`, `remove_ssh_key_item`
(T3). *Gate:* `blocking.rs` unit tests + the lock/remove narratives in the
broker proofs. Risk: trivial.

**Move 4 — one SSH item walk, and de-quadratic verify-all.**
In `blocking.rs`, factor a single internal all-items walk;
`ssh_key_items` and `find_exact_ssh_key_items` become filters over it. Then
give all-mode verify a single-walk path: derive duplicate ambiguity from the
enumerated set (count equal `ssh_key_path`s) instead of re-walking per key,
reading secrets per item already in hand (T4). Preserve: stable order, one
line per key, ERROR lines for storage failures, single-key mode unchanged.
*Gate:* this is the pass's riskiest move — sequence it after the mechanical
ones and run the full broker CLI proof against the real daemon before and
after; add a duplicates fixture case to the proof if one does not exist.
Risk: medium; the semantics to protect are exactly the ones the proof
narrates. If the single-walk variant proves gnarly, the walk consolidation
alone (no CLI change) is still worth the commit, with the quadratic
documented in `doc/status.md` as a known limit.

**Move 5 — split `ssh.rs` into `ssh/verify.rs` + `ssh/askpass.rs`.**
Pure motion along the seam the file itself draws (T6); `main.rs` entry
points unchanged. *Gate:* `tests/ssh_verify.rs`, the prompt-parse unit
tests, `askpass_provider_is_not_a_clap_subcommand`. Risk: trivial.

**Move 6 — fence `login-control` against invisible rot.**
Keep the backend (see §5), but add `cargo check --features login-control`
(and its test compile) to the routine check script so a default-off module
cannot silently break. Optionally note in `lib.rs` that the module is a
candidate for crate-split if a second consumer appears. *Gate:* check runs
green both ways. Risk: none.

**Move 7 (optional, last) — factor `broker_common.rs` into a directory.**
`tests/harness/broker_common/{mod,fixture,monitor,secrets}.rs` with the
`#[path]` inclusion updated at the four targets (T8). Hoist the CLI-driving
tail of `broker_cli.rs` (`run_gmellon`, `password_line`, `lines_stdin`,
`change_stdin`, `exit_code`,
[broker_cli.rs:1639-1751](/tests/harness/broker_cli.rs)) into the shared
module *only* as `broker_collections` can actually share them. Do **not**
touch the `run_proof` narrative. *Gate:* `redaction_scan` positive controls
+ every target compiles + one real proof run. Risk: low, but it buys
navigation, not correctness — skip if the tree is about to see heavy
traffic elsewhere.

## 5. What I would not do

- **Not touch `session.rs`** beyond Move 0's fmt. KAT-pinned, upstream-derived
  tests, sans-I/O — the highest-value module per line in the tree.
- **Not unify `Verdict`/`VerifyOutcome`/`RunOutcome`.** The layering is
  deliberate and each maps forward only (§2.3); a single enum would drag
  process plumbing into the CLI's output contract.
- **Not split the clap `Command` enum** per family. One grammar, one help
  surface, one `debug_assert` pin. Families split at the *handler* layer.
- **Not abstract the three tab-separated renderers** into a table framework.
  They are 20–40 lines each, total, tested verbatim; parallel simplicity is
  cheaper than the abstraction.
- **Not retire `login-control` in this pass.** It is documented, proven, and
  honestly fenced; deleting proven capability is churn. Fence it (Move 6),
  revisit crate-split on a second consumer.
- **Not data-drive the broker proof narratives.** The 1,465-line `run_proof`
  is a narrative on purpose — it is the review artifact the harness docs
  point at. Sharing *scaffolding* is fine; restaging the story is not.
- **Not introduce the async Tokio client now.** The seams are already cut
  (§2.6); building the sibling before a caller exists would freeze the wrong
  interface.
- **Not touch `main.rs`'s pre-clap dispatch.** 45 lines, each branch has a
  verified reason to exist, and it is multiply pinned by tests.

## Cross-references

- [`design/askpass/askpass.glm53.md`](/design/askpass/askpass.glm53.md) —
  the askpass provider contract and threat model; the per-key grant invariants
  that Move 2 and Move 5 must not disturb.
- [`doc/status.md`](/doc/status.md) — the exit-table and compatibility
  contract that `report.rs` (Move 1) continues to implement.
- [`doc/harness/README.md`](/doc/harness/README.md) — harness architecture;
  the context for Move 7's factoring and for what the proofs pin in place.
- [`README.md`](/README.md) — user-facing structure; unaffected by every
  move above (no public API or CLI surface changes proposed).
