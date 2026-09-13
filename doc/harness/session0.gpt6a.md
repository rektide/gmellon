---
type: Evidence
title: Encrypted Secret Service session implementation and body-scan monitor proof
description: Installed-host evidence that gmellon negotiates the standard dh-ietf1024-sha256-aes128-cbc-pkcs7 Secret Service session on every connection and that passwords travel only as ciphertext — the sans-I/O crypto core with pinned known-answer vectors, the first-live-run interop facts against gnome-keyring-daemon 48.0, and the private-bus body-scanning monitor whose absence (no generated password in any captured body) and presence (per-member encrypted shape, per-negotiation DH algorithm) verdicts close the gmell-encrypted-session release blocker.
resource: /doc/harness/session0.gpt6a.md
tags: [gmellon, harness, dbus-broker, gnome-keyring, secret-service, encryption, dh, hkdf, aes-cbc]
status: draft
generated: { by: model:openai/gpt-6, at: 2026-09-13T05:45:00-04:00 }
verified: { by: model:openai/gpt-6, at: 2026-09-13T06:10:00-04:00 }
stale_after: 2027-03-13
sources:
  - id: session-core
    resource: /src/secret_service/session.rs
    title: Sans-I/O encrypted-session crypto core with pinned KATs (commit 52bfa653)
  - id: wiring
    resource: /src/secret_service/blocking.rs
    title: Blocking-client negotiation and sealed call sites (commit 6d4ef8e9)
  - id: monitors
    resource: /tests/harness/broker_common.rs
    title: Body-scanning monitor machinery and encrypted fixture (commit 0c9298e5)
  - id: collection-proof
    resource: /tests/harness/broker_collections.rs
    title: Multi-collection proof with encrypted-session wire assertions
  - id: cli-proof
    resource: /tests/harness/broker_cli.rs
    title: CLI binary proof with encrypted-session wire assertions
  - id: scanner-controls
    resource: /tests/harness/redaction_scan.rs
    title: Ordinary positive controls for the body scanner and redaction scanners
  - id: check-entry
    resource: /dev/harness/check
    title: Explicit check modes (unchanged by this work)
  - id: broker-lifecycle
    resource: /dev/harness/broker.py
    title: Reusable private dbus-broker harness lifecycle
  - id: installed-daemon
    resource: package:gnome-keyring-daemon@48.0
    title: Installed gnome-keyring-daemon 48.0
  - id: installed-systemd
    resource: package:systemd@261
    title: Installed systemd 261 (busctl monitor, --match)
  - id: installed-broker
    resource: package:dbus-broker@37
    title: Installed dbus-broker 37
  - id: upstream-daemon
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/daemon/dbus/gkd-secret-session.c
    title: Upstream daemon negotiation, HKDF derivation, and NotSupported rejection
  - id: upstream-egg-dh
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/egg/egg-dh.c
    title: Upstream DH group bytes and prime-length shared-secret normalization
  - id: upstream-egg-hkdf
    resource: https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/egg/egg-hkdf.c
    title: Upstream HKDF with NULL-salt-as-HashLen-zeros semantics
  - id: shape-probe
    resource: .test-agent/session-monitor-probe/probe4.sh
    title: Benign probes capturing the installed busctl monitor body and OpenSession renderings
  - id: kat-oracle
    resource: /home/rektide/tmp-opencode/gmell_kat.py
    title: Independent Python KAT oracle (int modpow plus hand-rolled RFC 5869)
---

# Encrypted Secret Service session implementation and body-scan monitor proof

## Result

`gmell-encrypted-session` is closed. Every `BlockingClient` connection —
and therefore every CLI invocation, which constructs one — negotiates the
standard encrypted Secret Service session
`dh-ietf1024-sha256-aes128-cbc-pkcs7`, and every password crosses the bus
only as AES-128-CBC ciphertext with a fresh per-Secret IV. A private-bus
monitor with body-scanning verdicts proves both directions: no generated
password appears in any captured password-method body, and every captured
call demonstrably carried well-formed encrypted secrets. Three commits carry
the work: `52bfa653` (sans-I/O crypto core and tests), `6d4ef8e9` (blocking
client wiring and error mapping), `0c9298e5` (encrypted test fixture,
body-scanning monitors, proof assertions).

## Design as implemented

[`src/secret_service/session.rs`](/src/secret_service/session.rs) is pure
computation over byte slices — no zbus or I/O types — so the blocking client
and a future Tokio adapter share it verbatim (the ticket's reuse
acceptance):

1. **Keypair.** A fresh 1024-bit exponent per connection
   (`getrandom`), top bit masked so the exponent stays below `p/2`
   (mirroring `egg_dh_gen_pair`'s `gcry_mpi_clear_highbit(priv, pbits - 1)`),
   zeroized on drop. The public key `g^x mod p` is sent as the OpenSession
   input variant in minimal unsigned big-endian.
2. **Peer validation.** The daemon's public key must be 1..=128 bytes and
   decode to `1 < y < p - 1`; anything else fails closed before any modpow.
   The comparisons are variable-time on purpose and documented: `y` is
   peer-controlled public data and the verdict is reported either way.
3. **Modpow.** `crypto-bigint`'s `BoxedUint::pow_mod`, the constant-time
   Montgomery ladder with respect to the exponent; the peer-influenced base
   is mitigated by the fresh never-reused exponent.
4. **Normalization.** The shared secret is left-padded with zero bytes to
   exactly the 128-byte prime length before the KDF, matching
   `egg_dh_gen_secret`'s memmove+memset in `egg/egg-dh.c`. A minimal-length
   encoding would derive a wrong key with no visible error; this is the
   interop-critical step.
5. **KDF.** AES-128 key = HKDF-SHA256(ikm, salt empty, info empty, L=16) —
   not `sha256(ikm)[..16]`. Both peers use HKDF: libsecret's
   `egg_hkdf_perform("sha256", ikm, NULL, 0, NULL, 0, out, 16)` and the
   daemon's `CKM_G_HKDF_SHA256_DERIVE` with a NULL parameter; an empty salt
   is RFC 5869's HashLen zeros.
6. **Sealing.** PKCS#7 pads to a 16-byte multiple (a full block on
   16-byte multiples), a fresh random IV per Secret, AES-128-CBC in place
   inside a zeroizing buffer. The Secret tuple's `parameters` carries the
   IV and `value` the ciphertext; the `(oayays)` signature is untouched.
   gmellon only ever encrypts — no product decrypt path exists.

Hygiene follows the crate's established pattern: private exponent, shared
secret, padded IKM, AES key, IV, and padded plaintext live in zeroizing
allocations; `ClientKeypair`, `SessionKey`, and `SealedSecret` implement
none of `Debug`, `Clone`, or `Display`. New dependencies stay in the
RustCrypto family: `crypto-bigint` (alloc, zeroize), `sha2` + `hkdf`,
`aes` + `cbc` (the `aes-cbc` crate is no longer published; `cbc` + `aes`
is its successor), and `getrandom`.

### Known-answer and unit coverage

The ordinary suite pins the crypto without any daemon:

- the prime byte-for-byte against a hex transcription of
  `dh_group_1024_prime` (`egg/egg-dh.c` lines 47–54) plus RFC 2409
  structural checks (1024 bits, top and bottom 64 bits all ones, odd);
- RFC 5869 test cases 1–3 (adapted from `egg/test-hkdf.c`, which
  transcribes the RFC appendix) through the exact hkdf helper the session
  uses — case 3's empty salt and info is the session configuration;
- a fixed negotiation vector computed independently in Python (`int`
  modpow plus a hand-rolled RFC 5869, no Rust crypto crates in the oracle):
  both sides reproduce the pinned public keys, agree on the AES key, and
  the key equals HKDF over the independently computed shared secret;
- two left-pad vectors (shared secrets 3 and 625) proving the 128-byte
  normalization changes the derived key — deriving over the minimal
  encoding yields a different, wrong key;
- peer-key rejection of empty, zero, 1, `p-1`, `p`, longer-than-prime, and
  all-ones inputs, and acceptance of small and zero-padded valid keys;
- seal shape (16-multiple ciphertext, PKCS#7 full block at the boundary,
  fresh IVs), round-trip through a `#[cfg(test)]`-only decrypt helper, and
  wrong-key failure.

## Interop findings from the live daemon

Against the manually launched `gnome-keyring-daemon` 48.0 on the private
`dbus-broker`:

1. **The first live handshake succeeded without adjustment.** The
   `rust-broker` and `rust-cli` proofs passed on their first run after the
   wiring landed — variant shape, minimal big-endian public key, 128-byte
   normalization, HKDF configuration, and seal all correct as implemented.
2. **Variant shape.** The daemon unwraps the outer `v` itself
   (`g_variant_get_variant` in `gkd-secret-service.c`) and requires the
   inner type to be `G_VARIANT_TYPE_BYTESTRING` (`ay`); the client sends
   `Value::from(Vec<u8>)`, which zbus serializes exactly so. In zvariant 5
   the reply decodes as `Value::Array` of `U8` — there is no `ByteArray`
   variant — so the shared `decode_open_session_output` accepts that shape
   and fails closed otherwise.
3. **The daemon does not validate the client's public key.** A probe with
   a 3-byte "public key" was accepted and answered with a full 128-byte
   server key. gmellon's strict `1 < y < p - 1` validator is client-side
   hardening the daemon lacks.
4. **Algorithm rejection path confirmed.** An unknown algorithm raises
   `org.freedesktop.DBus.Error.NotSupported` from
   `gkd_secret_session_handle_open`; the client maps that to a distinct
   `EncryptedSessionUnsupported` error and never falls back to a plain
   session — a deliberate divergence from libsecret, which does fall back.
5. **Rendering facts the monitor depends on** (installed `busctl` 261,
   captured under the private broker by
   `.test-agent/session-monitor-probe/`): `ay` bodies render as
   `ARRAY "y" {` blocks with one `BYTE <decimal>;` line per element; an
   empty array renders as the `ARRAY` line with no `BYTE` lines (so a
   plain secret's empty IV is distinguishable by length); an OpenSession
   body renders the algorithm as `STRING "<algorithm>";` followed by
   `VARIANT "ay" { ARRAY "y" { … } }`.

## Monitor design and positive controls

[`broker_common.rs`](/tests/harness/broker_common.rs) gained a `BodyMonitor`
alongside the existing header-fact monitors. It runs `busctl monitor` with
one match rule — every member of
`org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` — plus a second
instance for `Service.OpenSession`, both armed before any fixture traffic
and both streaming stdout through a pipe drained by an owned reader thread:

- **Absence.** Every raw line is scanned for every generated password
  (literal and hex), and — the load-bearing check — every reconstructed
  `ay` run is scanned for contiguous plaintext, because a password inside
  a `BYTE`-decimal rendering is invisible to line scans. Runs are
  reconstructed one zeroized buffer at a time and dropped immediately; no
  decoded body ever exists on disk, in any form, on any teardown path.
  Leak records carry the member and the proof-secret name, never bytes.
- **Presence.** Each captured password-method call is verdicted by member
  arity: Unlock = one `[16, m]` pair, Change = two pairs, Create = trailing
  pair, with `m` a non-empty 16-multiple. A plain secret (empty IV array)
  or absent body fails the verdict, so an absent-password assertion from a
  blind monitor cannot pass vacuously. Each captured OpenSession must carry
  the pinned DH algorithm line, and a `plain` negotiation fails closed.
- **Fail-closed parsing.** Header lines must carry both `Sender` and
  `Member` with a unique-bus-name sender; `BYTE` outside an `ARRAY "y"`
  block, unexpected members, and unattributable headers all fail the proof.
- **Retained artifacts.** `password-body-monitor.txt` and
  `open-session-monitor.txt` summaries hold member, sender, array lengths,
  and verdicts only. Banner-only readiness logs are secret-scanned and
  deleted. The proof secrets are scanned out of every retained regular
  artifact by the existing symlink-failing-closed walk.

The test fixture itself now negotiates the same encrypted session through
the shared core (and the exported `decode_open_session_output` decode
step), so even fixture `CreateWithMasterPassword` bodies carry ciphertext —
which is what makes the interface-wide absence assertion sound.

Positive controls in the ordinary suite
([`redaction_scan.rs`](/tests/harness/redaction_scan.rs)) pin the scanner
against the captured rendering: encrypted-shape verdicts, plain-shape
rejection, leak detection inside a decoded run and in raw line bytes,
fail-closed header/BYTE cases, OpenSession DH/plain verdicts, and the
change-call two-Secret arity.

## Wire-evidence assertions

- `rust-broker`: exactly two encrypted fixture creations, six product
  unlocks, one product change — all encrypted-shape; exactly two OpenSession
  negotiations (fixture and product client), both DH.
- `rust-cli`: exactly eleven binary unlock calls and three change bodies,
  the latter cross-checked equal to the independent header monitor's count;
  OpenSession count equals the invocation count plus the fixture's own, all
  DH, exactly one from the fixture sender.

## Exact check results

All maintained entry points, run 2026-09-13 on the installed host
(daemon 48.0, systemd 261, dbus-broker 37):

```text
cargo nextest run                 106 passed, 4 skipped (baseline skips unchanged)
dev/harness/check rust-nextest   2/2 passed
dev/harness/check rust-broker    1/1 passed
dev/harness/check rust-cli       1/1 passed
dev/harness/check broker         7/7 passed plus the private-bus probe
dev/harness/check all            all of the above plus the control-only Python suites
cargo fmt --check                clean
cargo clippy --all-targets --all-features -- -D warnings   clean
cargo doc                        warning-free
```

The four ordinary skips are the explicit opt-in external proofs, unchanged
by this work.

## Honest limits

- The monitor observes the proof bus and the generated secrets of each run;
  it is wire evidence for those runs, not a standing guarantee for other
  hosts or daemons.
- The session is the spec-mandated 1024-bit DH group with AES-128-CBC —
  dated cryptography chosen by the protocol, not gmellon. Fresh
  per-connection exponents, per-Secret IVs, and gmellon's strict peer-key
  validation are the available mitigations.
- Zeroization is best-effort process-memory hygiene; zbus, broker, and
  daemon copies of ciphertext metadata and ciphertext remain outside
  gmellon's control.
