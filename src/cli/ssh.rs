//! SSH key passphrase command handlers: ssh-list, ssh-add, ssh-allow,
//! ssh-deny, ssh-remove, and ssh-verify, plus the per-key `VerifyOutcome`
//! machinery the verify paths share.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use gmellon::secret_input;
use gmellon::secret_service::{BlockingClient, CollectionId, Error as ServiceError, Item};
use gmellon::ssh::{self, Verdict};

use super::render::render_ssh_items;
use super::report::{EXIT_DENIED, EXIT_ERROR, EXIT_OK, report_service_error};

/// List stored SSH key passphrases across all collections.
pub(crate) fn ssh_list() -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-list");
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.ssh_key_items() {
            Ok(entries) => {
                print!("{}", render_ssh_items(&entries));
                tracing::info!(count = entries.len(), "ssh key items listed");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// Verify a key's passphrase and store it the way gcr-ssh-agent finds it.
pub(crate) fn ssh_add(key: &Path, stdin: bool, askpass: bool) -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-add", key = %key.display());
    span.in_scope(|| {
        // The absolute path is the storage key (the unique attribute), so
        // resolve symlinks and relative paths once, up front. This is the
        // strict flavor, deliberately unlike the lenient
        // canonical_or_absolute sites: ssh-add needs the real file to
        // verify the passphrase, so a missing key is a hard error.
        let canonical = match std::fs::canonicalize(key) {
            Ok(canonical) => canonical,
            Err(error) => {
                eprintln!(
                    "gmellon: cannot resolve key path {}: {error}",
                    key.display()
                );
                return EXIT_ERROR;
            }
        };

        let secret = if stdin {
            secret_input::read_stdin_line(&mut io::stdin().lock())
        } else {
            secret_input::prompt(&format!(
                "SSH key passphrase for {} (the KEY's passphrase, not the keyring password): ",
                canonical.display()
            ))
        };
        let secret = match secret {
            Ok(secret) => secret,
            Err(error) => {
                eprintln!("gmellon: {error}");
                return EXIT_ERROR;
            }
        };

        match ssh::verify_passphrase(&canonical, secret.as_bytes()) {
            Verdict::Verified => {
                tracing::info!(verdict = "Verified", "key passphrase verified");
            }
            Verdict::Rejected => {
                eprintln!(
                    "gmellon: WRONG — that does not unlock {}, nothing stored",
                    canonical.display()
                );
                return EXIT_DENIED;
            }
            Verdict::NotEncrypted => {
                eprintln!(
                    "gmellon: {} is not passphrase-protected; there is nothing to store",
                    canonical.display()
                );
                return EXIT_ERROR;
            }
            Verdict::Unavailable(reason) => {
                eprintln!("gmellon: {reason}");
                return EXIT_ERROR;
            }
        }

        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        // gcr-ssh-agent's libsecret lookup goes to the default-alias
        // collection; store exactly there and say where.
        let target = match client.default_collection() {
            Ok(collection) => collection,
            Err(error) => return report_service_error(error),
        };
        match client.create_ssh_key_item(
            &target.id,
            &canonical.display().to_string(),
            secret.as_bytes(),
            askpass,
        ) {
            Ok(()) => {
                if askpass {
                    println!(
                        "stored in collection {} & verified against the key; askpass will answer for it",
                        target.id
                    );
                } else {
                    println!(
                        "stored in collection {} & verified against the key",
                        target.id
                    );
                }
                tracing::info!(outcome = "Stored", collection = %target.id, askpass, "ssh key passphrase stored");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// Grant or revoke the per-key askpass opt-in on a stored passphrase item.
/// The item and its secret stay exactly as gcr-ssh-agent expects; only the
/// gmellon:askpass attribute changes.
pub(crate) fn ssh_allow(key: &Path, allowed: bool) -> u8 {
    let span = tracing::info_span!(
        "operation",
        operation = if allowed { "ssh-allow" } else { "ssh-deny" },
        key = %key.display()
    );
    span.in_scope(|| {
        // The lenient join-key discipline ([gmellon::ssh::
        // canonical_or_absolute]), shared with the askpass provider: the
        // unique attribute must match even when the key file is gone.
        let absolute = ssh::canonical_or_absolute(key);
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.set_ssh_key_askpass(&absolute.display().to_string(), allowed) {
            Ok(collection) => {
                if allowed {
                    println!(
                        "askpass may now answer for {} (collection {collection})",
                        absolute.display()
                    );
                } else {
                    println!(
                        "askpass no longer answers for {} (collection {collection})",
                        absolute.display()
                    );
                }
                tracing::info!(outcome = if allowed { "Allowed" } else { "Denied" }, collection = %collection, "askpass grant updated");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// Remove the stored passphrase item for an SSH key. The key file may no
/// longer exist — stale stored passphrases are the point — so the path is
/// only canonicalized when present, and otherwise made absolute verbatim.
pub(crate) fn ssh_remove(key: &Path) -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-remove", key = %key.display());
    span.in_scope(|| {
        // The lenient join-key discipline ([gmellon::ssh::
        // canonical_or_absolute]): stale stored passphrases are the point,
        // so a missing key file is not an error.
        let absolute = ssh::canonical_or_absolute(key);
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.remove_ssh_key_item(&absolute.display().to_string()) {
            Ok(collection) => {
                println!(
                    "removed stored passphrase for {} from collection {collection}",
                    absolute.display()
                );
                tracing::info!(outcome = "Removed", collection = %collection, "ssh key passphrase removed");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// One per-key outcome of `ssh-verify`: the storage and file facts plus
/// the ssh-keygen verdict. The decrypted passphrase never reaches this
/// type — it lives only in the zeroizing read and the verifier's pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
enum VerifyOutcome {
    /// The stored passphrase still unlocks the key.
    Match,
    /// The key rejected the stored passphrase: it was regenerated under a
    /// different passphrase and the stored secret is stale.
    Stale,
    /// The key file is gone; the stored passphrase can no longer be
    /// checked (or used by gcr-ssh-agent either).
    MissingKey,
    /// The key was regenerated without a passphrase; there is nothing the
    /// stored secret could unlock.
    NotEncrypted,
    /// The owning collection is locked, so the stored passphrase cannot be
    /// read without unlocking the keyring first.
    Locked { collection: String },
    /// Verification could not run at all (ssh-keygen missing, spawn
    /// failure); reported as an error line, not a passphrase verdict.
    Unavailable { reason: String },
    /// A storage or read failure other than the outcomes above — for
    /// example an ambiguous duplicate item, reported per key in
    /// verify-all mode.
    Failed { reason: String },
}

/// The one deterministic output line for a verified key. The leading
/// words are the stable contract (asserted in tests); the parenthetical
/// explains the verdict and names the command that fixes it. Never
/// carries secret bytes.
fn render_verify_line(key_path: &str, outcome: &VerifyOutcome) -> String {
    match outcome {
        VerifyOutcome::Match => format!("MATCH {key_path}\n"),
        VerifyOutcome::Stale => format!(
            "STALE {key_path} (stored passphrase no longer unlocks the key — \
             regenerate it with gmellon ssh-add)\n"
        ),
        VerifyOutcome::MissingKey => format!(
            "MISSING-KEY {key_path} (key file is gone; \
             gmellon ssh-remove cleans it up)\n"
        ),
        VerifyOutcome::NotEncrypted => format!(
            "NOT-ENCRYPTED {key_path} (the key is no longer passphrase-protected; \
             gmellon ssh-remove cleans the stored passphrase up)\n"
        ),
        VerifyOutcome::Locked { collection } => format!(
            "LOCKED {key_path} (collection {collection} is locked; \
             gmellon unlock {collection} makes the stored passphrase readable)\n"
        ),
        VerifyOutcome::Unavailable { reason } => {
            format!("UNAVAILABLE {key_path} ({reason})\n")
        }
        VerifyOutcome::Failed { reason } => format!("ERROR {key_path} ({reason})\n"),
    }
}

/// Whether one per-key outcome counts against the run's exit: only a
/// match succeeds; every other verdict, error, and unavailable report
/// fails the run with exit 1 — the house table gains no new code.
fn verify_outcome_failed(outcome: &VerifyOutcome) -> bool {
    !matches!(outcome, VerifyOutcome::Match)
}

/// Fixed word for the `-v` event stream: scalar, secret-free, stable.
fn verify_outcome_word(outcome: &VerifyOutcome) -> &'static str {
    match outcome {
        VerifyOutcome::Match => "Match",
        VerifyOutcome::Stale => "Stale",
        VerifyOutcome::MissingKey => "MissingKey",
        VerifyOutcome::NotEncrypted => "NotEncrypted",
        VerifyOutcome::Locked { .. } => "Locked",
        VerifyOutcome::Unavailable { .. } => "Unavailable",
        VerifyOutcome::Failed { .. } => "Failed",
    }
}

/// Verify the stored passphrase for one key path (the exact
/// `unique=ssh-store:` value): resolve metadata and file existence before
/// any secret is read, decrypt under the encrypted session through the
/// askpass read path (`ssh_key_secret` — no second read path), and check
/// the passphrase against the key. Storage failures return Err for the
/// caller's house error reporting.
fn verify_stored_passphrase(
    client: &BlockingClient,
    key_path: &str,
) -> Result<VerifyOutcome, ServiceError> {
    // Metadata first: exactly-one existence and lock state, so a verdict
    // that needs no secret never decrypts anything.
    let (collection, item) = client.ssh_key_item(key_path)?;
    if item.locked {
        return Ok(VerifyOutcome::Locked {
            collection: collection.to_string(),
        });
    }
    // A missing key file is decided without reading any secret: the stored
    // passphrase can no longer be checked, and nothing at that path could
    // be unlocked either.
    if !Path::new(key_path).exists() {
        return Ok(VerifyOutcome::MissingKey);
    }
    // The one decrypting read (GetSecret under the encrypted session,
    // zeroized); the bytes go only into the verifier's stdin pipe.
    let secret = client.ssh_key_secret(key_path)?;
    Ok(
        match ssh::verify_passphrase(Path::new(key_path), secret.as_slice()) {
            Verdict::Verified => VerifyOutcome::Match,
            Verdict::Rejected => VerifyOutcome::Stale,
            Verdict::NotEncrypted => VerifyOutcome::NotEncrypted,
            Verdict::Unavailable(reason) => VerifyOutcome::Unavailable { reason },
        },
    )
}

/// Verify one enumerated item already in hand — the single-walk verify-all
/// path. Duplicate ambiguity derives from the enumerated set (the count of
/// entries claiming one `ssh_key_path`) instead of the per-key re-walk
/// `ssh_key_item` performed, so the store is walked once for the whole
/// run; the produced error string is exactly the re-walk's
/// [`ServiceError::SshKeyItemsAmbiguous`]. The gate order matches
/// [`verify_stored_passphrase`] exactly: metadata and lock state first,
/// then file existence, and only then the one decrypting read.
fn verify_enumerated_item(
    client: &BlockingClient,
    collection: &CollectionId,
    key_path: &str,
    item: &Item,
    claims: usize,
) -> VerifyOutcome {
    if claims > 1 {
        return VerifyOutcome::Failed {
            reason: ServiceError::SshKeyItemsAmbiguous {
                key: key_path.to_owned(),
                count: claims,
            }
            .to_string(),
        };
    }
    if item.locked {
        return VerifyOutcome::Locked {
            collection: collection.to_string(),
        };
    }
    // A missing key file is decided without reading any secret: the stored
    // passphrase can no longer be checked, and nothing at that path could
    // be unlocked either.
    if !Path::new(key_path).exists() {
        return VerifyOutcome::MissingKey;
    }
    let secret = match client.ssh_key_item_secret(key_path, item) {
        Ok(secret) => secret,
        Err(error) => {
            return VerifyOutcome::Failed {
                reason: error.to_string(),
            };
        }
    };
    match ssh::verify_passphrase(Path::new(key_path), secret.as_slice()) {
        Verdict::Verified => VerifyOutcome::Match,
        Verdict::Rejected => VerifyOutcome::Stale,
        Verdict::NotEncrypted => VerifyOutcome::NotEncrypted,
        Verdict::Unavailable(reason) => VerifyOutcome::Unavailable { reason },
    }
}

/// Re-verify stored passphrases against their keys: the one given key,
/// or every stored ssh-store item across all collections. One verdict
/// line per key on stdout; exit 0 only when every checked key matched.
pub(crate) fn ssh_verify(key: Option<&Path>) -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-verify");
    span.in_scope(|| {
        // The lenient join-key discipline ([gmellon::ssh::
        // canonical_or_absolute]): the stored unique attribute is the join
        // key, so resolve when present, verbatim-absolute otherwise.
        let requested = key.map(ssh::canonical_or_absolute);
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        let mut failed = false;
        match requested {
            // Single-key mode: a storage error is a house service error on
            // stderr (no stored passphrase, ambiguous duplicates, …).
            Some(absolute) => {
                let key_string = absolute.display().to_string();
                match verify_stored_passphrase(&client, &key_string) {
                    Ok(outcome) => {
                        print!("{}", render_verify_line(&key_string, &outcome));
                        tracing::info!(
                            outcome = verify_outcome_word(&outcome),
                            "ssh key verify verdict"
                        );
                        failed = verify_outcome_failed(&outcome);
                    }
                    Err(error) => return report_service_error(error),
                }
            }
            // Verify-all mode: every stored item in the client's stable
            // order, one line each; per-key storage failures become ERROR
            // lines and fail the run without stopping the remaining keys.
            // The store is walked once here: ambiguity comes from counting
            // equal ssh_key_path entries in the enumerated set, and
            // secrets are read from the items already in hand — no
            // per-key re-walk.
            None => {
                let entries = match client.ssh_key_items() {
                    Ok(entries) => entries,
                    Err(error) => return report_service_error(error),
                };
                if entries.is_empty() {
                    println!("no stored SSH key passphrases");
                    return EXIT_OK;
                }
                let mut claims: HashMap<&str, usize> = HashMap::new();
                for (_collection, item) in &entries {
                    if let Some(key_path) = item.ssh_key_path() {
                        *claims.entry(key_path).or_default() += 1;
                    }
                }
                for (collection, item) in &entries {
                    // ssh_key_items only returns items whose unique
                    // attribute carries the ssh-store: prefix, so the key
                    // path is always present.
                    let Some(key_path) = item.ssh_key_path() else {
                        continue;
                    };
                    let outcome = verify_enumerated_item(
                        &client,
                        collection,
                        key_path,
                        item,
                        claims.get(key_path).copied().unwrap_or_default(),
                    );
                    print!("{}", render_verify_line(key_path, &outcome));
                    tracing::info!(
                        outcome = verify_outcome_word(&outcome),
                        "ssh key verify verdict"
                    );
                    failed |= verify_outcome_failed(&outcome);
                }
            }
        }
        if failed { EXIT_ERROR } else { EXIT_OK }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rendering_words_are_stable() {
        // The verdict words and advisory text are output contract; the
        // broker proof asserts the MATCH, STALE, and MISSING-KEY shapes
        // against the compiled binary.
        assert_eq!(
            render_verify_line("/k", &VerifyOutcome::Match),
            "MATCH /k\n"
        );
        assert_eq!(
            render_verify_line("/k", &VerifyOutcome::Stale),
            "STALE /k (stored passphrase no longer unlocks the key — \
             regenerate it with gmellon ssh-add)\n"
        );
        assert_eq!(
            render_verify_line("/k", &VerifyOutcome::MissingKey),
            "MISSING-KEY /k (key file is gone; gmellon ssh-remove cleans it up)\n"
        );
        assert_eq!(
            render_verify_line("/k", &VerifyOutcome::NotEncrypted),
            "NOT-ENCRYPTED /k (the key is no longer passphrase-protected; \
             gmellon ssh-remove cleans the stored passphrase up)\n"
        );
        assert_eq!(
            render_verify_line(
                "/k",
                &VerifyOutcome::Locked {
                    collection: "login".to_owned()
                }
            ),
            "LOCKED /k (collection login is locked; \
             gmellon unlock login makes the stored passphrase readable)\n"
        );
        assert_eq!(
            render_verify_line(
                "/k",
                &VerifyOutcome::Unavailable {
                    reason: "ssh-keygen is not on PATH".to_owned()
                }
            ),
            "UNAVAILABLE /k (ssh-keygen is not on PATH)\n"
        );
        assert_eq!(
            render_verify_line(
                "/k",
                &VerifyOutcome::Failed {
                    reason: "boom".to_owned()
                }
            ),
            "ERROR /k (boom)\n"
        );
    }

    #[test]
    fn verify_exit_fails_on_every_non_match_outcome() {
        assert!(!verify_outcome_failed(&VerifyOutcome::Match));
        for outcome in [
            VerifyOutcome::Stale,
            VerifyOutcome::MissingKey,
            VerifyOutcome::NotEncrypted,
            VerifyOutcome::Locked {
                collection: "login".to_owned(),
            },
            VerifyOutcome::Unavailable {
                reason: String::new(),
            },
            VerifyOutcome::Failed {
                reason: String::new(),
            },
        ] {
            assert!(
                verify_outcome_failed(&outcome),
                "{outcome:?} must fail the run"
            );
        }
    }

    #[test]
    fn verify_outcome_words_are_scalar_and_distinct() {
        let outcomes = [
            VerifyOutcome::Match,
            VerifyOutcome::Stale,
            VerifyOutcome::MissingKey,
            VerifyOutcome::NotEncrypted,
            VerifyOutcome::Locked {
                collection: "login".to_owned(),
            },
            VerifyOutcome::Unavailable {
                reason: String::new(),
            },
            VerifyOutcome::Failed {
                reason: String::new(),
            },
        ];
        let mut words: Vec<_> = outcomes.iter().map(verify_outcome_word).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(
            words.len(),
            outcomes.len(),
            "each -v verdict word must be distinct: {words:?}"
        );
    }
}
