//! The command-line surface: one clap grammar, one dispatch. Handlers live
//! in the per-family siblings (`collections`, `ssh`), renderers in
//! `render`, exit codes and error reporting in `report`, completions in
//! `completions`. The grammar and help surface stay here so there is
//! exactly one definition of the user-facing command set.

mod collections;
mod completions;
mod render;
mod report;
mod ssh;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

use collections::{change, items, list, lock, status, unlock};
use completions::completions;
use ssh::{ssh_add, ssh_allow, ssh_list, ssh_remove, ssh_verify};

const DEFAULT_COLLECTION: &str = "login";

/// List, unlock, and re-key GNOME keyring collections without a GUI or PAM.
///
/// Discovery uses the standard Secret Service API; unlocking and re-keying
/// use GNOME Keyring's private, unsupported password interface. Every
/// connection negotiates the encrypted Secret Service session, and
/// passwords are read only from a TTY prompt or stdin — never argv.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    after_help = "unlock and change speak \
                  org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface, a deliberately \
                  undocumented GNOME interface that may change or vanish without notice. \
                  Compatibility limits and verification evidence: doc/status.md"
)]
pub struct Cli {
    /// Print redacted diagnostic events on stderr (operations, results,
    /// lengths). Password bytes and key material are never printed.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List collection IDs, labels, and lock state.
    ///
    /// Deterministic tab-separated ID, LOCKED, and LABEL columns, sorted by
    /// stable collection ID. Control characters in labels are escaped.
    List,

    /// Report service capabilities and collection lock state.
    ///
    /// A prompt-free health report, distinct from `list`'s deterministic
    /// column output: it never prompts, never unlocks or locks anything,
    /// and never calls a password method — the private-interface fact comes
    /// from a read-only D-Bus Introspect probe. Per-collection lines carry
    /// the stable ID and lock state only; labels belong to `list`.
    ///
    /// Exits nonzero only through the existing table: 4 when the Secret
    /// Service is unavailable, 1 when the encrypted session is refused.
    Status,

    /// Unlock an existing collection.
    ///
    /// Prompts for the collection password on the TTY with echo disabled,
    /// or reads one password line from stdin with --stdin. An
    /// already-unlocked collection returns success without reading or
    /// checking a password, and unlocking never locks or relocks a
    /// collection to verify one.
    Unlock {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,

        /// Read one password line from stdin instead of prompting on the TTY.
        #[arg(long)]
        stdin: bool,
    },

    /// Lock an existing collection.
    ///
    /// An explicit state change through the standard Secret Service Lock
    /// API: ordinary unlock never locks anything, and lock is never called
    /// implicitly. Locking is prompt-free; if the service demands an
    /// interactive prompt object, the command fails instead of performing
    /// one. An already-locked collection is a successful no-op.
    Lock {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,
    },

    /// List items inside a collection: labels, lock state, attributes.
    ///
    /// Metadata only — no secret is ever read. Deterministic tab-separated
    /// LABEL, LOCKED, and sorted k=v ATTRIBUTES columns, sorted by label
    /// then attributes. Control characters in labels are escaped.
    Items {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,
    },

    /// List stored SSH key passphrases.
    ///
    /// Every item across all collections whose unique attribute carries
    /// the gcr-ssh-agent ssh-store: prefix, with its owning collection,
    /// lock state, and whether the askpass helper may answer for it.
    /// Metadata only; the passphrases are not read.
    SshList,

    /// Store an SSH key passphrase, verified against the key first.
    ///
    /// Prompts for the KEY's passphrase (not the keyring password), checks
    /// it actually decrypts KEY with ssh-keygen, and only then stores it
    /// the way gcr-ssh-agent finds it — in the default collection, keyed by
    /// the key's absolute path. A wrong passphrase stores nothing; an
    /// unencrypted key has nothing to store. Replaces any previously
    /// stored passphrase for the same key.
    ///
    /// --askpass also grants the hidden askpass helper permission to
    /// answer OpenSSH passphrase prompts for this key; see
    /// design/askpass/askpass.glm53.md for the threat model. Without a
    /// grant, stored passphrases are never answerable.
    SshAdd {
        /// Path to the SSH private key.
        #[arg(value_name = "KEY")]
        key: PathBuf,

        /// Read one passphrase line from stdin instead of prompting on the TTY.
        #[arg(long)]
        stdin: bool,

        /// Also allow the askpass helper to answer for this key.
        #[arg(long)]
        askpass: bool,
    },

    /// Grant the askpass helper permission to answer for a stored key.
    ///
    /// Marks the stored passphrase item for KEY with the per-key opt-in
    /// (gmellon:askpass=allow), so `gmellon __askpass` — or the
    /// gmellon-askpass multicall binary — will answer OpenSSH passphrase
    /// prompts for that key. Nothing about the item changes for
    /// gcr-ssh-agent. Exactly one stored item must exist; ssh-list shows
    /// the candidates.
    SshAllow {
        /// Path to the SSH private key the passphrase was stored for.
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },

    /// Revoke the askpass helper's permission to answer for a stored key.
    ///
    /// Removes the per-key opt-in from the stored passphrase item for KEY.
    /// The stored passphrase itself is untouched — gcr-ssh-agent keeps
    /// working; only the askpass helper refuses. Revoking an un-granted
    /// key is a successful no-op.
    SshDeny {
        /// Path to the SSH private key the passphrase was stored for.
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },

    /// Remove a stored SSH key passphrase.
    ///
    /// Deletes the item gcr-ssh-agent would read for KEY (exact key-path
    /// match). The key file itself may already be gone — removing a stale
    /// stored passphrase is the point. Exactly one stored item must match;
    /// duplicates are listed by ssh-list and change nothing here.
    SshRemove {
        /// Path to the SSH private key the passphrase was stored for.
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },

    /// Re-verify stored SSH key passphrases against their keys.
    ///
    /// Reads each stored passphrase back (the one place gmellon decrypts a
    /// secret, under the encrypted session) and checks it still unlocks the
    /// key with the same ssh-keygen verification ssh-add performs —
    /// catching a key regenerated under a new passphrase that left a stale
    /// stored secret behind. With KEY, verifies that key's stored
    /// passphrase; without KEY, verifies every stored item across all
    /// collections. One deterministic verdict line per key, and the
    /// passphrase itself is never printed. Exits 0 only when every checked
    /// key matched.
    SshVerify {
        /// Path to the SSH private key whose stored passphrase is verified.
        #[arg(value_name = "KEY")]
        key: Option<PathBuf>,
    },

    /// Change an existing collection's password.
    ///
    /// Prompts for the current password, then the new password twice on the
    /// TTY; with --stdin reads current, new, and confirmation lines in that
    /// order. A denied current password leaves the old password valid.
    Change {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,

        /// Read current, new, and confirmation lines from stdin.
        #[arg(long)]
        stdin: bool,
    },

    /// Generate shell completions.
    ///
    /// Writes the completion script for SHELL to standard output; redirect
    /// it wherever your shell looks. For zsh:
    ///
    ///   gmellon completions zsh > ~/.zfunc/_gmellon
    ///
    /// with ~/.zfunc on fpath before compinit — or use the bundled zimfw
    /// module, which installs and regenerates the file automatically.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

pub fn run(cli: Cli) -> ExitCode {
    // The tracing subscriber exists only under -v: without the flag no
    // event is ever emitted (or formatted), and RUST_LOG never activates
    // one either.
    if cli.verbose {
        install_verbose_subscriber();
    }
    let code = match cli.command {
        Command::List => list(),
        Command::Status => status(),
        Command::Items { collection } => items(&collection),
        Command::SshList => ssh_list(),
        Command::SshAdd {
            key,
            stdin,
            askpass,
        } => ssh_add(&key, stdin, askpass),
        Command::SshAllow { key } => ssh_allow(&key, true),
        Command::SshDeny { key } => ssh_allow(&key, false),
        Command::SshRemove { key } => ssh_remove(&key),
        Command::SshVerify { key } => ssh_verify(key.as_deref()),
        Command::Unlock { collection, stdin } => unlock(&collection, stdin),
        Command::Lock { collection } => lock(&collection),
        Command::Change { collection, stdin } => change(&collection, stdin),
        Command::Completions { shell } => completions(shell),
    };
    tracing::info!(exit = code, "exit classified");
    ExitCode::from(code)
}

/// Install the -v diagnostics subscriber on stderr. Every event the code
/// emits carries explicit scalar fields — operation names, results,
/// lengths, outcomes, exit codes — and never password bytes, key material,
/// IV values, ciphertext bodies, or secret-bearing structs.
fn install_verbose_subscriber() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::{CommandFactory, Parser, ValueEnum};
    use clap_complete::Shell;

    use super::*;

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn verbose_defaults_off() {
        let cli = Cli::try_parse_from(["gmellon", "list"]).unwrap();
        assert!(!cli.verbose);
    }

    #[test]
    fn verbose_is_a_global_flag_in_both_positions() {
        for argv in [
            vec!["gmellon", "-v", "list"],
            vec!["gmellon", "--verbose", "list"],
            vec!["gmellon", "list", "-v"],
            vec!["gmellon", "unlock", "work", "--stdin", "-v"],
        ] {
            let cli = Cli::try_parse_from(argv.clone()).unwrap();
            assert!(cli.verbose, "-v must parse globally for {argv:?}");
        }
    }

    #[test]
    fn help_exposes_collection_commands() {
        let help = Cli::command().render_long_help().to_string();

        for command in ["list", "status", "unlock", "change", "completions"] {
            assert!(help.contains(command), "help omitted {command}");
        }
        assert!(!help.contains("control-dir"));
        assert!(!help.contains("allow-create"));
    }

    #[test]
    fn help_names_the_unsupported_interface_caveat() {
        let help = Cli::command().render_long_help().to_string();

        assert!(
            help.contains("InternalUnsupportedGuiltRiddenInterface"),
            "after_help must name the unsupported private interface"
        );
        assert!(
            help.contains("doc/status.md"),
            "after_help must point at the compatibility document"
        );
        assert!(
            help.contains("may change or vanish"),
            "after_help must stay honest about upstream volatility"
        );
    }

    #[test]
    fn completions_parse_every_advertised_shell_and_reject_others() {
        for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
            let cli = Cli::try_parse_from(["gmellon", "completions", shell]).unwrap();
            assert!(
                matches!(cli.command, Command::Completions { .. }),
                "{shell} must parse"
            );
        }
        assert!(Cli::try_parse_from(["gmellon", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn completions_render_subcommands_for_every_supported_shell() {
        for shell in Shell::value_variants() {
            let mut buffer = Vec::new();
            clap_complete::generate(*shell, &mut Cli::command(), "gmellon", &mut buffer);
            assert!(
                !buffer.is_empty(),
                "completions for {shell:?} must not be empty"
            );
        }

        let mut zsh = Vec::new();
        clap_complete::generate(Shell::Zsh, &mut Cli::command(), "gmellon", &mut zsh);
        let text = String::from_utf8(zsh).expect("zsh completions are UTF-8");
        for subcommand in ["list", "status", "unlock", "change", "completions"] {
            assert!(
                text.contains(subcommand),
                "zsh completions must name the {subcommand} subcommand"
            );
        }
    }

    #[test]
    fn unlock_defaults_to_login() {
        let cli = Cli::try_parse_from(["gmellon", "unlock"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Unlock {
                collection,
                stdin: false
            } if collection == "login"
        ));
    }

    #[test]
    fn unlock_accepts_an_explicit_collection_and_stdin() {
        let cli = Cli::try_parse_from(["gmellon", "unlock", "work", "--stdin"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Unlock {
                collection,
                stdin: true
            } if collection == "work"
        ));
    }

    #[test]
    fn lock_defaults_to_login() {
        let cli = Cli::try_parse_from(["gmellon", "lock"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Lock { collection } if collection == "login"
        ));
    }

    #[test]
    fn lock_accepts_an_explicit_collection() {
        let cli = Cli::try_parse_from(["gmellon", "lock", "work"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Lock { collection } if collection == "work"
        ));
    }

    #[test]
    fn change_defaults_to_login() {
        let cli = Cli::try_parse_from(["gmellon", "change"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Change {
                collection,
                stdin: false
            } if collection == "login"
        ));
    }

    #[test]
    fn change_accepts_an_explicit_collection_and_stdin() {
        let cli = Cli::try_parse_from(["gmellon", "change", "work", "--stdin"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Change {
                collection,
                stdin: true
            } if collection == "work"
        ));
    }

    #[test]
    fn ssh_add_accepts_the_askpass_flag() {
        let cli = Cli::try_parse_from(["gmellon", "ssh-add", "/tmp/k", "--askpass"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::SshAdd {
                key,
                stdin: false,
                askpass: true,
            } if key == Path::new("/tmp/k")
        ));
    }

    #[test]
    fn ssh_allow_and_deny_parse_a_key() {
        let allowed = Cli::try_parse_from(["gmellon", "ssh-allow", "/tmp/k"]).unwrap();
        assert!(
            matches!(&allowed.command, Command::SshAllow { key } if *key == Path::new("/tmp/k"))
        );

        let denied = Cli::try_parse_from(["gmellon", "ssh-deny", "/tmp/k"]).unwrap();
        assert!(matches!(&denied.command, Command::SshDeny { key } if *key == Path::new("/tmp/k")));
    }

    #[test]
    fn ssh_verify_takes_an_optional_key() {
        let bare = Cli::try_parse_from(["gmellon", "ssh-verify"]).unwrap();
        assert!(matches!(&bare.command, Command::SshVerify { key: None }));

        let keyed = Cli::try_parse_from(["gmellon", "ssh-verify", "/tmp/k"]).unwrap();
        assert!(
            matches!(&keyed.command, Command::SshVerify { key } if key.as_deref() == Some(Path::new("/tmp/k")))
        );
    }

    #[test]
    fn askpass_provider_is_not_a_clap_subcommand() {
        // The provider is intercepted in main before clap parsing, so it
        // must not parse as a subcommand and must never appear in help or
        // generated completions (clap_complete's generators would
        // advertise a hidden subcommand — verified against 4.6.5).
        assert!(Cli::try_parse_from(["gmellon", "__askpass", "prompt text"]).is_err());

        let help = Cli::command().render_long_help().to_string();
        assert!(
            !help.contains("__askpass"),
            "the askpass provider must stay out of help"
        );
        for shell in Shell::value_variants() {
            let mut buffer = Vec::new();
            clap_complete::generate(*shell, &mut Cli::command(), "gmellon", &mut buffer);
            let text = String::from_utf8_lossy(&buffer).to_string();
            assert!(
                !text.contains("__askpass"),
                "{shell:?} completions must not mention the hidden provider"
            );
        }
    }
}
