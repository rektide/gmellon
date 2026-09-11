use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Unlock and re-key the GNOME login keyring without a GUI or PAM.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Use DIR/control instead of $XDG_RUNTIME_DIR/keyring/control.
    #[arg(long, global = true, value_name = "DIR")]
    pub control_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Unlock the login keyring.
    Unlock {
        /// Read one password line from stdin instead of prompting on the TTY.
        #[arg(long)]
        stdin: bool,

        /// Permit the daemon to create a missing login keyring.
        #[arg(long)]
        allow_create: bool,
    },

    /// Change the login keyring password.
    Change,

    /// Inspect the control socket and local keyring files without unlocking.
    Status,
}

pub fn run(cli: Cli) -> ExitCode {
    eprintln!("gmellon {:?} is not implemented yet", cli.command);
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::Cli;

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_exposes_the_planned_commands() {
        let help = Cli::command().render_long_help().to_string();

        for command in ["unlock", "change", "status"] {
            assert!(help.contains(command), "help omitted {command}");
        }
    }

    #[test]
    fn control_directory_is_global() {
        let cli = Cli::try_parse_from(["gmellon", "unlock", "--control-dir", "/tmp/test-keyring"])
            .expect("global option should be accepted after a subcommand");

        assert_eq!(
            cli.control_dir.as_deref(),
            Some(std::path::Path::new("/tmp/test-keyring"))
        );
    }
}
