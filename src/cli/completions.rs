//! Shell completion generation for the one clap grammar.

use std::io::{self, Write};

use clap::CommandFactory;
use clap_complete::Shell;

use super::Cli;
use super::report::{EXIT_ERROR, EXIT_OK};

/// Emit the completion script for one shell. Buffered and written once so
/// a broken pipe reports an exit-1 diagnostic instead of a panic.
pub(crate) fn completions(shell: Shell) -> u8 {
    let span = tracing::info_span!("operation", operation = "completions", shell = %shell);
    span.in_scope(|| {
        let mut command = Cli::command();
        let name = command.get_name().to_owned();
        let mut buffer = Vec::new();
        clap_complete::generate(shell, &mut command, name, &mut buffer);
        tracing::info!(bytes = buffer.len(), "completions generated");
        match io::stdout().write_all(&buffer) {
            Ok(()) => EXIT_OK,
            Err(error) => {
                eprintln!("gmellon: writing completions failed: {error}");
                EXIT_ERROR
            }
        }
    })
}
