mod cli;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Askpass mode: ssh-keygen execs the SSH_ASKPASS program with the
    // prompt as argv[1], not as a subcommand, so this branch is selected by
    // the environment marker the verifier sets on its child and must run
    // before clap parsing. It reads one line from stdin (the verifier's
    // pipe) and prints it for ssh-keygen to capture.
    if std::env::var_os("GMELLON_ASKPASS").is_some() {
        return gmellon::ssh::askpass_main();
    }
    cli::run(cli::Cli::parse())
}
