mod cli;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Askpass echo mode: ssh-keygen execs the SSH_ASKPASS program with the
    // prompt as argv[1], not as a subcommand, so this branch is selected by
    // the environment marker the verifier sets on its child and must run
    // before clap parsing. It reads one line from stdin (the verifier's
    // pipe) and prints it for ssh-keygen to capture.
    if std::env::var_os("GMELLON_ASKPASS").is_some() {
        return gmellon::ssh::askpass_main();
    }
    // Askpass provider mode, subcommand form for wrapper scripts
    // (`exec gmellon __askpass "$1"`). Intercepted before clap — the same
    // discipline as the marker above — so the provider never exists as a
    // documented subcommand: clap_complete's generators would otherwise
    // advertise it even under `hide = true` (verified against 4.6.5).
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__askpass")) {
        let prompt = std::env::args_os().nth(2).unwrap_or_default();
        return gmellon::ssh::askpass_provider(&prompt);
    }
    // Askpass provider mode, multicall form: OpenSSH execs exactly one
    // program with the prompt as the single argument, so users point
    // SSH_ASKPASS at a symlink or copy of this binary named
    // `gmellon-askpass`. Selected by argv[0] before clap parsing; the
    // prompt is argv[1]. See design/askpass/askpass.glm53.md.
    if is_gmellon_askpass_argv0() {
        let prompt = std::env::args_os().nth(1).unwrap_or_default();
        return gmellon::ssh::askpass_provider(&prompt);
    }
    cli::run(cli::Cli::parse())
}

/// Whether argv[0]'s file name is `gmellon-askpass`, selecting the
/// askpass provider entry (the busybox multicall convention).
fn is_gmellon_askpass_argv0() -> bool {
    std::env::args_os()
        .next()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|argv0| std::path::Path::new(argv0).file_name())
        .is_some_and(|name| name == "gmellon-askpass")
}
