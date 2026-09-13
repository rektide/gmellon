//! Binary-level checks of `gmellon completions <shell>`.
//!
//! These are ordinary tests — no daemon, bus, or harness environment —
//! running the compiled binary through Cargo's `CARGO_BIN_EXE_gmellon`.
//! The proof burden from `gmell-polish`: every shell clap_complete offers
//! exits 0 with non-empty output, the zsh script names each subcommand,
//! and the zsh script passes `zsh -n` (a real syntax check, not a string
//! glance). An unknown shell is a usage error, not a crash.

use std::process::{Command, Stdio};

fn run_completions(shell: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gmellon"))
        .args(["completions", shell])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("spawn the gmellon binary for `{shell}`: {error}"))
}

#[test]
fn completions_exit_zero_nonempty_for_every_shell() {
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let output = run_completions(shell);
        assert_eq!(
            output.status.code(),
            Some(0),
            "`completions {shell}` must exit 0"
        );
        assert!(
            !output.stdout.is_empty(),
            "`completions {shell}` must write a script"
        );
        assert!(
            output.stderr.is_empty(),
            "`completions {shell}` must stay quiet on stderr"
        );
    }
}

#[test]
fn zsh_completions_name_subcommands_and_pass_zsh_n() {
    let output = run_completions("zsh");
    assert_eq!(output.status.code(), Some(0));
    let script = String::from_utf8(output.stdout.clone()).expect("zsh script is UTF-8");
    for subcommand in ["list", "status", "unlock", "change", "completions"] {
        assert!(
            script.contains(subcommand),
            "the zsh script must name the {subcommand} subcommand"
        );
    }

    // A real syntax check through the system zsh. The same interpreter runs
    // the zimfw module suite, so it is a hard prerequisite here too.
    let file = tempfile::NamedTempFile::new().expect("temp file for the zsh script");
    std::fs::write(file.path(), &output.stdout).expect("write the zsh script");
    let check = Command::new("zsh")
        .arg("-n")
        .arg(file.path())
        .output()
        .unwrap_or_else(|error| panic!("run zsh -n (zsh is required for this proof): {error}"));
    assert_eq!(
        check.status.code(),
        Some(0),
        "the generated zsh script must pass `zsh -n`: {}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn an_unknown_shell_is_a_usage_error() {
    let output = run_completions("tcsh");
    assert_ne!(
        output.status.code(),
        Some(0),
        "an unknown shell must not exit 0"
    );
    assert!(
        output.stdout.is_empty(),
        "a rejected shell must not write a script"
    );
}
