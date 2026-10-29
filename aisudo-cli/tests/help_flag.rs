//! #2650: -h/--help is aisudo's own flag only before the command name.
//! After it, the flag belongs to the wrapped command (`sudo df -h`).

use std::process::Command;

fn run(args: &[&str]) -> String {
    // Point at a socket that cannot exist, so a command that gets past option
    // parsing fails at connect instead of reaching a real daemon.
    let out = Command::new(env!("CARGO_BIN_EXE_aisudo"))
        .args(args)
        .env("AISUDO_SOCKET", "/nonexistent/aisudo-test.sock")
        .output()
        .expect("run aisudo");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn leading_help_prints_usage() {
    assert!(run(&["-h"]).contains("Usage:"));
    assert!(run(&["--help"]).contains("Usage:"));
    assert!(run(&["-r", "why", "-h"]).contains("Usage:"));
}

#[test]
fn help_after_command_is_passed_through() {
    for args in [
        &["df", "-h", "/"][..],
        &["ls", "--help"][..],
        &["-r", "why", "du", "-h"][..],
    ] {
        let err = run(args);
        assert!(!err.contains("Usage:"), "{args:?} printed usage: {err}");
        assert!(
            err.contains("failed to connect"),
            "{args:?} did not reach connect: {err}"
        );
    }
}
