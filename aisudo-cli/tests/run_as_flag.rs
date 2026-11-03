//! #2799: what `aisudo -u` puts on the wire, and what it does with the answers.
//! A fake daemon on a scratch socket stands in for the real one.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Output};

/// Run aisudo against a daemon that reads one request and sends `replies`.
/// Returns the request as JSON, and the client's result.
fn run(args: &[&str], replies: &[&str]) -> (serde_json::Value, Output) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let replies: Vec<String> = replies.iter().map(|r| r.to_string()).collect();
    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let mut writer = stream;
        for reply in replies {
            writeln!(writer, "{reply}").unwrap();
        }
        line
    });
    let out = Command::new(env!("CARGO_BIN_EXE_aisudo"))
        .args(args)
        .env("AISUDO_SOCKET", &path)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let line = daemon.join().unwrap();
    (serde_json::from_str(&line).unwrap(), out)
}

const APPROVED_EXIT_0: &[&str] = &[
    r#"{"request_id":"r","decision":"approved"}"#,
    r#"{"stream":"exit","data":"","exit_code":0}"#,
];

#[test]
fn dash_u_sends_the_target_in_the_mode_an_old_daemon_refuses() {
    for flag in ["-u", "--user"] {
        let (req, out) = run(&[flag, "rich", "id", "-u"], APPROVED_EXIT_0);
        assert_eq!(req["run_as"], "rich");
        assert_eq!(req["mode"], "execas");
        assert_eq!(req["command"], "id -u");
        assert!(out.status.success());
    }
}

#[test]
fn dash_u_on_a_dry_run_also_uses_the_refused_mode() {
    let (req, _) = run(
        &["-n", "-u", "rich", "id"],
        &[r#"{"request_id":"","decision":"approved"}"#],
    );
    assert_eq!(req["run_as"], "rich");
    assert_eq!(req["mode"], "execas");
    assert_eq!(req["dry_run"], true);
}

#[test]
fn without_dash_u_the_request_is_a_plain_root_request() {
    let (req, _) = run(&["id"], APPROVED_EXIT_0);
    assert!(req.get("run_as").is_none(), "{req}");
    assert_eq!(req["mode"], "exec");
    let (req, _) = run(
        &["-n", "id"],
        &[r#"{"request_id":"","decision":"approved"}"#],
    );
    assert!(req.get("run_as").is_none(), "{req}");
    assert_eq!(req["mode"], "pam");
}

#[test]
fn a_dash_u_after_the_command_name_belongs_to_the_command() {
    let (req, _) = run(&["id", "-u", "rich"], APPROVED_EXIT_0);
    assert!(req.get("run_as").is_none(), "{req}");
    assert_eq!(req["command"], "id -u rich");
}

/// The NOPASSWD fallback runs `sudo -n sh -c`, which is root. It must not fire for -u.
#[test]
fn a_nopasswd_answer_to_a_dash_u_request_runs_nothing() {
    let dir = tempfile::TempDir::new().unwrap();
    let marker = dir.path().join("ran");
    let command = format!("touch {}", marker.display());
    let (_, out) = run(
        &["-u", "rich", "sh", "-c", &command],
        &[r#"{"request_id":"r","decision":"usesudo"}"#],
    );
    assert!(!out.status.success());
    assert!(!marker.exists(), "the command ran");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("refusing to run it as root"), "{err}");
}

#[test]
fn dash_u_without_a_name_is_an_error_before_any_request() {
    for args in [&["-u"][..], &["-u", ""][..], &["--user"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_aisudo"))
            .args(args)
            .env("AISUDO_SOCKET", "/nonexistent/aisudo-test.sock")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("requires a user name"), "{args:?}: {err}");
    }
}
