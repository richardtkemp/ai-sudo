use aisudo_common::{
    Decision, ExecOutput, ListRulesRequest, ListRulesResponse, RequestMode, RequestStatus,
    SocketMessage, StatusFrame, SudoRequest, SudoResponse, TempRuleRequest, TempRuleResponse,
    DEFAULT_SOCKET_PATH,
};
use base64::Engine as _;
use shell_escape::escape;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

const MAX_STDIN_SIZE: usize = 10 * 1024 * 1024; // 10 MB

const BINARY_NAME: &str = "aisudo";

fn main() -> ExitCode {
    // Reset SIGPIPE to default behavior so writes to closed pipes (e.g. `aisudo find / | head -5`)
    // terminate the process cleanly instead of panicking. Rust sets SIG_IGN by default.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage: {} [OPTIONS] <command> [args...]", BINARY_NAME);
        eprintln!(
            "       {} --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]",
            BINARY_NAME
        );
        eprintln!("       {} -l | --list-rules", BINARY_NAME);
        eprintln!("       {} --status", BINARY_NAME);
        eprintln!("       {} --history [N]", BINARY_NAME);
        eprintln!();
        eprintln!("Options:");
        eprintln!("  -r, --reason <text>      Reason for the command (shown in approval request)");
        eprintln!("  -t, --timeout <seconds>  Override approval timeout for this request");
        eprintln!(
            "  -n, --dry-run            Check if command would be approved without executing"
        );
        eprintln!("  -l, --list-rules         Show active rules for current user");
        eprintln!("  --status                 Show daemon status");
        eprintln!("  --history [N]            Show last N requests (default 20)");
        eprintln!("  -h, --help               Show this help message");
        return ExitCode::from(1);
    }

    // Parse flags: -r/--reason, -t/--timeout, -n/--dry-run, and mode flags
    // Stop at first non-flag argument - everything after is the command
    let mut reason: Option<String> = None;
    let mut timeout: Option<u32> = None;
    let mut dry_run = false;
    let mut cmd_start = 1;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-l" | "--list-rules" => {
                return handle_list_rules();
            }
            "--status" => {
                return handle_status();
            }
            "--history" => {
                return handle_history(&args, i);
            }
            "--request-rule" => {
                return handle_request_rule(&args);
            }
            "-r" | "--reason" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{}: -r/--reason requires a value", BINARY_NAME);
                    return ExitCode::from(1);
                }
                reason = Some(args[i].clone());
                i += 1;
                cmd_start = i;
            }
            "-t" | "--timeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{}: -t/--timeout requires a value", BINARY_NAME);
                    return ExitCode::from(1);
                }
                match args[i].parse::<u32>() {
                    Ok(t) => {
                        timeout = Some(t);
                        i += 1;
                        cmd_start = i;
                    }
                    Err(_) => {
                        eprintln!("{}: -t/--timeout must be a positive integer", BINARY_NAME);
                        return ExitCode::from(1);
                    }
                }
            }
            "-n" | "--dry-run" => {
                dry_run = true;
                i += 1;
                cmd_start = i;
            }
            "--" => {
                // Explicit end of flags
                cmd_start = i + 1;
                break;
            }
            other if other.starts_with('-') => {
                eprintln!("{}: unrecognized option '{}'", BINARY_NAME, other);
                return ExitCode::from(1);
            }
            _ => {
                // Found command start
                break;
            }
        }
    }

    if cmd_start >= args.len() {
        eprintln!("Usage: sudo [OPTIONS] <command> [args...]");
        eprintln!("       sudo -h | --help");
        return ExitCode::from(1);
    }

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string());

    let mut cmd_args = args[cmd_start..].to_vec();
    resolve_cwd_script(&mut cmd_args, &cwd);
    let command = build_command(&cmd_args);
    let user = get_current_user();
    let pid = std::process::id();

    // Capture stdin if piped/redirected (not a terminal)
    let stdin_data = match capture_stdin() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{}: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let request = SudoRequest {
        user: user.clone(),
        command: command.clone(),
        cwd,
        pid,
        mode: if dry_run {
            RequestMode::Pam
        } else {
            RequestMode::Exec
        },
        reason,
        stdin: stdin_data.clone(),
        skip_nopasswd: false,
        timeout_seconds: timeout,
        dry_run,
        wants_status: true,
    };

    if dry_run {
        eprintln!(
            "{}: checking if command would be approved: {command}",
            BINARY_NAME
        );
    }

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}: failed to connect to daemon at {socket_path}: {e}",
                BINARY_NAME
            );
            eprintln!("{}: is the daemon running?", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    // No read timeout while waiting for approval — the daemon handles its own
    // approval timeout (default 7200s) and will always send a response.
    // A premature client-side timeout causes spurious EAGAIN (os error 11).

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}: socket error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let request_json = match serde_json::to_string(&request) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: serialization error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(request_json.as_bytes()) {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("{}: flush error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);

    // First line is the SudoResponse (approval decision)
    let mut lines = reader.lines();

    // The daemon answers with a StatusFrame first when we asked for one, saying which path
    // the request took (#1719). Only WaitingForHuman means a person is actually being asked,
    // and that is the only case worth warning about — the old code warned on EVERY command,
    // including ones the allowlist approved in milliseconds, which taught the reader to skip
    // the line that matters. A daemon that predates the frame sends the decision straight
    // away; that parses as SudoResponse and not as StatusFrame, so falling through is the
    // whole of the compatibility story.
    let (_status, first_line) = match read_status_and_decision(&mut lines, "main", |s| {
        if should_warn_a_human_is_waiting(Some(s)) {
            warn_a_human_is_waiting(&command);
        }
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let response: SudoResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: invalid response from daemon: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    match response.decision {
        Decision::Approved => {
            if dry_run {
                eprintln!("\x1b[32msudo: command would be auto-approved\x1b[0m");
                return ExitCode::from(0);
            }
            // In exec mode, the daemon will now stream output lines
        }
        Decision::UseSudo => {
            if dry_run {
                eprintln!("\x1b[32msudo: command would be approved via NOPASSWD rule\x1b[0m");
                return ExitCode::from(0);
            }
            eprintln!(
                "{}: command permitted by sudo NOPASSWD rule, executing via sudo",
                BINARY_NAME
            );
            return run_via_sudo(&command, &stdin_data);
        }
        Decision::Denied => {
            if dry_run {
                if let Some(ref err) = response.error {
                    if err.contains("rate limit") {
                        eprintln!("\x1b[33msudo: command would be denied (rate limit)\x1b[0m");
                    } else {
                        eprintln!("\x1b[33msudo: command would require approval\x1b[0m");
                    }
                } else {
                    eprintln!("\x1b[33msudo: command would require approval\x1b[0m");
                }
                return ExitCode::from(0);
            }
            if let Some(ref err) = response.error {
                eprintln!("\x1b[31msudo: denied due to error: {err}\x1b[0m");
            } else {
                eprintln!("\x1b[31msudo: request denied by user\x1b[0m");
            }
            return ExitCode::from(1);
        }
        Decision::Timeout => {
            if dry_run {
                eprintln!("\x1b[33msudo: dry-run check timed out\x1b[0m");
                return ExitCode::from(1);
            }
            eprintln!(
                "\x1b[33msudo: request timed out (no response within approval window)\x1b[0m"
            );
            return ExitCode::from(1);
        }
        Decision::Pending => {
            eprintln!("{}: unexpected pending response", BINARY_NAME);
            return ExitCode::from(1);
        }
    }

    // Now that we have the approval response, set a read timeout for output streaming.
    // Uses the cloned writer fd (same underlying socket) to set SO_RCVTIMEO.
    writer.set_read_timeout(Some(Duration::from_secs(300))).ok();

    ExitCode::from(stream_exec_output(lines) as u8)
}

fn handle_request_rule(args: &[String]) -> ExitCode {
    let mut duration: Option<u32> = None;
    let mut reason: Option<String> = None;
    let mut patterns: Vec<String> = Vec::new();

    let mut i = 1; // skip argv[0]
    while i < args.len() {
        match args[i].as_str() {
            "--request-rule" => {}
            "--duration" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{}: --duration requires a value", BINARY_NAME);
                    return ExitCode::from(1);
                }
                match args[i].parse::<u32>() {
                    Ok(d) => duration = Some(d),
                    Err(_) => {
                        eprintln!("{}: --duration must be a positive integer", BINARY_NAME);
                        return ExitCode::from(1);
                    }
                }
            }
            "-r" | "--reason" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{}: -r/--reason requires a value", BINARY_NAME);
                    return ExitCode::from(1);
                }
                reason = Some(args[i].clone());
            }
            other => {
                patterns.push(other.to_string());
            }
        }
        i += 1;
    }

    let duration = match duration {
        Some(d) => d,
        None => {
            eprintln!(
                "{}: --duration is required with --request-rule",
                BINARY_NAME
            );
            eprintln!("Usage: sudo --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]");
            return ExitCode::from(1);
        }
    };

    if patterns.is_empty() {
        eprintln!("{}: at least one pattern is required", BINARY_NAME);
        eprintln!("Usage: sudo --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]");
        return ExitCode::from(1);
    }

    let user = get_current_user();

    let request = TempRuleRequest {
        user,
        patterns: patterns.clone(),
        duration_seconds: duration,
        reason,
    };

    let msg = SocketMessage::TempRuleRequest(request);

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    eprintln!(
        "sudo: requesting temp rule for patterns {:?} (duration: {}s)",
        patterns, duration
    );

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}: failed to connect to daemon at {socket_path}: {e}",
                BINARY_NAME
            );
            eprintln!("{}: is the daemon running?", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    // No read timeout — daemon waits for Telegram approval and always sends a response.

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}: socket error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: serialization error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("{}: flush error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!(
                "{}: connection to daemon lost (request_rule): {e}",
                BINARY_NAME
            );
            return ExitCode::from(1);
        }
        None => {
            eprintln!("{}: daemon closed connection unexpectedly", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let response: TempRuleResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: invalid response from daemon: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    match response.decision {
        Decision::Approved => {
            let expires = response.expires_at.as_deref().unwrap_or("unknown");
            eprintln!("{}: temp rule approved (expires: {expires})", BINARY_NAME);
            ExitCode::from(0)
        }
        Decision::Denied => {
            if let Some(ref err) = response.error {
                eprintln!("{}: temp rule denied: {err}", BINARY_NAME);
            } else {
                eprintln!("{}: temp rule denied", BINARY_NAME);
            }
            ExitCode::from(1)
        }
        Decision::Timeout => {
            eprintln!("{}: temp rule request timed out", BINARY_NAME);
            ExitCode::from(1)
        }
        _ => {
            eprintln!("{}: unexpected response", BINARY_NAME);
            ExitCode::from(1)
        }
    }
}

fn handle_list_rules() -> ExitCode {
    let user = get_current_user();

    let request = ListRulesRequest { user: user.clone() };
    let msg = SocketMessage::ListRules(request);

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}: failed to connect to daemon at {socket_path}: {e}",
                BINARY_NAME
            );
            eprintln!("{}: is the daemon running?", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}: socket error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: serialization error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("{}: flush error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!(
                "{}: connection to daemon lost (list_rules): {e}",
                BINARY_NAME
            );
            return ExitCode::from(1);
        }
        None => {
            eprintln!("{}: daemon closed connection unexpectedly", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let response: ListRulesResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: invalid response from daemon: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    println!("Active rules for user: {user}");
    println!();

    println!("=== Permanent Allowlist ===");
    if response.allowlist.is_empty() {
        println!("  (none)");
    } else {
        for entry in &response.allowlist {
            println!("  {entry}");
        }
    }
    println!();

    println!("=== Active Temp Rules ===");
    if response.temp_rules.is_empty() {
        println!("  (none)");
    } else {
        for rule in &response.temp_rules {
            println!("  patterns: {:?}", rule.patterns);
            println!("  expires:  {}", rule.expires_at);
            println!();
        }
    }

    println!("=== Sudo NOPASSWD Rules ===");
    if response.nopasswd_rules.is_empty() {
        println!("  (none)");
    } else {
        for rule in &response.nopasswd_rules {
            println!("  {rule}");
        }
    }

    ExitCode::from(0)
}

fn handle_status() -> ExitCode {
    use aisudo_common::{StatusRequest, StatusResponse};

    let user = get_current_user();
    let request = StatusRequest { user: user.clone() };
    let msg = SocketMessage::Status(request);

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}: failed to connect to daemon at {socket_path}: {e}",
                BINARY_NAME
            );
            eprintln!("{}: is the daemon running?", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}: socket error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: serialization error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("{}: flush error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("{}: connection to daemon lost (status): {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
        None => {
            eprintln!("{}: daemon closed connection unexpectedly", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let response: StatusResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: invalid response from daemon: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    println!("=== sudo daemon status ===");
    println!();
    println!(
        "  Uptime: {}s ({:.1} hours)",
        response.uptime_seconds,
        response.uptime_seconds as f64 / 3600.0
    );
    println!("  Pending requests: {}", response.pending_requests);
    println!("  Requests (last hour): {}", response.requests_last_hour);
    println!(
        "  Approval rate (last hour): {:.1}%",
        response.approval_rate * 100.0
    );
    println!(
        "  Bitwarden: {}",
        if response.bw_active {
            "active"
        } else {
            "inactive"
        }
    );

    ExitCode::from(0)
}

fn handle_history(args: &[String], history_idx: usize) -> ExitCode {
    use aisudo_common::{HistoryRequest, HistoryResponse};

    let user = get_current_user();

    // Parse optional limit argument (after --history flag)
    let limit = if args.len() > history_idx + 1 {
        match args[history_idx + 1].parse::<u32>() {
            Ok(n) if n > 0 && n <= 100 => n,
            _ => {
                eprintln!("{}: history limit must be between 1 and 100", BINARY_NAME);
                return ExitCode::from(1);
            }
        }
    } else {
        20
    };

    let request = HistoryRequest {
        user: user.clone(),
        limit,
    };
    let msg = SocketMessage::History(request);

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}: failed to connect to daemon at {socket_path}: {e}",
                BINARY_NAME
            );
            eprintln!("{}: is the daemon running?", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}: socket error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: serialization error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("{}: flush error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("{}: connection to daemon lost (history): {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
        None => {
            eprintln!("{}: daemon closed connection unexpectedly", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let response: HistoryResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: invalid response from daemon: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    println!(
        "=== Command history (last {} entries) ===",
        response.entries.len()
    );
    println!();

    if response.entries.is_empty() {
        println!("  (no history)");
    } else {
        for entry in &response.entries {
            let status_color = match entry.status.as_str() {
                "approved" => "\x1b[32m",
                "denied" => "\x1b[31m",
                "timeout" => "\x1b[33m",
                _ => "",
            };
            let reset = if status_color.is_empty() {
                ""
            } else {
                "\x1b[0m"
            };
            println!(
                "  {}[{:8}]{}\t{} — {}",
                status_color, entry.status, reset, entry.timestamp, entry.command
            );
        }
    }

    ExitCode::from(0)
}

/// Run a command via sudo -n. If sudo needs a password (NOPASSWD rule no longer
/// applies), fall back to requesting normal aisudo approval.
fn run_via_sudo(command: &str, stdin_data: &Option<String>) -> ExitCode {
    // Try sudo -n (non-interactive: fail immediately if password required)
    let mut child = match std::process::Command::new("sudo")
        .args(["-n", "sh", "-c", command])
        .stdin(if stdin_data.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::inherit()
        })
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: failed to exec sudo: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    // Write stdin if present
    if let Some(ref b64) = stdin_data {
        if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        {
            if let Some(mut stdin_pipe) = child.stdin.take() {
                let _ = stdin_pipe.write_all(&decoded);
                // drop closes the pipe
            }
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}: sudo wait error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    // Check if sudo failed because a password was required
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && stderr.contains("a password is required") {
        eprintln!(
            "{}: sudo NOPASSWD rule no longer applies, requesting approval...",
            BINARY_NAME
        );
        return retry_with_approval(command, stdin_data);
    }

    // Print any stderr from the command itself
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    ExitCode::from(output.status.code().unwrap_or(1) as u8)
}

/// Retry the command through the normal aisudo approval flow with skip_nopasswd=true.
/// Step past the optional leading [`StatusFrame`] (#1719) and return it alongside the line
/// that carries the decision.
///
/// Both request paths set `wants_status`, so both receive this frame and both must consume
/// it. Sharing one reader is the point: the first cut of #1719 open-coded the step in the
/// main path only, and `retry_with_approval` then died with "invalid response from daemon:
/// missing field `request_id`" — on the NOPASSWD-retry path, which is precisely the
/// path that always waits on a human.
///
/// A daemon predating the frame sends the decision straight away. That parses as a
/// [`SudoResponse`] and not as a [`StatusFrame`], so returning `None` and passing the line
/// through unchanged is the whole of the backward-compatibility story.
fn read_status_and_decision<I: Iterator<Item = std::io::Result<String>>>(
    lines: &mut I,
    context: &str,
    on_status: impl FnOnce(RequestStatus),
) -> Result<(Option<RequestStatus>, String), String> {
    fn next_line<I: Iterator<Item = std::io::Result<String>>>(
        lines: &mut I,
        context: &str,
    ) -> Result<String, String> {
        match lines.next() {
            Some(Ok(line)) => Ok(line),
            Some(Err(e)) => Err(format!("connection to daemon lost ({context}): {e}")),
            None => Err(format!("daemon closed connection unexpectedly ({context})")),
        }
    }
    let first = next_line(lines, context)?;
    match serde_json::from_str::<StatusFrame>(&first) {
        Ok(frame) => {
            // MUST run before the next read. That read blocks for as long as the human takes
            // — the entire reason the frame exists is to say something DURING that wait. An
            // earlier version returned both lines and left the caller to react afterwards;
            // strace on the installed binary showed the banner landing 4.0s late, after the
            // decision had already arrived, which is worse than not printing it at all.
            on_status(frame.status);
            Ok((Some(frame.status), next_line(lines, context)?))
        }
        Err(_) => Ok((None, first)),
    }
}

/// The warning that #1719 exists to make honest: it fires only when a person is genuinely
/// being asked. An older daemon sends no frame at all and so stays silent — the old text
/// was wrong far more often than it was right, so silence is the better default.
fn should_warn_a_human_is_waiting(status: Option<RequestStatus>) -> bool {
    status == Some(RequestStatus::WaitingForHuman)
}

fn warn_a_human_is_waiting(command: &str) {
    eprintln!("{}: requesting approval for: {command}", BINARY_NAME);
    eprintln!(
        "{}: approval is asynchronous — a human must tap approve/deny and may take minutes or longer. Waiting; do not retry or assume failure.",
        BINARY_NAME
    );
}

fn retry_with_approval(command: &str, stdin_data: &Option<String>) -> ExitCode {
    let user = get_current_user();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string());
    let pid = std::process::id();

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let request = SudoRequest {
        user,
        command: command.to_string(),
        cwd,
        pid,
        mode: RequestMode::Exec,
        reason: None,
        stdin: stdin_data.clone(),
        skip_nopasswd: true,
        timeout_seconds: None,
        dry_run: false,
        wants_status: true,
    };

    let msg = SocketMessage::SudoRequest(request);

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}: failed to connect to daemon at {socket_path}: {e}",
                BINARY_NAME
            );
            return ExitCode::from(1);
        }
    };

    // No read timeout — daemon waits for Telegram approval and always sends a response.

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}: socket error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}: serialization error: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("{}: write error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("{}: flush error: {e}", BINARY_NAME);
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    // Must step past the status frame: this request sets wants_status, so the daemon sends
    // one. And this path escalates by construction (skip_nopasswd), so the frame is
    // WaitingForHuman and the warning here is always true — the gap the first cut of
    // #1719 left open.
    let (_status, first_line) = match read_status_and_decision(&mut lines, "retry_approval", |s| {
        if should_warn_a_human_is_waiting(Some(s)) {
            warn_a_human_is_waiting(command);
        }
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    let response: SudoResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: invalid response from daemon: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
    };

    match response.decision {
        Decision::Approved => {}
        Decision::Denied => {
            if let Some(ref err) = response.error {
                eprintln!("{}: denied: {err}", BINARY_NAME);
            } else {
                eprintln!("{}: request denied by user", BINARY_NAME);
            }
            return ExitCode::from(1);
        }
        Decision::Timeout => {
            eprintln!("{}: request timed out", BINARY_NAME);
            return ExitCode::from(1);
        }
        _ => {
            eprintln!("{}: unexpected response", BINARY_NAME);
            return ExitCode::from(1);
        }
    }

    // Set read timeout for output streaming phase
    writer.set_read_timeout(Some(Duration::from_secs(300))).ok();

    ExitCode::from(stream_exec_output(lines) as u8)
}

/// Consume the exec-output stream from the daemon: print stdout/stderr lines as they
/// arrive and return the command's exit code once the "exit" record is seen.
///
/// The socket has a read timeout (SO_RCVTIMEO) applied by the caller so the client
/// doesn't block forever on a dead connection. But a long-running remote command can
/// legitimately go quiet (no stdout/stderr) for longer than any single read timeout
/// while still running fine — a disk scan between progress lines, for example. When
/// that happens the read syscall returns EAGAIN/EWOULDBLOCK (or ETIMEDOUT), which is
/// indistinguishable at this layer from a real problem unless we retry: erroring out
/// here misreports a live, still-running command as a failure (#1402) even though the
/// daemon-side process survives and completes correctly. So only treat a genuine
/// connection loss as fatal; an idle-timeout read error just means "try again".
fn stream_exec_output<I: Iterator<Item = std::io::Result<String>>>(lines: I) -> i32 {
    let mut exit_code: i32 = 1;

    for line_result in lines {
        let line = match line_result {
            Ok(l) => l,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // Idle read timeout — the command may still be running quietly.
                // Retry rather than declaring failure.
                continue;
            }
            Err(e) => {
                eprintln!("{}: read error during execution: {e}", BINARY_NAME);
                return 1;
            }
        };

        if line.is_empty() {
            continue;
        }

        let output: ExecOutput = match serde_json::from_str(&line) {
            Ok(o) => o,
            Err(_) => continue,
        };

        match output.stream.as_str() {
            "stdout" => {
                print!("{}", output.data);
                let _ = std::io::stdout().flush();
            }
            "stderr" => {
                eprint!("{}", output.data);
                let _ = std::io::stderr().flush();
            }
            "exit" => {
                exit_code = output.exit_code.unwrap_or(1);
                break;
            }
            _ => {}
        }
    }

    exit_code
}

fn get_current_user() -> String {
    // Use the real UID from the kernel, not the spoofable $USER env var.
    // The daemon also verifies this via SO_PEERCRED, so this is for display only.
    let uid = unsafe { libc::getuid() };
    // Try to resolve UID to username via passwd database
    unsafe {
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let name = std::ffi::CStr::from_ptr((*pw).pw_name);
            if let Ok(s) = name.to_str() {
                return s.to_string();
            }
        }
    }
    format!("uid:{uid}")
}

/// Check if stdin has data or EOF available without blocking.
/// Uses poll(2) with zero timeout for a non-blocking check.
fn stdin_has_data_or_eof() -> bool {
    let fd = std::io::stdin().as_raw_fd();

    let mut fds = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    // poll with 0ms timeout: returns immediately
    // > 0 means POLLIN (data available) or POLLHUP (write end closed) was set
    let result = unsafe { libc::poll(&mut fds as *mut _, 1, 0) };
    result > 0
}

/// Read stdin if it's piped/redirected (not a terminal).
/// Returns base64-encoded data, or None if stdin is a terminal or empty.
/// Rejects input exceeding MAX_STDIN_SIZE.
fn capture_stdin() -> Result<Option<String>, String> {
    let stdin = std::io::stdin();

    if stdin.is_terminal() {
        return Ok(None);
    }

    // Check if stdin has data or EOF immediately available.
    // Without this, read_to_end() blocks forever when stdin is redirected
    // but the writer never sends data or closes the pipe (e.g., automation
    // tools that set up piped stdin without writing to it).
    if !stdin_has_data_or_eof() {
        return Ok(None);
    }

    let mut buffer = Vec::new();
    // Read up to MAX_STDIN_SIZE + 1 to detect oversize input
    let bytes_read = stdin
        .lock()
        .take(MAX_STDIN_SIZE as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|e| format!("failed to read stdin: {e}"))?;

    if bytes_read > MAX_STDIN_SIZE {
        return Err(format!(
            "stdin exceeds size limit ({} bytes max)",
            MAX_STDIN_SIZE
        ));
    }

    if buffer.is_empty() {
        return Ok(None);
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
    Ok(Some(encoded))
}

/// Build the command string sent to the daemon from the positional args.
///
/// Two cases:
///   * Exactly one argument — the user handed us a complete command line as a
///     single (shell-quoted) blob, e.g. `sudo 'cp a b && chown x b'`. Forward it
///     VERBATIM so the daemon's chain parser can split and validate the operators
///     (`&&`, `||`, `;`, `|`). Escaping here would re-quote the whole blob and the
///     daemon suppresses operator detection inside quotes, so the compound would
///     never run. This is safe: the daemon validates every chain segment against
///     approval and rejects dangerous metacharacters ($, backtick, (), <>, bare &,
///     newline) itself — the CLI escaping was a transport convenience, not the
///     security boundary.
///   * Multiple arguments — escape each to preserve argument boundaries; any
///     operator passed as its own arg stays literal.
/// When the first argument is a bare filename (no path separator) that exists
/// in the current directory, prepend `./` so the daemon's `sh -c` / `Command::new`
/// finds it. Without this, `aisudo script.sh` fails because the shell only
/// searches PATH for bare names — the user must type `aisudo ./script.sh`.
fn resolve_cwd_script(args: &mut [String], cwd: &str) {
    if args.is_empty() {
        return;
    }
    let first = &args[0];
    // Only resolve bare names — anything with a path separator is already
    // a relative or absolute path.
    if first.contains('/') {
        return;
    }
    let candidate = std::path::Path::new(cwd).join(first);
    if candidate.exists() {
        args[0] = format!("./{}", first);
    }
}

fn build_command(args: &[String]) -> String {
    if args.len() == 1 {
        args[0].clone()
    } else {
        shell_escape_command(args)
    }
}

/// Shell-escape individual arguments and join them with spaces.
/// This prevents shell metacharacters in arguments from being interpreted as shell operators.
fn shell_escape_command(args: &[String]) -> String {
    args.iter()
        .map(|arg| escape(std::borrow::Cow::from(arg.as_str())).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_escape_command() {
        // Test basic command with no special characters
        let args = vec!["ls".to_string(), "-la".to_string()];
        assert_eq!(shell_escape_command(&args), "ls -la");

        // Test command with pipe character (the bug we're fixing)
        let args = vec![
            "sed".to_string(),
            "-i".to_string(),
            "s/foo|bar/baz/".to_string(),
            "file".to_string(),
        ];
        let result = shell_escape_command(&args);
        assert!(
            result.contains("'s/foo|bar/baz/'"),
            "Pipe character should be escaped: {}",
            result
        );

        // Test command with shell metacharacters
        let args = vec!["echo".to_string(), "hello; rm -rf /".to_string()];
        let result = shell_escape_command(&args);
        assert!(
            result.contains("'hello; rm -rf /'"),
            "Semicolon should be escaped: {}",
            result
        );

        // Test command with spaces
        let args = vec!["echo".to_string(), "hello world".to_string()];
        let result = shell_escape_command(&args);
        assert!(
            result.contains("'hello world'"),
            "Spaces should be escaped: {}",
            result
        );

        // Test command with dollar signs (variable expansion)
        let args = vec!["echo".to_string(), "$HOME/test".to_string()];
        let result = shell_escape_command(&args);
        assert!(
            result.contains("'$HOME/test'"),
            "Dollar sign should be escaped: {}",
            result
        );

        // Test empty args
        let args: Vec<String> = vec![];
        assert_eq!(shell_escape_command(&args), "");

        // Test single argument
        let args = vec!["ls".to_string()];
        assert_eq!(shell_escape_command(&args), "ls");
    }

    #[test]
    fn test_build_command() {
        // Single arg (a quoted blob) is forwarded verbatim so the daemon can
        // split/validate operators — NOT re-quoted.
        let args = vec!["cp a b && chown x b".to_string()];
        assert_eq!(build_command(&args), "cp a b && chown x b");

        // Single arg with no operators is also verbatim (no surrounding quotes).
        let args = vec!["rm -rf /tmp/x".to_string()];
        assert_eq!(build_command(&args), "rm -rf /tmp/x");

        // A bare single-word command is unchanged.
        let args = vec!["systemctl".to_string()];
        assert_eq!(build_command(&args), "systemctl");

        // Multiple args: per-arg escaping preserves boundaries; an operator
        // passed as its own arg stays literal (quoted).
        let args = vec!["echo".to_string(), "hello && rm -rf /".to_string()];
        let result = build_command(&args);
        assert!(
            result.contains("'hello && rm -rf /'"),
            "Embedded operator in a multi-arg invocation must stay escaped: {}",
            result
        );

        // Multiple args with no specials: plain join.
        let args = vec!["cp".to_string(), "a".to_string(), "b".to_string()];
        assert_eq!(build_command(&args), "cp a b");
    }

    #[test]
    fn test_resolve_cwd_script() {
        let cwd = std::env::current_dir().unwrap();
        let cwd_str = cwd.to_string_lossy();

        // Bare filename that exists in cwd → prepended with ./
        // (using this source file as the existing file)
        let existing = cwd.join("Cargo.toml").to_string_lossy().to_string();
        let dir = std::path::Path::new(&existing)
            .parent()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let mut args = vec!["Cargo.toml".to_string()];
        resolve_cwd_script(&mut args, &dir);
        assert_eq!(args[0], "./Cargo.toml");

        // Bare filename that doesn't exist → unchanged (PATH command like systemctl)
        let mut args = vec!["systemctl".to_string(), "restart".to_string()];
        resolve_cwd_script(&mut args, &cwd_str);
        assert_eq!(args[0], "systemctl");

        // Already has a path separator → unchanged
        let mut args = vec!["./script.sh".to_string()];
        resolve_cwd_script(&mut args, &cwd_str);
        assert_eq!(args[0], "./script.sh");

        let mut args = vec!["/usr/bin/ls".to_string()];
        resolve_cwd_script(&mut args, &cwd_str);
        assert_eq!(args[0], "/usr/bin/ls");

        // Empty args → no-op
        let mut args: Vec<String> = vec![];
        resolve_cwd_script(&mut args, &cwd_str);
        assert!(args.is_empty());

        // Args after the first are never touched
        let mut args = vec!["Cargo.toml".to_string(), "Cargo.toml".to_string()];
        resolve_cwd_script(&mut args, &dir);
        assert_eq!(args[0], "./Cargo.toml");
        assert_eq!(args[1], "Cargo.toml");
    }

    #[test]
    fn test_is_aisudo_flag() {
        assert!(is_aisudo_flag("-l"));
        assert!(is_aisudo_flag("--list-rules"));
        assert!(is_aisudo_flag("--status"));
        assert!(is_aisudo_flag("--history"));
        assert!(is_aisudo_flag("--request-rule"));
        assert!(is_aisudo_flag("-r"));
        assert!(is_aisudo_flag("--reason"));
        assert!(is_aisudo_flag("-t"));
        assert!(is_aisudo_flag("--timeout"));
        assert!(is_aisudo_flag("-n"));
        assert!(is_aisudo_flag("--dry-run"));
        assert!(is_aisudo_flag("--"));
        assert!(is_aisudo_flag("--unknown-flag"));

        assert!(!is_aisudo_flag("crontab"));
        assert!(!is_aisudo_flag("ls"));
        assert!(!is_aisudo_flag("sudo"));
    }

    #[test]
    fn test_find_command_start_no_flags() {
        let args = vec![
            "aisudo".to_string(),
            "crontab".to_string(),
            "-l".to_string(),
        ];
        assert_eq!(find_command_start(&args), 1);
    }

    #[test]
    fn test_find_command_start_with_reason() {
        let args = vec![
            "aisudo".to_string(),
            "-r".to_string(),
            "reason".to_string(),
            "crontab".to_string(),
            "-l".to_string(),
        ];
        assert_eq!(find_command_start(&args), 3);
    }

    #[test]
    fn test_find_command_start_with_timeout() {
        let args = vec![
            "aisudo".to_string(),
            "-t".to_string(),
            "30".to_string(),
            "crontab".to_string(),
            "-l".to_string(),
        ];
        assert_eq!(find_command_start(&args), 3);
    }

    #[test]
    fn test_find_command_start_with_dry_run() {
        let args = vec![
            "aisudo".to_string(),
            "-n".to_string(),
            "crontab".to_string(),
            "-l".to_string(),
        ];
        assert_eq!(find_command_start(&args), 2);
    }

    #[test]
    fn test_find_command_start_with_double_dash() {
        let args = vec![
            "aisudo".to_string(),
            "--".to_string(),
            "crontab".to_string(),
            "-l".to_string(),
        ];
        assert_eq!(find_command_start(&args), 2);
    }

    #[test]
    fn test_crontab_l_not_interpreted_as_list_rules() {
        // This is the bug case: "aisudo crontab -l" should NOT trigger list-rules
        let args = vec![
            "aisudo".to_string(),
            "crontab".to_string(),
            "-l".to_string(),
        ];
        let cmd_start = find_command_start(&args);

        // -l at index 2 should NOT be recognized as a mode flag since it's after the command
        // The mode flags should only be checked in args[1..cmd_start)
        for i in 1..cmd_start {
            assert!(
                !matches!(args[i].as_str(), "-l" | "--list-rules"),
                "-l should not be found before command start"
            );
        }

        // The command should be "crontab -l"
        assert_eq!(&args[cmd_start..], &["crontab", "-l"]);
    }

    #[test]
    fn test_list_rules_at_start_is_recognized() {
        // "aisudo -l" should trigger list-rules
        let args = vec!["aisudo".to_string(), "-l".to_string()];
        let cmd_start = find_command_start(&args);

        // At index 1, -l should be recognized as a mode flag
        assert!(
            args[1..cmd_start.min(args.len())]
                .iter()
                .any(|a| a == "-l" || a == "--list-rules")
                || args.get(1).map(|s| s.as_str()) == Some("-l")
        );
    }

    #[test]
    fn idle_read_timeout_is_retried_not_fatal() {
        // Repro for #1402: a long-running command that goes quiet for longer than the
        // client's SO_RCVTIMEO produces a WouldBlock/TimedOut read error on the socket
        // even though the daemon-side process is still alive and will finish normally.
        // The streaming loop must retry on that error, not treat it as connection loss.
        let lines: Vec<std::io::Result<String>> = vec![
            Ok(r#"{"stream":"stdout","data":"part 1\n"}"#.to_string()),
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)), // idle timeout mid-stream
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),   // a second idle timeout
            Ok(r#"{"stream":"stdout","data":"part 2\n"}"#.to_string()),
            Ok(r#"{"stream":"exit","data":"","exit_code":0}"#.to_string()),
        ];
        let exit_code = stream_exec_output(lines.into_iter());
        assert_eq!(
            exit_code, 0,
            "idle read timeouts must be retried, not surfaced as a failed command"
        );
    }

    #[test]
    fn real_connection_loss_is_still_fatal() {
        // A genuine broken connection (not an idle timeout) must still be reported as
        // a failure — only WouldBlock/TimedOut are safe to retry.
        let lines: Vec<std::io::Result<String>> = vec![
            Ok(r#"{"stream":"stdout","data":"part 1\n"}"#.to_string()),
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ];
        let exit_code = stream_exec_output(lines.into_iter());
        assert_eq!(exit_code, 1);
    }
}

#[allow(dead_code)]
fn is_aisudo_flag(arg: &str) -> bool {
    matches!(
        arg,
        "-l" | "--list-rules"
            | "--status"
            | "--history"
            | "--request-rule"
            | "-r"
            | "--reason"
            | "-t"
            | "--timeout"
            | "-n"
            | "--dry-run"
            | "--"
    ) || arg.starts_with('-')
}

#[allow(dead_code)]
fn find_command_start(args: &[String]) -> usize {
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--reason" => {
                i += 2;
            }
            "-t" | "--timeout" => {
                i += 2;
            }
            "-n" | "--dry-run" | "-l" | "--list-rules" | "--status" | "--history"
            | "--request-rule" => {
                i += 1;
            }
            "--" => {
                return i + 1;
            }
            other if other.starts_with('-') => {
                i += 1;
            }
            _ => {
                return i;
            }
        }
    }
    i
}

#[cfg(test)]
mod status_frame_reader_tests {
    use super::*;

    fn lines(v: &[&str]) -> std::vec::IntoIter<std::io::Result<String>> {
        v.iter()
            .map(|s| Ok(s.to_string()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    const DECISION: &str = r#"{"request_id":"abc","decision":"approved"}"#;

    /// The regression this module exists for. `retry_with_approval` set `wants_status` but
    /// open-coded no step past the frame, so it fed the frame to `SudoResponse` and failed
    /// with "missing field `request_id`" on every NOPASSWD retry. Both call sites now share
    /// this reader, so the frame is consumed once and the decision is what comes back.
    #[test]
    fn a_status_frame_is_consumed_and_the_decision_is_returned() {
        let mut it = lines(&[r#"{"status":"waiting_for_human"}"#, DECISION]);
        let (status, decision) = read_status_and_decision(&mut it, "t", |_| {}).unwrap();
        assert_eq!(status, Some(RequestStatus::WaitingForHuman));
        assert_eq!(decision, DECISION);
    }

    /// An older daemon sends no frame. The decision must pass through untouched, and no
    /// second line may be demanded — the daemon has already closed by then.
    #[test]
    fn an_old_daemon_sending_only_a_decision_needs_no_second_line() {
        let mut it = lines(&[DECISION]);
        let (status, decision) = read_status_and_decision(&mut it, "t", |_| {}).unwrap();
        assert_eq!(status, None);
        assert_eq!(decision, DECISION);
    }

    #[test]
    fn a_truncated_stream_after_a_status_frame_is_an_error_not_a_hang() {
        let mut it = lines(&[r#"{"status":"auto_approved"}"#]);
        let err = read_status_and_decision(&mut it, "retry_approval", |_| {}).unwrap_err();
        assert!(err.contains("closed connection"), "got: {err}");
        assert!(err.contains("retry_approval"), "context lost: {err}");
    }

    #[test]
    fn an_empty_stream_is_an_error_not_a_hang() {
        let mut it = lines(&[]);
        assert!(read_status_and_decision(&mut it, "main", |_| {}).is_err());
    }

    /// The whole point of #1719: the warning fires for exactly one status, and not for the
    /// auto paths that never involve a person.
    #[test]
    fn the_human_warning_fires_only_for_waiting_for_human() {
        assert!(should_warn_a_human_is_waiting(Some(
            RequestStatus::WaitingForHuman
        )));
        assert!(!should_warn_a_human_is_waiting(Some(
            RequestStatus::AutoApproved
        )));
        assert!(!should_warn_a_human_is_waiting(Some(
            RequestStatus::AutoDenied
        )));
        assert!(!should_warn_a_human_is_waiting(None));
    }

    /// Every status the daemon can send must round-trip through the reader, or a new variant
    /// would silently be read as "no frame" and its decision line eaten as the decision.
    #[test]
    fn every_status_is_recognised_by_the_reader() {
        for (wire, want) in [
            ("auto_approved", RequestStatus::AutoApproved),
            ("auto_denied", RequestStatus::AutoDenied),
            ("waiting_for_human", RequestStatus::WaitingForHuman),
        ] {
            let frame = format!(r#"{{"status":"{wire}"}}"#);
            let mut it = lines(&[&frame, DECISION]);
            let (status, decision) = read_status_and_decision(&mut it, "t", |_| {}).unwrap();
            assert_eq!(status, Some(want), "wire form {wire}");
            assert_eq!(decision, DECISION);
        }
    }
    /// The ordering test, and the one this module was missing when f59b330 shipped. That
    /// version returned BOTH lines and let the caller react afterwards, so the warning was
    /// emitted only after the read that blocks for as long as the human takes. strace on the
    /// installed binary showed it landing 4.0s late, after the decision had already arrived.
    /// Every other test in this module passes against that version, because an in-memory
    /// iterator never blocks and so ordering is invisible to it.
    ///
    /// This probe makes it visible: it records, at the instant the SECOND line is demanded,
    /// whether the callback has run yet.
    #[test]
    fn the_warning_runs_before_the_read_that_blocks_on_the_human() {
        use std::cell::Cell;
        use std::rc::Rc;

        struct OrderProbe {
            items: std::vec::IntoIter<String>,
            reads: usize,
            fired: Rc<Cell<bool>>,
            fired_before_second_read: Rc<Cell<Option<bool>>>,
        }
        impl Iterator for OrderProbe {
            type Item = std::io::Result<String>;
            fn next(&mut self) -> Option<Self::Item> {
                self.reads += 1;
                if self.reads == 2 {
                    self.fired_before_second_read.set(Some(self.fired.get()));
                }
                self.items.next().map(Ok)
            }
        }

        let fired = Rc::new(Cell::new(false));
        let observed = Rc::new(Cell::new(None));
        let mut probe = OrderProbe {
            items: vec![
                r#"{"status":"waiting_for_human"}"#.to_string(),
                DECISION.to_string(),
            ]
            .into_iter(),
            reads: 0,
            fired: Rc::clone(&fired),
            fired_before_second_read: Rc::clone(&observed),
        };

        let f = Rc::clone(&fired);
        let (status, decision) =
            read_status_and_decision(&mut probe, "t", move |_| f.set(true)).unwrap();

        assert_eq!(status, Some(RequestStatus::WaitingForHuman));
        assert_eq!(decision, DECISION);
        assert_eq!(
            observed.get(),
            Some(true),
            "the warning had not run when the blocking read was issued — it would reach the user only AFTER the human answered, which is the whole failure this guards"
        );
    }

    /// The callback must NOT fire when there is no frame, or an old daemon's plain decision
    /// would produce a spurious warning — the exact thing #1719 set out to remove.
    #[test]
    fn no_frame_means_no_callback() {
        use std::cell::Cell;
        use std::rc::Rc;
        let fired = Rc::new(Cell::new(false));
        let f = Rc::clone(&fired);
        let mut it = lines(&[DECISION]);
        let (status, _) = read_status_and_decision(&mut it, "t", move |_| f.set(true)).unwrap();
        assert_eq!(status, None);
        assert!(!fired.get(), "callback fired with no status frame present");
    }
}
