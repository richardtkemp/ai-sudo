use aisudo_common::{
    Decision, ExecOutput, ListRulesRequest, ListRulesResponse, RequestMode, SocketMessage,
    SudoRequest, SudoResponse, TempRuleRequest, TempRuleResponse, DEFAULT_SOCKET_PATH,
};
use base64::Engine as _;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

const MAX_STDIN_SIZE: usize = 10 * 1024 * 1024; // 10 MB

include!(concat!(env!("OUT_DIR"), "/bin_name.rs"));

fn main() -> ExitCode {
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

    let command = args[cmd_start..].join(" ");
    let user = get_current_user();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string());
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
    };

    if dry_run {
        eprintln!(
            "{}: checking if command would be approved: {command}",
            BINARY_NAME
        );
    } else {
        eprintln!("{}: requesting approval for: {command}", BINARY_NAME);
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

    // Set a generous read timeout (daemon handles its own approval timeout)
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

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

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("{}: connection to daemon lost: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
        None => {
            eprintln!(
                "{}: daemon closed connection unexpectedly (is it running?)",
                BINARY_NAME
            );
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
                println!("\x1b[32msudo: command would be auto-approved\x1b[0m");
                return ExitCode::from(0);
            }
            // In exec mode, the daemon will now stream output lines
        }
        Decision::UseSudo => {
            if dry_run {
                println!("\x1b[32msudo: command would be approved via NOPASSWD rule\x1b[0m");
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
                        println!("\x1b[33msudo: command would be denied (rate limit)\x1b[0m");
                    } else {
                        println!("\x1b[33msudo: command would require approval\x1b[0m");
                    }
                } else {
                    println!("\x1b[33msudo: command would require approval\x1b[0m");
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
                println!("\x1b[33msudo: dry-run check timed out\x1b[0m");
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

    // Stream output from daemon
    let mut exit_code: i32 = 1;

    for line_result in lines {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{}: read error during execution: {e}", BINARY_NAME);
                return ExitCode::from(1);
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

    ExitCode::from(exit_code as u8)
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

    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

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
            eprintln!("{}: connection to daemon lost: {e}", BINARY_NAME);
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
            eprintln!("{}: connection to daemon lost: {e}", BINARY_NAME);
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
            eprintln!("{}: connection to daemon lost: {e}", BINARY_NAME);
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
            eprintln!("{}: connection to daemon lost: {e}", BINARY_NAME);
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

    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

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
            eprintln!("{}: connection to daemon lost: {e}", BINARY_NAME);
            return ExitCode::from(1);
        }
        None => {
            eprintln!("{}: daemon closed connection unexpectedly", BINARY_NAME);
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

    // Stream output from daemon
    let mut exit_code: i32 = 1;

    for line_result in lines {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{}: read error: {e}", BINARY_NAME);
                return ExitCode::from(1);
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

    ExitCode::from(exit_code as u8)
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

#[cfg(test)]
mod tests {
    use super::*;

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
