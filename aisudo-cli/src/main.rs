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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage: aisudo [OPTIONS] <command> [args...]");
        eprintln!("       aisudo --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]");
        eprintln!("       aisudo -l | --list-rules");
        eprintln!("       aisudo --status");
        eprintln!("       aisudo --history [N]");
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

    // Check for --list-rules / -l mode
    if args.iter().any(|a| a == "--list-rules" || a == "-l") {
        return handle_list_rules();
    }

    // Check for --status mode
    if args.iter().any(|a| a == "--status") {
        return handle_status();
    }

    // Check for --history mode
    if args.iter().any(|a| a == "--history") {
        return handle_history(&args);
    }

    // Check for --request-rule mode
    if args.iter().any(|a| a == "--request-rule") {
        return handle_request_rule(&args);
    }

    // Parse flags: -r/--reason, -t/--timeout, -n/--dry-run
    let mut reason: Option<String> = None;
    let mut timeout: Option<u32> = None;
    let mut dry_run = false;
    let mut cmd_start = 1;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--reason" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("aisudo: -r/--reason requires a value");
                    return ExitCode::from(1);
                }
                reason = Some(args[i].clone());
                i += 1;
                cmd_start = i;
            }
            "-t" | "--timeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("aisudo: -t/--timeout requires a value");
                    return ExitCode::from(1);
                }
                match args[i].parse::<u32>() {
                    Ok(t) => {
                        timeout = Some(t);
                        i += 1;
                        cmd_start = i;
                    }
                    Err(_) => {
                        eprintln!("aisudo: -t/--timeout must be a positive integer");
                        return ExitCode::from(1);
                    }
                }
            }
            "-n" | "--dry-run" => {
                dry_run = true;
                i += 1;
                cmd_start = i;
            }
            other if other.starts_with('-') => {
                eprintln!("aisudo: unrecognized option '{}'", other);
                return ExitCode::from(1);
            }
            _ => {
                // Found command start
                break;
            }
        }
    }

    if cmd_start >= args.len() {
        eprintln!("Usage: aisudo [OPTIONS] <command> [args...]");
        eprintln!("       aisudo -h | --help");
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
            eprintln!("aisudo: {e}");
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
        eprintln!("aisudo: checking if command would be approved: {command}");
    } else {
        eprintln!("aisudo: requesting approval for: {command}");
    }

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aisudo: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    // Set a generous read timeout (daemon handles its own approval timeout)
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aisudo: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let request_json = match serde_json::to_string(&request) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aisudo: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(request_json.as_bytes()) {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aisudo: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);

    // First line is the SudoResponse (approval decision)
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aisudo: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aisudo: daemon closed connection unexpectedly (is it running?)");
            return ExitCode::from(1);
        }
    };

    let response: SudoResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aisudo: invalid response from daemon: {e}");
            return ExitCode::from(1);
        }
    };

    match response.decision {
        Decision::Approved => {
            if dry_run {
                println!("\x1b[32maisudo: command would be auto-approved\x1b[0m");
                return ExitCode::from(0);
            }
            // In exec mode, the daemon will now stream output lines
        }
        Decision::UseSudo => {
            if dry_run {
                println!("\x1b[32maisudo: command would be approved via NOPASSWD rule\x1b[0m");
                return ExitCode::from(0);
            }
            eprintln!("aisudo: command permitted by sudo NOPASSWD rule, executing via sudo");
            return run_via_sudo(&command, &stdin_data);
        }
        Decision::Denied => {
            if dry_run {
                if let Some(ref err) = response.error {
                    if err.contains("rate limit") {
                        println!("\x1b[33maisudo: command would be denied (rate limit)\x1b[0m");
                    } else {
                        println!("\x1b[33maisudo: command would require approval\x1b[0m");
                    }
                } else {
                    println!("\x1b[33maisudo: command would require approval\x1b[0m");
                }
                return ExitCode::from(0);
            }
            if let Some(ref err) = response.error {
                eprintln!("\x1b[31maisudo: denied due to error: {err}\x1b[0m");
            } else {
                eprintln!("\x1b[31maisudo: request denied by user\x1b[0m");
            }
            return ExitCode::from(1);
        }
        Decision::Timeout => {
            if dry_run {
                println!("\x1b[33maisudo: dry-run check timed out\x1b[0m");
                return ExitCode::from(1);
            }
            eprintln!(
                "\x1b[33maisudo: request timed out (no response within approval window)\x1b[0m"
            );
            return ExitCode::from(1);
        }
        Decision::Pending => {
            eprintln!("aisudo: unexpected pending response");
            return ExitCode::from(1);
        }
    }

    // Stream output from daemon
    let mut exit_code: i32 = 1;

    for line_result in lines {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("aisudo: read error during execution: {e}");
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
                    eprintln!("aisudo: --duration requires a value");
                    return ExitCode::from(1);
                }
                match args[i].parse::<u32>() {
                    Ok(d) => duration = Some(d),
                    Err(_) => {
                        eprintln!("aisudo: --duration must be a positive integer");
                        return ExitCode::from(1);
                    }
                }
            }
            "-r" | "--reason" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("aisudo: -r/--reason requires a value");
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
            eprintln!("aisudo: --duration is required with --request-rule");
            eprintln!("Usage: aisudo --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]");
            return ExitCode::from(1);
        }
    };

    if patterns.is_empty() {
        eprintln!("aisudo: at least one pattern is required");
        eprintln!("Usage: aisudo --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]");
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
        "aisudo: requesting temp rule for patterns {:?} (duration: {}s)",
        patterns, duration
    );

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aisudo: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aisudo: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aisudo: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aisudo: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aisudo: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aisudo: daemon closed connection unexpectedly");
            return ExitCode::from(1);
        }
    };

    let response: TempRuleResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aisudo: invalid response from daemon: {e}");
            return ExitCode::from(1);
        }
    };

    match response.decision {
        Decision::Approved => {
            let expires = response.expires_at.as_deref().unwrap_or("unknown");
            eprintln!("aisudo: temp rule approved (expires: {expires})");
            ExitCode::from(0)
        }
        Decision::Denied => {
            if let Some(ref err) = response.error {
                eprintln!("aisudo: temp rule denied: {err}");
            } else {
                eprintln!("aisudo: temp rule denied");
            }
            ExitCode::from(1)
        }
        Decision::Timeout => {
            eprintln!("aisudo: temp rule request timed out");
            ExitCode::from(1)
        }
        _ => {
            eprintln!("aisudo: unexpected response");
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
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aisudo: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aisudo: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aisudo: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aisudo: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aisudo: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aisudo: daemon closed connection unexpectedly");
            return ExitCode::from(1);
        }
    };

    let response: ListRulesResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aisudo: invalid response from daemon: {e}");
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
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aisudo: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aisudo: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aisudo: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aisudo: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aisudo: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aisudo: daemon closed connection unexpectedly");
            return ExitCode::from(1);
        }
    };

    let response: StatusResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aisudo: invalid response from daemon: {e}");
            return ExitCode::from(1);
        }
    };

    println!("=== aisudo daemon status ===");
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

fn handle_history(args: &[String]) -> ExitCode {
    use aisudo_common::{HistoryRequest, HistoryResponse};

    let user = get_current_user();

    // Parse optional limit argument
    let limit = if args.len() > 2 {
        match args[2].parse::<u32>() {
            Ok(n) if n > 0 && n <= 100 => n,
            _ => {
                eprintln!("aisudo: history limit must be between 1 and 100");
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
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aisudo: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aisudo: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aisudo: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aisudo: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aisudo: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aisudo: daemon closed connection unexpectedly");
            return ExitCode::from(1);
        }
    };

    let response: HistoryResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aisudo: invalid response from daemon: {e}");
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
            eprintln!("aisudo: failed to exec sudo: {e}");
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
            eprintln!("aisudo: sudo wait error: {e}");
            return ExitCode::from(1);
        }
    };

    // Check if sudo failed because a password was required
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && stderr.contains("a password is required") {
        eprintln!("aisudo: sudo NOPASSWD rule no longer applies, requesting approval...");
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
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            return ExitCode::from(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aisudo: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aisudo: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aisudo: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aisudo: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let first_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aisudo: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aisudo: daemon closed connection unexpectedly");
            return ExitCode::from(1);
        }
    };

    let response: SudoResponse = match serde_json::from_str(&first_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aisudo: invalid response from daemon: {e}");
            return ExitCode::from(1);
        }
    };

    match response.decision {
        Decision::Approved => {}
        Decision::Denied => {
            if let Some(ref err) = response.error {
                eprintln!("aisudo: denied: {err}");
            } else {
                eprintln!("aisudo: request denied by user");
            }
            return ExitCode::from(1);
        }
        Decision::Timeout => {
            eprintln!("aisudo: request timed out");
            return ExitCode::from(1);
        }
        _ => {
            eprintln!("aisudo: unexpected response");
            return ExitCode::from(1);
        }
    }

    // Stream output from daemon
    let mut exit_code: i32 = 1;

    for line_result in lines {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("aisudo: read error: {e}");
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
