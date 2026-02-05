use aisudo_common::{
    Decision, ExecOutput, RequestMode, SocketMessage, SudoRequest, SudoResponse,
    TempRuleRequest, TempRuleResponse, DEFAULT_SOCKET_PATH,
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

    if args.len() < 2 {
        eprintln!("Usage: aisudo [-r \"reason\"] <command> [args...]");
        eprintln!("       aisudo --request-rule --duration <seconds> [-r \"reason\"] <pattern> [pattern...]");
        return ExitCode::from(1);
    }

    // Check for --request-rule mode
    if args.iter().any(|a| a == "--request-rule") {
        return handle_request_rule(&args);
    }

    // Parse optional -r/--reason flag before the command
    let (reason, cmd_start) = if (args[1] == "-r" || args[1] == "--reason") && args.len() >= 4 {
        (Some(args[2].clone()), 3)
    } else {
        (None, 1)
    };

    if cmd_start >= args.len() {
        eprintln!("Usage: aisudo [-r \"reason\"] <command> [args...]");
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
        mode: RequestMode::Exec,
        reason,
        stdin: stdin_data,
    };

    eprintln!("aisudo: requesting approval for: {command}");

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aisudo: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aisudo: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    // Set a generous read timeout (daemon handles its own approval timeout)
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .ok();

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
            // In exec mode, the daemon will now stream output lines
        }
        Decision::Denied => {
            if let Some(ref err) = response.error {
                eprintln!("aisudo: denied due to error: {err}");
            } else {
                eprintln!("aisudo: request denied by user");
            }
            return ExitCode::from(1);
        }
        Decision::Timeout => {
            eprintln!("aisudo: request timed out (no response within approval window)");
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

    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .ok();

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
        Decision::Pending => {
            eprintln!("aisudo: unexpected pending response");
            ExitCode::from(1)
        }
    }
}

fn get_current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
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
