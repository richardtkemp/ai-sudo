use aisudo_common::{
    Decision, ExecOutput, RequestMode, SudoRequest, SudoResponse, DEFAULT_SOCKET_PATH,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: aisudo <command> [args...]");
        eprintln!("Example: aisudo apt update");
        return ExitCode::from(1);
    }

    let command = args[1..].join(" ");
    let user = get_current_user();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string());
    let pid = std::process::id();

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let request = SudoRequest {
        user: user.clone(),
        command: command.clone(),
        cwd,
        pid,
        mode: RequestMode::Exec,
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

fn get_current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
