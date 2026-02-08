use aisudo_common::{
    BwGetRequest, BwGetResponse, BwLockRequest, BwLockResponse, BwStatusRequest, BwStatusResponse,
    Decision, SocketMessage, DEFAULT_SOCKET_PATH,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return ExitCode::from(if args.iter().any(|a| a == "--help" || a == "-h") { 0 } else { 1 });
    }

    match args[1].as_str() {
        "get" => handle_get(&args[2..]),
        "lock" => handle_lock(),
        "status" => handle_status(),
        other => {
            eprintln!("aibw: unknown command '{other}'");
            print_usage();
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    eprintln!("Usage: aibw get <item-name> [--field password|username|totp|notes|uri]");
    eprintln!("       aibw lock");
    eprintln!("       aibw status");
    eprintln!("       aibw --help");
}

fn handle_get(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("aibw: item name is required");
        eprintln!("Usage: aibw get <item-name> [--field password|username|totp|notes|uri]");
        return ExitCode::from(1);
    }

    let mut item_name = String::new();
    let mut field = "password".to_string();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--field" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("aibw: --field requires a value");
                    return ExitCode::from(1);
                }
                let f = &args[i];
                match f.as_str() {
                    "password" | "username" | "totp" | "notes" | "uri" => {
                        field = f.clone();
                    }
                    _ => {
                        eprintln!("aibw: unknown field '{f}'. Must be one of: password, username, totp, notes, uri");
                        return ExitCode::from(1);
                    }
                }
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("aibw: unrecognized option '{other}'");
                    return ExitCode::from(1);
                }
                if !item_name.is_empty() {
                    item_name.push(' ');
                }
                item_name.push_str(other);
            }
        }
        i += 1;
    }

    if item_name.is_empty() {
        eprintln!("aibw: item name is required");
        return ExitCode::from(1);
    }

    let user = get_current_user();

    let msg = SocketMessage::BwGet(BwGetRequest {
        user,
        item_name: item_name.clone(),
        field: field.clone(),
    });

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    eprintln!("aibw: requesting credential for: {item_name} (field: {field})");

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aibw: failed to connect to daemon at {socket_path}: {e}");
            eprintln!("aibw: is aisudo-daemon running?");
            return ExitCode::from(1);
        }
    };

    // Generous timeout — daemon handles its own approval timeout
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aibw: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aibw: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aibw: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aibw: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aibw: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    // Phase 1 response: awaiting_confirmation or immediate denial
    let phase1_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aibw: connection to daemon lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aibw: daemon closed connection unexpectedly");
            return ExitCode::from(1);
        }
    };

    let phase1: BwGetResponse = match serde_json::from_str(&phase1_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aibw: invalid response from daemon: {e}");
            return ExitCode::from(1);
        }
    };

    match phase1.decision {
        Decision::Denied => {
            if let Some(ref err) = phase1.error {
                eprintln!("aibw: denied: {err}");
            } else {
                eprintln!("aibw: request denied");
            }
            return ExitCode::from(1);
        }
        Decision::Timeout => {
            eprintln!("aibw: request timed out");
            return ExitCode::from(1);
        }
        Decision::Approved => {
            // Phase 1 approved
            if let Some(ref resolved) = phase1.resolved_item_name {
                eprintln!("aibw: approved, resolved to: {resolved}");
            }
        }
        _ => {
            if let Some(ref err) = phase1.error {
                eprintln!("aibw: error: {err}");
            } else {
                eprintln!("aibw: unexpected response");
            }
            return ExitCode::from(1);
        }
    }

    // If not awaiting confirmation, credential is in phase 1
    if !phase1.awaiting_confirmation {
        if let Some(ref value) = phase1.value {
            // Print credential to stdout with no trailing newline
            print!("{value}");
            let _ = std::io::stdout().flush();
            return ExitCode::from(0);
        }
        eprintln!("aibw: approved but no credential returned");
        return ExitCode::from(1);
    }

    // Phase 2: wait for confirmation result
    eprintln!("aibw: waiting for confirmation...");

    let phase2_line = match lines.next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("aibw: connection to daemon lost during confirmation: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aibw: daemon closed connection during confirmation");
            return ExitCode::from(1);
        }
    };

    let phase2: BwGetResponse = match serde_json::from_str(&phase2_line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aibw: invalid phase 2 response: {e}");
            return ExitCode::from(1);
        }
    };

    match phase2.decision {
        Decision::Approved => {
            if let Some(ref value) = phase2.value {
                // Print credential to stdout with no trailing newline
                print!("{value}");
                let _ = std::io::stdout().flush();
                ExitCode::from(0)
            } else {
                eprintln!("aibw: confirmed but no credential returned");
                ExitCode::from(1)
            }
        }
        Decision::Denied => {
            if let Some(ref err) = phase2.error {
                eprintln!("aibw: cancelled: {err}");
            } else {
                eprintln!("aibw: request cancelled by user");
            }
            ExitCode::from(1)
        }
        _ => {
            eprintln!("aibw: unexpected phase 2 response");
            ExitCode::from(1)
        }
    }
}

fn handle_lock() -> ExitCode {
    let user = get_current_user();
    let msg = SocketMessage::BwLock(BwLockRequest { user });

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aibw: failed to connect to daemon at {socket_path}: {e}");
            return ExitCode::from(1);
        }
    };

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aibw: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aibw: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aibw: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aibw: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aibw: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let line = match lines.next() {
        Some(Ok(l)) => l,
        Some(Err(e)) => {
            eprintln!("aibw: connection lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aibw: daemon closed connection");
            return ExitCode::from(1);
        }
    };

    let response: BwLockResponse = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aibw: invalid response: {e}");
            return ExitCode::from(1);
        }
    };

    if response.success {
        eprintln!("aibw: vault locked");
        ExitCode::from(0)
    } else {
        eprintln!(
            "aibw: lock failed: {}",
            response.error.as_deref().unwrap_or("unknown error")
        );
        ExitCode::from(1)
    }
}

fn handle_status() -> ExitCode {
    let user = get_current_user();
    let msg = SocketMessage::BwStatus(BwStatusRequest { user });

    let socket_path =
        std::env::var("AISUDO_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aibw: failed to connect to daemon at {socket_path}: {e}");
            return ExitCode::from(1);
        }
    };

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("aibw: socket error: {e}");
            return ExitCode::from(1);
        }
    };

    let msg_json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("aibw: serialization error: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = writer.write_all(msg_json.as_bytes()) {
        eprintln!("aibw: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.write_all(b"\n") {
        eprintln!("aibw: write error: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("aibw: flush error: {e}");
        return ExitCode::from(1);
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    let line = match lines.next() {
        Some(Ok(l)) => l,
        Some(Err(e)) => {
            eprintln!("aibw: connection lost: {e}");
            return ExitCode::from(1);
        }
        None => {
            eprintln!("aibw: daemon closed connection");
            return ExitCode::from(1);
        }
    };

    let response: BwStatusResponse = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aibw: invalid response: {e}");
            return ExitCode::from(1);
        }
    };

    if response.session_active {
        eprintln!("Session: unlocked");
        if let Some(ref last_used) = response.last_used {
            eprintln!("Last used: {last_used}");
        }
    } else {
        eprintln!("Session: locked");
        if let Some(ref since) = response.locked_since {
            eprintln!("Locked since: {since}");
        }
    }

    ExitCode::from(0)
}

fn get_current_user() -> String {
    let uid = unsafe { libc::getuid() };
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
