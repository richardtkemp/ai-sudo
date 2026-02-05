use aisudo_common::{
    Decision, ExecOutput, RequestMode, SudoRequest, SudoRequestRecord, SudoResponse,
};
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::db::Database;
use crate::notification::NotificationBackend;

pub async fn run_socket_listener(
    config: &Config,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
) -> Result<()> {
    let socket_path = &config.socket_path;

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale socket file
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Make socket accessible (the daemon runs as root)
    set_socket_permissions(socket_path)?;

    info!("Listening on Unix socket: {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let db = Arc::clone(&db);
                let backend = Arc::clone(&backend);
                let timeout = config.timeout_seconds;
                let allowlist = config.allowlist.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, db, backend, timeout, &allowlist).await
                    {
                        error!("Connection handler error: {e:#}");
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {e}");
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
    timeout_seconds: u32,
    allowlist: &[String],
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let result = handle_request(reader, &mut writer, db, backend, timeout_seconds, allowlist).await;
    if let Err(ref e) = result {
        // Try to send the error back to the client so it doesn't just see "connection closed"
        error!("Request handling error: {e:#}");
        let response = SudoResponse {
            request_id: String::new(),
            decision: Decision::Denied,
            error: Some(format!("{e:#}")),
        };
        if let Ok(resp_json) = serde_json::to_string(&response) {
            let _ = writer.write_all(resp_json.as_bytes()).await;
            let _ = writer.write_all(b"\n").await;
        }
    }
    result
}

async fn handle_request(
    reader: tokio::net::unix::OwnedReadHalf,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
    timeout_seconds: u32,
    allowlist: &[String],
) -> Result<()> {
    let mut reader = BufReader::new(reader);

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let line = line.trim();

    let request: SudoRequest = serde_json::from_str(line)
        .map_err(|e| anyhow::anyhow!("invalid request JSON: {e}"))?;
    let mode = request.mode;
    info!(
        "Received sudo request: user={} command={} mode={:?}",
        request.user, request.command, mode
    );

    // Rate limiting: max 10 requests per minute per user
    if !db.check_rate_limit(&request.user, 10)? {
        warn!("Rate limit exceeded for user: {}", request.user);
        let response = SudoResponse {
            request_id: String::new(),
            decision: Decision::Denied,
            error: Some("rate limit exceeded".to_string()),
        };
        let resp_json = serde_json::to_string(&response)?;
        writer.write_all(resp_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        return Ok(());
    }

    // Check allowlist - auto-approve matching commands
    let command = request.command.clone();
    let cwd = request.cwd.clone();
    if is_allowed(&command, allowlist) {
        info!("Command auto-approved via allowlist: {}", command);
        let record = SudoRequestRecord::new(request, timeout_seconds);
        db.insert_request(&record)?;
        db.update_decision(&record.id, Decision::Approved, "allowlist")?;
        let response = SudoResponse {
            request_id: record.id,
            decision: Decision::Approved,
            error: None,
        };
        let resp_json = serde_json::to_string(&response)?;
        writer.write_all(resp_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        if mode == RequestMode::Exec {
            exec_command(&command, &cwd, writer).await?;
        }
        return Ok(());
    }

    // Create request record
    let record = SudoRequestRecord::new(request, timeout_seconds);
    db.insert_request(&record)?;

    // Send notification and wait for response
    let (decision, error_msg) = match backend.send_and_wait(&record).await {
        Ok(d) => (d, None),
        Err(e) => {
            error!("Notification backend error for request {}: {e:#}", record.id);
            (Decision::Denied, Some(format!("notification error: {e}")))
        }
    };

    // Update database
    db.update_decision(&record.id, decision, backend.name())?;

    // Send response
    let response = SudoResponse {
        request_id: record.id,
        decision,
        error: error_msg,
    };
    let resp_json = serde_json::to_string(&response)?;
    writer.write_all(resp_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    // If exec mode and approved, execute the command and stream output
    if mode == RequestMode::Exec && decision == Decision::Approved {
        exec_command(&command, &cwd, writer).await?;
    }

    Ok(())
}

/// Execute a command as root and stream stdout/stderr back over the socket.
async fn exec_command(
    command: &str,
    cwd: &str,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<()> {
    use tokio::process::Command;

    info!("Executing command: {command}");

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Use a channel to collect output from both streams, then write serially.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ExecOutput>(64);

    if let Some(stdout) = stdout {
        let tx_out = tx.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut reader = BufReader::new(stdout);
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = String::from_utf8_lossy(&buf[..n]).to_string();
                        let _ = tx_out
                            .send(ExecOutput {
                                stream: "stdout".to_string(),
                                data,
                                exit_code: None,
                            })
                            .await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    if let Some(stderr) = stderr {
        let tx_err = tx.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut reader = BufReader::new(stderr);
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = String::from_utf8_lossy(&buf[..n]).to_string();
                        let _ = tx_err
                            .send(ExecOutput {
                                stream: "stderr".to_string(),
                                data,
                                exit_code: None,
                            })
                            .await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Drop the last sender so rx completes when both streams are done
    drop(tx);

    // Forward all output to the socket
    while let Some(output) = rx.recv().await {
        let json = serde_json::to_string(&output)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    // Wait for exit code
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(1);

    info!("Command finished with exit code: {exit_code}");

    let exit_msg = ExecOutput {
        stream: "exit".to_string(),
        data: String::new(),
        exit_code: Some(exit_code),
    };
    let json = serde_json::to_string(&exit_msg)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    Ok(())
}

fn is_allowed(command: &str, allowlist: &[String]) -> bool {
    for pattern in allowlist {
        if command.starts_with(pattern) {
            return true;
        }
    }
    false
}

fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(path, perms)?;

    // Set group to 'aisudo' so members of that group can connect
    if let Some(group) = nix::unistd::Group::from_name("aisudo")? {
        nix::unistd::chown(path, None, Some(group.gid))?;
    }

    Ok(())
}
