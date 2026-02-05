use aisudo_common::{
    Decision, ExecOutput, RequestMode, SudoRequest, SudoRequestRecord, SudoResponse,
};
use anyhow::Result;
use base64::Engine as _;
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

    // Decode stdin if present
    let stdin_bytes = if let Some(ref stdin_b64) = request.stdin {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(stdin_b64)
            .map_err(|e| anyhow::anyhow!("invalid stdin encoding: {e}"))?;
        info!("Request includes stdin: {} bytes", decoded.len());
        Some(decoded)
    } else {
        None
    };

    // Check allowlist first - auto-approved commands skip rate limiting
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
            exec_command(&command, &cwd, stdin_bytes, writer).await?;
        }
        return Ok(());
    }

    // Rate limiting: max 30 non-allowlisted requests per minute per user
    if !db.check_rate_limit(&request.user, 30)? {
        warn!("Rate limit exceeded for user: {}", request.user);
        let response = SudoResponse {
            request_id: String::new(),
            decision: Decision::Denied,
            error: Some("rate limit exceeded".to_string()),
        };
        let resp_json = serde_json::to_string(&response)?;
        writer.write_all(resp_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
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
        exec_command(&command, &cwd, stdin_bytes, writer).await?;
    }

    Ok(())
}

/// Execute a command as root and stream stdout/stderr back over the socket.
async fn exec_command(
    command: &str,
    cwd: &str,
    stdin_bytes: Option<Vec<u8>>,
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
        .stdin(if stdin_bytes.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .spawn()?;

    // Write stdin to child process if present
    if let Some(data) = stdin_bytes {
        if let Some(mut stdin_pipe) = child.stdin.take() {
            tokio::spawn(async move {
                if let Err(e) = stdin_pipe.write_all(&data).await {
                    error!("Failed to write stdin to child: {e}");
                }
                // Dropping stdin_pipe closes the pipe, signaling EOF to the child
            });
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;

    #[async_trait::async_trait]
    impl crate::notification::NotificationBackend for MockBackend {
        async fn send_and_wait(&self, _record: &SudoRequestRecord) -> anyhow::Result<Decision> {
            panic!("send_and_wait should not be called when rate-limited");
        }
        fn name(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn rate_limit_sends_denial_response() {
        let dir = std::env::temp_dir().join(format!(
            "aisudo-rate-limit-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.join("test.db")).unwrap());

        // Insert 30 requests to exceed the rate limit
        for i in 0..30 {
            let req = SudoRequest {
                user: "testuser".to_string(),
                command: format!("cmd-{}", i),
                cwd: "/tmp".to_string(),
                pid: 1000 + i as u32,
                mode: RequestMode::Exec,
                reason: None,
                stdin: None,
            };
            let record = SudoRequestRecord::new(req, 60);
            db.insert_request(&record).unwrap();
        }

        // Create a connected socket pair
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);
        let db_clone = Arc::clone(&db);

        // Spawn the daemon handler
        let handler = tokio::spawn(async move {
            handle_connection(server, db_clone, backend, 60, &[]).await
        });

        // Client side: send a request that should be rate-limited
        let (reader, mut writer) = client.into_split();
        let request = SudoRequest {
            user: "testuser".to_string(),
            command: "should-be-rate-limited".to_string(),
            cwd: "/tmp".to_string(),
            pid: 9999,
            mode: RequestMode::Exec,
            reason: None,
            stdin: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        writer.write_all(json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        // Client side: read response (with timeout to detect hangs)
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        let read_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            buf_reader.read_line(&mut line),
        )
        .await;
        let bytes_read = read_result
            .expect("client timed out waiting for response — daemon did not send one")
            .unwrap();
        assert!(
            bytes_read > 0,
            "daemon closed connection without sending a response"
        );

        let response: SudoResponse = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(response.decision, Decision::Denied);
        assert!(
            response
                .error
                .as_deref()
                .unwrap()
                .contains("rate limit"),
            "expected 'rate limit' in error, got: {:?}",
            response.error
        );

        // Daemon handler should have returned Ok
        handler.await.unwrap().unwrap();

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }
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
