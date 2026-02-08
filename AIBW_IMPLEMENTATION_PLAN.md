# aibw Implementation Plan

## Overview

Integrate Bitwarden credential retrieval into the existing aisudo daemon with human-in-the-loop approval via Telegram. The agent requests vault items by name; the human approves via Telegram (or enters the master password via a web UI if the vault is locked); credentials are returned to the agent and later scrubbed from session logs.

### Security Decisions (from review)

The following decisions from the security review are incorporated throughout this plan:

| Decision | Implementation |
|---|---|
| Session key via env var, not CLI arg | `BW_SESSION` env var on child process (C1) |
| Credential over Unix socket is accepted risk | No encryption layer; socket is local-only (C2) |
| Eventual scrubbing accepted | Scrubber notifies via Telegram on completion (C3) |
| Direct exec bw, validate item_name | No shell; reject control chars, max 256 chars (H1) |
| Use --passwordenv for unlock | Password in child env, never touches disk (H2) |
| Store credential plaintext in scrub queue | Root is trusted; no encryption layer needed (H3) |
| Two-phase approval | Human sees resolved BW item before final approve (H4) |
| Extract only requested field from bw output | Daemon parses full JSON, returns single field (M4) |
| Startup cleanup for partial scrubs | Scan for orphaned `.aibw-scrub-tmp` files (M5) |
| Multi-encoding scrub | Scrub raw + JSON-escaped + URL-encoded variants (L5) |
| Daemon discovers session files | Ignore client-provided paths; use configured dir (G5) |
| Credential exposure beyond session files | Accepted risk, documented (M2) |

---

## 1. Architecture Decision: Extend vs. Separate Binary

**Decision: Extend the existing daemon, add a separate `aibw` CLI binary.**

Rationale:
- The daemon already has Telegram bot polling, SQLite, rate limiting, Unix socket IPC — all reusable.
- A new `aibw` CLI binary keeps the client simple and avoids overloading the `aisudo` CLI with unrelated subcommands.
- The daemon gains new `SocketMessage` variants and a new handler path for BW requests.
- The web UI for password entry is a new HTTP server component embedded in the daemon.

### Workspace Changes

```
ai-sudo/
├── aisudo-common/        # Add BW message types
├── aisudo-daemon/        # Add BW handler, session mgr, web UI, scrubber
├── aisudo-cli/           # Unchanged
└── aibw-cli/             # NEW — lightweight BW client binary
```

---

## 2. aisudo-common: New Message Types

### 2.1 New Types

```rust
/// Request to retrieve a Bitwarden vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwGetRequest {
    pub user: String,
    pub item_name: String,
    /// Which field to retrieve: "password", "username", "totp", "notes", "uri"
    #[serde(default = "default_bw_field")]
    pub field: String,
}

fn default_bw_field() -> String {
    "password".to_string()
}

/// Response to a Bitwarden get request.
/// Phase 1 response (after initial approval, before retrieval):
///   - decision: Approved, resolved_item_name set, value: None, awaiting_confirmation: true
/// Phase 2 response (after human confirms resolved item):
///   - decision: Approved, value set (credential), awaiting_confirmation: false
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwGetResponse {
    pub request_id: String,
    pub decision: Decision,
    /// The credential value (only set on phase 2 after confirmed retrieval)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The actual item name resolved by BW (may differ from requested name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_item_name: Option<String>,
    /// If true, the client should wait for phase 2 (human confirming resolved item)
    #[serde(default)]
    pub awaiting_confirmation: bool,
}

/// Request to lock the Bitwarden vault session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwLockRequest {
    pub user: String,
}

/// Response to a lock request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwLockResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request to check vault session status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwStatusRequest {
    pub user: String,
}

/// Response with vault status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwStatusResponse {
    pub session_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
}
```

**Note (G5):** `BwGetRequest` intentionally has no `session_files` field. The daemon discovers which session files to scrub from its configured `session_log_dir`.

### 2.2 SocketMessage Extension

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SocketMessage {
    SudoRequest(SudoRequest),
    TempRuleRequest(TempRuleRequest),
    ListRules(ListRulesRequest),
    BwGet(BwGetRequest),          // NEW
    BwLock(BwLockRequest),        // NEW
    BwStatus(BwStatusRequest),    // NEW
}
```

---

## 3. aibw-cli: New Client Binary

### 3.1 Crate Setup

```toml
# aibw-cli/Cargo.toml
[package]
name = "aibw-cli"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "aibw"
path = "src/main.rs"

[dependencies]
aisudo-common = { path = "../aisudo-common" }
serde_json = "1"
libc = "0.2"
```

### 3.2 CLI Interface

```
aibw get <item-name> [--field password|username|totp|notes|uri]
aibw lock
aibw status
aibw --help
```

### 3.3 Implementation

The CLI follows the same pattern as aisudo-cli:
1. Resolve real UID via `getuid()` (display only; daemon uses `SO_PEERCRED`)
2. Connect to Unix socket at `DEFAULT_SOCKET_PATH` (or `$AISUDO_SOCKET`)
3. Send JSON-encoded `SocketMessage::BwGet/BwLock/BwStatus`
4. For `BwGet`, handle the two-phase response protocol:
   - Read line 1: `BwGetResponse` with `awaiting_confirmation: true` — daemon is waiting for human to confirm the resolved item. Print status to stderr.
   - Read line 2: `BwGetResponse` with `value` set — print credential to stdout.
   - If line 1 has `decision: Denied/Timeout`, exit immediately.
5. For `lock`/`status`: read single JSON response, print human-readable output to stderr.

**Critical**: The credential value is printed to stdout with no trailing newline, allowing `$(aibw get "item")` shell substitution. All status/error messages go to stderr.

**Accepted risk (M2):** Once the credential is printed to stdout, it exists in the agent's process memory, shell pipe buffers, and potentially in session logs. The scrubber provides best-effort cleanup of session log files only. Other locations (process memory, shell history, agent temp files) are not addressed.

---

## 4. aisudo-daemon: Bitwarden Session Manager

### 4.1 New Module: `bw_session.rs`

```rust
use zeroize::Zeroizing;

pub struct BwSessionManager {
    /// The BW session key (from `bw unlock`). Protected by Mutex.
    session_key: Mutex<Option<Zeroizing<String>>>,
    /// Last time the session was used (for auto-lock).
    last_used: Mutex<Option<Instant>>,
    /// Auto-lock timeout from config.
    auto_lock_timeout: Duration,
    /// Path to `bw` binary.
    bw_binary: PathBuf,
}
```

Key methods:

```rust
impl BwSessionManager {
    /// Check if vault is unlocked and session is still valid.
    pub async fn is_session_active(&self) -> bool

    /// Unlock the vault with the given master password.
    /// Uses --passwordenv: sets BW_PASSWORD in child process environment.
    /// Password never touches disk. Zeroized after use.
    pub async fn unlock(&self, password: &str) -> Result<()>

    /// Retrieve a vault item by name. Returns the full BW item JSON.
    /// Session key is passed via BW_SESSION env var on the child process
    /// (not via --session CLI arg, which would be visible in /proc/PID/cmdline).
    /// The bw binary is invoked via direct exec (no shell).
    /// item_name is validated before use (see validate_item_name).
    pub async fn get_item_raw(&self, item_name: &str) -> Result<serde_json::Value>

    /// Extract a specific field from a BW item JSON response.
    /// Only the requested field is returned; the full JSON is zeroized.
    pub fn extract_field(item_json: &serde_json::Value, field: &str) -> Result<String>

    /// Lock the vault, clearing the session key (zeroized).
    pub async fn lock(&self) -> Result<()>

    /// Touch the last-used timestamp (called on each successful get).
    fn touch(&self)

    /// Check if auto-lock timeout has expired.
    fn is_auto_lock_expired(&self) -> bool
}
```

### 4.2 Session Key Handling (C1)

- The session key is held **only in memory** wrapped in `Zeroizing<String>`.
- It is never written to disk, never logged, never included in audit records.
- On daemon restart, the session is lost (user must re-unlock).
- **The session key is passed to `bw` commands via the `BW_SESSION` environment variable** on the child process. This is NOT visible in `/proc/PID/cmdline` (unlike `--session`). `/proc/PID/environ` is only readable by the process owner (root) and by root.

```rust
async fn run_bw_command(&self, args: &[&str]) -> Result<std::process::Output> {
    let session_key = self.session_key.lock().await;
    let mut cmd = tokio::process::Command::new(&self.bw_binary);
    cmd.args(args);
    if let Some(ref key) = *session_key {
        cmd.env("BW_SESSION", key.as_str());
    }
    // No shell — direct exec (H1)
    cmd.stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped())
       .spawn()?
       .wait_with_output()
       .await
       .map_err(Into::into)
}
```

### 4.3 Password Handling for Unlock (H2)

When the human provides the master password via the web UI:

```rust
pub async fn unlock(&self, password: &str) -> Result<()> {
    let password = Zeroizing::new(password.to_string());
    let mut cmd = tokio::process::Command::new(&self.bw_binary);
    cmd.args(["unlock", "--passwordenv", "BW_PASSWORD"]);
    // Password is set ONLY in the child process environment.
    // It never touches disk. /proc/PID/environ is root-readable only.
    cmd.env("BW_PASSWORD", password.as_str());
    cmd.stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped());

    let output = cmd.spawn()?.wait_with_output().await?;
    // password is zeroized when Zeroizing<String> is dropped

    if !output.status.success() {
        return Err(anyhow!("bw unlock failed"));
    }

    // Parse session key from stdout (bw outputs it after "export BW_SESSION=...")
    let stdout = String::from_utf8_lossy(&output.stdout);
    let session_key = parse_session_key(&stdout)?;
    *self.session_key.lock().await = Some(Zeroizing::new(session_key));
    self.touch();
    Ok(())
}
```

### 4.4 Item Name Validation (H1)

```rust
/// Validate an item name before passing to bw CLI.
/// Rejects control characters, null bytes, and excessive length.
fn validate_item_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("item name cannot be empty"));
    }
    if name.len() > 256 {
        return Err(anyhow!("item name too long (max 256 characters)"));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(anyhow!("item name contains invalid characters"));
    }
    Ok(())
}
```

### 4.5 Field Extraction (M4)

```rust
/// Extract only the requested field from bw's full item JSON.
/// The full JSON (containing all fields) is never returned to the client.
pub fn extract_field(item_json: &serde_json::Value, field: &str) -> Result<String> {
    let value = match field {
        "password" => item_json
            .get("login").and_then(|l| l.get("password"))
            .and_then(|v| v.as_str()),
        "username" => item_json
            .get("login").and_then(|l| l.get("username"))
            .and_then(|v| v.as_str()),
        "totp" => item_json
            .get("login").and_then(|l| l.get("totp"))
            .and_then(|v| v.as_str()),
        "notes" => item_json
            .get("notes")
            .and_then(|v| v.as_str()),
        "uri" => item_json
            .get("login").and_then(|l| l.get("uris"))
            .and_then(|u| u.as_array())
            .and_then(|arr| arr.first())
            .and_then(|u| u.get("uri"))
            .and_then(|v| v.as_str()),
        _ => return Err(anyhow!("unknown field: {field}")),
    };
    value
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("field '{field}' not found in item"))
    // Note: after this returns, caller should zeroize the full item_json
}
```

### 4.6 Auto-Lock Timer

A background task checks `last_used` vs `auto_lock_timeout`:

```rust
tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        if session_mgr.is_auto_lock_expired() {
            session_mgr.lock().await.ok();
            info!("BW session auto-locked due to idle timeout");
        }
    }
});
```

---

## 5. aisudo-daemon: BW Request Handler

### 5.1 Socket Handler Extension

In `socket.rs`, extend `handle_connection` to dispatch new message types:

```rust
SocketMessage::BwGet(mut request) => {
    override_user_from_peer(&mut request.user, peer_uid);
    handle_bw_get(request, &mut writer, db, backend, bw_session, scrubber).await
}
SocketMessage::BwLock(mut request) => {
    override_user_from_peer(&mut request.user, peer_uid);
    handle_bw_lock(request, &mut writer, bw_session).await
}
SocketMessage::BwStatus(mut request) => {
    override_user_from_peer(&mut request.user, peer_uid);
    handle_bw_status(request, &mut writer, bw_session).await
}
```

### 5.2 `handle_bw_get` Flow — Two-Phase Approval (H4)

The two-phase flow ensures the human sees the *actual* resolved BW item name before the credential is delivered. This prevents the agent from requesting "Harmless Token" when BW's fuzzy matching resolves to "Production Database Root".

```
Phase 1: Request + Initial Approval
  1. Validate item_name (H1: reject control chars, max 256)
  2. Rate limit check (reuse existing rate limiter)
  3. Create BW request record in DB (audit)
  4. Check if BW session is active:
     a. If ACTIVE → Send Telegram with [Approve] [Deny]
     b. If LOCKED → Send Telegram with unlock URL
  5. Wait for initial approval
  6. On denial/timeout → send BwGetResponse{decision: Denied}, done
  7. On initial approval → proceed to Phase 2

Phase 2: Resolve + Confirm + Deliver
  8.  Call bw_session.get_item_raw(item_name) to resolve the actual item
  9.  Extract the actual item name from BW response JSON
  10. Compare requested name vs resolved name
  11. Send Telegram confirmation message:
      "Resolved: <actual_name> (requested: <requested_name>). Field: <field>. [Confirm] [Cancel]"
      - If names match exactly → auto-confirm (skip human step)
      - If names differ → require human confirmation
  12. On confirm:
      a. Extract requested field only (M4), zeroize full JSON
      b. Send BwGetResponse{value: credential} to client
      c. Schedule scrub (G5: daemon discovers session files)
      d. Audit log: bw_item_retrieved with credential_hash
  13. On cancel:
      a. Send BwGetResponse{decision: Denied}
      b. Audit log: bw_request_cancelled (name mismatch)
```

### 5.3 Approval Integration with Web UI

When the session is locked, the Telegram message includes a URL like:
```
https://nuc.brown-ordinal.ts.net/aibw/unlock?request=<request-id>
```

The web UI handler (see section 7) handles:
1. Display the pending request details (item name, user, field)
2. Accept master password input
3. Attempt `bw unlock` with provided password
4. On success: mark session as unlocked, approve the pending request (enters Phase 2)
5. Signal the waiting handler via a oneshot channel

---

## 6. aisudo-daemon: Database Extensions

### 6.1 New Tables

```sql
CREATE TABLE IF NOT EXISTS bw_requests (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    item_name TEXT NOT NULL,
    field TEXT NOT NULL DEFAULT 'password',
    timestamp TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'pending',
    -- status values: pending, approved, confirmed, denied, timeout, cancelled
    decided_at TEXT,
    decided_by TEXT,
    nonce TEXT NOT NULL,
    -- Actual resolved item name from BW (set after Phase 1 approval)
    resolved_item_name TEXT,
    -- SHA-256 hash of credential for audit/scrub correlation (never the value itself)
    credential_hash TEXT
);

CREATE TABLE IF NOT EXISTS bw_scrub_queue (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    -- Actual credential value stored plaintext. Root-only DB access (0600).
    -- Accepted risk: root is trusted on this system. (H3)
    credential_value TEXT NOT NULL,
    scrub_at TEXT NOT NULL,
    -- JSON array of file paths (discovered by daemon, not client)
    session_files TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    -- status values: pending, in_progress, completed, failed
    completed_at TEXT,
    retry_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bw_session_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,  -- 'unlock', 'lock', 'auto_lock', 'get_item'
    timestamp TEXT DEFAULT (datetime('now')),
    details TEXT
);
```

**Note (H3):** Credential values in `bw_scrub_queue` are stored as plaintext. The SQLite database file is at `/var/lib/aisudo/aisudo.db` with permissions `0600 root:root`. No encryption layer is needed because root is the trust boundary on this system.

### 6.2 Session File Discovery (G5)

The daemon discovers which session files to scrub based on the configured `session_log_dir`, ignoring any paths the client might try to provide:

```rust
/// Discover all .jsonl session files modified after the given timestamp.
fn discover_session_files(session_log_dir: &Path, after: DateTime<Utc>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(session_log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "jsonl") {
                if let Ok(meta) = path.metadata() {
                    if let Ok(modified) = meta.modified() {
                        let modified: DateTime<Utc> = modified.into();
                        if modified >= after {
                            files.push(path);
                        }
                    }
                }
            }
        }
    }
    files
}
```

---

## 7. aisudo-daemon: Web UI for Password Entry

### 7.1 HTTP Server

Add an embedded HTTP server using `axum` (lightweight, tokio-native):

```toml
# Additional daemon dependencies
axum = "0.7"
```

The server binds to `127.0.0.1:<port>` and is exposed via Tailscale Serve (TLS termination by Tailscale).

### 7.2 Routes

```
GET  /aibw/                              → Dashboard showing all pending requests (RH2)
GET  /aibw/unlock?request=<request-id>  → Render password entry form
POST /aibw/unlock                        → Handle password submission
GET  /aibw/status                        → JSON session status (for health checks)
```

### 7.2.1 Dashboard Page (RH2)

**Security decision:** Telegram messages do NOT include clickable unlock URLs. Instead, the human bookmarks the dashboard URL and navigates there directly. This prevents phishing attacks via fake URLs in Telegram.

The dashboard at `GET /aibw/` shows:
- List of all pending BW requests (request ID, item name, user, field, requested at)
- Session status (locked/unlocked, auto-lock countdown if unlocked)
- For each pending request: [Approve] [Deny] buttons (if session unlocked) or [Unlock & Approve] button (if locked)
- Clicking a request opens the unlock/approval flow for that specific request

Minimal HTML (no JS framework, inline CSS). Auto-refreshes every 30 seconds via `<meta http-equiv="refresh" content="30">`.

### 7.3 Unlock Page

Minimal HTML (no JS framework, inline CSS):
- Shows: "Credential requested: {item_name}" and "Requested by: {user}" and "Field: {field}"
- Password input field (`type=password`, `autocomplete=off`)
- Submit button
- On POST:
  1. Validate request ID exists and is pending
  2. Attempt `bw unlock` with provided password (via `--passwordenv`, H2)
  3. On success: unlock vault, approve the pending request (enters Phase 2), return success page
  4. On failure: return error page with retry option

### 7.4 Security

- Bound to `127.0.0.1` only; accessed via Tailscale Serve (TLS termination by Tailscale).
- Request ID is a UUID (unguessable).
- Rate limit password attempts (max 5 per minute per request ID).
- Request IDs expire with the same timeout as sudo requests.
- The HTML form uses `autocomplete="off"` and `<meta http-equiv="Cache-Control" content="no-store">`.

---

## 8. aisudo-daemon: Credential Scrubber

### 8.1 New Module: `scrubber.rs`

```rust
pub struct CredentialScrubber {
    db: Arc<Database>,
    backend: Arc<dyn NotificationBackend>,
    scrub_check_interval: Duration,  // Default: 30 seconds
    session_log_dir: PathBuf,
}
```

### 8.2 Scrub Loop

```rust
async fn run_scrub_loop(&self) {
    loop {
        tokio::time::sleep(self.scrub_check_interval).await;
        let pending = match self.db.get_pending_scrubs() {
            Ok(p) => p,
            Err(e) => { error!("Failed to get pending scrubs: {e}"); continue; }
        };
        for entry in pending {
            if entry.scrub_at > Utc::now() {
                continue;  // Not yet due
            }
            self.db.update_scrub_status(&entry.id, "in_progress").ok();
            let mut all_scrubbed = true;
            for file_path in &entry.session_files {
                let lock_path = format!("{}.lock", file_path);
                if Path::new(&lock_path).exists() {
                    self.db.defer_scrub(&entry.id, Duration::from_secs(30)).ok();
                    info!("Deferred scrub {} — session file locked", entry.id);
                    all_scrubbed = false;
                    break;
                }
                if let Err(e) = self.scrub_file(file_path, &entry.credential_value) {
                    error!("Scrub failed for {}: {e}", file_path);
                    all_scrubbed = false;
                }
            }
            if all_scrubbed {
                self.db.complete_scrub(&entry.id).ok();
                info!("Scrub completed for request {}", entry.request_id);
                // (C3) Notify via Telegram that scrub is done
                self.send_scrub_notification(&entry).await;
            }
        }
    }
}
```

### 8.3 File Scrubbing — Multi-Encoding (L5)

```rust
/// Scrub a credential from a file, handling multiple encoding variants.
fn scrub_file(&self, path: &str, credential: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)?;

    // Build all encoding variants to scrub
    let mut scrubbed = content.clone();
    let redacted = "[REDACTED:aibw]";

    // 1. Raw string match
    scrubbed = scrubbed.replace(credential, redacted);

    // 2. JSON-escaped variant (handles quotes, backslashes, forward slashes)
    let json_escaped = serde_json::to_string(credential)
        .unwrap_or_default();
    // Strip the surrounding quotes from JSON serialization
    if json_escaped.len() >= 2 {
        let inner = &json_escaped[1..json_escaped.len() - 1];
        if inner != credential {
            scrubbed = scrubbed.replace(inner, redacted);
        }
    }

    // 3. URL-encoded variant
    let url_encoded = percent_encode(credential);
    if url_encoded != credential {
        scrubbed = scrubbed.replace(&url_encoded, redacted);
    }

    if scrubbed == content {
        return Ok(());  // Nothing changed
    }

    // Atomic write: write to temp file, then rename
    let tmp_path = format!("{}.aibw-scrub-tmp", path);
    std::fs::write(&tmp_path, &scrubbed)?;
    std::fs::rename(&tmp_path, path)?;
    info!("Scrubbed credential from {path}");
    Ok(())
}
```

### 8.4 Scrub Timer Extension

When the same credential is requested again:
1. Look up existing pending scrub entry by `credential_hash`
2. If found, extend `scrub_at` by the configured delay
3. If not found, create a new entry with session files discovered at that point (G5)

### 8.5 Startup Cleanup (M5)

On daemon startup, before starting the scrub loop:

```rust
/// Clean up orphaned temp files from interrupted scrub operations.
fn cleanup_partial_scrubs(session_log_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(session_log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "aibw-scrub-tmp") {
                warn!("Removing orphaned scrub temp file: {}", path.display());
                std::fs::remove_file(&path).ok();
            }
        }
    }
    // Also reset any in_progress scrubs back to pending
    // (they were interrupted by the previous daemon shutdown)
}
```

### 8.6 Scrub Completion Notification (C3)

After a scrub completes, send a Telegram notification:

```
✅ Credential Scrubbed

Item: `GitHub Token` (sha256:abc123...)
Files scrubbed: 2
Request ID: `req-456`
```

This lets the human know the credential has been cleaned from session logs.

---

## 9. aisudo-daemon: Telegram Notification Extension

### 9.1 New Notification Methods

Add to `NotificationBackend` trait:

```rust
#[async_trait]
pub trait NotificationBackend: Send + Sync {
    // ... existing methods ...

    /// Phase 1: Send a Bitwarden credential request notification and wait for initial approval.
    async fn send_bw_request_and_wait(
        &self,
        record: &BwRequestRecord,
        session_active: bool,
    ) -> Result<Decision>;

    /// Phase 2: Send a confirmation message showing the resolved item name.
    /// If requested_name == resolved_name, auto-confirm (return Approved immediately).
    /// Otherwise, show a confirmation prompt with [Confirm] [Cancel].
    async fn send_bw_confirm_and_wait(
        &self,
        record: &BwRequestRecord,
        resolved_name: &str,
        field: &str,
    ) -> Result<Decision>;

    /// Send a notification that scrubbing completed for a credential.
    async fn send_scrub_complete(&self, item_name: &str, credential_hash: &str, files_count: usize);
}
```

### 9.2 Telegram Message Formats

**Phase 1 — Session active:**
```
🔐 Bitwarden Request

User: `rich`
Item: `GitHub Token`
Field: `password`
Session: ✅ active
Request ID: `abc-123`

[✅ Approve] [❌ Deny]
```

**Phase 1 — Session locked (RH2 — no clickable URL):**
```
🔐 Bitwarden Request

User: `rich`
Item: `GitHub Token`
Field: `password`
Session: 🔒 locked

Unlock via dashboard to approve.
```

*Note: No clickable URL in Telegram (RH2 security decision). Human navigates to bookmarked dashboard at `https://nuc.brown-ordinal.ts.net/aibw/` instead.*

**Phase 2 — Confirm resolved item (only shown if names differ):**
```
🔐 Confirm Credential

Requested: `GitHub Token`
Resolved to: `GitHub Personal Access Token`
Field: `password`
Request ID: `abc-123`

[✅ Confirm] [❌ Cancel]
```

**Scrub complete (C3):**
```
✅ Credential Scrubbed

Item: `GitHub Token`
Hash: `sha256:abc1...`
Files: 2 scrubbed
```

### 9.3 Callback Handling

Add new callback data patterns:
- `approve_bw:<request-id>` → Phase 1: initial approve (session active)
- `deny_bw:<request-id>` → Phase 1: deny
- `confirm_bw:<request-id>` → Phase 2: confirm resolved item
- `cancel_bw:<request-id>` → Phase 2: cancel (name mismatch rejection)

In `handle_callback`, add:
```rust
"approve_bw" => (format!("bw:{request_id}"), Decision::Approved),
"deny_bw" => (format!("bw:{request_id}"), Decision::Denied),
"confirm_bw" => (format!("bw_confirm:{request_id}"), Decision::Approved),
"cancel_bw" => (format!("bw_confirm:{request_id}"), Decision::Denied),
```

---

## 10. Configuration

### 10.1 New Config Section

```toml
[bitwarden]
# Enable Bitwarden integration
enabled = true

# Path to the bw CLI binary
bw_binary = "/usr/bin/bw"

# Auto-lock timeout (seconds of idle before session is locked)
auto_lock_timeout = 3600  # 1 hour

# Scrub delay (seconds after retrieval before scrubbing from logs)
scrub_delay = 600  # 10 minutes

# Scrub check interval (how often the scrubber checks for pending scrubs)
scrub_interval = 30

# Session log directory to monitor for scrubbing (G5: daemon-controlled)
session_log_dir = "/home/rich/git/openclaw/config/agents/main/sessions"

# Web UI port (bound to localhost, exposed via Tailscale Serve)
web_ui_port = 8377

# Rate limit: max BW requests per minute per user
max_requests_per_minute = 10

# Max password entry attempts per request
max_password_attempts = 5
```

### 10.2 Config Struct

```rust
#[derive(Debug, Deserialize)]
pub struct BitwardenConfig {
    #[serde(default = "default_bw_enabled")]
    pub enabled: bool,
    #[serde(default = "default_bw_binary")]
    pub bw_binary: PathBuf,
    #[serde(default = "default_auto_lock_timeout")]
    pub auto_lock_timeout: u32,
    #[serde(default = "default_scrub_delay")]
    pub scrub_delay: u32,
    #[serde(default = "default_scrub_interval")]
    pub scrub_interval: u32,
    pub session_log_dir: PathBuf,
    #[serde(default = "default_web_ui_port")]
    pub web_ui_port: u16,
    #[serde(default = "default_bw_max_rpm")]
    pub max_requests_per_minute: u32,
    #[serde(default = "default_max_password_attempts")]
    pub max_password_attempts: u32,
}
```

---

## 11. Implementation Order

### Phase 1: Foundation
1. Add new types to `aisudo-common` (BwGetRequest/Response, BwLockRequest/Response, BwStatusRequest/Response, SocketMessage variants)
2. Add `BitwardenConfig` to daemon config with defaults
3. Add `bw_session.rs` module — session manager with `BW_SESSION` env var (C1), `--passwordenv` (H2), item name validation (H1), field extraction (M4)
4. Add new DB tables (`bw_requests`, `bw_scrub_queue`, `bw_session_events`) and methods

### Phase 2: Core Flow
5. Add `aibw-cli` crate with `get` (two-phase protocol), `lock`, `status` commands
6. Wire up socket handler in daemon for BW message types
7. Implement `handle_bw_get` two-phase flow (H4): rate limit → DB record → initial approval → resolve item → confirm → extract field → deliver → schedule scrub
8. Extend Telegram backend with BW-specific notifications and phase 2 confirmation callbacks

### Phase 3: Web UI
9. Add `axum` web server to daemon
10. Implement `/aibw/` dashboard showing pending requests (RH2)
11. Implement `/aibw/unlock` GET (password form) and POST (submit) routes
12. Wire web UI approval into the pending-request oneshot channel
13. Configure Tailscale Serve to route `https://nuc.brown-ordinal.ts.net/aibw/*`

### Phase 4: Scrubber
14. Add `scrubber.rs` module with multi-encoding scrub (L5)
15. Implement session file discovery (G5: daemon-controlled, not client-controlled)
16. Implement scrub loop with lock-file awareness
17. Add startup cleanup for orphaned temp files (M5)
18. Add scrub completion Telegram notification (C3)
19. Spawn scrub loop in daemon startup

### Phase 5: Testing & Hardening
20. Unit tests for BW session manager (mock `bw` binary)
20. Unit tests for item name validation, field extraction
21. Integration tests for two-phase socket flow (mock backend)
22. Tests for scrubber (temp files, lock file behavior, multi-encoding, startup cleanup)
23. Tests for web UI routes
24. Security hardening pass: zeroize all credential strings, audit log completeness, error sanitization

---

## 12. New Dependencies

```toml
# aisudo-daemon additions
axum = "0.7"
zeroize = "1"            # Zero sensitive data in memory (session key, passwords, credentials)
sha2 = "0.10"            # Hash credentials for audit/scrub correlation
percent-encoding = "2"   # URL-encode credentials for multi-encoding scrub (L5)
```

Note: `aes-gcm` and `rand` are NOT needed — scrub queue stores plaintext (H3 accepted).

---

## 13. Systemd Service Changes

The existing `aisudo-daemon.service` needs no changes beyond ensuring the `bw` binary is accessible. The web UI port should be documented:

```ini
# /etc/systemd/system/aisudo-daemon.service
# No changes needed — daemon already runs as root
# Web UI binds to 127.0.0.1:8377 (exposed via Tailscale Serve)
```

Tailscale Serve configuration:
```bash
tailscale serve --bg --https=443 --set-path=/aibw localhost:8377
```

---

## 14. Error Handling Strategy

- **bw CLI not found**: Log error at startup, disable BW feature, respond to BW requests with "Bitwarden integration not available".
- **bw CLI errors**: Map exit codes to user-friendly messages. Never expose raw stderr to client.
- **Invalid item name (H1)**: Return "invalid item name" — reject control characters, null bytes, names > 256 chars.
- **Item not found**: Return "item not found" (don't distinguish from "access denied" to prevent enumeration).
- **Web UI password wrong (H2)**: Return generic "unlock failed" with retry. Rate limit attempts.
- **Scrub failures**: Log and retry with exponential backoff (max 5 retries). Notify via Telegram if all retries exhausted (C3).
- **Orphaned temp files (M5)**: Cleaned up automatically on daemon startup.

---

## 15. Audit Trail

All BW operations are logged to the `audit_log` table:

| Event | Details |
|---|---|
| `bw_request_created` | user, item_name, field |
| `bw_request_approved` | by whom (telegram/web_ui) — Phase 1 |
| `bw_request_confirmed` | by whom — Phase 2 (or auto if names match) |
| `bw_request_cancelled` | name mismatch rejected by human — Phase 2 |
| `bw_request_denied` | by whom — Phase 1 |
| `bw_request_timeout` | auto-expired |
| `bw_item_retrieved` | item_name, resolved_name, credential_hash (NOT the value) |
| `bw_session_unlock` | via web_ui |
| `bw_session_lock` | manual or auto_lock |
| `bw_scrub_scheduled` | credential_hash, scrub_at, file count |
| `bw_scrub_completed` | files scrubbed, credential_hash |
| `bw_scrub_failed` | error details, retry count |
| `bw_scrub_deferred` | locked file, retry count |
| `bw_scrub_notified` | Telegram notification sent (C3) |
