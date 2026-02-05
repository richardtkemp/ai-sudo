use super::{NotificationBackend, TempRuleRecord};
use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::{anyhow, Result};
use base64::Engine as _;
use dashmap::DashMap;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex};
use chrono::Local;
use tracing::{debug, error, info, warn};

pub struct TelegramBackend {
    bot_token: String,
    chat_id: i64,
    client: Client,
    /// Maps pending key -> oneshot sender for delivering callback responses.
    pending: Arc<DashMap<String, oneshot::Sender<Decision>>>,
    /// Offset for Telegram getUpdates long polling.
    update_offset: Arc<Mutex<i64>>,
    /// How long to wait for a response before giving up.
    request_timeout: Duration,
    /// Maps pending key -> (message_id, original_text) for editing messages after decision.
    message_map: Arc<DashMap<String, (i64, String)>>,
    /// Max bytes of stdin to show in notification preview.
    stdin_preview_bytes: usize,
    /// Timeout in seconds for Telegram long-polling requests.
    poll_timeout_seconds: u32,
}

#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id: i64,
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    from: CallbackUser,
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CallbackUser {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct Message {
    message_id: i64,
}

impl TelegramBackend {
    pub fn new(bot_token: String, chat_id: i64, timeout_seconds: u32, stdin_preview_bytes: usize, poll_timeout_seconds: u32) -> Self {
        Self {
            bot_token,
            chat_id,
            client: Client::new(),
            pending: Arc::new(DashMap::new()),
            update_offset: Arc::new(Mutex::new(0)),
            request_timeout: Duration::from_secs(timeout_seconds as u64),
            message_map: Arc::new(DashMap::new()),
            stdin_preview_bytes,
            poll_timeout_seconds,
        }
    }

    /// Start the background polling loop for Telegram callback queries.
    /// This must be spawned as a tokio task.
    pub fn start_polling(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            info!("Telegram polling loop started");
            loop {
                if let Err(e) = this.poll_updates().await {
                    error!("Telegram poll error (will retry in 5s): {e:#}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });
    }

    /// Test the bot token by calling getMe. Logs success/failure but does not fail.
    pub async fn validate_bot_token(&self) {
        match self.client.get(self.api_url("getMe")).send().await {
            Ok(resp) => {
                let http_status = resp.status();
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        if body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                            let username = body
                                .get("result")
                                .and_then(|r| r.get("username"))
                                .and_then(|u| u.as_str())
                                .unwrap_or("unknown");
                            info!("Telegram bot token valid: @{username}");
                        } else {
                            let desc = body
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("no description");
                            error!("Telegram bot token INVALID (HTTP {http_status}): {desc}");
                        }
                    }
                    Err(e) => {
                        error!("Telegram getMe: failed to parse response (HTTP {http_status}): {e}");
                    }
                }
            }
            Err(e) => {
                error!("Telegram getMe request failed (bot may be unreachable): {e}");
            }
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!(
            "https://api.telegram.org/bot{}/{}",
            self.bot_token, method
        )
    }

    async fn send_message(&self, record: &SudoRequestRecord) -> Result<i64> {
        info!("Attempting to send Telegram message for request {}", record.id);
        let reason_line = match &record.reason {
            Some(r) => format!("\n*Reason:* {}", r),
            None => String::new(),
        };
        let stdin_line = match &record.stdin {
            Some(stdin_b64) => {
                let preview = format_stdin_preview(stdin_b64, self.stdin_preview_bytes);
                format!("\n\n*Stdin:*\n```\n{}\n```", preview)
            }
            None => String::new(),
        };
        let text = format!(
            "🔐 *Sudo Request*\n\n\
             *User:* `{}`\n\
             *Command:* `{}`\n\
             *CWD:* `{}`\n\
             *PID:* `{}`\n\
             *Request ID:* `{}`\n\
             *Timeout:* {}s{}{}",
            record.user, record.command, record.cwd, record.pid, record.id, record.timeout_seconds, reason_line, stdin_line
        );

        let approve_data = format!("approve:{}", record.id);
        let deny_data = format!("deny:{}", record.id);

        // Send main message with inline buttons (for when user opens chat)
        let main_body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Approve", "callback_data": approve_data},
                    {"text": "❌ Deny", "callback_data": deny_data}
                ]]
            }
        });

        let resp = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&main_body)
            .send()
            .await
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {e}"))?;

        let http_status = resp.status();
        let result: TelegramResponse<Message> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {e}", http_status))?;
        if !result.ok {
            let desc = result
                .description
                .unwrap_or_else(|| "no description".to_string());
            error!("Telegram sendMessage API error (HTTP {}): {}", http_status, desc);
            return Err(anyhow!(
                "Telegram sendMessage failed (HTTP {}): {}",
                http_status, desc
            ));
        }

        let main_message_id = result.result.map(|m| m.message_id).unwrap_or(0);
        self.message_map
            .insert(record.id.clone(), (main_message_id, text));
        info!(
            "Telegram main message sent: message_id={}, chat_id={}",
            main_message_id, self.chat_id
        );

        Ok(main_message_id)
    }

    async fn send_temp_rule_message(&self, record: &TempRuleRecord) -> Result<i64> {
        info!("Sending Telegram temp rule message for rule {}", record.id);

        let patterns_list: String = record
            .patterns
            .iter()
            .map(|p| format!("  \u{2022} `{p}`"))
            .collect::<Vec<_>>()
            .join("\n");

        let hours = record.duration_seconds as f64 / 3600.0;
        let reason_line = match &record.reason {
            Some(r) => format!("\n*Reason:* {r}"),
            None => String::new(),
        };

        let text = format!(
            "\u{23f1}\u{fe0f} *Temporary Rule Request*\n\n\
             *User:* `{}`\n\
             *Patterns:*\n{}\n\
             *Duration:* {}s ({:.1} hour{})\n\
             *Expires at:* `{}`\n\
             *Request ID:* `{}`{}",
            record.user,
            patterns_list,
            record.duration_seconds,
            hours,
            if hours == 1.0 { "" } else { "s" },
            record.expires_at,
            record.id,
            reason_line,
        );

        let approve_data = format!("approve_rule:{}", record.id);
        let deny_data = format!("deny_rule:{}", record.id);

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "\u{2705} Approve", "callback_data": approve_data},
                    {"text": "\u{274c} Deny", "callback_data": deny_data}
                ]]
            }
        });

        let resp = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {e}"))?;

        let http_status = resp.status();
        let result: TelegramResponse<Message> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {e}", http_status))?;
        if !result.ok {
            let desc = result
                .description
                .unwrap_or_else(|| "no description".to_string());
            return Err(anyhow!("Telegram sendMessage failed (HTTP {}): {}", http_status, desc));
        }

        let message_id = result.result.map(|m| m.message_id).unwrap_or(0);
        let pending_key = format!("rule:{}", record.id);
        self.message_map.insert(pending_key, (message_id, text));
        info!("Telegram temp rule message sent: message_id={}", message_id);

        Ok(message_id)
    }

    async fn edit_message_status(&self, message_id: i64, original_text: &str, status_line: &str) -> Result<()> {
        info!("Editing Telegram message {} to show: {}", message_id, status_line);

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "text": format!("{}\n\n{}", original_text, status_line),
            "parse_mode": "Markdown"
        });

        let resp = self
            .client
            .post(self.api_url("editMessageText"))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Telegram editMessageText HTTP request failed: {e}"))?;

        let http_status = resp.status();
        let result: TelegramResponse<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| anyhow!("Telegram editMessageText: failed to parse response (HTTP {}): {e}", http_status))?;

        if !result.ok {
            let desc = result
                .description
                .unwrap_or_else(|| "no description".to_string());
            warn!(
                "Telegram editMessageText API error (HTTP {}): {}",
                http_status, desc
            );
        } else {
            info!("✅ Telegram message edited successfully");
        }

        Ok(())
    }

    async fn poll_updates(&self) -> Result<()> {
        let offset = *self.update_offset.lock().await;

        let resp = self
            .client
            .get(self.api_url("getUpdates"))
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", self.poll_timeout_seconds.to_string()),
                ("allowed_updates", "[\"callback_query\"]".to_string()),
            ])
            .timeout(Duration::from_secs(self.poll_timeout_seconds as u64 + 5))
            .send()
            .await
            .map_err(|e| anyhow!("getUpdates HTTP request failed (offset={}): {e}", offset))?;

        let http_status = resp.status();
        let result: TelegramResponse<Vec<Update>> = resp.json().await
            .map_err(|e| anyhow!("getUpdates: failed to parse response (HTTP {}): {e}", http_status))?;
        if !result.ok {
            return Err(anyhow!(
                "getUpdates API error (HTTP {}): {}",
                http_status,
                result.description.unwrap_or_else(|| "no description".to_string())
            ));
        }

        if let Some(updates) = result.result {
            for update in updates {
                // Always advance offset past this update
                let new_offset = update.update_id + 1;
                {
                    let mut off = self.update_offset.lock().await;
                    if new_offset > *off {
                        *off = new_offset;
                    }
                }

                if let Some(cb) = update.callback_query {
                    self.handle_callback(cb).await;
                }
            }
        }

        Ok(())
    }

    async fn handle_callback(&self, cb: CallbackQuery) {
        // Verify the callback comes from the authorized user (matching chat_id).
        // This prevents unauthorized users in group chats from approving/denying.
        if cb.from.id != self.chat_id {
            warn!(
                "Ignoring callback from unauthorized user {} (expected {})",
                cb.from.id, self.chat_id
            );
            return;
        }

        let data = match cb.data {
            Some(d) => d,
            None => return,
        };

        debug!("Received callback: {data}");

        let (action, request_id) = match data.split_once(':') {
            Some(parts) => parts,
            None => return,
        };

        // Determine pending key and decision based on action
        let (pending_key, decision) = match action {
            "approve" => (request_id.to_string(), Decision::Approved),
            "deny" => (request_id.to_string(), Decision::Denied),
            "approve_rule" => (format!("rule:{request_id}"), Decision::Approved),
            "deny_rule" => (format!("rule:{request_id}"), Decision::Denied),
            _ => return,
        };

        // Answer the callback query to dismiss the loading indicator
        let answer_body = serde_json::json!({
            "callback_query_id": cb.id,
            "text": if decision == Decision::Approved { "Approved!" } else { "Denied." }
        });
        let _ = self
            .client
            .post(self.api_url("answerCallbackQuery"))
            .json(&answer_body)
            .send()
            .await;

        // Edit the message to replace buttons with status
        let time = Local::now().format("%H:%M:%S");
        let status_line = match decision {
            Decision::Approved => format!("\u{2705} Approved at {time}"),
            Decision::Denied => format!("\u{274c} Denied at {time}"),
            _ => format!("{decision:?} at {time}"),
        };
        if let Some((_, (msg_id, original_text))) = self.message_map.remove(&pending_key) {
            let _ = self
                .edit_message_status(msg_id, &original_text, &status_line)
                .await;
        }

        // Deliver the decision to the waiting request
        if let Some((_, sender)) = self.pending.remove(&pending_key) {
            info!("Delivering {decision:?} for {pending_key}");
            let _ = sender.send(decision);
        } else {
            warn!("No pending request for callback: {pending_key}");
        }
    }
}

#[async_trait::async_trait]
impl NotificationBackend for TelegramBackend {
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision> {
        let pending_key = record.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(pending_key.clone(), tx);

        let msg_id = self.send_message(record).await.map_err(|e| {
            self.pending.remove(&pending_key);
            e
        })?;
        info!(
            "Sent Telegram notification for request {} (message_id: {})",
            record.id, msg_id
        );

        info!("Waiting for Telegram callback for request {} (timeout: {}s)", record.id, self.request_timeout.as_secs());
        let timeout = self.request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                info!("Received decision {decision:?} for request {}", record.id);
                Ok(decision)
            }
            Ok(Err(_)) => {
                self.pending.remove(&pending_key);
                Err(anyhow!("Response channel dropped"))
            }
            Err(_) => {
                self.pending.remove(&pending_key);
                info!("Request {} timed out", record.id);

                let time = Local::now().format("%H:%M:%S");
                let status_line = format!("\u{23f1}\u{fe0f} Timed out at {time}");
                if let Some((_, (msg_id, original_text))) = self.message_map.remove(&pending_key) {
                    let _ = self
                        .edit_message_status(msg_id, &original_text, &status_line)
                        .await;
                }

                Ok(Decision::Timeout)
            }
        }
    }

    async fn send_temp_rule_and_wait(&self, record: &TempRuleRecord) -> Result<Decision> {
        let pending_key = format!("rule:{}", record.id);
        let (tx, rx) = oneshot::channel();
        self.pending.insert(pending_key.clone(), tx);

        let msg_id = self.send_temp_rule_message(record).await.map_err(|e| {
            self.pending.remove(&pending_key);
            e
        })?;
        info!(
            "Sent Telegram temp rule notification for {} (message_id: {})",
            record.id, msg_id
        );

        let timeout = self.request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                info!("Received decision {decision:?} for temp rule {}", record.id);
                Ok(decision)
            }
            Ok(Err(_)) => {
                self.pending.remove(&pending_key);
                Err(anyhow!("Response channel dropped"))
            }
            Err(_) => {
                self.pending.remove(&pending_key);
                info!("Temp rule {} timed out", record.id);

                let time = Local::now().format("%H:%M:%S");
                let status_line = format!("\u{23f1}\u{fe0f} Timed out at {time}");
                if let Some((_, (msg_id, original_text))) = self.message_map.remove(&pending_key) {
                    let _ = self
                        .edit_message_status(msg_id, &original_text, &status_line)
                        .await;
                }

                Ok(Decision::Timeout)
            }
        }
    }

    fn name(&self) -> &'static str {
        "telegram"
    }
}

/// Format a base64-encoded stdin payload for display in a Telegram message.
fn format_stdin_preview(stdin_b64: &str, max_preview_bytes: usize) -> String {
    let decoded = match base64::engine::general_purpose::STANDARD.decode(stdin_b64) {
        Ok(bytes) => bytes,
        Err(_) => return "[invalid base64]".to_string(),
    };

    if is_likely_binary(&decoded) {
        return format!("[binary data, {} bytes]", decoded.len());
    }

    let text = String::from_utf8_lossy(&decoded);
    if text.len() <= max_preview_bytes {
        text.to_string()
    } else {
        format!(
            "{}... ({} bytes total, truncated)",
            &text[..max_preview_bytes],
            decoded.len()
        )
    }
}

/// Heuristic: if >5% of the first 512 bytes are non-printable control chars, treat as binary.
fn is_likely_binary(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample_size = data.len().min(512);
    let sample = &data[..sample_size];
    let non_printable = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    (non_printable as f64 / sample_size as f64) > 0.05
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_stdin_preview_text() {
        let data = b"hello world\nline two\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let preview = format_stdin_preview(&b64, 2048);
        assert_eq!(preview, "hello world\nline two\n");
    }

    #[test]
    fn test_format_stdin_preview_large() {
        let data = "x".repeat(5000);
        let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
        let preview = format_stdin_preview(&b64, 2048);
        assert!(preview.contains("truncated"));
        assert!(preview.contains("5000 bytes total"));
    }

    #[test]
    fn test_format_stdin_preview_binary() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        let preview = format_stdin_preview(&b64, 2048);
        assert_eq!(preview, "[binary data, 256 bytes]");
    }

    #[test]
    fn test_format_stdin_preview_invalid_base64() {
        let preview = format_stdin_preview("not-valid-base64!!!", 2048);
        assert_eq!(preview, "[invalid base64]");
    }

    #[test]
    fn test_is_likely_binary_text() {
        assert!(!is_likely_binary(b"hello world\n"));
    }

    #[test]
    fn test_is_likely_binary_with_nulls() {
        let mut data = vec![0u8; 100];
        data[0] = b'h';
        assert!(is_likely_binary(&data));
    }

    #[test]
    fn test_is_likely_binary_empty() {
        assert!(!is_likely_binary(b""));
    }

    #[test]
    fn test_api_url() {
        let backend = TelegramBackend::new("TOKEN123".to_string(), 42, 60, 2048, 30);
        assert_eq!(
            backend.api_url("getMe"),
            "https://api.telegram.org/botTOKEN123/getMe"
        );
        assert_eq!(
            backend.api_url("sendMessage"),
            "https://api.telegram.org/botTOKEN123/sendMessage"
        );
    }

    #[test]
    fn test_backend_creation() {
        let backend = TelegramBackend::new("TOK".to_string(), 99, 120, 4096, 45);
        assert_eq!(backend.request_timeout, Duration::from_secs(120));
        assert_eq!(backend.stdin_preview_bytes, 4096);
        assert_eq!(backend.poll_timeout_seconds, 45);
        assert_eq!(backend.chat_id, 99);
    }

    #[test]
    fn test_telegram_name() {
        let backend = TelegramBackend::new("TOK".to_string(), 1, 60, 2048, 30);
        assert_eq!(<TelegramBackend as super::NotificationBackend>::name(&backend), "telegram");
    }

    #[test]
    fn test_format_stdin_preview_exactly_at_limit() {
        let data = "x".repeat(2048);
        let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
        let preview = format_stdin_preview(&b64, 2048);
        // Exactly at the limit — should NOT be truncated
        assert!(!preview.contains("truncated"));
        assert_eq!(preview.len(), 2048);
    }

    #[test]
    fn test_format_stdin_preview_one_over_limit() {
        let data = "x".repeat(2049);
        let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
        let preview = format_stdin_preview(&b64, 2048);
        assert!(preview.contains("truncated"));
    }

    #[test]
    fn test_is_likely_binary_newlines_and_tabs_are_not_binary() {
        let data = b"line1\nline2\ttab\rcarriage";
        assert!(!is_likely_binary(data));
    }
}
