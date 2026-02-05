use super::NotificationBackend;
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

const STDIN_PREVIEW_BYTES: usize = 2048;

pub struct TelegramBackend {
    bot_token: String,
    chat_id: i64,
    client: Client,
    /// Maps request_id -> oneshot sender for delivering callback responses.
    pending: Arc<DashMap<String, oneshot::Sender<Decision>>>,
    /// Offset for Telegram getUpdates long polling.
    update_offset: Arc<Mutex<i64>>,
    /// How long to wait for a response before giving up.
    request_timeout: Duration,
    /// Message ID and original text for the main message with buttons.
    main_message: Arc<Mutex<Option<(i64, String)>>>,
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
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Message {
    message_id: i64,
}

impl TelegramBackend {
    pub fn new(bot_token: String, chat_id: i64, timeout_seconds: u32) -> Self {
        let pending = Arc::new(DashMap::new());
        let backend = Self {
            bot_token,
            chat_id,
            client: Client::new(),
            pending: pending.clone(),
            update_offset: Arc::new(Mutex::new(0)),
            request_timeout: Duration::from_secs(timeout_seconds as u64),
            main_message: Arc::new(Mutex::new(None)),
        };
        backend
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
                let preview = format_stdin_preview(stdin_b64);
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
        self.main_message
            .lock()
            .await
            .replace((main_message_id, text));
        info!(
            "Telegram main message sent: message_id={}, chat_id={}",
            main_message_id, self.chat_id
        );

        Ok(main_message_id)
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
                ("timeout", "30".to_string()),
                ("allowed_updates", "[\"callback_query\"]".to_string()),
            ])
            .timeout(Duration::from_secs(35))
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
        let data = match cb.data {
            Some(d) => d,
            None => return,
        };

        debug!("Received callback: {data}");

        let (action, request_id) = match data.split_once(':') {
            Some(parts) => parts,
            None => return,
        };

        let decision = match action {
            "approve" => Decision::Approved,
            "deny" => Decision::Denied,
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

        // Edit the main message to replace buttons with status
        let time = Local::now().format("%H:%M:%S");
        let status_line = match decision {
            Decision::Approved => format!("✅ Approved at {time}"),
            Decision::Denied => format!("❌ Denied at {time}"),
            _ => format!("{decision:?} at {time}"),
        };
        let main_msg = self.main_message.lock().await.clone();
        if let Some((msg_id, original_text)) = main_msg {
            let _ = self
                .edit_message_status(msg_id, &original_text, &status_line)
                .await;
        }

        // Deliver the decision to the waiting request
        if let Some((_, sender)) = self.pending.remove(request_id) {
            info!("Delivering {decision:?} for request {request_id}");
            let _ = sender.send(decision);
        } else {
            warn!("No pending request for callback: {request_id}");
        }
    }
}

#[async_trait::async_trait]
impl NotificationBackend for TelegramBackend {
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision> {
        // Create a channel for receiving the callback response
        let (tx, rx) = oneshot::channel();
        self.pending.insert(record.id.clone(), tx);

        // Send the Telegram message
        let msg_id = self.send_message(record).await.map_err(|e| {
            self.pending.remove(&record.id);
            e
        })?;
        info!(
            "Sent Telegram notification for request {} (message_id: {})",
            record.id, msg_id
        );

        // Wait for callback response via Telegram inline keyboard
        info!("Waiting for Telegram callback for request {} (timeout: {}s)", record.id, self.request_timeout.as_secs());
        let timeout = self.request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                info!("Received decision {decision:?} for request {}", record.id);
                Ok(decision)
            }
            Ok(Err(_)) => {
                // Channel dropped without sending
                self.pending.remove(&record.id);
                Err(anyhow!("Response channel dropped"))
            }
            Err(_) => {
                // Timeout - edit messages to show timeout status
                self.pending.remove(&record.id);
                info!("Request {} timed out", record.id);

                let time = Local::now().format("%H:%M:%S");
                let status_line = format!("⏱️ Timed out at {time}");
                let main_msg = self.main_message.lock().await.clone();
                if let Some((msg_id, original_text)) = main_msg {
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
fn format_stdin_preview(stdin_b64: &str) -> String {
    let decoded = match base64::engine::general_purpose::STANDARD.decode(stdin_b64) {
        Ok(bytes) => bytes,
        Err(_) => return "[invalid base64]".to_string(),
    };

    if is_likely_binary(&decoded) {
        return format!("[binary data, {} bytes]", decoded.len());
    }

    let text = String::from_utf8_lossy(&decoded);
    if text.len() <= STDIN_PREVIEW_BYTES {
        text.to_string()
    } else {
        format!(
            "{}... ({} bytes total, truncated)",
            &text[..STDIN_PREVIEW_BYTES],
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
        let preview = format_stdin_preview(&b64);
        assert_eq!(preview, "hello world\nline two\n");
    }

    #[test]
    fn test_format_stdin_preview_large() {
        let data = "x".repeat(5000);
        let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
        let preview = format_stdin_preview(&b64);
        assert!(preview.contains("truncated"));
        assert!(preview.contains("5000 bytes total"));
    }

    #[test]
    fn test_format_stdin_preview_binary() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        let preview = format_stdin_preview(&b64);
        assert_eq!(preview, "[binary data, 256 bytes]");
    }

    #[test]
    fn test_format_stdin_preview_invalid_base64() {
        let preview = format_stdin_preview("not-valid-base64!!!");
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
}
