use super::{BwConfirmRecord, BwRequestRecord, CompletionInfo, NotificationBackend, TempRuleRecord};
use crate::config::ConfigHolder;
use crate::db::Database;
use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::{anyhow, Result};
use base64::Engine as _;
use dashmap::DashMap;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};
use chrono::Local;
use tracing::{debug, error, info, warn};

/// Default message template matching the original hardcoded format (HTML).
const DEFAULT_TEMPLATE: &str = "\u{1f510} <b>Sudo Request</b>\n\n\
    <b>User:</b> <code>{{user}}</code>\n\
    <b>Command:</b> <code>{{command}}</code>\n\
    <b>CWD:</b> <code>{{directory}}</code>\n\
    <b>PID:</b> <code>{{pid}}</code>\n\
    <b>Request ID:</b> <code>{{request_id}}</code>\n\
    <b>Timeout:</b> {{timeout}}s{{reason}}{{stdin}}";

pub struct TelegramBackend {
    bot_token: String,
    chat_id: i64,
    client: Client,
    pending: Arc<DashMap<String, oneshot::Sender<Decision>>>,
    update_offset: Arc<Mutex<i64>>,
    request_timeout: Duration,
    /// request_id -> (telegram message id, original text, inserted-at). The
    /// Instant lets a periodic sweep drop entries whose request never produced a
    /// callback/completion (L9 leak).
    message_map: Arc<DashMap<String, (i64, String, Instant)>>,
    completion_map: Arc<DashMap<String, (i64, String, String, Instant)>>,
    stdin_preview_bytes: usize,
    poll_timeout_seconds: u32,
    config_holder: Arc<ConfigHolder>,
    db: Option<Arc<Database>>,
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
    message: Option<TelegramMessage>,
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
struct TelegramMessage {
    message_id: i64,
    from: Option<CallbackUser>,
    text: Option<String>,
    chat: Option<ChatInfo>,
}

#[derive(Debug, Deserialize)]
struct ChatInfo {
    id: i64,
}

impl TelegramBackend {
    pub fn new(
        bot_token: String,
        chat_id: i64,
        timeout_seconds: u32,
        stdin_preview_bytes: usize,
        poll_timeout_seconds: u32,
        config_holder: Arc<ConfigHolder>,
    ) -> Self {
        Self {
            bot_token,
            chat_id,
            client: Client::new(),
            pending: Arc::new(DashMap::new()),
            update_offset: Arc::new(Mutex::new(0)),
            request_timeout: Duration::from_secs(timeout_seconds as u64),
            message_map: Arc::new(DashMap::new()),
            completion_map: Arc::new(DashMap::new()),
            stdin_preview_bytes,
            poll_timeout_seconds,
            config_holder,
            db: None,
        }
    }

    /// Set the database reference for stats queries.
    pub fn set_db(&mut self, db: Arc<Database>) {
        self.db = Some(db);
    }

    /// Start the background polling loop for Telegram callback queries.
    /// This must be spawned as a tokio task.
    pub fn start_polling(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            // Resume from the persisted update offset so a restart doesn't replay
            // ~24h of buffered Telegram updates (L9).
            if let Some(db) = &this.db {
                if let Ok(Some(v)) = db.get_daemon_state("telegram_update_offset") {
                    if let Ok(off) = v.parse::<i64>() {
                        *this.update_offset.lock().await = off;
                        info!("Resumed Telegram update offset at {off}");
                    }
                }
            }
            info!("Telegram polling loop started");
            loop {
                if let Err(e) = this.poll_updates().await {
                    error!("Telegram poll error (will retry in 5s): {}", this.redact(format!("{e:#}")));
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
                        error!("Telegram getMe: failed to parse response (HTTP {http_status}): {}", self.redact(e));
                    }
                }
            }
            Err(e) => {
                error!("Telegram getMe request failed (bot may be unreachable): {}", self.redact(e));
            }
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!(
            "https://api.telegram.org/bot{}/{}",
            self.bot_token, method
        )
    }

    /// Redact the bot token from a string before it is logged or carried in an
    /// error. The token is embedded in every API URL, and reqwest/anyhow `Display`
    /// includes the request URL on transport errors — so without this, a single
    /// network error would write the token to the logs.
    fn redact(&self, s: impl std::fmt::Display) -> String {
        s.to_string().replace(&self.bot_token, "<redacted>")
    }

    async fn send_message(&self, record: &SudoRequestRecord) -> Result<i64> {
        info!("Attempting to send Telegram message for request {}", record.id);
        let config = self.config_holder.config();
        let custom_template = config.telegram.as_ref().and_then(|tg| tg.message_template.as_deref());
        let template = match custom_template {
            Some(tmpl) if tmpl.contains("{{user}}") && tmpl.contains("{{command}}") => tmpl,
            Some(_) => {
                warn!(
                    "message_template missing required {{{{user}}}} or {{{{command}}}}; using default"
                );
                DEFAULT_TEMPLATE
            }
            None => DEFAULT_TEMPLATE,
        };
        let text = render_template(template, record, self.stdin_preview_bytes);

        let approve_data = format!("approve:{}", record.id);
        let deny_data = format!("deny:{}", record.id);

        // Send main message with inline buttons (for when user opens chat)
        let main_body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
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
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {}", self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<TelegramMessage> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;
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
            .insert(record.id.clone(), (main_message_id, text, Instant::now()));
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
            .map(|p| format!("  \u{2022} <code>{}</code>", escape_html(p)))
            .collect::<Vec<_>>()
            .join("\n");

        let hours = record.duration_seconds as f64 / 3600.0;
        let reason_line = match &record.reason {
            Some(r) => format!("\n<b>Reason:</b> {}", escape_html(r)),
            None => String::new(),
        };

        let text = format!(
            "\u{23f1}\u{fe0f} <b>Temporary Rule Request</b>\n\n\
             <b>User:</b> <code>{}</code>\n\
             <b>Patterns:</b>\n{}\n\
             <b>Duration:</b> {}s ({:.1} hour{})\n\
             <b>Expires at:</b> <code>{}</code>\n\
             <b>Request ID:</b> <code>{}</code>{}",
            escape_html(&record.user),
            patterns_list,
            record.duration_seconds,
            hours,
            if hours == 1.0 { "" } else { "s" },
            escape_html(&record.expires_at),
            escape_html(&record.id),
            reason_line,
        );

        let approve_data = format!("approve_rule:{}", record.id);
        let deny_data = format!("deny_rule:{}", record.id);

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
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
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {}", self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<TelegramMessage> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;
        if !result.ok {
            let desc = result
                .description
                .unwrap_or_else(|| "no description".to_string());
            return Err(anyhow!("Telegram sendMessage failed (HTTP {}): {}", http_status, desc));
        }

        let message_id = result.result.map(|m| m.message_id).unwrap_or(0);
        let pending_key = format!("rule:{}", record.id);
        self.message_map.insert(pending_key, (message_id, text, Instant::now()));
        info!("Telegram temp rule message sent: message_id={}", message_id);

        Ok(message_id)
    }

    async fn send_bw_request_message(&self, record: &BwRequestRecord) -> Result<i64> {
        info!("Sending BW request Telegram message for request {}", record.id);

        let session_status = if record.session_active { "unlocked" } else { "locked" };
        let text = format!(
            "\u{1f511} <b>Bitwarden Request</b>\n\n\
             <b>User:</b> <code>{}</code>\n\
             <b>Item:</b> <code>{}</code>\n\
             <b>Field:</b> <code>{}</code>\n\
             <b>Vault:</b> {}\n\
             <b>Request ID:</b> <code>{}</code>",
            escape_html(&record.user), escape_html(&record.item_name),
            escape_html(&record.field), session_status, escape_html(&record.id),
        );

        let approve_data = format!("approve_bw:{}", record.id);
        let deny_data = format!("deny_bw:{}", record.id);

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
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
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {}", self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<TelegramMessage> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;
        if !result.ok {
            let desc = result.description.unwrap_or_else(|| "no description".to_string());
            return Err(anyhow!("Telegram sendMessage failed (HTTP {}): {}", http_status, desc));
        }

        let message_id = result.result.map(|m| m.message_id).unwrap_or(0);
        let pending_key = format!("bw:{}", record.id);
        self.message_map.insert(pending_key, (message_id, text, Instant::now()));
        info!("BW request Telegram message sent: message_id={}", message_id);

        Ok(message_id)
    }

    async fn send_bw_confirm_message(&self, record: &BwConfirmRecord) -> Result<i64> {
        info!("Sending BW confirm Telegram message for request {}", record.id);

        let text = format!(
            "\u{1f50d} <b>Bitwarden Confirmation</b>\n\n\
             <b>User:</b> <code>{}</code>\n\
             <b>Requested:</b> <code>{}</code>\n\
             <b>Resolved to:</b> <code>{}</code>\n\
             <b>Field:</b> <code>{}</code>\n\
             <b>Request ID:</b> <code>{}</code>\n\n\
             \u{26a0}\u{fe0f} Names differ \u{2014} please confirm.",
            escape_html(&record.user), escape_html(&record.requested_item_name),
            escape_html(&record.resolved_item_name),
            escape_html(&record.field), escape_html(&record.id),
        );

        let confirm_data = format!("confirm_bw:{}", record.id);
        let cancel_data = format!("cancel_bw:{}", record.id);

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "\u{2705} Confirm", "callback_data": confirm_data},
                    {"text": "\u{274c} Cancel", "callback_data": cancel_data}
                ]]
            }
        });

        let resp = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {}", self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<TelegramMessage> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;
        if !result.ok {
            let desc = result.description.unwrap_or_else(|| "no description".to_string());
            return Err(anyhow!("Telegram sendMessage failed (HTTP {}): {}", http_status, desc));
        }

        let message_id = result.result.map(|m| m.message_id).unwrap_or(0);
        let pending_key = format!("bw_confirm:{}", record.id);
        self.message_map.insert(pending_key, (message_id, text, Instant::now()));
        info!("BW confirm Telegram message sent: message_id={}", message_id);

        Ok(message_id)
    }

    async fn send_bw_scrub_complete_message(&self, request_id: &str, item_name: &str) -> Result<()> {
        let text = format!(
            "\u{1f9f9} <b>Credential Scrubbed</b>\n\n\
             <b>Item:</b> <code>{}</code>\n\
             <b>Request ID:</b> <code>{}</code>",
            escape_html(item_name), escape_html(request_id),
        );

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML"
        });

        let resp = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Telegram sendMessage HTTP request failed: {}", self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<TelegramMessage> = resp.json().await
            .map_err(|e| anyhow!("Telegram sendMessage: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;
        if !result.ok {
            let desc = result.description.unwrap_or_else(|| "no description".to_string());
            warn!("Telegram scrub notification failed (HTTP {}): {}", http_status, desc);
        }

        Ok(())
    }

    async fn edit_message_status(&self, message_id: i64, original_text: &str, status_line: &str) -> Result<()> {
        info!("Editing Telegram message {} to show: {}", message_id, status_line);

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "text": format!("{}\n\n{}", original_text, status_line),
            "parse_mode": "HTML"
        });

        let resp = self
            .client
            .post(self.api_url("editMessageText"))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Telegram editMessageText HTTP request failed: {}", self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| anyhow!("Telegram editMessageText: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;

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

    /// Drop message/completion map entries older than `ttl` — a backstop for
    /// requests that never produced a callback or completion (L9 leak). The TTL
    /// is the approval timeout plus an execution margin, so a legitimately-slow
    /// approval is never swept early.
    fn sweep_stale_entries(&self, ttl: Duration) {
        let now = Instant::now();
        self.message_map.retain(|_, v| now.duration_since(v.2) <= ttl);
        self.completion_map.retain(|_, v| now.duration_since(v.3) <= ttl);
    }

    async fn poll_updates(&self) -> Result<()> {
        // Bound the bookkeeping maps every poll cycle.
        self.sweep_stale_entries(self.request_timeout + Duration::from_secs(600));

        let offset = *self.update_offset.lock().await;

        let resp = self
            .client
            .get(self.api_url("getUpdates"))
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", self.poll_timeout_seconds.to_string()),
                ("allowed_updates", "[\"callback_query\", \"message\"]".to_string()),
            ])
            .timeout(Duration::from_secs(self.poll_timeout_seconds as u64 + 5))
            .send()
            .await
            .map_err(|e| anyhow!("getUpdates HTTP request failed (offset={}): {}", offset, self.redact(e)))?;

        let http_status = resp.status();
        let result: TelegramResponse<Vec<Update>> = resp.json().await
            .map_err(|e| anyhow!("getUpdates: failed to parse response (HTTP {}): {}", http_status, self.redact(e)))?;
        if !result.ok {
            return Err(anyhow!(
                "getUpdates API error (HTTP {}): {}",
                http_status,
                result.description.unwrap_or_else(|| "no description".to_string())
            ));
        }

        if let Some(updates) = result.result {
            let had_updates = !updates.is_empty();
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

                if let Some(msg) = update.message {
                    self.handle_message(msg).await;
                }
            }

            // Persist the advanced offset so a restart doesn't replay ~24h of
            // buffered updates (L9). One write per non-empty poll batch.
            if had_updates {
                if let Some(db) = &self.db {
                    let off = *self.update_offset.lock().await;
                    if let Err(e) = db.set_daemon_state("telegram_update_offset", &off.to_string()) {
                        warn!("Failed to persist Telegram update offset: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle incoming Telegram messages (e.g., /stats command).
    async fn handle_message(&self, msg: TelegramMessage) {
        // Verify the message comes from the authorized chat
        let chat_id = match &msg.chat {
            Some(chat) => chat.id,
            None => return,
        };
        if chat_id != self.chat_id {
            return;
        }

        let text = match &msg.text {
            Some(t) => t.trim().to_lowercase(),
            None => return,
        };

        // Handle /stats command
        if text == "/stats" || text.starts_with("/stats@") {
            self.send_stats_response(msg.message_id).await;
        }
    }

    /// Send stats response to a /stats command.
    async fn send_stats_response(&self, reply_to: i64) {
        let stats_text = match &self.db {
            Some(db) => {
                let pending = db.get_pending_count().unwrap_or(0);
                let last_hour = db.get_requests_last_hour().unwrap_or(0);
                let approval_rate = db.get_approval_rate_last_hour().unwrap_or(0.0);
                
                format!(
                    "📊 <b>aisudo stats</b>\n\n\
                     <b>Pending:</b> {}\n\
                     <b>Requests (1h):</b> {}\n\
                     <b>Approval rate:</b> {:.1}%",
                    pending, last_hour, approval_rate * 100.0
                )
            }
            None => "Stats unavailable (no database)".to_string(),
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": stats_text,
            "parse_mode": "HTML",
            "reply_to_message_id": reply_to,
        });

        let _ = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await;
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
            "approve_bw" => (format!("bw:{request_id}"), Decision::Approved),
            "deny_bw" => (format!("bw:{request_id}"), Decision::Denied),
            "confirm_bw" => (format!("bw_confirm:{request_id}"), Decision::Approved),
            "cancel_bw" => (format!("bw_confirm:{request_id}"), Decision::Denied),
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
        if let Some((_, (msg_id, original_text, _))) = self.message_map.remove(&pending_key) {
            if decision == Decision::Approved {
                self.completion_map.insert(
                    pending_key.clone(),
                    (msg_id, original_text.clone(), status_line.clone(), Instant::now()),
                );
            }
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
                if let Some((_, (msg_id, original_text, _))) = self.message_map.remove(&pending_key) {
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
                if let Some((_, (msg_id, original_text, _))) = self.message_map.remove(&pending_key) {
                    let _ = self
                        .edit_message_status(msg_id, &original_text, &status_line)
                        .await;
                }

                Ok(Decision::Timeout)
            }
        }
    }

    async fn send_bw_request_and_wait(&self, record: &BwRequestRecord) -> Result<Decision> {
        let pending_key = format!("bw:{}", record.id);
        let (tx, rx) = oneshot::channel();
        self.pending.insert(pending_key.clone(), tx);

        let msg_id = self.send_bw_request_message(record).await.map_err(|e| {
            self.pending.remove(&pending_key);
            e
        })?;
        info!(
            "Sent BW request notification for {} (message_id: {})",
            record.id, msg_id
        );

        let timeout = self.request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                info!("Received decision {decision:?} for BW request {}", record.id);
                Ok(decision)
            }
            Ok(Err(_)) => {
                self.pending.remove(&pending_key);
                Err(anyhow!("Response channel dropped"))
            }
            Err(_) => {
                self.pending.remove(&pending_key);
                info!("BW request {} timed out", record.id);

                let time = Local::now().format("%H:%M:%S");
                let status_line = format!("\u{23f1}\u{fe0f} Timed out at {time}");
                if let Some((_, (msg_id, original_text, _))) = self.message_map.remove(&pending_key) {
                    let _ = self
                        .edit_message_status(msg_id, &original_text, &status_line)
                        .await;
                }

                Ok(Decision::Timeout)
            }
        }
    }

    async fn send_bw_confirm_and_wait(&self, record: &BwConfirmRecord) -> Result<Decision> {
        let pending_key = format!("bw_confirm:{}", record.id);
        let (tx, rx) = oneshot::channel();
        self.pending.insert(pending_key.clone(), tx);

        let msg_id = self.send_bw_confirm_message(record).await.map_err(|e| {
            self.pending.remove(&pending_key);
            e
        })?;
        info!(
            "Sent BW confirm notification for {} (message_id: {})",
            record.id, msg_id
        );

        let timeout = self.request_timeout;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                info!("Received decision {decision:?} for BW confirm {}", record.id);
                Ok(decision)
            }
            Ok(Err(_)) => {
                self.pending.remove(&pending_key);
                Err(anyhow!("Response channel dropped"))
            }
            Err(_) => {
                self.pending.remove(&pending_key);
                info!("BW confirm {} timed out", record.id);

                let time = Local::now().format("%H:%M:%S");
                let status_line = format!("\u{23f1}\u{fe0f} Timed out at {time}");
                if let Some((_, (msg_id, original_text, _))) = self.message_map.remove(&pending_key) {
                    let _ = self
                        .edit_message_status(msg_id, &original_text, &status_line)
                        .await;
                }

                Ok(Decision::Timeout)
            }
        }
    }

    async fn send_bw_locked_notification(&self, record: &BwRequestRecord) -> Result<()> {
        // A tappable single-use unlock link when configured; otherwise point at the
        // dashboard. The link is daemon-generated (not request-controlled), so it is
        // safe to embed without escaping.
        let action = match &record.unlock_url {
            Some(url) => format!("\u{1f513} Unlock &amp; approve: {url}"),
            None => "Unlock via dashboard to approve.".to_string(),
        };
        let text = format!(
            "\u{1f512} <b>Bitwarden Request</b>\n\n\
             <b>User:</b> <code>{}</code>\n\
             <b>Item:</b> <code>{}</code>\n\
             <b>Field:</b> <code>{}</code>\n\
             <b>Vault:</b> \u{1f512} locked\n\
             <b>Request ID:</b> <code>{}</code>\n\n\
             {action}",
            escape_html(&record.user), escape_html(&record.item_name),
            escape_html(&record.field), escape_html(&record.id),
        );

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML"
        });

        // Fire and forget — no buttons, no waiting
        match self.client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
        {
            Ok(_) => info!("BW locked notification sent for request {}", record.id),
            Err(e) => warn!("Failed to send BW locked notification: {}", self.redact(e)),
        }

        Ok(())
    }

    async fn send_access_link(&self, url: &str) -> Result<()> {
        // url is daemon-generated; safe to embed without escaping.
        let text = format!(
            "\u{1f513} <b>aibw web access</b>\n\n\
             Tap to open the vault dashboard (single-use, expires shortly):\n{url}"
        );
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML"
        });
        match self.client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
        {
            Ok(_) => info!("Sent web access link"),
            Err(e) => warn!("Failed to send web access link: {}", self.redact(e)),
        }
        Ok(())
    }

    async fn send_scrub_complete(&self, request_id: &str, item_name: &str) -> Result<()> {
        self.send_bw_scrub_complete_message(request_id, item_name).await
    }

    async fn update_completion_status(&self, info: &CompletionInfo) {
        if let Some((_, (msg_id, original_text, approved_status, _))) = self.completion_map.remove(&info.request_id) {
            let completion_text = if info.exit_code == 0 {
                format!("{} \u{2192} Exit 0", approved_status)
            } else {
                let error_indicator = "\u{274c}";
                let base = format!("{} \u{2192} {} Exit {}", approved_status, error_indicator, info.exit_code);
                if let Some(ref last_lines) = info.last_lines {
                    format!("{}\n<pre>{}</pre>", base, escape_html(last_lines))
                } else {
                    base
                }
            };
            
            let body = serde_json::json!({
                "chat_id": self.chat_id,
                "message_id": msg_id,
                "text": format!("{}\n\n{}", original_text, completion_text),
                "parse_mode": "HTML"
            });

            match self
                .client
                .post(self.api_url("editMessageText"))
                .json(&body)
                .send()
                .await
            {
                Ok(_) => info!("Updated completion status for request {}", info.request_id),
                Err(e) => warn!("Failed to update completion status: {}", self.redact(e)),
            }
        }
    }

    fn name(&self) -> &'static str {
        "telegram"
    }
}

/// Render a message template by replacing {{variable}} placeholders with values from the record.
fn render_template(template: &str, record: &SudoRequestRecord, stdin_preview_bytes: usize) -> String {
    let hostname = gethostname::gethostname()
        .to_string_lossy()
        .to_string();
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let reason_val = match &record.reason {
        Some(r) => format!("\n<b>Reason:</b> {}", escape_html(r)),
        None => String::new(),
    };
    let stdin_val = match &record.stdin {
        Some(stdin_b64) => {
            let preview = format_stdin_preview(stdin_b64, stdin_preview_bytes);
            format!("\n\n<b>Stdin:</b>\n<pre>{}</pre>", escape_html(&preview))
        }
        None => String::new(),
    };

    // Single-pass substitution: each {{key}} is replaced once with its value and
    // substituted values are NEVER re-scanned. This prevents a placeholder
    // embedded in an attacker-controlled value (command/cwd/reason/stdin) from
    // being expanded by a later pass (M5). Unknown keys are left literal.
    let lookup = |key: &str| -> Option<String> {
        Some(match key {
            "user" => escape_html(&record.user),
            "command" => escape_html(&record.command),
            "directory" => escape_html(&record.cwd),
            "hostname" => escape_html(&hostname),
            "timestamp" => escape_html(&timestamp),
            "reason" => reason_val.clone(),
            "pid" => record.pid.to_string(),
            "request_id" => escape_html(&record.id),
            "timeout" => record.timeout_seconds.to_string(),
            "stdin" => stdin_val.clone(),
            _ => return None,
        })
    };

    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        match after.find("}}") {
            Some(j) => {
                let key = &after[..j];
                match lookup(key) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push_str("{{");
                        out.push_str(key);
                        out.push_str("}}");
                    }
                }
                rest = &after[j + 2..];
            }
            None => {
                // No closing braces — emit the remainder verbatim.
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
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
        // Truncate at the largest char boundary <= max_preview_bytes so we never
        // slice through a multibyte character (attacker-controlled stdin could
        // otherwise straddle the boundary and panic).
        let mut end = max_preview_bytes.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        format!(
            "{}... ({} bytes total, truncated)",
            &text[..end],
            decoded.len()
        )
    }
}

/// Escape special characters for Telegram HTML parse mode.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

    /// Create a minimal ConfigHolder for tests.
    fn test_config_holder() -> Arc<ConfigHolder> {
        use tempfile::TempDir;
        use std::fs;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aisudo.toml");
        fs::write(&path, r#"
[telegram]
bot_token = "tok"
chat_id = 1
"#).unwrap();
        // Leak TempDir so it lives long enough for all tests
        let holder = Arc::new(ConfigHolder::new(path.to_str().unwrap()).unwrap());
        std::mem::forget(tmp);
        holder
    }

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
        let backend = TelegramBackend::new("TOKEN123".to_string(), 42, 60, 2048, 30, test_config_holder());
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
    fn test_sweep_stale_entries() {
        let backend = TelegramBackend::new("tok".to_string(), 1, 60, 2048, 30, test_config_holder());

        backend.message_map.insert("a".to_string(), (10, "x".to_string(), Instant::now()));
        backend.completion_map.insert(
            "b".to_string(),
            (11, "x".to_string(), "ok".to_string(), Instant::now()),
        );

        // A zero TTL drops anything inserted before now → both swept.
        backend.sweep_stale_entries(Duration::from_secs(0));
        assert!(backend.message_map.is_empty(), "stale message entry should be swept");
        assert!(backend.completion_map.is_empty(), "stale completion entry should be swept");

        // Fresh entries with a generous TTL are kept.
        backend.message_map.insert("c".to_string(), (12, "y".to_string(), Instant::now()));
        backend.completion_map.insert(
            "d".to_string(),
            (13, "y".to_string(), "ok".to_string(), Instant::now()),
        );
        backend.sweep_stale_entries(Duration::from_secs(3600));
        assert_eq!(backend.message_map.len(), 1, "fresh message entry must be kept");
        assert_eq!(backend.completion_map.len(), 1, "fresh completion entry must be kept");
    }

    #[test]
    fn test_redact_removes_token() {
        let backend = TelegramBackend::new("SECRET-TOKEN".to_string(), 42, 60, 2048, 30, test_config_holder());
        // Simulate a reqwest-style error string that embeds the API URL (with token).
        let err = "error sending request for url (https://api.telegram.org/botSECRET-TOKEN/getUpdates): connection refused";
        let redacted = backend.redact(err);
        assert!(!redacted.contains("SECRET-TOKEN"), "token must not survive redaction: {redacted}");
        assert!(redacted.contains("<redacted>"));
        // A string without the token is unchanged.
        assert_eq!(backend.redact("plain message"), "plain message");
    }

    #[test]
    fn test_backend_creation() {
        let backend = TelegramBackend::new("TOK".to_string(), 99, 120, 4096, 45, test_config_holder());
        assert_eq!(backend.request_timeout, Duration::from_secs(120));
        assert_eq!(backend.stdin_preview_bytes, 4096);
        assert_eq!(backend.poll_timeout_seconds, 45);
        assert_eq!(backend.chat_id, 99);
    }

    #[test]
    fn test_telegram_name() {
        let backend = TelegramBackend::new("TOK".to_string(), 1, 60, 2048, 30, test_config_holder());
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
    fn test_format_stdin_preview_multibyte_boundary_no_panic() {
        // The truncation point falls in the middle of a 2-byte char (é = 0xC3 0xA9).
        // Slicing at a non-char-boundary byte must not panic.
        let data = format!("{}{}", "a".repeat(3), "é"); // 5 bytes; é occupies bytes [3,4]
        let b64 = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
        let preview = format_stdin_preview(&b64, 4); // byte 4 is mid-é
        assert!(preview.contains("truncated"));
        // Truncated to the largest char boundary <= 4, i.e. "aaa".
        assert!(preview.starts_with("aaa"), "unexpected preview: {preview}");
    }

    #[test]
    fn test_is_likely_binary_newlines_and_tabs_are_not_binary() {
        let data = b"line1\nline2\ttab\rcarriage";
        assert!(!is_likely_binary(data));
    }

    fn make_test_record() -> SudoRequestRecord {
        SudoRequestRecord {
            id: "req-123".to_string(),
            user: "alice".to_string(),
            command: "apt install nginx".to_string(),
            cwd: "/home/alice".to_string(),
            pid: 4567,
            timestamp: chrono::Utc::now(),
            status: Decision::Pending,
            timeout_seconds: 60,
            nonce: "nonce".to_string(),
            decided_at: None,
            decided_by: None,
            reason: Some("deploying web server".to_string()),
            stdin: None,
            stdin_bytes: None,
        }
    }

    #[test]
    fn test_render_template_basic_variables() {
        let record = make_test_record();
        let tmpl = "User: {{user}}, Cmd: {{command}}, Dir: {{directory}}";
        let result = render_template(tmpl, &record, 2048);
        assert_eq!(result, "User: alice, Cmd: apt install nginx, Dir: /home/alice");
    }

    #[test]
    fn test_render_template_all_variables() {
        let record = make_test_record();
        let tmpl = "{{user}} {{command}} {{directory}} {{pid}} {{request_id}} {{timeout}} {{hostname}} {{timestamp}} {{reason}}";
        let result = render_template(tmpl, &record, 2048);
        assert!(result.contains("alice"));
        assert!(result.contains("apt install nginx"));
        assert!(result.contains("/home/alice"));
        assert!(result.contains("4567"));
        assert!(result.contains("req-123"));
        assert!(result.contains("60"));
        // hostname and timestamp are dynamic, just check they got replaced
        assert!(!result.contains("{{hostname}}"));
        assert!(!result.contains("{{timestamp}}"));
        assert!(result.contains("deploying web server"));
    }

    #[test]
    fn test_render_template_no_placeholder_injection_via_command() {
        // M5: a placeholder embedded in an attacker-controlled value (here the
        // command) must NOT be expanded by a later substitution pass.
        let mut record = make_test_record();
        record.command = "x {{stdin}}".to_string();
        record.stdin = Some(base64::engine::general_purpose::STANDARD.encode("SECRET"));

        let result = render_template("{{command}}", &record, 2048);

        // The injected {{stdin}} stays literal; no Stdin block is forged.
        assert!(result.contains("{{stdin}}"), "injected placeholder should remain literal: {result}");
        assert!(!result.contains("<b>Stdin:</b>"), "command must not forge a Stdin section: {result}");
        assert!(!result.contains("SECRET"), "attacker stdin must not appear via command injection: {result}");
    }

    #[test]
    fn test_render_template_no_reason_injection_via_command() {
        // Same class via {{reason}}: a command containing {{reason}} must not
        // expand into the trusted "Reason:" block.
        let mut record = make_test_record();
        record.command = "y {{reason}}".to_string();
        record.reason = Some("attacker reason".to_string());

        let result = render_template("{{command}}", &record, 2048);
        assert!(result.contains("{{reason}}"));
        assert!(!result.contains("<b>Reason:</b>"), "command must not forge a Reason section: {result}");
    }

    #[test]
    fn test_render_template_unknown_placeholder_left_literal() {
        let record = make_test_record();
        let result = render_template("a {{nope}} b {{command}}", &record, 2048);
        assert_eq!(result, "a {{nope}} b apt install nginx");
    }

    #[test]
    fn test_render_template_reason_empty_when_none() {
        let mut record = make_test_record();
        record.reason = None;
        let tmpl = "CMD: {{command}}{{reason}}END";
        let result = render_template(tmpl, &record, 2048);
        assert_eq!(result, "CMD: apt install nginxEND");
    }

    #[test]
    fn test_render_template_stdin_empty_when_none() {
        let record = make_test_record();
        let tmpl = "CMD: {{command}}{{stdin}}END";
        let result = render_template(tmpl, &record, 2048);
        assert_eq!(result, "CMD: apt install nginxEND");
    }

    #[test]
    fn test_render_template_stdin_present() {
        let mut record = make_test_record();
        record.stdin = Some(base64::engine::general_purpose::STANDARD.encode(b"hello stdin"));
        let tmpl = "CMD: {{command}}{{stdin}}";
        let result = render_template(tmpl, &record, 2048);
        assert!(result.contains("hello stdin"));
    }

    #[test]
    fn test_render_template_default_matches_format() {
        let record = make_test_record();
        let result = render_template(DEFAULT_TEMPLATE, &record, 2048);
        assert!(result.contains("alice"));
        assert!(result.contains("apt install nginx"));
        assert!(result.contains("/home/alice"));
        assert!(result.contains("4567"));
        assert!(result.contains("req-123"));
        assert!(result.contains("60s"));
        assert!(result.contains("deploying web server"));
    }

    #[test]
    fn test_render_template_multiline() {
        let record = make_test_record();
        let tmpl = "Line1: {{user}}\nLine2: {{command}}\nLine3: {{directory}}";
        let result = render_template(tmpl, &record, 2048);
        assert_eq!(result, "Line1: alice\nLine2: apt install nginx\nLine3: /home/alice");
    }

    #[test]
    fn test_render_template_html_passthrough() {
        let record = make_test_record();
        let tmpl = "<b>Bold</b> <code>{{command}}</code> <i>italic</i> {{user}}";
        let result = render_template(tmpl, &record, 2048);
        assert_eq!(result, "<b>Bold</b> <code>apt install nginx</code> <i>italic</i> alice");
    }


    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("hello"), "hello");
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("foo(bar) + baz"), "foo(bar) + baz");
        assert_eq!(escape_html("a<b>c&d"), "a&lt;b&gt;c&amp;d");
    }

    #[test]
    fn test_render_template_reason_with_special_chars() {
        let mut record = make_test_record();
        record.reason = Some("install nginx (v1.2+3) & reload <config>".to_string());
        let result = render_template(DEFAULT_TEMPLATE, &record, 2048);
        assert!(result.contains("install nginx (v1.2+3) &amp; reload &lt;config&gt;"));
        assert!(!result.contains("<config>"));
    }

    #[test]
    fn test_render_template_command_with_angle_brackets() {
        let mut record = make_test_record();
        record.command = "echo <hello>".to_string();
        let result = render_template(DEFAULT_TEMPLATE, &record, 2048);
        assert!(result.contains("echo &lt;hello&gt;"));
    }

    #[test]
    fn test_config_message_template_deserialization() {
        use crate::config::Config;
        use tempfile::TempDir;
        use std::fs;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aisudo.toml");
        fs::write(&path, r#"
[telegram]
bot_token = "tok"
chat_id = 1
message_template = """
Request: {{user}} {{command}}
"""
"#).unwrap();
        let config = Config::load(path.to_str().unwrap()).unwrap();
        let tg = config.telegram.unwrap();
        assert!(tg.message_template.is_some());
        let tmpl = tg.message_template.unwrap();
        assert!(tmpl.contains("{{user}}"));
        assert!(tmpl.contains("{{command}}"));
    }

    #[test]
    fn test_config_message_template_default_none() {
        use crate::config::Config;
        use tempfile::TempDir;
        use std::fs;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aisudo.toml");
        fs::write(&path, r#"
[telegram]
bot_token = "tok"
chat_id = 1
"#).unwrap();
        let config = Config::load(path.to_str().unwrap()).unwrap();
        let tg = config.telegram.unwrap();
        assert!(tg.message_template.is_none());
    }
}
