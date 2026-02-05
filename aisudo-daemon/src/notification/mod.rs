pub mod telegram;

use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::Result;

/// Daemon-internal record for a pending temp rule request.
pub struct TempRuleRecord {
    pub id: String,
    pub user: String,
    pub patterns: Vec<String>,
    pub duration_seconds: u32,
    pub expires_at: String,
    #[allow(dead_code)] // used by HTTP API path, carried for backend implementations
    pub nonce: String,
    pub reason: Option<String>,
}

/// Pluggable notification backend trait.
///
/// Renamed from E2ENotificationBackend — Telegram uses HTTPS transport
/// security rather than E2E encryption, which is acceptable for our
/// personal-server threat model.
#[async_trait::async_trait]
pub trait NotificationBackend: Send + Sync {
    /// Send a sudo approval request notification and wait for a response.
    /// Returns the decision (Approved/Denied) or errors on timeout/failure.
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision>;

    /// Send a temp rule approval notification and wait for a response.
    async fn send_temp_rule_and_wait(&self, record: &TempRuleRecord) -> Result<Decision>;

    /// Backend name for logging/audit.
    fn name(&self) -> &'static str;
}

/// Backend used when no notification service is configured.
/// Waits for approval via the HTTP API only (approve/deny endpoints).
pub struct HttpOnlyBackend {
    timeout: std::time::Duration,
    db: std::sync::Arc<crate::db::Database>,
}

impl HttpOnlyBackend {
    pub fn new(timeout_seconds: u32, db: std::sync::Arc<crate::db::Database>) -> Self {
        Self {
            timeout: std::time::Duration::from_secs(timeout_seconds as u64),
            db,
        }
    }
}

#[async_trait::async_trait]
impl NotificationBackend for HttpOnlyBackend {
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision> {
        tracing::info!(
            "No notification backend configured. Waiting for HTTP API approval for request {}",
            record.id
        );

        let start = std::time::Instant::now();
        loop {
            if start.elapsed() >= self.timeout {
                return Ok(Decision::Timeout);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if let Ok(Some(req)) = self.db.get_request(&record.id) {
                if req.status != Decision::Pending {
                    return Ok(req.status);
                }
            }
        }
    }

    async fn send_temp_rule_and_wait(&self, record: &TempRuleRecord) -> Result<Decision> {
        tracing::info!(
            "No notification backend configured. Waiting for HTTP API approval for temp rule {}",
            record.id
        );

        let start = std::time::Instant::now();
        loop {
            if start.elapsed() >= self.timeout {
                return Ok(Decision::Timeout);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if let Ok(Some(rule)) = self.db.get_temp_rule(&record.id) {
                if rule.status != "pending" {
                    return Ok(Decision::from_str(&rule.status).unwrap_or(Decision::Denied));
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "http_api"
    }
}
