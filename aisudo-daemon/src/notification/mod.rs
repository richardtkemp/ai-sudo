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

