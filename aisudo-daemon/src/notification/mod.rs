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

/// Record for a pending BW credential retrieval request.
pub struct BwRequestRecord {
    pub id: String,
    pub user: String,
    pub item_name: String,
    pub field: String,
    pub session_active: bool,
}

/// Record for BW confirmation phase (after item resolution).
pub struct BwConfirmRecord {
    pub id: String,
    pub user: String,
    pub requested_item_name: String,
    pub resolved_item_name: String,
    pub field: String,
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

    /// Send a BW credential retrieval approval notification and wait for response.
    async fn send_bw_request_and_wait(&self, record: &BwRequestRecord) -> Result<Decision>;

    /// Send a BW confirmation notification (resolved item name) and wait for confirm/cancel.
    async fn send_bw_confirm_and_wait(&self, record: &BwConfirmRecord) -> Result<Decision>;

    /// Send a notification that the vault is locked and the user should unlock via dashboard.
    /// Fire-and-forget: does not wait for a callback response.
    async fn send_bw_locked_notification(&self, record: &BwRequestRecord) -> Result<()>;

    /// Send a notification about completed credential scrubbing.
    async fn send_scrub_complete(&self, request_id: &str, item_name: &str) -> Result<()>;

    /// Backend name for logging/audit.
    fn name(&self) -> &'static str;
}

