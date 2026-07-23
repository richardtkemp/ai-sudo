//! Placeholder backend for when no approval mechanism is configured.
//!
//! Installed by `main.rs` in place of a bail when none of `[askgw]`,
//! `[askgw_http]`, `[telegram]` is set, so the daemon starts and stays useful
//! for its allowlist (allowlisted commands are auto-approved by `socket.rs`
//! *before* any backend is consulted — see `handle_sudo_request`). Anything
//! that actually needs a human is denied.
//!
//! `socket.rs` is expected to check [`super::NotificationBackend::is_configured`]
//! and deny with a caller-visible reason *before* ever calling one of the
//! `send_*_and_wait` methods here, so an operator sees exactly why a request
//! was denied rather than a generic "notification error". The methods below
//! are a second, defense-in-depth layer: if some future code path forgets
//! that check and calls through anyway, they still fail closed (deny/no-op)
//! rather than approving anything — a misconfigured daemon must never be
//! *more* permissive than a configured one.

use super::{
    BwConfirmRecord, BwRequestRecord, CompletionInfo, NotificationBackend, TempRuleRecord,
};
use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::Result;
use tracing::error;

pub struct NoBackend;

#[async_trait::async_trait]
impl NotificationBackend for NoBackend {
    async fn send_and_wait(&self, _record: &SudoRequestRecord) -> Result<Decision> {
        error!(
            "BUG: NoBackend::send_and_wait was called directly — the is_configured() guard in \
             socket.rs should have denied this before reaching the backend. Denying anyway."
        );
        Ok(Decision::Denied)
    }

    async fn send_temp_rule_and_wait(&self, _record: &TempRuleRecord) -> Result<Decision> {
        error!(
            "BUG: NoBackend::send_temp_rule_and_wait was called directly — the is_configured() \
             guard in socket.rs should have denied this before reaching the backend. Denying anyway."
        );
        Ok(Decision::Denied)
    }

    async fn send_bw_request_and_wait(&self, _record: &BwRequestRecord) -> Result<Decision> {
        error!(
            "BUG: NoBackend::send_bw_request_and_wait was called directly — the is_configured() \
             guard in socket.rs should have denied this before reaching the backend. Denying anyway."
        );
        Ok(Decision::Denied)
    }

    async fn send_bw_confirm_and_wait(&self, _record: &BwConfirmRecord) -> Result<Decision> {
        error!(
            "BUG: NoBackend::send_bw_confirm_and_wait was called directly — the is_configured() \
             guard in socket.rs should have denied this before reaching the backend. Denying anyway."
        );
        Ok(Decision::Denied)
    }

    /// Fire-and-forget notifications don't gate any decision, so there's
    /// nothing unsafe about a silent no-op here (unlike the *_and_wait
    /// methods above, which must fail closed).
    async fn send_bw_locked_notification(&self, _record: &BwRequestRecord) -> Result<()> {
        Ok(())
    }

    async fn send_access_link(&self, _url: &str) -> Result<()> {
        Ok(())
    }

    async fn send_scrub_complete(&self, _request_id: &str, _item_name: &str) -> Result<()> {
        Ok(())
    }

    async fn update_completion_status(&self, _info: &CompletionInfo) {}

    fn name(&self) -> &'static str {
        "none"
    }

    fn is_configured(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisudo_common::{RequestMode, SudoRequest};

    fn sudo_record() -> SudoRequestRecord {
        SudoRequestRecord::new(
            SudoRequest {
                user: "testuser".to_string(),
                command: "rm -rf /".to_string(),
                cwd: "/tmp".to_string(),
                pid: 1,
                mode: RequestMode::Pam,
                reason: None,
                stdin: None,
                skip_nopasswd: false,
                timeout_seconds: None,
                dry_run: false,
            },
            60,
        )
    }

    #[test]
    fn is_not_configured() {
        // This is the property socket.rs's is_configured() checks rely on to
        // deny before ever calling through. If this ever flips to true, every
        // request-needing-approval would silently be routed to the methods
        // below (which themselves still fail closed, but the caller-visible
        // "no approval mechanism configured" message would be lost).
        assert!(!NoBackend.is_configured());
    }

    #[test]
    fn name_is_none() {
        assert_eq!(NoBackend.name(), "none");
    }

    #[tokio::test]
    async fn send_and_wait_fails_closed_even_if_called_directly() {
        // Defense in depth: even bypassing the is_configured() guard, this
        // must never approve.
        let decision = NoBackend.send_and_wait(&sudo_record()).await.unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn send_temp_rule_and_wait_fails_closed() {
        let record = TempRuleRecord {
            id: "id".to_string(),
            user: "testuser".to_string(),
            patterns: vec!["apt install".to_string()],
            duration_seconds: 3600,
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            nonce: "nonce".to_string(),
            reason: None,
        };
        let decision = NoBackend.send_temp_rule_and_wait(&record).await.unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn send_bw_request_and_wait_fails_closed() {
        let record = BwRequestRecord {
            id: "id".to_string(),
            user: "testuser".to_string(),
            item_name: "item".to_string(),
            field: "password".to_string(),
            session_active: true,
            unlock_url: None,
        };
        let decision = NoBackend.send_bw_request_and_wait(&record).await.unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn send_bw_confirm_and_wait_fails_closed() {
        let record = BwConfirmRecord {
            id: "id".to_string(),
            user: "testuser".to_string(),
            requested_item_name: "item".to_string(),
            resolved_item_name: "resolved-item".to_string(),
            field: "password".to_string(),
        };
        let decision = NoBackend.send_bw_confirm_and_wait(&record).await.unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn fire_and_forget_methods_are_harmless_no_ops() {
        let record = BwRequestRecord {
            id: "id".to_string(),
            user: "testuser".to_string(),
            item_name: "item".to_string(),
            field: "password".to_string(),
            session_active: false,
            unlock_url: None,
        };
        assert!(NoBackend.send_bw_locked_notification(&record).await.is_ok());
        assert!(NoBackend
            .send_access_link("https://example.com")
            .await
            .is_ok());
        assert!(NoBackend.send_scrub_complete("id", "item").await.is_ok());
        NoBackend
            .update_completion_status(&CompletionInfo {
                request_id: "id".to_string(),
                exit_code: 0,
                last_lines: None,
            })
            .await;
    }
}
