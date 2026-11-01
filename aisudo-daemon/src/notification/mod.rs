pub mod askgw;
pub mod askgw_http;
pub mod none;
pub mod telegram;

use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::Result;

/// Information needed to tell the approver what became of an approved command.
pub struct CompletionInfo {
    pub request_id: String,
    pub outcome: RunOutcome,
}

/// What happened to a command after a human approved it (#2741). Before, the approver
/// heard only about a command that ran to an exit; one that never ran said nothing,
/// so an approval lost to a dead requester looked exactly like one that worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// It ran and exited. `last_lines` is set only on a non-zero exit.
    Exited {
        exit_code: i32,
        last_lines: Option<String>,
    },
    /// It never started (e.g. the requester was gone before it could run).
    NotRun { reason: String },
    /// It started but did not finish normally (e.g. killed when the requester left).
    Unfinished { reason: String },
}

impl CompletionInfo {
    #[cfg(test)]
    pub fn exited(request_id: &str, exit_code: i32, last_lines: Option<String>) -> Self {
        Self {
            request_id: request_id.to_string(),
            outcome: RunOutcome::Exited {
                exit_code,
                last_lines,
            },
        }
    }
}

/// (level, text) of the askgw `notify` frame that reports a [`CompletionInfo`]; shared
/// by the socket and HTTP askgw backends.
pub(crate) fn askgw_completion_notice(info: &CompletionInfo) -> (&'static str, String) {
    let id = &info.request_id;
    match &info.outcome {
        RunOutcome::Exited { exit_code: 0, .. } => {
            ("info", format!("Command completed: exit 0 (request {id})"))
        }
        RunOutcome::Exited {
            exit_code,
            last_lines,
        } => {
            let detail = last_lines
                .as_ref()
                .map(|l| format!(": {l}"))
                .unwrap_or_default();
            (
                "info",
                format!("Command failed: exit {exit_code} (request {id}){detail}"),
            )
        }
        RunOutcome::NotRun { reason } => (
            "warning",
            format!("\u{274c} Approved command NOT run: {reason} (request {id})"),
        ),
        RunOutcome::Unfinished { reason } => (
            "warning",
            format!("\u{26a0}\u{fe0f} Approved command did not finish: {reason} (request {id})"),
        ),
    }
}

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
    /// Tappable web unlock link, set only on the locked path when link delivery
    /// is configured. None elsewhere.
    pub unlock_url: Option<String>,
}

/// Record for BW confirmation phase (after item resolution).
pub struct BwConfirmRecord {
    pub id: String,
    pub user: String,
    pub requested_item_name: String,
    pub resolved_item_name: String,
    pub field: String,
}

/// Agent-supplied reason, flattened to one line. The reason is caller-controlled,
/// so a newline in it could forge trusted-looking lines ("User: root") in the
/// plain-text askgw prompt; collapsing all whitespace runs closes that.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// "\nReason: ..." suffix for an askgw prompt, or "" when there is no
/// (non-blank) reason.
fn askgw_reason_line(reason: Option<&str>) -> String {
    match reason.map(one_line) {
        Some(r) if !r.is_empty() => format!("\nReason: {r}"),
        _ => String::new(),
    }
}

/// The command as a fenced markdown code block, so the app shows it in a
/// monospace, scrollable card (#2740). Single backticks did not work: a
/// multi-line command is not an inline code span in the app's renderer. The
/// fence is longer than any backtick run in the command, so no line of the
/// (caller-controlled) command can close it early and spill text out as prose.
fn code_fence(command: &str) -> String {
    let longest = command.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat((longest + 1).max(3));
    format!("{fence}\n{command}\n{fence}")
}

/// (status, exit_code, message) of the completion `notify`, in the fields foci renders
/// (foci internal/askgw NotifyFrame): an exit code gives "completed, exit N" with a tick
/// or a cross; otherwise foci shows `status`, then `message` on its own line.
pub(crate) fn askgw_completion_fields(
    info: &CompletionInfo,
) -> (Option<String>, Option<i32>, Option<String>) {
    match &info.outcome {
        RunOutcome::Exited {
            exit_code,
            last_lines,
        } => (None, Some(*exit_code), last_lines.clone()),
        RunOutcome::NotRun { reason } => {
            (Some("\u{274c} NOT run".into()), None, Some(reason.clone()))
        }
        RunOutcome::Unfinished { reason } => (
            Some("\u{26a0}\u{fe0f} did not finish".into()),
            None,
            Some(reason.clone()),
        ),
    }
}

/// Question text for a sudo request on the askgw backends (socket and HTTP).
/// The command sits in its own code block so a long command does not wrap
/// into the verb (#2738) and reads as code (#2740).
pub(crate) fn askgw_sudo_question(record: &SudoRequestRecord) -> String {
    format!(
        "Run as root?\n{}\n\nUser: {}\nCWD: {}{}",
        code_fence(&record.command),
        record.user,
        record.cwd,
        askgw_reason_line(record.reason.as_deref())
    )
}

/// Question text for a temp-rule request on the askgw backends.
pub(crate) fn askgw_temp_rule_question(record: &TempRuleRecord) -> String {
    let patterns = record
        .patterns
        .iter()
        .map(|p| format!("  • {p}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Allow temporary rule for {}?\n\nPatterns:\n{}\nDuration: {}s{}",
        record.user,
        patterns,
        record.duration_seconds,
        askgw_reason_line(record.reason.as_deref())
    )
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

    /// Send a standalone web-UI access link (the "send access code" button).
    /// Fire-and-forget delivery of a tappable unlock URL.
    async fn send_access_link(&self, url: &str) -> Result<()>;

    /// Send a notification about completed credential scrubbing.
    async fn send_scrub_complete(&self, request_id: &str, item_name: &str) -> Result<()>;

    /// Update an approved notification with command completion status.
    async fn update_completion_status(&self, info: &CompletionInfo);

    /// Backend name for logging/audit.
    fn name(&self) -> &'static str;

    /// False only for [`none::NoBackend`], the placeholder installed when no
    /// approval mechanism ([askgw]/[askgw_http]/[telegram]) is configured.
    /// Callers MUST check this before routing a request that needs human
    /// approval to `send_and_wait`/`send_temp_rule_and_wait`/
    /// `send_bw_request_and_wait`/`send_bw_confirm_and_wait` and deny outright
    /// (with a caller-visible reason) instead of calling through — see
    /// `socket.rs`. Defaults to true so every real backend gets this for free.
    fn is_configured(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sudo_record(reason: Option<&str>) -> SudoRequestRecord {
        SudoRequestRecord {
            id: "req-1".to_string(),
            user: "rich".to_string(),
            command: "ls /root".to_string(),
            cwd: "/home/rich".to_string(),
            pid: 1,
            timestamp: chrono::Utc::now(),
            status: Decision::Pending,
            timeout_seconds: 60,
            nonce: "n".to_string(),
            decided_at: None,
            decided_by: None,
            reason: reason.map(str::to_string),
            stdin: None,
            stdin_bytes: None,
        }
    }

    fn temp_rule_record(reason: Option<&str>) -> TempRuleRecord {
        TempRuleRecord {
            id: "rule-1".to_string(),
            user: "rich".to_string(),
            patterns: vec!["apt *".to_string()],
            duration_seconds: 600,
            expires_at: "later".to_string(),
            nonce: "n".to_string(),
            reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn sudo_question_shows_reason_and_puts_command_on_own_line() {
        let q = askgw_sudo_question(&sudo_record(Some("check root's files")));
        assert_eq!(
            q,
            "Run as root?\n```\nls /root\n```\n\nUser: rich\nCWD: /home/rich\nReason: check root's files"
        );
    }

    #[test]
    fn sudo_question_omits_reason_when_absent_or_blank() {
        let want = "Run as root?\n```\nls /root\n```\n\nUser: rich\nCWD: /home/rich";
        assert_eq!(askgw_sudo_question(&sudo_record(None)), want);
        assert_eq!(askgw_sudo_question(&sudo_record(Some("  \n "))), want);
    }

    #[test]
    fn sudo_question_reason_cannot_forge_lines() {
        let q = askgw_sudo_question(&sudo_record(Some("ok\n\nUser: root\nCWD: /")));
        assert!(q.ends_with("\nReason: ok User: root CWD: /"), "{q}");
        assert_eq!(q.matches("\nUser:").count(), 1, "{q}");
    }

    #[test]
    fn sudo_question_fence_outlasts_backticks_in_command() {
        let mut r = sudo_record(None);
        r.command = "echo a\n````\nUser: root\necho `id`".to_string();
        let q = askgw_sudo_question(&r);
        assert!(q.starts_with("Run as root?\n`````\necho a\n"), "{q}");
        assert!(q.contains("echo `id`\n`````\n\nUser: rich"), "{q}");
    }

    #[test]
    fn temp_rule_question_shows_reason() {
        let q = askgw_temp_rule_question(&temp_rule_record(Some("bulk installs")));
        assert_eq!(
            q,
            "Allow temporary rule for rich?\n\nPatterns:\n  • apt *\nDuration: 600s\nReason: bulk installs"
        );
        assert!(!askgw_temp_rule_question(&temp_rule_record(None)).contains("Reason"));
    }
}
