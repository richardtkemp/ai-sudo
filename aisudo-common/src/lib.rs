use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request mode: PAM (just approve/deny) or Exec (approve then execute).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestMode {
    Pam,
    Exec,
}

/// Request sent from the PAM module or CLI wrapper to the daemon over the Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoRequest {
    pub user: String,
    pub command: String,
    pub cwd: String,
    pub pid: u32,
    #[serde(default = "default_mode")]
    pub mode: RequestMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Base64-encoded stdin data captured from pipe/heredoc (None if stdin was a terminal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Skip NOPASSWD check (set on retry after sudo -n fails).
    #[serde(default)]
    pub skip_nopasswd: bool,
}

fn default_mode() -> RequestMode {
    RequestMode::Pam
}

/// A chunk of output streamed back from the daemon during exec mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutput {
    /// "stdout", "stderr", or "exit"
    pub stream: String,
    /// The data (for stdout/stderr) or empty (for exit)
    pub data: String,
    /// Exit code, only set when stream == "exit"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Internal request record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoRequestRecord {
    pub id: String,
    pub user: String,
    pub command: String,
    pub cwd: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub status: Decision,
    pub timeout_seconds: u32,
    pub nonce: String,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
    /// Base64-encoded stdin data (carried through for notification preview, not stored in DB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Size of decoded stdin in bytes (logged to audit DB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_bytes: Option<usize>,
}

impl SudoRequestRecord {
    pub fn new(req: SudoRequest, timeout_seconds: u32) -> Self {
        // Estimate decoded stdin size from base64 length (3 bytes per 4 chars)
        let stdin_bytes = req.stdin.as_ref().map(|s| s.len() * 3 / 4);
        Self {
            id: Uuid::new_v4().to_string(),
            user: req.user,
            command: req.command,
            cwd: req.cwd,
            pid: req.pid,
            timestamp: Utc::now(),
            status: Decision::Pending,
            timeout_seconds,
            nonce: Uuid::new_v4().to_string(),
            decided_at: None,
            decided_by: None,
            reason: req.reason,
            stdin: req.stdin,
            stdin_bytes,
        }
    }
}

/// Response sent from the daemon back to the PAM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoResponse {
    pub request_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request for temporary allowlist rules sent from the CLI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempRuleRequest {
    pub user: String,
    pub patterns: Vec<String>,
    pub duration_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response to a temporary rule request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempRuleResponse {
    pub request_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Request to list all active rules for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRulesRequest {
    pub user: String,
}

/// An active temporary rule with its patterns and expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveTempRule {
    pub patterns: Vec<String>,
    pub expires_at: String,
}

/// Response containing all active rules for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRulesResponse {
    pub allowlist: Vec<String>,
    pub temp_rules: Vec<ActiveTempRule>,
    pub nopasswd_rules: Vec<String>,
}

/// Wire-level message wrapper for the Unix socket protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SocketMessage {
    SudoRequest(SudoRequest),
    TempRuleRequest(TempRuleRequest),
    ListRules(ListRulesRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Pending,
    Approved,
    Denied,
    Timeout,
    /// Command matches a sudo NOPASSWD rule — CLI should exec via sudo directly.
    UseSudo,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Pending => "pending",
            Decision::Approved => "approved",
            Decision::Denied => "denied",
            Decision::Timeout => "timeout",
            Decision::UseSudo => "use_sudo",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Decision::Pending),
            "approved" => Some(Decision::Approved),
            "denied" => Some(Decision::Denied),
            "timeout" => Some(Decision::Timeout),
            "use_sudo" => Some(Decision::UseSudo),
            _ => None,
        }
    }
}

/// Default socket path for daemon communication.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/aisudo/aisudo.sock";

/// Default timeout in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_as_str_all_variants() {
        assert_eq!(Decision::Pending.as_str(), "pending");
        assert_eq!(Decision::Approved.as_str(), "approved");
        assert_eq!(Decision::Denied.as_str(), "denied");
        assert_eq!(Decision::Timeout.as_str(), "timeout");
        assert_eq!(Decision::UseSudo.as_str(), "use_sudo");
    }

    #[test]
    fn decision_from_str_all_variants() {
        assert_eq!(Decision::from_str("pending"), Some(Decision::Pending));
        assert_eq!(Decision::from_str("approved"), Some(Decision::Approved));
        assert_eq!(Decision::from_str("denied"), Some(Decision::Denied));
        assert_eq!(Decision::from_str("timeout"), Some(Decision::Timeout));
        assert_eq!(Decision::from_str("use_sudo"), Some(Decision::UseSudo));
        assert_eq!(Decision::from_str("unknown"), None);
        assert_eq!(Decision::from_str(""), None);
    }

    #[test]
    fn sudo_request_record_new_with_stdin() {
        let req = SudoRequest {
            user: "alice".to_string(),
            command: "ls -la".to_string(),
            cwd: "/home/alice".to_string(),
            pid: 1234,
            mode: RequestMode::Exec,
            reason: Some("testing".to_string()),
            stdin: Some("aGVsbG8=".to_string()),
            skip_nopasswd: false,
        };
        let record = SudoRequestRecord::new(req, 60);
        assert_eq!(record.user, "alice");
        assert_eq!(record.command, "ls -la");
        assert_eq!(record.cwd, "/home/alice");
        assert_eq!(record.pid, 1234);
        assert_eq!(record.status, Decision::Pending);
        assert_eq!(record.timeout_seconds, 60);
        assert_eq!(record.reason.as_deref(), Some("testing"));
        assert!(record.stdin.is_some());
        assert_eq!(record.stdin_bytes, Some(6));
        assert!(!record.id.is_empty());
        assert!(!record.nonce.is_empty());
    }

    #[test]
    fn sudo_request_record_new_without_stdin() {
        let req = SudoRequest {
            user: "bob".to_string(),
            command: "whoami".to_string(),
            cwd: "/".to_string(),
            pid: 42,
            mode: RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        };
        let record = SudoRequestRecord::new(req, 30);
        assert_eq!(record.user, "bob");
        assert!(record.stdin.is_none());
        assert!(record.stdin_bytes.is_none());
        assert!(record.decided_at.is_none());
        assert!(record.decided_by.is_none());
    }

    #[test]
    fn default_mode_is_pam() {
        let json = r#"{"user":"a","command":"b","cwd":"/","pid":1}"#;
        let req: SudoRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.mode, RequestMode::Pam);
    }

    #[test]
    fn socket_message_sudo_request_roundtrip() {
        let msg = SocketMessage::SudoRequest(SudoRequest {
            user: "test".to_string(),
            command: "ls".to_string(),
            cwd: "/".to_string(),
            pid: 1,
            mode: RequestMode::Exec,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"sudo_request\""));
        let _: SocketMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn socket_message_temp_rule_request_roundtrip() {
        let msg = SocketMessage::TempRuleRequest(TempRuleRequest {
            user: "test".to_string(),
            patterns: vec!["apt install".to_string()],
            duration_seconds: 3600,
            reason: Some("need deps".to_string()),
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"temp_rule_request\""));
        let _: SocketMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn socket_message_list_rules_roundtrip() {
        let msg = SocketMessage::ListRules(ListRulesRequest {
            user: "test".to_string(),
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"list_rules\""));
        let _: SocketMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn sudo_response_serde() {
        let resp = SudoResponse {
            request_id: "abc".to_string(),
            decision: Decision::Approved,
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: SudoResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.decision, Decision::Approved);
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn sudo_response_with_error() {
        let resp = SudoResponse {
            request_id: "abc".to_string(),
            decision: Decision::Denied,
            error: Some("rate limit exceeded".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: SudoResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.error.as_deref(), Some("rate limit exceeded"));
    }

    #[test]
    fn exec_output_serde() {
        let output = ExecOutput {
            stream: "stdout".to_string(),
            data: "hello".to_string(),
            exit_code: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("exit_code"));

        let output_exit = ExecOutput {
            stream: "exit".to_string(),
            data: String::new(),
            exit_code: Some(0),
        };
        let json = serde_json::to_string(&output_exit).unwrap();
        assert!(json.contains("\"exit_code\":0"));
    }

    #[test]
    fn temp_rule_response_serde() {
        let resp = TempRuleResponse {
            request_id: "r1".to_string(),
            decision: Decision::Approved,
            error: None,
            expires_at: Some("2025-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: TempRuleResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expires_at.as_deref(), Some("2025-01-01T00:00:00Z"));
    }

    #[test]
    fn list_rules_response_serde() {
        let resp = ListRulesResponse {
            allowlist: vec!["apt list".to_string()],
            temp_rules: vec![ActiveTempRule {
                patterns: vec!["docker ps".to_string()],
                expires_at: "2025-01-01T00:00:00Z".to_string(),
            }],
            nopasswd_rules: vec!["/usr/bin/apt".to_string()],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: ListRulesResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowlist.len(), 1);
        assert_eq!(deserialized.temp_rules.len(), 1);
        assert_eq!(deserialized.nopasswd_rules.len(), 1);
    }
}
