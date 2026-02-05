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
}

impl SudoRequestRecord {
    pub fn new(req: SudoRequest, timeout_seconds: u32) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Pending,
    Approved,
    Denied,
    Timeout,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Pending => "pending",
            Decision::Approved => "approved",
            Decision::Denied => "denied",
            Decision::Timeout => "timeout",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Decision::Pending),
            "approved" => Some(Decision::Approved),
            "denied" => Some(Decision::Denied),
            "timeout" => Some(Decision::Timeout),
            _ => None,
        }
    }
}

/// Default socket path for daemon communication.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/aisudo/aisudo.sock";

/// Default timeout in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 60;
