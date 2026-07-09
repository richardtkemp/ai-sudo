use super::{
    BwConfirmRecord, BwRequestRecord, CompletionInfo, NotificationBackend, TempRuleRecord,
};
use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const PROTOCOL: &str = "askgw/1";
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const CHANNEL_BUFFER: usize = 64;

#[derive(Debug, Serialize)]
struct AskFrame<'a> {
    protocol: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    id: String,
    source: &'a str,
    timeout_seconds: f64,
    questions: Vec<Question<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct Question<'a> {
    key: &'a str,
    header: &'a str,
    question: String,
    options: Vec<QuestionOption<'a>>,
}

#[derive(Debug, Serialize)]
struct QuestionOption<'a> {
    label: &'a str,
    description: String,
}

#[derive(Debug, Serialize)]
struct NotifyFrame<'a> {
    protocol: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    text: String,
}

#[derive(Debug, Serialize)]
struct CancelFrame<'a> {
    protocol: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    id: String,
    reason: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum GatewayFrame {
    #[serde(rename = "answer")]
    Answer {
        id: String,
        status: String,
        #[serde(default)]
        answers: HashMap<String, serde_json::Value>,
    },
    #[serde(rename = "ack")]
    Ack { id: String },
    #[serde(rename = "error")]
    Error {
        #[serde(default)]
        id: Option<String>,
        code: String,
        #[serde(default)]
        message: Option<String>,
    },
    #[serde(other)]
    Other,
}

pub struct AskgwBackend {
    timeout: Duration,
    agent: Option<String>,
    outbox: mpsc::Sender<String>,
    pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>>,
}

impl AskgwBackend {
    pub fn new(
        socket_path: PathBuf,
        gateway_uid: u32,
        timeout: Duration,
        agent: Option<String>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER);
        let pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>> =
            Arc::new(DashMap::new());

        tokio::spawn(connection_loop(
            socket_path,
            gateway_uid,
            rx,
            Arc::clone(&pending),
        ));

        Self {
            timeout,
            agent,
            outbox: tx,
            pending,
        }
    }

    async fn ask_and_wait(
        &self,
        header: &str,
        question: String,
        approve_label: &str,
        deny_label: &str,
        approve_desc: String,
        deny_desc: String,
    ) -> Result<Decision> {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id.clone(), tx);

        let frame = AskFrame {
            protocol: PROTOCOL,
            frame_type: "ask",
            id: id.clone(),
            source: "aisudo",
            timeout_seconds: self.timeout.as_secs_f64(),
            questions: vec![Question {
                key: "decision",
                header,
                question,
                options: vec![
                    QuestionOption {
                        label: approve_label,
                        description: approve_desc,
                    },
                    QuestionOption {
                        label: deny_label,
                        description: deny_desc,
                    },
                ],
            }],
            agent: self.agent.as_deref(),
        };

        let json = serde_json::to_string(&frame)?;
        if self.outbox.send(json).await.is_err() {
            self.pending.remove(&id);
            return Err(anyhow!("askgw connection closed"));
        }

        let result = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(gateway_frame)) => map_answer(gateway_frame, approve_label),
            Ok(Err(_)) => {
                self.pending.remove(&id);
                Ok(Decision::Denied)
            }
            Err(_) => {
                self.pending.remove(&id);
                let cancel = CancelFrame {
                    protocol: PROTOCOL,
                    frame_type: "cancel",
                    id,
                    reason: "timeout",
                };
                let _ = serde_json::to_string(&cancel)
                    .map(|j| self.outbox.try_send(j));
                Ok(Decision::Timeout)
            }
        };

        result
    }

    async fn send_notify(
        &self,
        kind: Option<&str>,
        level: Option<&str>,
        title: Option<&str>,
        text: String,
    ) -> Result<()> {
        let frame = NotifyFrame {
            protocol: PROTOCOL,
            frame_type: "notify",
            id: Uuid::new_v4().to_string(),
            kind,
            level,
            title,
            text,
        };
        let json = serde_json::to_string(&frame)?;
        let _ = self.outbox.send(json).await;
        Ok(())
    }
}

fn map_answer(frame: GatewayFrame, approve_label: &str) -> Result<Decision> {
    match frame {
        GatewayFrame::Answer { status, answers, .. } => match status.as_str() {
            "answered" => {
                let label = answers
                    .get("decision")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if label == approve_label {
                    Ok(Decision::Approved)
                } else {
                    Ok(Decision::Denied)
                }
            }
            "timeout" => Ok(Decision::Timeout),
            "dismissed" | "unavailable" => Ok(Decision::Denied),
            _ => Ok(Decision::Denied),
        },
        GatewayFrame::Error { code, message, .. } => {
            warn!("askgw error: code={code} message={message:?}");
            Ok(Decision::Denied)
        },
        _ => Ok(Decision::Denied),
    }
}

async fn connection_loop(
    socket_path: PathBuf,
    gateway_uid: u32,
    mut rx: mpsc::Receiver<String>,
    pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>>,
) {
    let mut backoff = RECONNECT_INITIAL;
    loop {
        match verify_and_connect(&socket_path, gateway_uid).await {
            Ok(stream) => {
                info!("askgw connected to {}", socket_path.display());
                backoff = RECONNECT_INITIAL;

                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();

                loop {
                    tokio::select! {
                        line = lines.next_line() => {
                            match line {
                                Ok(Some(line)) => {
                                    if line.is_empty() { continue; }
                                    handle_gateway_frame(&line, &pending);
                                }
                                Ok(None) => {
                                    warn!("askgw connection closed by gateway");
                                    break;
                                }
                                Err(e) => {
                                    warn!("askgw read error: {e}");
                                    break;
                                }
                            }
                        }
                        frame = rx.recv() => {
                            match frame {
                                Some(json) => {
                                    if let Err(e) = writer.write_all(json.as_bytes()).await {
                                        warn!("askgw write error: {e}");
                                        break;
                                    }
                                    if let Err(e) = writer.write_all(b"\n").await {
                                        warn!("askgw write newline error: {e}");
                                        break;
                                    }
                                }
                                None => {
                                    info!("askgw outbox closed, shutting down connection");
                                    let _ = writer.shutdown().await;
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("askgw connect failed: {e:#}");
            }
        }

        fail_pending(&pending);
        debug!("askgw reconnecting in {:?}", backoff);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

fn fail_pending(pending: &DashMap<String, oneshot::Sender<GatewayFrame>>) {
    let keys: Vec<String> = pending.iter().map(|e| e.key().clone()).collect();
    for key in keys {
        if let Some((_, tx)) = pending.remove(&key) {
            let _ = tx.send(GatewayFrame::Error {
                id: Some(key),
                code: "disconnected".into(),
                message: Some("connection lost".into()),
            });
        }
    }
}

fn handle_gateway_frame(line: &str, pending: &DashMap<String, oneshot::Sender<GatewayFrame>>) {
    let frame: GatewayFrame = match serde_json::from_str(line) {
        Ok(f) => f,
        Err(e) => {
            debug!("askgw: unparseable frame: {e}");
            return;
        }
    };
    let id = match &frame {
        GatewayFrame::Answer { id, .. } => id.clone(),
        GatewayFrame::Error { id: Some(id), .. } => id.clone(),
        GatewayFrame::Ack { id } => {
            debug!("askgw: ack for {id}");
            return;
        }
        _ => return,
    };
    if let Some((_, tx)) = pending.remove(&id) {
        let _ = tx.send(frame);
    } else {
        debug!("askgw: no pending waiter for id={id}");
    }
}

async fn verify_and_connect(socket_path: &PathBuf, gateway_uid: u32) -> Result<UnixStream> {
    let meta = std::fs::metadata(socket_path)
        .map_err(|e| anyhow!("stat socket {}: {e}", socket_path.display()))?;
    if !meta.file_type().is_socket() {
        return Err(anyhow!("{} is not a socket", socket_path.display()));
    }
    if meta.uid() != gateway_uid {
        return Err(anyhow!(
            "socket owner uid {} does not match expected gateway uid {}",
            meta.uid(),
            gateway_uid
        ));
    }
    let parent = socket_path
        .parent()
        .ok_or_else(|| anyhow!("socket path has no parent"))?;
    if let Ok(parent_meta) = std::fs::metadata(parent) {
        if parent_meta.mode() & 0o022 != 0 {
            return Err(anyhow!(
                "socket parent dir is group- or world-writable (mode {:o})",
                parent_meta.mode() & 0o777
            ));
        }
    }
    UnixStream::connect(socket_path)
        .await
        .map_err(|e| anyhow!("connect {}: {e}", socket_path.display()))
}

#[async_trait::async_trait]
impl NotificationBackend for AskgwBackend {
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision> {
        let question = format!(
            "Run `{}` as root?\n\nUser: {}\nCWD: {}",
            record.command, record.user, record.cwd
        );
        self.ask_and_wait(
            "Sudo",
            question,
            "Approve",
            "Deny",
            "Execute the command as root".into(),
            "Reject the request".into(),
        )
        .await
    }

    async fn send_temp_rule_and_wait(&self, record: &TempRuleRecord) -> Result<Decision> {
        let patterns = record
            .patterns
            .iter()
            .map(|p| format!("  • {p}"))
            .collect::<Vec<_>>()
            .join("\n");
        let question = format!(
            "Allow temporary rule for {}?\n\nPatterns:\n{}\nDuration: {}s",
            record.user, patterns, record.duration_seconds
        );
        self.ask_and_wait(
            "Temp rule",
            question,
            "Approve",
            "Deny",
            "Create the temporary rule".into(),
            "Reject the request".into(),
        )
        .await
    }

    async fn send_bw_request_and_wait(&self, record: &BwRequestRecord) -> Result<Decision> {
        let vault = if record.session_active { "unlocked" } else { "locked" };
        let question = format!(
            "Retrieve Bitwarden credential?\n\nUser: {}\nItem: {}\nField: {}\nVault: {}",
            record.user, record.item_name, record.field, vault
        );
        self.ask_and_wait(
            "Secret",
            question,
            "Approve",
            "Deny",
            "Retrieve the credential".into(),
            "Reject the request".into(),
        )
        .await
    }

    async fn send_bw_confirm_and_wait(&self, record: &BwConfirmRecord) -> Result<Decision> {
        let question = format!(
            "Confirm Bitwarden item?\n\nRequested: {}\nResolved to: {}\nField: {}\n\n⚠️ Names differ — please confirm.",
            record.requested_item_name, record.resolved_item_name, record.field
        );
        self.ask_and_wait(
            "Confirm secret",
            question,
            "Confirm",
            "Cancel",
            "Confirm and retrieve".into(),
            "Cancel the request".into(),
        )
        .await
    }

    async fn send_bw_locked_notification(&self, record: &BwRequestRecord) -> Result<()> {
        let text = format!(
            "Bitwarden vault is locked. Request for '{}' ({}) is waiting.\nUnlock via dashboard to approve.",
            record.item_name, record.field
        );
        self.send_notify(Some("locked"), Some("warning"), Some("BW Locked"), text)
            .await
    }

    async fn send_access_link(&self, url: &str) -> Result<()> {
        self.send_notify(
            Some("access_link"),
            Some("info"),
            Some("Web Access"),
            format!("Tap to open the vault dashboard:\n{url}"),
        )
        .await
    }

    async fn send_scrub_complete(&self, request_id: &str, item_name: &str) -> Result<()> {
        self.send_notify(
            Some("completion"),
            Some("success"),
            None,
            format!("Credential scrubbed: {item_name} (request {request_id})"),
        )
        .await
    }

    async fn update_completion_status(&self, info: &CompletionInfo) {
        let text = if info.exit_code == 0 {
            format!("Command completed: exit 0 (request {})", info.request_id)
        } else {
            let detail = info
                .last_lines
                .as_ref()
                .map(|l| format!(": {l}"))
                .unwrap_or_default();
            format!(
                "Command failed: exit {} (request {}){}",
                info.exit_code, info.request_id, detail
            )
        };
        let _ = self
            .send_notify(Some("completion"), Some("info"), None, text)
            .await;
    }

    fn name(&self) -> &'static str {
        "askgw"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_ask_frame() {
        let frame = AskFrame {
            protocol: PROTOCOL,
            frame_type: "ask",
            id: "test-123".into(),
            source: "aisudo",
            timeout_seconds: 60.0,
            questions: vec![Question {
                key: "decision",
                header: "Sudo",
                question: "Run `ls` as root?".into(),
                options: vec![
                    QuestionOption {
                        label: "Approve",
                        description: "Execute".into(),
                    },
                    QuestionOption {
                        label: "Deny",
                        description: "Reject".into(),
                    },
                ],
            }],
            agent: None,
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"protocol\":\"askgw/1\""));
        assert!(json.contains("\"type\":\"ask\""));
        assert!(json.contains("\"id\":\"test-123\""));
        assert!(json.contains("\"source\":\"aisudo\""));
        assert!(json.contains("\"key\":\"decision\""));
        assert!(json.contains("\"label\":\"Approve\""));
        assert!(json.contains("\"label\":\"Deny\""));
        assert!(!json.contains("agent"));
    }

    #[test]
    fn test_serialize_ask_frame_with_agent() {
        let frame = AskFrame {
            protocol: PROTOCOL,
            frame_type: "ask",
            id: "a1".into(),
            source: "aisudo",
            timeout_seconds: 30.0,
            questions: vec![Question {
                key: "decision",
                header: "Sudo",
                question: "q?".into(),
                options: vec![QuestionOption {
                    label: "Approve",
                    description: "".into(),
                }],
            }],
            agent: Some("clutch"),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"agent\":\"clutch\""));
    }

    #[test]
    fn test_serialize_notify_frame() {
        let frame = NotifyFrame {
            protocol: PROTOCOL,
            frame_type: "notify",
            id: "n1".into(),
            kind: Some("completion"),
            level: Some("success"),
            title: None,
            text: "exit 0".into(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"type\":\"notify\""));
        assert!(json.contains("\"kind\":\"completion\""));
        assert!(json.contains("\"level\":\"success\""));
        assert!(!json.contains("title"));
    }

    #[test]
    fn test_serialize_cancel_frame() {
        let frame = CancelFrame {
            protocol: PROTOCOL,
            frame_type: "cancel",
            id: "c1".into(),
            reason: "timeout",
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"type\":\"cancel\""));
        assert!(json.contains("\"reason\":\"timeout\""));
    }

    #[test]
    fn test_deserialize_answer_answered() {
        let raw = r#"{"protocol":"askgw/1","type":"answer","id":"x","status":"answered","answers":{"decision":"Approve"}}"#;
        let frame: GatewayFrame = serde_json::from_str(raw).unwrap();
        match frame {
            GatewayFrame::Answer { status, answers, .. } => {
                assert_eq!(status, "answered");
                assert_eq!(
                    answers.get("decision").and_then(|v| v.as_str()),
                    Some("Approve")
                );
            }
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn test_deserialize_answer_timeout() {
        let raw = r#"{"protocol":"askgw/1","type":"answer","id":"x","status":"timeout"}"#;
        let frame: GatewayFrame = serde_json::from_str(raw).unwrap();
        match frame {
            GatewayFrame::Answer { status, .. } => assert_eq!(status, "timeout"),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn test_deserialize_ack() {
        let raw = r#"{"protocol":"askgw/1","type":"ack","id":"x"}"#;
        let frame: GatewayFrame = serde_json::from_str(raw).unwrap();
        match frame {
            GatewayFrame::Ack { id } => assert_eq!(id, "x"),
            _ => panic!("expected Ack"),
        }
    }

    #[test]
    fn test_deserialize_error() {
        let raw = r#"{"protocol":"askgw/1","type":"error","id":"x","code":"malformed","message":"bad"}"#;
        let frame: GatewayFrame = serde_json::from_str(raw).unwrap();
        match frame {
            GatewayFrame::Error { code, message, .. } => {
                assert_eq!(code, "malformed");
                assert_eq!(message.as_deref(), Some("bad"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_deserialize_error_no_id() {
        let raw = r#"{"protocol":"askgw/1","type":"error","code":"bad_protocol"}"#;
        let frame: GatewayFrame = serde_json::from_str(raw).unwrap();
        match frame {
            GatewayFrame::Error { id, code, .. } => {
                assert!(id.is_none());
                assert_eq!(code, "bad_protocol");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_deserialize_unknown_type_tolerated() {
        let raw = r#"{"protocol":"askgw/1","type":"notify","id":"x","text":"hi"}"#;
        let frame: GatewayFrame = serde_json::from_str(raw).unwrap();
        assert!(matches!(frame, GatewayFrame::Other));
    }

    #[test]
    fn test_map_answer_approved() {
        let frame = GatewayFrame::Answer {
            id: "x".into(),
            status: "answered".into(),
            answers: HashMap::from([("decision".into(), serde_json::Value::String("Approve".into()))]),
        };
        assert_eq!(map_answer(frame, "Approve").unwrap(), Decision::Approved);
    }

    #[test]
    fn test_map_answer_denied() {
        let frame = GatewayFrame::Answer {
            id: "x".into(),
            status: "answered".into(),
            answers: HashMap::from([("decision".into(), serde_json::Value::String("Deny".into()))]),
        };
        assert_eq!(map_answer(frame, "Approve").unwrap(), Decision::Denied);
    }

    #[test]
    fn test_map_answer_timeout() {
        let frame = GatewayFrame::Answer {
            id: "x".into(),
            status: "timeout".into(),
            answers: HashMap::new(),
        };
        assert_eq!(map_answer(frame, "Approve").unwrap(), Decision::Timeout);
    }

    #[test]
    fn test_map_answer_dismissed() {
        let frame = GatewayFrame::Answer {
            id: "x".into(),
            status: "dismissed".into(),
            answers: HashMap::new(),
        };
        assert_eq!(map_answer(frame, "Approve").unwrap(), Decision::Denied);
    }

    #[test]
    fn test_map_answer_unavailable() {
        let frame = GatewayFrame::Answer {
            id: "x".into(),
            status: "unavailable".into(),
            answers: HashMap::new(),
        };
        assert_eq!(map_answer(frame, "Approve").unwrap(), Decision::Denied);
    }

    #[test]
    fn test_map_answer_error_frame() {
        let frame = GatewayFrame::Error {
            id: Some("x".into()),
            code: "malformed".into(),
            message: Some("bad".into()),
        };
        assert_eq!(map_answer(frame, "Approve").unwrap(), Decision::Denied);
    }

    #[test]
    fn test_handle_gateway_frame_dispatches_to_pending() {
        let pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>> =
            Arc::new(DashMap::new());
        let (tx, rx) = oneshot::channel();
        pending.insert("abc".into(), tx);

        let raw = r#"{"protocol":"askgw/1","type":"answer","id":"abc","status":"answered","answers":{"decision":"Approve"}}"#;
        handle_gateway_frame(raw, &pending);

        let frame = rx.blocking_recv().unwrap();
        match frame {
            GatewayFrame::Answer { status, .. } => assert_eq!(status, "answered"),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn test_handle_gateway_frame_no_waiter() {
        let pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>> =
            Arc::new(DashMap::new());
        let raw = r#"{"protocol":"askgw/1","type":"answer","id":"nope","status":"answered"}"#;
        handle_gateway_frame(raw, &pending);
        assert!(pending.is_empty());
    }

    #[test]
    fn test_handle_gateway_frame_ack_does_not_consume() {
        let pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>> =
            Arc::new(DashMap::new());
        let (tx, _rx) = oneshot::channel();
        pending.insert("abc".into(), tx);

        let raw = r#"{"protocol":"askgw/1","type":"ack","id":"abc"}"#;
        handle_gateway_frame(raw, &pending);

        assert!(pending.contains_key("abc"));
    }

    #[test]
    fn test_fail_pending_sends_error() {
        let pending: Arc<DashMap<String, oneshot::Sender<GatewayFrame>>> =
            Arc::new(DashMap::new());
        let (tx, rx) = oneshot::channel();
        pending.insert("k1".into(), tx);

        fail_pending(&pending);

        let frame = rx.blocking_recv().unwrap();
        match frame {
            GatewayFrame::Error { code, .. } => assert_eq!(code, "disconnected"),
            _ => panic!("expected Error"),
        }
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_verify_and_connect_rejects_wrong_uid() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let result = verify_and_connect(&sock, 99999).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("uid"), "error should mention uid: {msg}");
    }

    #[tokio::test]
    async fn test_verify_and_connect_rejects_non_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notasocket");
        std::fs::write(&path, "hello").unwrap();

        let result = verify_and_connect(&path, 0).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not a socket"), "error should mention socket: {msg}");
    }
}
