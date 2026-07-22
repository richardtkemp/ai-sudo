//! HTTP askgw backend — reaches foci's ask-gateway over the network instead
//! of a Unix socket, for a REMOTE host (e.g. a Mac running aisudo) that can't
//! reach a local `askgw.sock` without ssh-forwarding it.
//!
//! Mirrors [`super::askgw::AskgwBackend`]'s STRUCTURE (same `NotificationBackend`
//! impl, same "build an `ask` frame, submit it, wait for a `Decision`" shape,
//! same `askgw/1` question/answer semantics from `docs/askgw-protocol.md`) but
//! speaks HTTP instead of NDJSON-over-Unix-socket.
//!
//! # ASSUMED wire contract — RECONCILE against foci #1463 at review
//!
//! foci's HTTP askgw endpoint (todo #1463) was being built in parallel and was
//! still finalizing its exact shape when this was written. The contract below
//! is this side's assumption, chosen to mirror the socket backend's blocking
//! send-and-wait as closely as HTTP allows. See `notes-1464.md` (repo root) for
//! the exact request/response JSON, prominently, for reconciliation.
//!
//! In one line: `POST {endpoint}/askgw/ask` (submit, same `ask` frame body as
//! the socket transport) → 202 `{"id","status":"pending"}`; then repeated
//! `GET {endpoint}/askgw/ask/{id}?wait=<secs>` (bounded long-poll — blocks up
//! to `wait` seconds, returns `{"status":"pending"}` to re-poll or a terminal
//! `answered`/`timeout`/`dismissed`/`unavailable`/`cancelled` AnswerFrame);
//! `POST {endpoint}/askgw/ask/{id}/cancel` on client-side give-up. Auth is
//! `Authorization: Bearer <api_key>` — the same scheme as foci's `http.api_key`.
//!
//! # Adjustable interaction model
//!
//! The [`Transport`] trait isolates the wire shape (submit / poll / cancel)
//! from the ask-and-wait orchestration in [`AskgwHttpBackend`]. If foci #1463
//! lands a different shape (e.g. a single held-open call, or submit-returns-
//! id-then-webhook), only a new `Transport` impl is needed — the
//! `NotificationBackend` impl and the rest of this file are unaffected.
//!
//! # Known gap: fire-and-forget notifications
//!
//! The assumed contract only covers the `ask` flow (submit/poll/cancel) — it
//! has no equivalent of the socket transport's `notify` frame (used for
//! Bitwarden-locked notices, access links, scrub-complete, and command
//! completion status). Those four `NotificationBackend` methods are
//! implemented as local-log no-ops here (see `log_unsupported_notify`) rather
//! than silently dropped or hacked onto the `ask` endpoint. Flagged in
//! `notes-1464.md` for reconciliation: if #1463 wants these delivered
//! remotely too, foci's HTTP transport needs its own notify endpoint.

use super::{
    BwConfirmRecord, BwRequestRecord, CompletionInfo, NotificationBackend, TempRuleRecord,
};
use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use uuid::Uuid;

const PROTOCOL: &str = "askgw/1";

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

/// Terminal or in-progress answer, as returned by `GET /askgw/ask/{id}`.
/// `status` is one of the four wire statuses (`answered`/`timeout`/
/// `dismissed`/`unavailable`) plus the two HTTP-only synthetic ones this
/// contract is assumed to add: `pending` (still waiting — re-poll) and
/// `cancelled` (this side withdrew it).
#[derive(Debug, Deserialize)]
struct AnswerFrame {
    #[serde(default)]
    status: String,
    #[serde(default)]
    answers: HashMap<String, serde_json::Value>,
}

const STATUS_PENDING: &str = "pending";

/// Body returned by a non-2xx `POST /askgw/ask` (e.g. malformed frame,
/// duplicate id).
#[derive(Debug, Deserialize)]
struct SubmitError {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Wire-level operations against foci's HTTP askgw endpoint, split out from
/// the ask-and-wait orchestration in [`AskgwHttpBackend`] so the interaction
/// model can be swapped without touching that orchestration or the
/// `NotificationBackend` impl. See the module doc for why this seam exists.
#[async_trait::async_trait]
trait Transport: Send + Sync {
    /// Submit an `ask` frame. `Ok(())` means "accepted / presented" (mirrors
    /// the socket transport's `ack`) — it does NOT imply an answer yet.
    async fn submit(&self, frame: &AskFrame<'_>) -> Result<()>;

    /// Long-poll for `id`'s answer, blocking up to `wait`. A `status ==
    /// "pending"` result means the caller should call `poll` again (the
    /// server-side wait elapsed with no answer yet) — this is a resumable
    /// long-poll, not a single held-open call; see module doc.
    async fn poll(&self, id: &str, wait: Duration) -> Result<AnswerFrame>;

    /// Best-effort withdrawal of a pending ask (e.g. on client-side timeout).
    /// Errors are logged, not propagated — cancellation is a courtesy to free
    /// server-side state, not required for correctness on this side.
    async fn cancel(&self, id: &str, reason: &str);
}

/// [`Transport`] impl for the ASSUMED contract: `POST /askgw/ask`, `GET
/// /askgw/ask/{id}?wait=<secs>`, `POST /askgw/ask/{id}/cancel`.
struct LongPollTransport {
    client: Client,
    endpoint: String,
    api_key: String,
}

impl LongPollTransport {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.endpoint.trim_end_matches('/'))
    }
}

#[async_trait::async_trait]
impl Transport for LongPollTransport {
    async fn submit(&self, frame: &AskFrame<'_>) -> Result<()> {
        let resp = self
            .client
            .post(self.url("/askgw/ask"))
            .bearer_auth(&self.api_key)
            .json(frame)
            .send()
            .await
            .map_err(|e| anyhow!("askgw_http: submit request failed: {e}"))?;

        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body: Option<SubmitError> = resp.json().await.ok();
        let code = body
            .as_ref()
            .and_then(|b| b.code.clone())
            .unwrap_or_default();
        let msg = body
            .and_then(|b| b.error)
            .unwrap_or_else(|| "no error detail".into());
        Err(anyhow!(
            "askgw_http: submit rejected (HTTP {status}, code={code:?}): {msg}"
        ))
    }

    async fn poll(&self, id: &str, wait: Duration) -> Result<AnswerFrame> {
        let resp = self
            .client
            .get(self.url(&format!("/askgw/ask/{id}")))
            .bearer_auth(&self.api_key)
            .query(&[("wait", wait.as_secs().to_string())])
            .send()
            .await
            .map_err(|e| anyhow!("askgw_http: poll request failed: {e}"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("askgw_http: poll: unknown ask id {id:?}"));
        }
        if !resp.status().is_success() {
            return Err(anyhow!("askgw_http: poll: HTTP {}", resp.status()));
        }
        resp.json::<AnswerFrame>()
            .await
            .map_err(|e| anyhow!("askgw_http: poll: malformed answer body: {e}"))
    }

    async fn cancel(&self, id: &str, reason: &str) {
        let result = self
            .client
            .post(self.url(&format!("/askgw/ask/{id}/cancel")))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({"reason": reason}))
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                debug!("askgw_http: cancelled {id} ({reason})");
            }
            Ok(resp) => {
                warn!("askgw_http: cancel {id} returned HTTP {}", resp.status());
            }
            Err(e) => {
                warn!("askgw_http: cancel {id} request failed: {e}");
            }
        }
    }
}

pub struct AskgwHttpBackend {
    transport: Box<dyn Transport>,
    /// Overall wait for a human decision — bounds the submit+poll loop.
    /// Mirrors the socket backend's `timeout` field/semantics exactly.
    timeout: Duration,
    /// Per-GET long-poll wait, clamped by foci's own server-side max.
    poll_wait: Duration,
    agent: Option<String>,
}

impl AskgwHttpBackend {
    pub fn new(
        endpoint: String,
        api_key: String,
        agent: Option<String>,
        timeout: Duration,
        poll_wait: Duration,
        request_timeout: Duration,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| anyhow!("askgw_http: failed to build HTTP client: {e}"))?;
        Ok(Self {
            transport: Box::new(LongPollTransport {
                client,
                endpoint,
                api_key,
            }),
            timeout,
            poll_wait,
            agent,
        })
    }

    #[cfg(test)]
    fn with_transport(
        transport: Box<dyn Transport>,
        timeout: Duration,
        poll_wait: Duration,
        agent: Option<String>,
    ) -> Self {
        Self {
            transport,
            timeout,
            poll_wait,
            agent,
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

        self.transport.submit(&frame).await?;

        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.transport.cancel(&id, "timeout").await;
                return Ok(Decision::Timeout);
            }
            let wait = self.poll_wait.min(remaining);

            match self.transport.poll(&id, wait).await {
                Ok(answer) => match answer.status.as_str() {
                    STATUS_PENDING => continue,
                    "answered" => {
                        let label = answer
                            .answers
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        return Ok(if label == approve_label {
                            Decision::Approved
                        } else {
                            Decision::Denied
                        });
                    }
                    "timeout" => return Ok(Decision::Timeout),
                    "dismissed" | "unavailable" | "cancelled" => return Ok(Decision::Denied),
                    other => {
                        warn!("askgw_http: unrecognized answer status {other:?}, denying");
                        return Ok(Decision::Denied);
                    }
                },
                Err(e) => {
                    // Fail closed at the call site (Err -> Decision::Denied),
                    // same convention as the socket backend on a hard failure.
                    return Err(e);
                }
            }
        }
    }

    /// The assumed contract has no `notify`-equivalent endpoint (see module
    /// doc "Known gap"). Log locally so the operator isn't silently left
    /// without ANY record of the event, rather than pretending it was
    /// delivered.
    fn log_unsupported_notify(&self, what: &str, text: &str) {
        warn!(
            "askgw_http: {what} not delivered — HTTP askgw has no notify endpoint in the \
             assumed contract (see notification::askgw_http module doc, notes-1464.md): {text}"
        );
    }
}

#[async_trait::async_trait]
impl NotificationBackend for AskgwHttpBackend {
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
        let vault = if record.session_active {
            "unlocked"
        } else {
            "locked"
        };
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
        self.log_unsupported_notify(
            "BW-locked notification",
            &format!("item={} field={}", record.item_name, record.field),
        );
        Ok(())
    }

    async fn send_access_link(&self, url: &str) -> Result<()> {
        self.log_unsupported_notify("web access link", url);
        Ok(())
    }

    async fn send_scrub_complete(&self, request_id: &str, item_name: &str) -> Result<()> {
        self.log_unsupported_notify(
            "scrub-complete notification",
            &format!("request={request_id} item={item_name}"),
        );
        Ok(())
    }

    async fn update_completion_status(&self, info: &CompletionInfo) {
        self.log_unsupported_notify(
            "completion status update",
            &format!("request={} exit={}", info.request_id, info.exit_code),
        );
    }

    fn name(&self) -> &'static str {
        "askgw_http"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

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
    fn test_deserialize_answer_frame() {
        let raw = r#"{"protocol":"askgw/1","type":"answer","id":"x","status":"answered","answers":{"decision":"Approve"}}"#;
        let frame: AnswerFrame = serde_json::from_str(raw).unwrap();
        assert_eq!(frame.status, "answered");
        assert_eq!(
            frame.answers.get("decision").and_then(|v| v.as_str()),
            Some("Approve")
        );
    }

    #[test]
    fn test_deserialize_pending_answer() {
        let raw = r#"{"protocol":"askgw/1","type":"answer","id":"x","status":"pending"}"#;
        let frame: AnswerFrame = serde_json::from_str(raw).unwrap();
        assert_eq!(frame.status, STATUS_PENDING);
        assert!(frame.answers.is_empty());
    }

    /// Fake [`Transport`] driven by a scripted sequence of poll results, so
    /// `ask_and_wait`'s orchestration (loop-until-terminal, timeout, cancel-
    /// on-give-up) can be tested without a real HTTP server — the seam the
    /// module doc describes.
    struct FakeTransport {
        submit_result: Result<(), String>,
        /// Each poll() call pops the next scripted result.
        poll_results: Mutex<Vec<Result<AnswerFrame, String>>>,
        poll_calls: Arc<AtomicUsize>,
        cancel_calls: Arc<AtomicUsize>,
    }

    impl FakeTransport {
        fn answered(label: &str) -> Vec<Result<AnswerFrame, String>> {
            vec![Ok(AnswerFrame {
                status: "answered".into(),
                answers: HashMap::from([(
                    "decision".into(),
                    serde_json::Value::String(label.into()),
                )]),
            })]
        }
    }

    #[async_trait::async_trait]
    impl Transport for FakeTransport {
        async fn submit(&self, _frame: &AskFrame<'_>) -> Result<()> {
            self.submit_result.clone().map_err(|e| anyhow!(e))
        }

        async fn poll(&self, _id: &str, _wait: Duration) -> Result<AnswerFrame> {
            self.poll_calls.fetch_add(1, Ordering::SeqCst);
            let mut results = self.poll_results.lock().unwrap();
            if results.is_empty() {
                return Ok(AnswerFrame {
                    status: STATUS_PENDING.into(),
                    answers: HashMap::new(),
                });
            }
            results.remove(0).map_err(|e| anyhow!(e))
        }

        async fn cancel(&self, _id: &str, _reason: &str) {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Builds a backend over `transport`, returning it alongside the shared
    /// poll/cancel call counters (the test asserts on the counters directly,
    /// since the backend only exposes `transport` as `Box<dyn Transport>`).
    fn backend_with(
        transport_no_counters: FakeTransportSpec,
        timeout: Duration,
        poll_wait: Duration,
    ) -> (AskgwHttpBackend, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let poll_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let transport = FakeTransport {
            submit_result: transport_no_counters.submit_result,
            poll_results: Mutex::new(transport_no_counters.poll_results),
            poll_calls: Arc::clone(&poll_calls),
            cancel_calls: Arc::clone(&cancel_calls),
        };
        let backend =
            AskgwHttpBackend::with_transport(Box::new(transport), timeout, poll_wait, None);
        (backend, poll_calls, cancel_calls)
    }

    /// Plain-data spec for building a [`FakeTransport`] via [`backend_with`],
    /// decoupled from the shared atomics so callers don't have to construct
    /// those themselves.
    struct FakeTransportSpec {
        submit_result: Result<(), String>,
        poll_results: Vec<Result<AnswerFrame, String>>,
    }

    #[tokio::test]
    async fn test_ask_and_wait_approved() {
        let (backend, ..) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results: FakeTransport::answered("Approve"),
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let decision = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Approved);
    }

    #[tokio::test]
    async fn test_ask_and_wait_denied() {
        let (backend, ..) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results: FakeTransport::answered("Deny"),
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let decision = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn test_ask_and_wait_re_polls_while_pending() {
        let poll_results: Vec<Result<AnswerFrame, String>> = vec![
            Ok(AnswerFrame {
                status: STATUS_PENDING.into(),
                answers: HashMap::new(),
            }),
            Ok(AnswerFrame {
                status: STATUS_PENDING.into(),
                answers: HashMap::new(),
            }),
        ]
        .into_iter()
        .chain(FakeTransport::answered("Approve"))
        .collect();
        let (backend, poll_calls, _cancel_calls) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results,
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let decision = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Approved);
        assert_eq!(poll_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_ask_and_wait_dismissed_denies() {
        let (backend, ..) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results: vec![Ok(AnswerFrame {
                    status: "dismissed".into(),
                    answers: HashMap::new(),
                })],
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let decision = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn test_ask_and_wait_unavailable_denies() {
        let (backend, ..) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results: vec![Ok(AnswerFrame {
                    status: "unavailable".into(),
                    answers: HashMap::new(),
                })],
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let decision = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Denied);
    }

    #[tokio::test]
    async fn test_ask_and_wait_timeout_cancels_and_times_out() {
        let (backend, _poll_calls, cancel_calls) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                // Always pending -> overall deadline elapses -> Decision::Timeout + cancel.
                poll_results: vec![],
            },
            Duration::from_millis(30),
            Duration::from_millis(10),
        );
        let decision = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Timeout);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_ask_and_wait_submit_failure_errs() {
        let (backend, ..) = backend_with(
            FakeTransportSpec {
                submit_result: Err("connection refused".into()),
                poll_results: vec![],
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let result = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ask_and_wait_poll_error_errs() {
        let (backend, ..) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results: vec![Err("network blip".into())],
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        let result = backend
            .ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            )
            .await;
        assert!(result.is_err());
    }
}
