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
//! The [`Transport`] trait isolates the wire shape (submit / poll / cancel /
//! notify) from the ask-and-wait orchestration in [`AskgwHttpBackend`]. If
//! foci #1463 lands a different shape (e.g. a single held-open call, or
//! submit-returns-id-then-webhook), only a new `Transport` impl is needed —
//! the `NotificationBackend` impl and the rest of this file are unaffected.
//!
//! # Fire-and-forget notifications (#1467) — ASSUMED, RECONCILE against foci #1466
//!
//! The four `NotificationBackend` methods that don't wait for a decision
//! (Bitwarden-locked notices, access links, scrub-complete, and command
//! completion status) POST a `notify` frame to `{endpoint}/askgw/notify`
//! (Bearer-auth'd the same as `ask`, fire-and-forget — no id/poll, unlike the
//! `ask` flow). foci's HTTP notify endpoint (todo #1466) was unbuilt when this
//! was written, so the body shape below is this side's assumption — mirrors
//! the socket transport's `notify` frame ([`super::askgw::AskgwBackend`]'s
//! `NotifyFrame`: `protocol`, `type`, `id`, `kind`, `level`, `title`, `text`)
//! plus `source` and `agent` (present on `ask` but absent from the socket
//! transport's notify, since HTTP has no persistent per-agent connection to
//! carry that context implicitly). See `notes-1467.md` (repo root) for the
//! exact JSON, prominently, for reconciliation. A delivery failure (network
//! error or non-2xx) is logged and swallowed, never propagated to the
//! caller — these are informational, same as the socket backend's
//! `try_send`-and-drop.
//!
//! # Primary + fallback endpoint (#2742)
//!
//! `[askgw_http]` takes an optional `fallback_endpoint` next to `endpoint`
//! (e.g. foci's LAN address primary, its Tailscale address fallback, so an
//! approval still reaches Dick when the host is off the home LAN).
//! [`FallbackTransport`] tries the endpoints in order, and moves on ONLY when
//! the request cannot have had an effect on the endpoint it left:
//!
//! - `submit` and `notify` move on only when the request was NOT SENT (the
//!   connection could not be made: refused, no route, DNS, connect timeout).
//!   A request that was sent but got no response may already have created
//!   the ask or posted the message; resubmitting it elsewhere would show
//!   Dick a duplicate (two servers) or be rejected as `duplicate_id` (one
//!   server reached by two addresses — foci's askgw HTTP handler keys on the
//!   ask id). So that failure is returned as before.
//! - `poll` and `cancel` are idempotent, so they move on after any failure
//!   that produced no HTTP response. They start at the endpoint that
//!   accepted the submit (the ask lives there), then try the others. Any
//!   HTTP response (e.g. 404 unknown id from a different server) ends the
//!   attempt as before — fail closed.
//!
//! A `connect_timeout` on the HTTP client bounds how long an unreachable
//! address (a LAN IP blackholed on a foreign network) holds up the move to
//! the next endpoint.

use super::{
    BwConfirmRecord, BwRequestRecord, CompletionInfo, NotificationBackend, TempRuleRecord,
};
use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

/// Body for `POST /askgw/notify` — the ASSUMED fire-and-forget contract (see
/// module doc). Mirrors the socket transport's `NotifyFrame` fields, plus
/// `source`/`agent` to carry routing context HTTP has no other way to convey.
#[derive(Debug, Serialize)]
struct NotifyFrame<'a> {
    protocol: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    id: String,
    source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    text: String,
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
    /// The caller logs an `Err`, never propagates it — cancellation is a
    /// courtesy to free server-side state, not required for correctness on
    /// this side. (It returns `Result` so [`FallbackTransport`] can tell an
    /// unreachable endpoint from a delivered cancel.)
    async fn cancel(&self, id: &str, reason: &str) -> Result<()>;

    /// Deliver a fire-and-forget `notify` frame. `Err` means delivery failed
    /// (network error or non-2xx) — the caller logs and swallows it, same
    /// convention as `cancel`.
    async fn notify(&self, frame: &NotifyFrame<'_>) -> Result<()>;
}

/// Why a request produced no HTTP response. Carried inside the `anyhow::Error`
/// a [`LongPollTransport`] call returns, so [`FallbackTransport`] can decide
/// whether moving to the next endpoint is safe (see module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendFailureKind {
    /// The connection was never made, so the server saw nothing.
    NotSent,
    /// The request may have reached the server (e.g. timed out waiting for
    /// the response). Its effect on the server is unknown.
    NoResponse,
}

#[derive(Debug)]
struct SendFailure {
    kind: SendFailureKind,
    op: &'static str,
    source: reqwest::Error,
}

impl std::fmt::Display for SendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "askgw_http: {} request failed: {}", self.op, self.source)
    }
}

impl std::error::Error for SendFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn send_failure(op: &'static str, source: reqwest::Error) -> anyhow::Error {
    let kind = if source.is_connect() {
        SendFailureKind::NotSent
    } else {
        SendFailureKind::NoResponse
    };
    anyhow::Error::new(SendFailure { kind, op, source })
}

/// The [`SendFailureKind`] of `e`, or `None` when `e` is not a send failure
/// (an HTTP error response, a malformed body, ...).
fn send_failure_kind(e: &anyhow::Error) -> Option<SendFailureKind> {
    e.downcast_ref::<SendFailure>().map(|f| f.kind)
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
            .map_err(|e| send_failure("submit", e))?;

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
            .map_err(|e| send_failure("poll", e))?;

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

    async fn cancel(&self, id: &str, reason: &str) -> Result<()> {
        let resp = self
            .client
            .post(self.url(&format!("/askgw/ask/{id}/cancel")))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({"reason": reason}))
            .send()
            .await
            .map_err(|e| send_failure("cancel", e))?;
        if resp.status().is_success() {
            debug!("askgw_http: cancelled {id} ({reason})");
            return Ok(());
        }
        Err(anyhow!(
            "askgw_http: cancel {id} returned HTTP {}",
            resp.status()
        ))
    }

    async fn notify(&self, frame: &NotifyFrame<'_>) -> Result<()> {
        let resp = self
            .client
            .post(self.url("/askgw/notify"))
            .bearer_auth(&self.api_key)
            .json(frame)
            .send()
            .await
            .map_err(|e| send_failure("notify", e))?;

        if resp.status().is_success() {
            return Ok(());
        }
        Err(anyhow!(
            "askgw_http: notify rejected: HTTP {}",
            resp.status()
        ))
    }
}

/// Withdraws a live ask when its wait is abandoned (#2741): the future was dropped, or the
/// poll failed. `Transport::cancel` is async and `Drop` is not, so the cancel runs on a
/// spawned task; with no runtime (never the case in the daemon) it is skipped and logged.
struct HttpCancelOnDrop {
    id: String,
    reason: &'static str,
    transport: Arc<dyn Transport>,
    armed: bool,
}

impl Drop for HttpCancelOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (id, reason, transport) = (
            std::mem::take(&mut self.id),
            self.reason,
            Arc::clone(&self.transport),
        );
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                tracing::info!("askgw_http: withdrawing ask {id} ({reason})");
                handle.spawn(async move {
                    if let Err(e) = transport.cancel(&id, reason).await {
                        warn!("askgw_http: cancel {id} failed: {e:#}");
                    }
                });
            }
            Err(_) => warn!("askgw_http: no runtime to withdraw ask {id} ({reason})"),
        }
    }
}

/// Tries an ordered list of endpoints (primary first) — see the module doc
/// "Primary + fallback endpoint" for when it moves to the next one. With a
/// single endpoint it behaves exactly like that endpoint's transport.
struct FallbackTransport {
    /// (base URL for logs, transport), in preference order.
    endpoints: Vec<(String, Box<dyn Transport>)>,
    /// Ask id -> index of the endpoint that accepted its submit (or last
    /// answered its poll). Removed when the ask reaches a terminal state or
    /// is cancelled. A failed poll keeps it: the backend cancels after a
    /// failed poll (#2741), and that cancel must reach the endpoint holding
    /// the ask first.
    pinned: Mutex<HashMap<String, usize>>,
}

impl FallbackTransport {
    fn new(endpoints: Vec<(String, Box<dyn Transport>)>) -> Self {
        assert!(!endpoints.is_empty(), "FallbackTransport needs an endpoint");
        Self {
            endpoints,
            pinned: Mutex::new(HashMap::new()),
        }
    }

    /// Endpoint indices to try for an existing ask: its pinned endpoint
    /// first, then the rest in preference order.
    fn order_for(&self, id: &str) -> Vec<usize> {
        let first = self.pinned.lock().unwrap().get(id).copied().unwrap_or(0);
        std::iter::once(first)
            .chain((0..self.endpoints.len()).filter(|&i| i != first))
            .collect()
    }

    fn has_next(&self, pos: usize, total: usize) -> bool {
        pos + 1 < total
    }
}

#[async_trait::async_trait]
impl Transport for FallbackTransport {
    async fn submit(&self, frame: &AskFrame<'_>) -> Result<()> {
        let n = self.endpoints.len();
        for (i, (url, t)) in self.endpoints.iter().enumerate() {
            match t.submit(frame).await {
                Ok(()) => {
                    self.pinned.lock().unwrap().insert(frame.id.clone(), i);
                    return Ok(());
                }
                Err(e)
                    if send_failure_kind(&e) == Some(SendFailureKind::NotSent)
                        && self.has_next(i, n) =>
                {
                    warn!("askgw_http: {url} unreachable for submit, trying next endpoint: {e:#}");
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("the last endpoint always returns")
    }

    async fn poll(&self, id: &str, wait: Duration) -> Result<AnswerFrame> {
        let order = self.order_for(id);
        let n = order.len();
        for (pos, &i) in order.iter().enumerate() {
            let (url, t) = &self.endpoints[i];
            match t.poll(id, wait).await {
                Ok(answer) => {
                    let mut pinned = self.pinned.lock().unwrap();
                    if answer.status == STATUS_PENDING {
                        pinned.insert(id.to_string(), i);
                    } else {
                        pinned.remove(id);
                    }
                    return Ok(answer);
                }
                Err(e) if send_failure_kind(&e).is_some() && self.has_next(pos, n) => {
                    warn!("askgw_http: {url} gave no response to poll {id}, trying next endpoint: {e:#}");
                }
                // The pin stays: a cancel follows, and it clears the pin.
                Err(e) => return Err(e),
            }
        }
        unreachable!("the last endpoint always returns")
    }

    async fn cancel(&self, id: &str, reason: &str) -> Result<()> {
        let order = self.order_for(id);
        let n = order.len();
        let mut result = Ok(());
        for (pos, &i) in order.iter().enumerate() {
            let (url, t) = &self.endpoints[i];
            result = t.cancel(id, reason).await;
            match &result {
                Err(e) if send_failure_kind(e).is_some() && self.has_next(pos, n) => {
                    warn!("askgw_http: {url} gave no response to cancel {id}, trying next endpoint: {e:#}");
                }
                _ => break,
            }
        }
        self.pinned.lock().unwrap().remove(id);
        result
    }

    async fn notify(&self, frame: &NotifyFrame<'_>) -> Result<()> {
        let n = self.endpoints.len();
        for (i, (url, t)) in self.endpoints.iter().enumerate() {
            match t.notify(frame).await {
                Err(e)
                    if send_failure_kind(&e) == Some(SendFailureKind::NotSent)
                        && self.has_next(i, n) =>
                {
                    warn!("askgw_http: {url} unreachable for notify, trying next endpoint: {e:#}");
                }
                other => return other,
            }
        }
        unreachable!("the last endpoint always returns")
    }
}

pub struct AskgwHttpBackend {
    /// `Arc` so [`HttpCancelOnDrop`] can run the cancel on a spawned task.
    transport: Arc<dyn Transport>,
    /// Overall wait for a human decision — bounds the submit+poll loop.
    /// Mirrors the socket backend's `timeout` field/semantics exactly.
    timeout: Duration,
    /// Per-GET long-poll wait, clamped by foci's own server-side max.
    poll_wait: Duration,
    agent: Option<String>,
}

impl AskgwHttpBackend {
    /// `endpoints` is the preference order: `[askgw_http].endpoint`, then
    /// `fallback_endpoint` if set (see module doc "Primary + fallback
    /// endpoint").
    pub fn new(
        endpoints: Vec<String>,
        api_key: String,
        agent: Option<String>,
        timeout: Duration,
        poll_wait: Duration,
        request_timeout: Duration,
        connect_timeout: Duration,
    ) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(anyhow!("askgw_http: no endpoint configured"));
        }
        let client = Client::builder()
            .timeout(request_timeout)
            .connect_timeout(connect_timeout)
            .build()
            .map_err(|e| anyhow!("askgw_http: failed to build HTTP client: {e}"))?;
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| {
                let t: Box<dyn Transport> = Box::new(LongPollTransport {
                    // reqwest's Client is an Arc handle: clones share one pool.
                    client: client.clone(),
                    endpoint: endpoint.clone(),
                    api_key: api_key.clone(),
                });
                (endpoint, t)
            })
            .collect();
        Ok(Self {
            transport: Arc::new(FallbackTransport::new(endpoints)),
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
            transport: Arc::from(transport),
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

        // From here the ask is live on the approver's device. If this future is dropped
        // before a terminal answer (the requester disconnected, #2741) or the poll fails,
        // the guard withdraws it so nobody can approve a request whose answer goes nowhere.
        // The cancel goes through the same transport, so with a fallback endpoint it
        // reaches the endpoint that accepted the ask first.
        let mut guard = HttpCancelOnDrop {
            id: id.clone(),
            reason: "requester disconnected",
            transport: Arc::clone(&self.transport),
            armed: true,
        };

        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                guard.armed = false;
                if let Err(e) = self.transport.cancel(&id, "timeout").await {
                    warn!("askgw_http: cancel {id} failed: {e:#}");
                }
                return Ok(Decision::Timeout);
            }
            let wait = self.poll_wait.min(remaining);

            let polled = self.transport.poll(&id, wait).await;
            // Any status other than pending is terminal on the server: nothing to withdraw.
            if matches!(&polled, Ok(a) if a.status != STATUS_PENDING) {
                guard.armed = false;
            }
            match polled {
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
                    // The guard withdraws the ask: we have stopped listening for it.
                    guard.reason = "poll failed";
                    return Err(e);
                }
            }
        }
    }

    /// Build and POST a `notify` frame (see module doc "Fire-and-forget
    /// notifications"). Always returns `Ok(())` — delivery failure is
    /// logged, not propagated, matching the socket backend's
    /// try_send-and-drop semantics (see `askgw::AskgwBackend::send_notify`).
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
            source: "aisudo",
            agent: self.agent.as_deref(),
            kind,
            level,
            title,
            text,
        };
        if let Err(e) = self.transport.notify(&frame).await {
            warn!("askgw_http: notify delivery failed: {e:#}");
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl NotificationBackend for AskgwHttpBackend {
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision> {
        let question = super::askgw_sudo_question(record);
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
        let question = super::askgw_temp_rule_question(record);
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

    #[test]
    fn test_serialize_notify_frame() {
        let frame = NotifyFrame {
            protocol: PROTOCOL,
            frame_type: "notify",
            id: "n1".into(),
            source: "aisudo",
            agent: Some("clutch"),
            kind: Some("completion"),
            level: Some("success"),
            title: None,
            text: "exit 0".into(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"type\":\"notify\""));
        assert!(json.contains("\"kind\":\"completion\""));
        assert!(json.contains("\"level\":\"success\""));
        assert!(json.contains("\"agent\":\"clutch\""));
        assert!(!json.contains("title"));
    }

    #[test]
    fn test_serialize_notify_frame_without_agent() {
        let frame = NotifyFrame {
            protocol: PROTOCOL,
            frame_type: "notify",
            id: "n2".into(),
            source: "aisudo",
            agent: None,
            kind: None,
            level: None,
            title: None,
            text: "hi".into(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(!json.contains("agent"));
        assert!(!json.contains("kind"));
    }

    /// (kind, level, title, text) of one captured `notify()` call, owned
    /// since `NotifyFrame`'s fields borrow from the caller's stack frame.
    type NotifyCall = (Option<String>, Option<String>, Option<String>, String);

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
        notify_result: Result<(), String>,
        notify_calls: Arc<AtomicUsize>,
        notify_frames: Arc<Mutex<Vec<NotifyCall>>>,
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

        async fn poll(&self, _id: &str, wait: Duration) -> Result<AnswerFrame> {
            self.poll_calls.fetch_add(1, Ordering::SeqCst);
            let next = {
                let mut results = self.poll_results.lock().unwrap();
                (!results.is_empty()).then(|| results.remove(0))
            };
            if let Some(r) = next {
                return r.map_err(|e| anyhow!(e));
            }
            // Out of scripted answers: a long-poll that elapses with nothing, as the real
            // server's does. Sleeping (not returning at once) lets a caller's timeout fire.
            tokio::time::sleep(wait).await;
            Ok(AnswerFrame {
                status: STATUS_PENDING.into(),
                answers: HashMap::new(),
            })
        }

        async fn cancel(&self, _id: &str, _reason: &str) -> Result<()> {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn notify(&self, frame: &NotifyFrame<'_>) -> Result<()> {
            self.notify_calls.fetch_add(1, Ordering::SeqCst);
            self.notify_frames.lock().unwrap().push((
                frame.kind.map(String::from),
                frame.level.map(String::from),
                frame.title.map(String::from),
                frame.text.clone(),
            ));
            self.notify_result.clone().map_err(|e| anyhow!(e))
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
            notify_result: Ok(()),
            notify_calls: Arc::new(AtomicUsize::new(0)),
            notify_frames: Arc::new(Mutex::new(Vec::new())),
        };
        let backend =
            AskgwHttpBackend::with_transport(Box::new(transport), timeout, poll_wait, None);
        (backend, poll_calls, cancel_calls)
    }

    /// Builds a backend for exercising the four fire-and-forget notify
    /// methods, decoupled from the ask/poll/cancel infra above (a separate
    /// concern) — captures every `notify()` call's (kind, level, title,
    /// text) for assertion.
    fn notify_backend_with(
        notify_result: Result<(), String>,
    ) -> (
        AskgwHttpBackend,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<NotifyCall>>>,
    ) {
        let notify_calls = Arc::new(AtomicUsize::new(0));
        let notify_frames = Arc::new(Mutex::new(Vec::new()));
        let transport = FakeTransport {
            submit_result: Ok(()),
            poll_results: Mutex::new(Vec::new()),
            poll_calls: Arc::new(AtomicUsize::new(0)),
            cancel_calls: Arc::new(AtomicUsize::new(0)),
            notify_result,
            notify_calls: Arc::clone(&notify_calls),
            notify_frames: Arc::clone(&notify_frames),
        };
        let backend = AskgwHttpBackend::with_transport(
            Box::new(transport),
            Duration::from_secs(5),
            Duration::from_millis(10),
            Some("clutch".into()),
        );
        (backend, notify_calls, notify_frames)
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
        let (backend, _poll_calls, cancel_calls) = backend_with(
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
        // We stopped listening, so the ask must not stay approvable (#2741).
        settle().await;
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    }

    /// Lets a cancel spawned from a drop guard run to completion.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// #2741: the caller drops the wait (the requester disconnected) while the ask is
    /// live. The ask must be withdrawn, or the approver can approve into the void.
    #[tokio::test]
    async fn test_ask_and_wait_dropped_mid_wait_cancels() {
        let (backend, poll_calls, cancel_calls) = backend_with(
            FakeTransportSpec {
                submit_result: Ok(()),
                poll_results: vec![],
            },
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        let waited = tokio::time::timeout(
            Duration::from_millis(50),
            backend.ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            ),
        )
        .await;
        assert!(waited.is_err(), "the wait should still have been pending");
        assert!(poll_calls.load(Ordering::SeqCst) > 0, "ask was never live");
        settle().await;
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    }

    /// An answered ask is finished on the server: no cancel follows it.
    #[tokio::test]
    async fn test_ask_and_wait_answered_does_not_cancel() {
        let (backend, _poll_calls, cancel_calls) = backend_with(
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
        settle().await;
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_update_completion_status_success_delivers_notify() {
        let (backend, notify_calls, notify_frames) = notify_backend_with(Ok(()));
        backend
            .update_completion_status(&CompletionInfo {
                request_id: "req-1".into(),
                exit_code: 0,
                last_lines: None,
            })
            .await;
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
        let frames = notify_frames.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0]
            .3
            .contains("Command completed: exit 0 (request req-1)"));
    }

    #[tokio::test]
    async fn test_update_completion_status_failure_includes_last_lines() {
        let (backend, _calls, notify_frames) = notify_backend_with(Ok(()));
        backend
            .update_completion_status(&CompletionInfo {
                request_id: "req-2".into(),
                exit_code: 1,
                last_lines: Some("boom".into()),
            })
            .await;
        let frames = notify_frames.lock().unwrap();
        assert!(frames[0].3.contains("exit 1"));
        assert!(frames[0].3.contains("boom"));
    }

    #[tokio::test]
    async fn test_update_completion_status_delivery_failure_is_swallowed() {
        // Fire-and-forget: a failed POST must not panic or surface to the
        // caller (update_completion_status returns (), not Result).
        let (backend, notify_calls, _frames) = notify_backend_with(Err("network down".into()));
        backend
            .update_completion_status(&CompletionInfo {
                request_id: "req-3".into(),
                exit_code: 0,
                last_lines: None,
            })
            .await;
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_send_bw_locked_notification_delivers_notify() {
        let (backend, notify_calls, notify_frames) = notify_backend_with(Ok(()));
        let record = BwRequestRecord {
            id: "r1".into(),
            user: "alice".into(),
            item_name: "AWS".into(),
            field: "password".into(),
            session_active: false,
            unlock_url: None,
        };
        backend.send_bw_locked_notification(&record).await.unwrap();
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
        let frames = notify_frames.lock().unwrap();
        assert_eq!(frames[0].0.as_deref(), Some("locked"));
        assert!(frames[0].3.contains("AWS"));
    }

    #[tokio::test]
    async fn test_send_access_link_delivers_notify() {
        let (backend, notify_calls, notify_frames) = notify_backend_with(Ok(()));
        backend
            .send_access_link("https://example.com/unlock")
            .await
            .unwrap();
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
        let frames = notify_frames.lock().unwrap();
        assert_eq!(frames[0].0.as_deref(), Some("access_link"));
        assert!(frames[0].3.contains("https://example.com/unlock"));
    }

    #[tokio::test]
    async fn test_send_scrub_complete_delivers_notify() {
        let (backend, notify_calls, notify_frames) = notify_backend_with(Ok(()));
        backend.send_scrub_complete("req-9", "AWS").await.unwrap();
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
        let frames = notify_frames.lock().unwrap();
        assert_eq!(frames[0].0.as_deref(), Some("completion"));
        assert!(frames[0].3.contains("AWS"));
        assert!(frames[0].3.contains("req-9"));
    }

    #[tokio::test]
    async fn test_send_bw_locked_notification_delivery_failure_still_ok() {
        // Result<()>-returning notify methods must also swallow delivery
        // failures (fire-and-forget), returning Ok(()) regardless.
        let (backend, ..) = notify_backend_with(Err("network down".into()));
        let record = BwRequestRecord {
            id: "r1".into(),
            user: "alice".into(),
            item_name: "AWS".into(),
            field: "password".into(),
            session_active: false,
            unlock_url: None,
        };
        assert!(backend.send_bw_locked_notification(&record).await.is_ok());
    }

    // ---- FallbackTransport (#2742) ----

    /// A real `SendFailure` of the given kind, built from a genuine reqwest
    /// error (reqwest errors cannot be constructed directly).
    async fn real_send_failure(kind: SendFailureKind) -> anyhow::Error {
        let source = Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .expect_err("port 1 must refuse");
        anyhow::Error::new(SendFailure {
            kind,
            op: "test",
            source,
        })
    }

    /// One scripted outcome for a [`ScriptedEndpoint`] call.
    #[derive(Clone, Copy)]
    enum Outcome {
        Ok,
        Pending,
        NotSent,
        NoResponse,
        HttpError,
    }

    /// Inner transport for FallbackTransport tests: every call returns the
    /// endpoint's fixed outcome and is recorded as "<name>:<op>".
    struct ScriptedEndpoint {
        name: &'static str,
        outcome: Outcome,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl ScriptedEndpoint {
        async fn result(&self, op: &str) -> Result<()> {
            self.log.lock().unwrap().push(format!("{}:{op}", self.name));
            match self.outcome {
                Outcome::Ok | Outcome::Pending => Ok(()),
                Outcome::NotSent => Err(real_send_failure(SendFailureKind::NotSent).await),
                Outcome::NoResponse => Err(real_send_failure(SendFailureKind::NoResponse).await),
                Outcome::HttpError => Err(anyhow!("HTTP 404")),
            }
        }
    }

    #[async_trait::async_trait]
    impl Transport for ScriptedEndpoint {
        async fn submit(&self, _frame: &AskFrame<'_>) -> Result<()> {
            self.result("submit").await
        }
        async fn poll(&self, _id: &str, wait: Duration) -> Result<AnswerFrame> {
            self.result("poll").await?;
            if matches!(self.outcome, Outcome::Pending) {
                // A long-poll that elapses with no answer, so a caller's timeout can fire.
                tokio::time::sleep(wait).await;
            }
            Ok(AnswerFrame {
                status: match self.outcome {
                    Outcome::Pending => STATUS_PENDING.into(),
                    _ => "answered".into(),
                },
                answers: HashMap::new(),
            })
        }
        async fn cancel(&self, _id: &str, _reason: &str) -> Result<()> {
            self.result("cancel").await
        }
        async fn notify(&self, _frame: &NotifyFrame<'_>) -> Result<()> {
            self.result("notify").await
        }
    }

    fn fallback(
        primary: Outcome,
        secondary: Outcome,
    ) -> (FallbackTransport, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ep = |name: &'static str, outcome: Outcome| -> (String, Box<dyn Transport>) {
            (
                name.to_string(),
                Box::new(ScriptedEndpoint {
                    name,
                    outcome,
                    log: Arc::clone(&log),
                }),
            )
        };
        (
            FallbackTransport::new(vec![ep("lan", primary), ep("ts", secondary)]),
            log,
        )
    }

    fn ask_frame(id: &str) -> AskFrame<'static> {
        AskFrame {
            protocol: PROTOCOL,
            frame_type: "ask",
            id: id.into(),
            source: "aisudo",
            timeout_seconds: 60.0,
            questions: vec![],
            agent: None,
        }
    }

    fn notify_frame() -> NotifyFrame<'static> {
        NotifyFrame {
            protocol: PROTOCOL,
            frame_type: "notify",
            id: "n".into(),
            source: "aisudo",
            agent: None,
            kind: None,
            level: None,
            title: None,
            text: "t".into(),
        }
    }

    fn calls(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn fallback_primary_reachable_never_touches_fallback() {
        let (t, log) = fallback(Outcome::Ok, Outcome::Ok);
        t.submit(&ask_frame("a")).await.unwrap();
        t.poll("a", Duration::ZERO).await.unwrap();
        t.notify(&notify_frame()).await.unwrap();
        assert_eq!(calls(&log), ["lan:submit", "lan:poll", "lan:notify"]);
    }

    #[tokio::test]
    async fn fallback_submit_moves_on_when_primary_not_sent_and_pins_ask() {
        // Primary down for submit; both reachable later would still poll the
        // endpoint that holds the ask. Here the primary stays down, so poll
        // goes straight to the pinned fallback without retrying the primary.
        let (t, log) = fallback(Outcome::NotSent, Outcome::Pending);
        t.submit(&ask_frame("a")).await.unwrap();
        t.poll("a", Duration::ZERO).await.unwrap();
        t.cancel("a", "timeout").await.unwrap();
        assert_eq!(
            calls(&log),
            ["lan:submit", "ts:submit", "ts:poll", "ts:cancel"]
        );
    }

    #[tokio::test]
    async fn fallback_submit_does_not_resubmit_after_no_response() {
        // The primary may hold the ask already: resubmitting would duplicate
        // it, so the failure is returned and the fallback is not touched.
        let (t, log) = fallback(Outcome::NoResponse, Outcome::Ok);
        let err = t.submit(&ask_frame("a")).await.unwrap_err();
        assert_eq!(send_failure_kind(&err), Some(SendFailureKind::NoResponse));
        assert_eq!(calls(&log), ["lan:submit"]);
    }

    #[tokio::test]
    async fn fallback_submit_does_not_move_on_http_rejection() {
        let (t, log) = fallback(Outcome::HttpError, Outcome::Ok);
        t.submit(&ask_frame("a")).await.unwrap_err();
        assert_eq!(calls(&log), ["lan:submit"]);
    }

    #[tokio::test]
    async fn fallback_both_unreachable_returns_last_error() {
        let (t, log) = fallback(Outcome::NotSent, Outcome::NotSent);
        let err = t.submit(&ask_frame("a")).await.unwrap_err();
        assert_eq!(send_failure_kind(&err), Some(SendFailureKind::NotSent));
        assert_eq!(calls(&log), ["lan:submit", "ts:submit"]);
    }

    #[tokio::test]
    async fn fallback_poll_moves_on_after_no_response() {
        // Poll is idempotent, so even an ambiguous failure moves on.
        let (t, log) = fallback(Outcome::NoResponse, Outcome::Ok);
        let answer = t.poll("a", Duration::ZERO).await.unwrap();
        assert_eq!(answer.status, "answered");
        assert_eq!(calls(&log), ["lan:poll", "ts:poll"]);
    }

    #[tokio::test]
    async fn fallback_poll_does_not_move_on_http_error() {
        // A 404 from the endpoint that should hold the ask fails closed.
        let (t, log) = fallback(Outcome::HttpError, Outcome::Ok);
        t.poll("a", Duration::ZERO).await.unwrap_err();
        assert_eq!(calls(&log), ["lan:poll"]);
    }

    #[tokio::test]
    async fn fallback_notify_moves_on_only_when_not_sent() {
        let (t, log) = fallback(Outcome::NotSent, Outcome::Ok);
        t.notify(&notify_frame()).await.unwrap();
        assert_eq!(calls(&log), ["lan:notify", "ts:notify"]);

        let (t, log) = fallback(Outcome::NoResponse, Outcome::Ok);
        t.notify(&notify_frame()).await.unwrap_err();
        assert_eq!(calls(&log), ["lan:notify"]);
    }

    #[tokio::test]
    async fn fallback_terminal_poll_and_cancel_clear_pin() {
        let (t, _log) = fallback(Outcome::NotSent, Outcome::Ok);
        t.submit(&ask_frame("a")).await.unwrap();
        assert_eq!(t.pinned.lock().unwrap().get("a"), Some(&1));
        t.poll("a", Duration::ZERO).await.unwrap(); // "answered" = terminal
        assert!(t.pinned.lock().unwrap().is_empty());

        t.submit(&ask_frame("b")).await.unwrap();
        t.cancel("b", "timeout").await.unwrap();
        assert!(t.pinned.lock().unwrap().is_empty());
    }

    /// #2741: a failed poll keeps the pin, so the cancel that follows it goes to the
    /// endpoint holding the ask first, not to the primary.
    #[tokio::test]
    async fn fallback_cancel_after_failed_poll_goes_to_pinned_endpoint() {
        let (t, log) = fallback(Outcome::Ok, Outcome::HttpError);
        t.pinned.lock().unwrap().insert("a".into(), 1);
        t.poll("a", Duration::ZERO).await.unwrap_err();
        t.cancel("a", "poll failed").await.unwrap_err();
        assert_eq!(calls(&log), ["ts:poll", "ts:cancel"]);
        assert!(t.pinned.lock().unwrap().is_empty());
    }

    /// #2741 with a fallback: the ask was accepted by the fallback (primary down), then
    /// the requester disconnects. The withdrawal must reach the fallback, which holds it.
    #[tokio::test]
    async fn fallback_dropped_wait_cancels_on_accepting_endpoint() {
        let (t, log) = fallback(Outcome::NotSent, Outcome::Pending);
        let backend = AskgwHttpBackend::with_transport(
            Box::new(t),
            Duration::from_secs(60),
            Duration::from_millis(10),
            None,
        );
        let waited = tokio::time::timeout(
            Duration::from_millis(50),
            backend.ask_and_wait(
                "Sudo",
                "q".into(),
                "Approve",
                "Deny",
                "a".into(),
                "d".into(),
            ),
        )
        .await;
        assert!(waited.is_err(), "the wait should still have been pending");
        settle().await;
        let log = calls(&log);
        assert_eq!(&log[..2], ["lan:submit", "ts:submit"]);
        assert_eq!(log.last().map(String::as_str), Some("ts:cancel"), "{log:?}");
        assert!(!log.contains(&"lan:cancel".to_string()), "{log:?}");
    }

    /// End to end over real sockets: the primary is a closed localhost port
    /// (connection refused), the fallback a real HTTP server speaking the
    /// askgw contract. The approval must arrive through the fallback.
    #[tokio::test]
    async fn backend_approval_arrives_via_fallback_when_primary_refuses() {
        use axum::routing::{get, post};

        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let primary = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);

        let hits = Arc::new(Mutex::new(Vec::<String>::new()));
        let (h1, h2) = (Arc::clone(&hits), Arc::clone(&hits));
        let app = axum::Router::new()
            .route(
                "/askgw/ask",
                post(move || async move {
                    h1.lock().unwrap().push("submit".into());
                    (
                        axum::http::StatusCode::ACCEPTED,
                        axum::Json(serde_json::json!({"status": "pending"})),
                    )
                }),
            )
            .route(
                "/askgw/ask/:id",
                get(move || async move {
                    h2.lock().unwrap().push("poll".into());
                    axum::Json(serde_json::json!({
                        "status": "answered",
                        "answers": {"decision": "Approve"}
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let backend = AskgwHttpBackend::new(
            vec![primary, fallback_url],
            "k".into(),
            None,
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(5),
            Duration::from_secs(2),
        )
        .unwrap();
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
        assert_eq!(*hits.lock().unwrap(), ["submit", "poll"]);
    }

    /// The classification the fallback rests on: a refused connection is
    /// NotSent (safe to resubmit elsewhere).
    #[tokio::test]
    async fn refused_connection_is_classified_not_sent() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        let t = LongPollTransport {
            client: Client::new(),
            endpoint: url,
            api_key: "k".into(),
        };
        let err = t.submit(&ask_frame("a")).await.unwrap_err();
        assert_eq!(send_failure_kind(&err), Some(SendFailureKind::NotSent));
        assert!(err
            .to_string()
            .starts_with("askgw_http: submit request failed:"));
    }
}
