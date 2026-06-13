use crate::bw_session::BwSessionManager;
use crate::db::Database;
use crate::notification::NotificationBackend;
use crate::web_auth::WebAuth;
use axum::{
    body::Body,
    extract::{ConnectInfo, Form, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use dashmap::DashMap;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

const SESSION_COOKIE: &str = "aibw_session";
/// Window over which master-password attempts are counted for a session.
const ATTEMPT_WINDOW: Duration = Duration::from_secs(60);

/// Shared state for the web UI.
#[derive(Clone)]
pub struct WebState {
    pub bw_session: Arc<BwSessionManager>,
    pub db: Arc<Database>,
    /// Channels for signaling pending BW requests when vault is unlocked via web UI.
    pub pending_unlocks: Arc<DashMap<String, oneshot::Sender<()>>>,
    pub max_password_attempts: u32,
    pub web_auth: Arc<WebAuth>,
    pub backend: Arc<dyn NotificationBackend>,
    /// Master-password attempts per session: (count, window_start).
    password_attempts: Arc<DashMap<String, (u32, Instant)>>,
}

impl WebState {
    pub fn new(
        bw_session: Arc<BwSessionManager>,
        db: Arc<Database>,
        pending_unlocks: Arc<DashMap<String, oneshot::Sender<()>>>,
        max_password_attempts: u32,
        web_auth: Arc<WebAuth>,
        backend: Arc<dyn NotificationBackend>,
    ) -> Self {
        Self {
            bw_session,
            db,
            pending_unlocks,
            max_password_attempts,
            web_auth,
            backend,
            password_attempts: Arc::new(DashMap::new()),
        }
    }
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route(
            "/aibw",
            get(|| async { axum::response::Redirect::permanent("/aibw/") }),
        )
        .route("/aibw/", get(dashboard))
        .route("/aibw/request-code", axum::routing::post(request_code))
        .route("/aibw/unlock", get(unlock_get).post(unlock_submit))
        .route("/aibw/status", get(status_json))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

pub async fn run_web_server(state: WebState, port: u16) {
    let app = router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("Web UI listening on http://{addr}/aibw/");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind web UI to {addr}: {e}");
            return;
        }
    };

    // ConnectInfo gives handlers the peer address (used for code-request rate limiting).
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!("Web UI server error: {e}");
    }
}

// ---------------------------------------------------------------------------
// Middleware: security headers on every response
// ---------------------------------------------------------------------------

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    resp
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Extract the session id from the request cookies, if present.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        if let Some(v) = part.trim().strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// True if the request carries a valid session cookie.
fn has_session(headers: &HeaderMap, state: &WebState) -> bool {
    session_cookie(headers)
        .map(|sid| state.web_auth.is_session_valid(&sid))
        .unwrap_or(false)
}

/// Build a `Set-Cookie` header value for a freshly minted session.
fn session_cookie_header(state: &WebState, session_id: &str) -> String {
    format!(
        "{SESSION_COOKIE}={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/aibw; Max-Age={}",
        state.web_auth.session_max_age()
    )
}

/// Caller identity for code-request rate limiting: Tailscale login if present
/// (the daemon sees only loopback behind `tailscale serve`), else the peer IP.
fn caller_identity(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(login) = headers
        .get("tailscale-user-login")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        return format!("ts:{login}");
    }
    format!("ip:{}", addr.ip())
}

/// A 303 redirect that also sets the session cookie.
fn redirect_with_cookie(location: &str, cookie: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
        .into_response()
}

/// Escape text for safe interpolation into HTML.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Accept only UUID-shaped identifiers before reflecting them into HTML/links.
fn is_uuidish(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Sanitize a reflected request id: return it only if it is UUID-shaped.
fn clean_request_id(req: Option<&str>) -> Option<String> {
    req.filter(|r| is_uuidish(r)).map(|r| r.to_string())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn dashboard(State(state): State<WebState>, headers: HeaderMap) -> Html<String> {
    if !has_session(&headers, &state) {
        return Html(login_page(None));
    }

    let session_active = state.bw_session.is_session_active().await;
    let locked_since = state.bw_session.locked_since().await;
    let last_used = state.bw_session.last_used_time().await;

    let pending = state.db.get_pending_bw_requests().unwrap_or_default();
    let recent = state.db.get_recent_bw_requests(10).unwrap_or_default();

    let status_class = if session_active { "unlocked" } else { "locked" };
    let status_icon = if session_active {
        "&#x1f513;"
    } else {
        "&#x1f512;"
    };
    let status_text = if session_active { "Unlocked" } else { "Locked" };

    let locked_info = match locked_since {
        Some(since) => format!(
            "<br><small>Since: {}</small>",
            since.format("%Y-%m-%d %H:%M:%S UTC")
        ),
        None => String::new(),
    };
    let last_used_info = match last_used {
        Some(ref t) => format!("<br><small>Last used: {}</small>", html_escape(t)),
        None => String::new(),
    };

    let pending_rows = if pending.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\">No pending requests</td></tr>".to_string()
    } else {
        pending
            .iter()
            .map(|r| {
                let action = if session_active {
                    "<span class=\"muted\">Approve via Telegram</span>".to_string()
                } else if is_uuidish(&r.id) {
                    format!(
                        "<a class=\"btn btn-primary\" href=\"/aibw/unlock?request={}\">Unlock &amp; Approve</a>",
                        html_escape(&r.id)
                    )
                } else {
                    "<span class=\"muted\">Approve via Telegram</span>".to_string()
                };
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    html_escape(&r.id[..8.min(r.id.len())]),
                    html_escape(&r.user),
                    html_escape(&r.item_name),
                    html_escape(&r.field),
                    action,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let recent_rows = if recent.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\">No recent requests</td></tr>".to_string()
    } else {
        recent
            .iter()
            .map(|r| {
                let badge_class = match r.status.as_str() {
                    "approved" | "confirmed" => "badge badge-ok",
                    "denied" | "cancelled" => "badge badge-deny",
                    "timeout" => "badge badge-timeout",
                    _ => "badge",
                };
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td><td><span class=\"{}\">{}</span></td></tr>",
                    html_escape(&r.id[..8.min(r.id.len())]),
                    html_escape(&r.user),
                    html_escape(&r.item_name),
                    html_escape(&r.field),
                    badge_class,
                    html_escape(&r.status),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let body = format!(
        r#"<h1>aibw</h1>
<p class="subtitle">Bitwarden credential manager</p>
<div class="status {status_class}">
    {status_icon} Vault: <strong>{status_text}</strong>
    {locked_info}
    {last_used_info}
</div>
<h2>Pending Requests</h2>
<table>
    <thead><tr><th>ID</th><th>User</th><th>Item</th><th>Field</th><th>Action</th></tr></thead>
    <tbody>{pending_rows}</tbody>
</table>
<h2>Recent History</h2>
<table>
    <thead><tr><th>ID</th><th>User</th><th>Item</th><th>Field</th><th>Status</th></tr></thead>
    <tbody>{recent_rows}</tbody>
</table>"#
    );

    Html(page("aibw Dashboard", &body))
}

#[derive(Deserialize)]
struct UnlockQuery {
    c: Option<String>,
    request: Option<String>,
}

async fn unlock_get(
    State(state): State<WebState>,
    headers: HeaderMap,
    Query(params): Query<UnlockQuery>,
) -> Response {
    // Code-redemption branch: validate + consume the code, then strip it from the
    // URL via a redirect that sets the session cookie.
    if let Some(code) = params.c.as_deref() {
        if !is_uuidish(code) {
            return Html(login_page(Some("Invalid access code."))).into_response();
        }
        match state.web_auth.redeem(code) {
            Some((session_id, req_from_code)) => {
                let cookie = session_cookie_header(&state, &session_id);
                // Prefer the request bound to the code; fall back to the query param.
                let req = clean_request_id(req_from_code.as_deref())
                    .or_else(|| clean_request_id(params.request.as_deref()));
                let location = match req {
                    Some(r) => format!("/aibw/unlock?request={r}"),
                    None => "/aibw/unlock".to_string(),
                };
                return redirect_with_cookie(&location, &cookie);
            }
            None => {
                return Html(login_page(Some(
                    "That access code is invalid or has expired.",
                )))
                .into_response();
            }
        }
    }

    // No code: must already hold a session to see the password form.
    if !has_session(&headers, &state) {
        return Html(login_page(None)).into_response();
    }

    let req_id = clean_request_id(params.request.as_deref());
    Html(unlock_form_page(&state, req_id.as_deref()).await).into_response()
}

#[derive(Deserialize)]
struct UnlockForm {
    password: String,
    request_id: Option<String>,
}

async fn unlock_submit(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<UnlockForm>,
) -> Response {
    let Some(session_id) = session_cookie(&headers).filter(|s| state.web_auth.is_session_valid(s))
    else {
        return Html(login_page(Some(
            "Your session has expired. Request a new access code.",
        )))
        .into_response();
    };

    let req_id = clean_request_id(form.request_id.as_deref());
    // M7: take ownership of the password into a Zeroizing wrapper so this copy is
    // wiped on drop rather than left on the heap. (The raw request-body buffer
    // axum decoded is a separate transient we don't control here.)
    let password = zeroize::Zeroizing::new(form.password);

    // M3: per-session attempt window — never a shared/global bucket, and it
    // recovers after the window rather than locking out permanently.
    if !bump_attempts(&state, &session_id) {
        warn!("Master-password attempts exhausted for session (window backoff)");
        return Html(error_page(
            "Too many attempts",
            "Too many password attempts. Wait a minute and try again.",
            req_id.as_deref(),
        ))
        .into_response();
    }

    // Validate the targeted request if provided.
    if let Some(ref req_id) = req_id {
        match state.db.get_bw_request(req_id) {
            Ok(Some(r)) if r.status == "pending" => {}
            Ok(Some(r)) => {
                return Html(error_page(
                    "Request expired",
                    &format!(
                        "Request is no longer pending (status: {}).",
                        html_escape(&r.status)
                    ),
                    None,
                ))
                .into_response();
            }
            _ => {
                return Html(error_page(
                    "Request not found",
                    "The specified request was not found.",
                    None,
                ))
                .into_response();
            }
        }
    }

    match state.bw_session.unlock(&password).await {
        Ok(()) => {
            info!("Vault unlocked via web UI");
            state.db.log_bw_session_event("unlock", "via web_ui").ok();

            let request_signaled = if let Some(ref req_id) = req_id {
                if let Some((_, sender)) = state.pending_unlocks.remove(req_id) {
                    match sender.send(()) {
                        Ok(()) => {
                            info!("Signaled pending BW request {req_id} after web unlock");
                            true
                        }
                        Err(()) => {
                            warn!(
                                "Failed to signal pending BW request {req_id} (receiver dropped)"
                            );
                            false
                        }
                    }
                } else {
                    false
                }
            } else {
                false
            };

            state.password_attempts.remove(&session_id);
            Html(success_page(req_id.as_deref(), request_signaled)).into_response()
        }
        Err(e) => {
            warn!("Vault unlock failed via web UI: {e}");
            Html(error_page(
                "Unlock failed",
                "Incorrect master password. Please try again.",
                req_id.as_deref(),
            ))
            .into_response()
        }
    }
}

async fn request_code(
    State(state): State<WebState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Html<String> {
    if !state.web_auth.link_delivery_enabled() {
        return Html(info_page(
            "Link delivery not configured",
            "Set <code>web_external_url</code> in the Bitwarden config to enable access links.",
        ));
    }

    let identity = caller_identity(&headers, addr);
    if !state.web_auth.allow_code_request(&identity) {
        return Html(info_page(
            "Slow down",
            "An access code was requested recently. Please wait a moment before trying again.",
        ));
    }

    match state.web_auth.issue_link(None) {
        Some(url) => {
            if let Err(e) = state.backend.send_access_link(&url).await {
                error!("Failed to send access link: {e:#}");
                return Html(info_page(
                    "Send failed",
                    "Could not deliver the access link. Check the daemon logs.",
                ));
            }
            Html(info_page(
                "Code sent",
                "An access link has been sent to your Telegram. Tap it to open the vault dashboard.",
            ))
        }
        None => Html(info_page(
            "Link delivery not configured",
            "No public URL is configured.",
        )),
    }
}

async fn status_json(State(state): State<WebState>, headers: HeaderMap) -> Response {
    if !has_session(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response();
    }
    let session_active = state.bw_session.is_session_active().await;
    let locked_since = state
        .bw_session
        .locked_since()
        .await
        .map(|dt| dt.to_rfc3339());
    let last_used = state.bw_session.last_used_time().await;
    let pending_count = state
        .db
        .get_pending_bw_requests()
        .map(|v| v.len())
        .unwrap_or(0);

    Json(serde_json::json!({
        "session_active": session_active,
        "locked_since": locked_since,
        "last_used": last_used,
        "pending_requests": pending_count,
    }))
    .into_response()
}

/// M3 limiter: returns true if a master-password attempt is allowed for `session_id`,
/// counting within a sliding window keyed per session.
fn bump_attempts(state: &WebState, session_id: &str) -> bool {
    let now = Instant::now();
    let mut e = state
        .password_attempts
        .entry(session_id.to_string())
        .or_insert((0, now));
    let (count, start) = *e;
    if now.duration_since(start) >= ATTEMPT_WINDOW {
        *e = (1, now); // window elapsed → reset
        true
    } else if count >= state.max_password_attempts {
        false
    } else {
        e.0 = count + 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Page rendering
// ---------------------------------------------------------------------------

const STYLE: &str = r#"body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 860px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
h1 { color: #e94560; margin-bottom: 4px; }
h2 { color: #ccc; margin-top: 32px; font-size: 1.1em; }
h3 { color: #ccc; margin-top: 0; }
.subtitle { color: #888; font-size: 0.9em; margin-bottom: 24px; }
.status { padding: 12px 16px; border-radius: 8px; margin: 16px 0; }
.locked { background: #2d1b1b; border: 1px solid #e94560; }
.unlocked { background: #1b2d1b; border: 1px solid #4ecdc4; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 24px 0; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #333; }
th { color: #aaa; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
code { background: #2a2a3e; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
.empty { color: #666; font-style: italic; }
.muted { color: #888; font-size: 0.9em; }
.card { background: #2a2a3e; border: 1px solid #444; border-radius: 8px; padding: 16px; margin: 16px 0; }
.warn { border-color: #f0c040; background: #2d2d1b; }
.btn { display: inline-block; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-size: 0.9em; font-weight: 600; background: #4ecdc4; color: #1a1a2e; border: none; cursor: pointer; }
.btn:hover { background: #3dbdb5; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; background: #333; }
.badge-ok { background: #1b3d1b; color: #4ecdc4; }
.badge-deny { background: #3d1b1b; color: #e94560; }
.badge-timeout { background: #3d3d1b; color: #f0c040; }
label { display: block; margin: 16px 0 6px; color: #ccc; font-weight: 600; }
input[type="password"] { width: 100%; padding: 10px; border: 1px solid #444; border-radius: 4px; background: #2a2a3e; color: #e0e0e0; font-size: 1em; box-sizing: border-box; }
input[type="password"]:focus { border-color: #4ecdc4; outline: none; }
.error { background: #2d1b1b; border: 1px solid #e94560; border-radius: 8px; padding: 16px; margin: 16px 0; }
.success { background: #1b2d1b; border: 1px solid #4ecdc4; border-radius: 8px; padding: 16px; margin: 16px 0; }
.warn-text { color: #f0c040; }
small { color: #888; }
a { color: #4ecdc4; }
.back { margin-top: 24px; display: block; font-size: 0.9em; }"#;

/// Wrap a body in the shared HTML shell (styles are inline → CSP-clean).
fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{}</title>
<style>{STYLE}</style>
</head>
<body>
{body}
</body>
</html>"#,
        html_escape(title)
    )
}

/// Unauthenticated landing page: request an access code via Telegram.
fn login_page(error: Option<&str>) -> String {
    let err = match error {
        Some(e) => format!(r#"<div class="card warn"><p>{}</p></div>"#, html_escape(e)),
        None => String::new(),
    };
    let body = format!(
        r#"<h1>&#x1f512; aibw</h1>
<p class="subtitle">Bitwarden credential manager</p>
{err}
<div class="card">
    <p>Access requires a one-time code sent to your Telegram.</p>
    <form method="POST" action="/aibw/request-code">
        <button class="btn" type="submit">Send access code</button>
    </form>
</div>"#
    );
    page("aibw", &body)
}

async fn unlock_form_page(state: &WebState, request_id: Option<&str>) -> String {
    let request_info = if let Some(req_id) = request_id {
        match state.db.get_bw_request(req_id) {
            Ok(Some(r)) if r.status == "pending" => format!(
                r#"<div class="card">
                    <h3>Pending Request</h3>
                    <p><strong>Item:</strong> <code>{}</code></p>
                    <p><strong>User:</strong> {}</p>
                    <p><strong>Field:</strong> {}</p>
                </div>"#,
                html_escape(&r.item_name),
                html_escape(&r.user),
                html_escape(&r.field),
            ),
            Ok(Some(r)) => format!(
                r#"<div class="card warn"><p>Request is no longer pending (status: {}).</p></div>"#,
                html_escape(&r.status)
            ),
            _ => r#"<div class="card warn"><p>Request not found.</p></div>"#.to_string(),
        }
    } else {
        String::new()
    };

    let hidden = request_id
        .map(|id| {
            format!(
                r#"<input type="hidden" name="request_id" value="{}">"#,
                html_escape(id)
            )
        })
        .unwrap_or_default();

    let session_active = state.bw_session.is_session_active().await;
    let already = if session_active {
        r#"<div class="card" style="border-color:#4ecdc4;background:#1b2d1b;"><p>Vault is already unlocked. Enter the password to re-authenticate, or <a href="/aibw/">return to dashboard</a>.</p></div>"#
    } else {
        ""
    };

    let body = format!(
        r#"<h1>&#x1f511; Unlock Vault</h1>
{already}
{request_info}
<form method="POST" action="/aibw/unlock" autocomplete="off">
    {hidden}
    <label for="password">Master Password</label>
    <input type="password" id="password" name="password" autocomplete="off" autofocus required>
    <button class="btn" type="submit" style="margin-top:16px;">Unlock</button>
</form>
<a class="back" href="/aibw/">&larr; Back to dashboard</a>"#
    );
    page("aibw - Unlock Vault", &body)
}

fn success_page(request_id: Option<&str>, request_signaled: bool) -> String {
    let request_msg = if request_signaled {
        match request_id {
            Some(id) => format!(
                r#"<p>Request <code>{}</code> is unlocked. Approve the release in Telegram to complete it.</p>"#,
                html_escape(&id[..8.min(id.len())])
            ),
            None => String::new(),
        }
    } else if request_id.is_some() {
        r#"<p class="warn-text">The associated request may have already expired or been handled.</p>"#.to_string()
    } else {
        String::new()
    };

    let body = format!(
        r#"<h1>&#x1f513; Vault Unlocked</h1>
<div class="success">
    <p>The Bitwarden vault has been successfully unlocked.</p>
    {request_msg}
</div>
<a class="back" href="/aibw/">&larr; Back to dashboard</a>"#
    );
    page("aibw - Vault Unlocked", &body)
}

fn error_page(title: &str, message: &str, request_id: Option<&str>) -> String {
    let retry_link = match request_id.and_then(|id| clean_request_id(Some(id))) {
        Some(id) => format!(r#"<a class="btn" href="/aibw/unlock?request={id}">Try again</a>"#),
        None => r#"<a class="btn" href="/aibw/unlock">Try again</a>"#.to_string(),
    };
    let body = format!(
        r#"<h1>&#x274c; {}</h1>
<div class="error"><p>{}</p></div>
{retry_link}
<a class="back" href="/aibw/">&larr; Back to dashboard</a>"#,
        html_escape(title),
        html_escape(message),
    );
    page("aibw - Error", &body)
}

fn info_page(title: &str, message_html: &str) -> String {
    // message_html is trusted caller-provided markup (no request data).
    let body = format!(
        r#"<h1>{}</h1>
<div class="card"><p>{message_html}</p></div>
<a class="back" href="/aibw/">&larr; Back to dashboard</a>"#,
        html_escape(title),
    );
    page("aibw", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_neutralizes_markup() {
        let out = html_escape(r#"<script>alert("x")</script> & 'q'"#);
        assert!(!out.contains("<script>"));
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("&amp;"));
        assert!(out.contains("&quot;"));
        assert!(out.contains("&#x27;"));
    }

    #[test]
    fn is_uuidish_accepts_uuid_rejects_injection() {
        assert!(is_uuidish("3f2504e0-4f89-41d3-9a0c-0305e82c3301"));
        assert!(is_uuidish("abcDEF123"));
        assert!(!is_uuidish("\"><script>"));
        assert!(!is_uuidish("a b"));
        assert!(!is_uuidish(""));
        assert!(!is_uuidish(&"a".repeat(65)));
    }

    #[test]
    fn clean_request_id_filters() {
        // Real request ids are UUIDs (hex + hyphens).
        assert_eq!(
            clean_request_id(Some("3f2504e0-4f89-41d3-9a0c-0305e82c3301")),
            Some("3f2504e0-4f89-41d3-9a0c-0305e82c3301".to_string())
        );
        assert_eq!(clean_request_id(Some("<b>")), None);
        assert_eq!(clean_request_id(Some("req with space")), None);
        assert_eq!(clean_request_id(None), None);
    }

    #[test]
    fn success_page_escapes_and_renders() {
        let html = success_page(Some("abc-12345-def"), true);
        assert!(html.contains("abc-1234"));
        assert!(html.contains("Vault Unlocked"));
    }

    #[test]
    fn error_page_renders_and_escapes() {
        let html = error_page("Bad", "<script>", Some("abc12345"));
        assert!(html.contains("Bad"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("request=abc12345"));
        // A non-uuid id is dropped from the retry link, not reflected.
        let html2 = error_page("Bad", "x", Some("\"><script>"));
        assert!(!html2.contains("<script>"));
        assert!(html2.contains(r#"href="/aibw/unlock""#));
    }

    #[test]
    fn login_page_has_request_button() {
        let html = login_page(Some("nope"));
        assert!(html.contains("Send access code"));
        assert!(html.contains("nope"));
    }

    // --- Auth-gate integration (H2): drive the real handlers ---

    struct GateMockBackend;

    #[async_trait::async_trait]
    impl NotificationBackend for GateMockBackend {
        async fn send_and_wait(
            &self,
            _r: &aisudo_common::SudoRequestRecord,
        ) -> anyhow::Result<aisudo_common::Decision> {
            Ok(aisudo_common::Decision::Denied)
        }
        async fn send_temp_rule_and_wait(
            &self,
            _r: &crate::notification::TempRuleRecord,
        ) -> anyhow::Result<aisudo_common::Decision> {
            Ok(aisudo_common::Decision::Denied)
        }
        async fn send_bw_request_and_wait(
            &self,
            _r: &crate::notification::BwRequestRecord,
        ) -> anyhow::Result<aisudo_common::Decision> {
            Ok(aisudo_common::Decision::Denied)
        }
        async fn send_bw_confirm_and_wait(
            &self,
            _r: &crate::notification::BwConfirmRecord,
        ) -> anyhow::Result<aisudo_common::Decision> {
            Ok(aisudo_common::Decision::Denied)
        }
        async fn send_bw_locked_notification(
            &self,
            _r: &crate::notification::BwRequestRecord,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn send_access_link(&self, _url: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn send_scrub_complete(&self, _id: &str, _item: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn update_completion_status(&self, _i: &crate::notification::CompletionInfo) {}
        fn name(&self) -> &'static str {
            "gate-mock"
        }
    }

    fn test_state() -> (tempfile::TempDir, WebState) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(&dir.path().join("t.db")).unwrap());
        let bw = Arc::new(BwSessionManager::new(
            std::path::PathBuf::from("/usr/bin/bw"),
            3600,
        ));
        let web_auth = Arc::new(WebAuth::new(Some("https://h".to_string()), 600, 900, 30));
        let state = WebState::new(
            bw,
            db,
            Arc::new(DashMap::new()),
            5,
            web_auth,
            Arc::new(GateMockBackend),
        );
        (dir, state)
    }

    fn cookie_headers(sid: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{SESSION_COOKIE}={sid}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn status_requires_session() {
        let (_d, state) = test_state();
        // No cookie → 401.
        let resp = status_json(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid session → 200.
        let url = state.web_auth.issue_link(None).unwrap();
        let code = url
            .split("c=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();
        let (sid, _) = state.web_auth.redeem(&code).unwrap();
        let resp = status_json(State(state.clone()), cookie_headers(&sid)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_gated_by_session() {
        let (_d, state) = test_state();
        // No cookie → login page, no request data.
        let html = dashboard(State(state.clone()), HeaderMap::new()).await.0;
        assert!(html.contains("Send access code"));
        assert!(!html.contains("Pending Requests"));

        // Valid session → real dashboard.
        let url = state.web_auth.issue_link(None).unwrap();
        let code = url
            .split("c=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();
        let (sid, _) = state.web_auth.redeem(&code).unwrap();
        let html = dashboard(State(state.clone()), cookie_headers(&sid))
            .await
            .0;
        assert!(html.contains("Pending Requests"));
    }
}
