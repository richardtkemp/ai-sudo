use crate::bw_session::BwSessionManager;
use crate::db::Database;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Json, Redirect},
    routing::get,
    Router,
};
use dashmap::DashMap;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

/// Shared state for the web UI.
#[derive(Clone)]
pub struct WebState {
    pub bw_session: Arc<BwSessionManager>,
    pub db: Arc<Database>,
    /// Channels for signaling pending BW requests when vault is unlocked via web UI.
    pub pending_unlocks: Arc<DashMap<String, oneshot::Sender<()>>>,
    pub max_password_attempts: u32,
    /// Track password attempts per request ID.
    password_attempts: Arc<DashMap<String, u32>>,
}

impl WebState {
    pub fn new(
        bw_session: Arc<BwSessionManager>,
        db: Arc<Database>,
        pending_unlocks: Arc<DashMap<String, oneshot::Sender<()>>>,
        max_password_attempts: u32,
    ) -> Self {
        Self {
            bw_session,
            db,
            pending_unlocks,
            max_password_attempts,
            password_attempts: Arc::new(DashMap::new()),
        }
    }
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/aibw", get(|| async { Redirect::permanent("/aibw/") }))
        .route("/aibw/", get(dashboard))
        .route("/aibw/unlock", get(unlock_form).post(unlock_submit))
        .route("/aibw/status", get(status_json))
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

    if let Err(e) = axum::serve(listener, app).await {
        error!("Web UI server error: {e}");
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn dashboard(State(state): State<WebState>) -> Html<String> {
    let session_active = state.bw_session.is_session_active().await;
    let locked_since = state.bw_session.locked_since().await;
    let last_used = state.bw_session.last_used_time().await;

    let pending = state.db.get_pending_bw_requests().unwrap_or_default();
    let recent = state.db.get_recent_bw_requests(10).unwrap_or_default();

    let status_class = if session_active { "unlocked" } else { "locked" };
    let status_icon = if session_active { "&#x1f513;" } else { "&#x1f512;" };
    let status_text = if session_active { "Unlocked" } else { "Locked" };

    let locked_info = if let Some(since) = locked_since {
        format!("<br><small>Since: {}</small>", since.format("%Y-%m-%d %H:%M:%S UTC"))
    } else {
        String::new()
    };

    let last_used_info = match last_used {
        Some(ref t) => format!("<br><small>Last used: {t}</small>"),
        None => String::new(),
    };

    // Pending requests table
    let pending_rows = if pending.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\">No pending requests</td></tr>".to_string()
    } else {
        pending
            .iter()
            .map(|r| {
                let action = if session_active {
                    format!(
                        "<span class=\"muted\">Approve via Telegram</span>"
                    )
                } else {
                    format!(
                        "<a class=\"btn btn-primary\" href=\"/aibw/unlock?request={}\">Unlock &amp; Approve</a>",
                        r.id
                    )
                };
                format!(
                    "<tr>\
                        <td><code>{}</code></td>\
                        <td>{}</td>\
                        <td><code>{}</code></td>\
                        <td>{}</td>\
                        <td>{}</td>\
                    </tr>",
                    &r.id[..8],
                    r.user,
                    r.item_name,
                    r.field,
                    action,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Recent requests table
    let recent_rows = if recent.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\">No recent requests</td></tr>".to_string()
    } else {
        recent
            .iter()
            .map(|r| {
                let status_badge = match r.status.as_str() {
                    "approved" | "confirmed" => format!("<span class=\"badge badge-ok\">{}</span>", r.status),
                    "denied" | "cancelled" => format!("<span class=\"badge badge-deny\">{}</span>", r.status),
                    "timeout" => format!("<span class=\"badge badge-timeout\">{}</span>", r.status),
                    _ => format!("<span class=\"badge\">{}</span>", r.status),
                };
                format!(
                    "<tr>\
                        <td><code>{}</code></td>\
                        <td>{}</td>\
                        <td><code>{}</code></td>\
                        <td>{}</td>\
                        <td>{}</td>\
                    </tr>",
                    &r.id[..8.min(r.id.len())],
                    r.user,
                    r.item_name,
                    r.field,
                    status_badge,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<meta http-equiv="Cache-Control" content="no-store">
<title>aibw Dashboard</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 860px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #e94560; margin-bottom: 4px; }}
h2 {{ color: #ccc; margin-top: 32px; font-size: 1.1em; }}
.subtitle {{ color: #888; font-size: 0.9em; margin-bottom: 24px; }}
.status {{ padding: 12px 16px; border-radius: 8px; margin: 16px 0; }}
.locked {{ background: #2d1b1b; border: 1px solid #e94560; }}
.unlocked {{ background: #1b2d1b; border: 1px solid #4ecdc4; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0 24px 0; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #333; }}
th {{ color: #aaa; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
code {{ background: #2a2a3e; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
.empty {{ color: #666; font-style: italic; }}
.muted {{ color: #888; font-size: 0.9em; }}
.btn {{ display: inline-block; padding: 6px 14px; border-radius: 4px; text-decoration: none; font-size: 0.85em; font-weight: 600; }}
.btn-primary {{ background: #4ecdc4; color: #1a1a2e; }}
.btn-primary:hover {{ background: #3dbdb5; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; background: #333; }}
.badge-ok {{ background: #1b3d1b; color: #4ecdc4; }}
.badge-deny {{ background: #3d1b1b; color: #e94560; }}
.badge-timeout {{ background: #3d3d1b; color: #f0c040; }}
small {{ color: #888; }}
</style>
</head>
<body>
<h1>aibw</h1>
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
</table>

<p class="muted" style="margin-top: 32px; font-size: 0.8em;">Auto-refreshes every 30s</p>
</body>
</html>"#
    );

    Html(html)
}

#[derive(Deserialize)]
struct UnlockQuery {
    request: Option<String>,
}

async fn unlock_form(
    State(state): State<WebState>,
    Query(params): Query<UnlockQuery>,
) -> Html<String> {
    let request_info = if let Some(ref req_id) = params.request {
        match state.db.get_bw_request(req_id) {
            Ok(Some(r)) if r.status == "pending" => {
                format!(
                    r#"<div class="request-info">
                        <h3>Pending Request</h3>
                        <p><strong>Item:</strong> <code>{}</code></p>
                        <p><strong>User:</strong> {}</p>
                        <p><strong>Field:</strong> {}</p>
                        <p><strong>Request ID:</strong> <code>{}</code></p>
                    </div>"#,
                    r.item_name, r.user, r.field, &r.id[..8.min(r.id.len())]
                )
            }
            Ok(Some(r)) => {
                format!(
                    r#"<div class="request-info warn">
                        <p>Request <code>{}</code> is no longer pending (status: {}).</p>
                    </div>"#,
                    &r.id[..8.min(r.id.len())],
                    r.status
                )
            }
            _ => {
                r#"<div class="request-info warn"><p>Request not found.</p></div>"#.to_string()
            }
        }
    } else {
        String::new()
    };

    let request_id_field = params
        .request
        .as_deref()
        .map(|id| format!(r#"<input type="hidden" name="request_id" value="{id}">"#))
        .unwrap_or_default();

    let session_active = state.bw_session.is_session_active().await;
    let already_unlocked = if session_active {
        r#"<div class="request-info" style="border-color: #4ecdc4; background: #1b2d1b;">
            <p>Vault is already unlocked. You can enter the password to re-authenticate, or <a href="/aibw/">return to dashboard</a>.</p>
        </div>"#
    } else {
        ""
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>aibw - Unlock Vault</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #e94560; }}
.request-info {{ background: #2a2a3e; border: 1px solid #444; border-radius: 8px; padding: 16px; margin: 16px 0; }}
.request-info h3 {{ margin-top: 0; color: #ccc; }}
.request-info p {{ margin: 6px 0; }}
.warn {{ border-color: #f0c040; background: #2d2d1b; }}
code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 3px; }}
label {{ display: block; margin: 16px 0 6px; color: #ccc; font-weight: 600; }}
input[type="password"] {{ width: 100%; padding: 10px; border: 1px solid #444; border-radius: 4px; background: #2a2a3e; color: #e0e0e0; font-size: 1em; box-sizing: border-box; }}
input[type="password"]:focus {{ border-color: #4ecdc4; outline: none; }}
button {{ margin-top: 16px; padding: 10px 24px; background: #4ecdc4; color: #1a1a2e; border: none; border-radius: 4px; font-size: 1em; font-weight: 600; cursor: pointer; }}
button:hover {{ background: #3dbdb5; }}
a {{ color: #4ecdc4; }}
.back {{ margin-top: 24px; display: block; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>&#x1f511; Unlock Vault</h1>

{already_unlocked}
{request_info}

<form method="POST" action="/aibw/unlock" autocomplete="off">
    {request_id_field}
    <label for="password">Master Password</label>
    <input type="password" id="password" name="password" autocomplete="off" autofocus required>
    <button type="submit">Unlock</button>
</form>

<a class="back" href="/aibw/">&larr; Back to dashboard</a>
</body>
</html>"#
    );

    Html(html)
}

#[derive(Deserialize)]
struct UnlockForm {
    password: String,
    request_id: Option<String>,
}

async fn unlock_submit(
    State(state): State<WebState>,
    Form(form): Form<UnlockForm>,
) -> impl IntoResponse {
    // Rate limit password attempts per request
    let attempt_key = form.request_id.clone().unwrap_or_else(|| "global".to_string());
    let attempts = {
        let mut entry = state.password_attempts.entry(attempt_key.clone()).or_insert(0);
        *entry += 1;
        *entry
    };

    if attempts > state.max_password_attempts {
        warn!("Password attempt rate limit exceeded for key={attempt_key}");
        return Html(error_page(
            "Too many attempts",
            "Password attempt limit exceeded. Please wait and try again.",
            form.request_id.as_deref(),
        ));
    }

    // Validate request if provided
    if let Some(ref req_id) = form.request_id {
        match state.db.get_bw_request(req_id) {
            Ok(Some(r)) if r.status == "pending" => {}
            Ok(Some(r)) => {
                return Html(error_page(
                    "Request expired",
                    &format!("Request is no longer pending (status: {}).", r.status),
                    None,
                ));
            }
            _ => {
                return Html(error_page("Request not found", "The specified request was not found.", None));
            }
        }
    }

    // Attempt unlock
    match state.bw_session.unlock(&form.password).await {
        Ok(()) => {
            info!("Vault unlocked via web UI");
            state.db.log_bw_session_event("unlock", "via web_ui").ok();

            // Signal the pending request handler if a request_id was provided
            let request_signaled = if let Some(ref req_id) = form.request_id {
                if let Some((_, sender)) = state.pending_unlocks.remove(req_id) {
                    match sender.send(()) {
                        Ok(()) => {
                            info!("Signaled pending BW request {req_id} after web unlock");
                            true
                        }
                        Err(()) => {
                            warn!("Failed to signal pending BW request {req_id} (receiver dropped)");
                            false
                        }
                    }
                } else {
                    false
                }
            } else {
                false
            };

            // Reset attempt counter on success
            state.password_attempts.remove(&attempt_key);

            Html(success_page(form.request_id.as_deref(), request_signaled))
        }
        Err(e) => {
            warn!("Vault unlock failed via web UI: {e}");
            Html(error_page(
                "Unlock failed",
                "Incorrect master password. Please try again.",
                form.request_id.as_deref(),
            ))
        }
    }
}

async fn status_json(State(state): State<WebState>) -> Json<serde_json::Value> {
    let session_active = state.bw_session.is_session_active().await;
    let locked_since = state.bw_session.locked_since().await.map(|dt| dt.to_rfc3339());
    let last_used = state.bw_session.last_used_time().await;
    let pending_count = state.db.get_pending_bw_requests().map(|v| v.len()).unwrap_or(0);

    Json(serde_json::json!({
        "session_active": session_active,
        "locked_since": locked_since,
        "last_used": last_used,
        "pending_requests": pending_count,
    }))
}

// ---------------------------------------------------------------------------
// Response page helpers
// ---------------------------------------------------------------------------

fn success_page(request_id: Option<&str>, request_signaled: bool) -> String {
    let request_msg = if request_signaled {
        if let Some(id) = request_id {
            format!(
                r#"<p>Request <code>{}</code> has been approved and is being processed.</p>"#,
                &id[..8.min(id.len())]
            )
        } else {
            String::new()
        }
    } else if request_id.is_some() {
        "<p class=\"warn-text\">The associated request may have already expired or been handled.</p>"
            .to_string()
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>aibw - Vault Unlocked</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #4ecdc4; }}
.success {{ background: #1b2d1b; border: 1px solid #4ecdc4; border-radius: 8px; padding: 16px; margin: 16px 0; }}
code {{ background: #2a2a3e; padding: 2px 6px; border-radius: 3px; }}
a {{ color: #4ecdc4; }}
.warn-text {{ color: #f0c040; }}
.back {{ margin-top: 24px; display: block; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>&#x1f513; Vault Unlocked</h1>
<div class="success">
    <p>The Bitwarden vault has been successfully unlocked.</p>
    {request_msg}
</div>
<a class="back" href="/aibw/">&larr; Back to dashboard</a>
</body>
</html>"#
    )
}

fn error_page(title: &str, message: &str, request_id: Option<&str>) -> String {
    let retry_link = match request_id {
        Some(id) => format!(r#"<a class="btn" href="/aibw/unlock?request={id}">Try again</a>"#),
        None => r#"<a class="btn" href="/aibw/unlock">Try again</a>"#.to_string(),
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>aibw - Error</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #e94560; }}
.error {{ background: #2d1b1b; border: 1px solid #e94560; border-radius: 8px; padding: 16px; margin: 16px 0; }}
a {{ color: #4ecdc4; text-decoration: none; }}
.btn {{ display: inline-block; padding: 8px 16px; background: #4ecdc4; color: #1a1a2e; border-radius: 4px; font-weight: 600; margin-top: 12px; }}
.btn:hover {{ background: #3dbdb5; }}
.back {{ margin-top: 24px; display: block; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>&#x274c; {title}</h1>
<div class="error">
    <p>{message}</p>
</div>
{retry_link}
<a class="back" href="/aibw/">&larr; Back to dashboard</a>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_page_renders() {
        let html = success_page(None, false);
        assert!(html.contains("Vault Unlocked"));
    }

    #[test]
    fn success_page_with_request() {
        let html = success_page(Some("abc-12345-def"), true);
        assert!(html.contains("abc-1234"));
        assert!(html.contains("approved"));
    }

    #[test]
    fn error_page_renders() {
        let html = error_page("Test Error", "Something went wrong", None);
        assert!(html.contains("Test Error"));
        assert!(html.contains("Something went wrong"));
        assert!(html.contains("Try again"));
    }

    #[test]
    fn error_page_with_request_id() {
        let html = error_page("Unlock failed", "Bad password", Some("req-123"));
        assert!(html.contains("request=req-123"));
    }
}
