use aisudo_common::Decision;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

use crate::db::Database;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
}

pub fn router(db: Arc<Database>) -> Router {
    let state = AppState { db };
    Router::new()
        .route("/health", get(health))
        .route("/requests", get(list_pending))
        .route("/requests/{id}", get(get_request))
        .route("/approve/{id}/{nonce}", get(approve_request))
        .route("/deny/{id}/{nonce}", get(deny_request))
        .route("/temp-rules", get(list_temp_rules))
        .route("/approve-rule/{id}/{nonce}", get(approve_temp_rule))
        .route("/deny-rule/{id}/{nonce}", get(deny_temp_rule))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct RequestInfo {
    id: String,
    user: String,
    command: String,
    cwd: String,
    pid: u32,
    status: String,
    timestamp: String,
}

async fn list_pending(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_pending_requests() {
        Ok(requests) => {
            let infos: Vec<RequestInfo> = requests
                .into_iter()
                .map(|r| RequestInfo {
                    id: r.id,
                    user: r.user,
                    command: r.command,
                    cwd: r.cwd,
                    pid: r.pid,
                    status: r.status.as_str().to_string(),
                    timestamp: r.timestamp.to_rfc3339(),
                })
                .collect();
            (StatusCode::OK, Json(infos)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_request(&id) {
        Ok(Some(r)) => {
            let info = RequestInfo {
                id: r.id,
                user: r.user,
                command: r.command,
                cwd: r.cwd,
                pid: r.pid,
                status: r.status.as_str().to_string(),
                timestamp: r.timestamp.to_rfc3339(),
            };
            (StatusCode::OK, Json(info)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn approve_request(
    State(state): State<AppState>,
    Path((id, nonce)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.db.get_request(&id) {
        Ok(Some(r)) => {
            if r.nonce != nonce {
                return (StatusCode::FORBIDDEN, "Invalid nonce").into_response();
            }
            if r.status != Decision::Pending {
                return (
                    StatusCode::CONFLICT,
                    format!("Request already {}", r.status.as_str()),
                )
                    .into_response();
            }
            match state.db.update_decision(&id, Decision::Approved, "http_api") {
                Ok(true) => {
                    info!("Request {id} approved via HTTP API");
                    (StatusCode::OK, "Approved").into_response()
                }
                Ok(false) => (StatusCode::CONFLICT, "Request already decided").into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn deny_request(
    State(state): State<AppState>,
    Path((id, nonce)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.db.get_request(&id) {
        Ok(Some(r)) => {
            if r.nonce != nonce {
                return (StatusCode::FORBIDDEN, "Invalid nonce").into_response();
            }
            if r.status != Decision::Pending {
                return (
                    StatusCode::CONFLICT,
                    format!("Request already {}", r.status.as_str()),
                )
                    .into_response();
            }
            match state.db.update_decision(&id, Decision::Denied, "http_api") {
                Ok(true) => {
                    info!("Request {id} denied via HTTP API");
                    (StatusCode::OK, "Denied").into_response()
                }
                Ok(false) => (StatusCode::CONFLICT, "Request already decided").into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_temp_rules(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_all_temp_rules() {
        Ok(rules) => (StatusCode::OK, Json(rules)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn approve_temp_rule(
    State(state): State<AppState>,
    Path((id, nonce)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.db.get_temp_rule(&id) {
        Ok(Some(rule)) => {
            if rule.nonce != nonce {
                return (StatusCode::FORBIDDEN, "Invalid nonce").into_response();
            }
            if rule.status != "pending" {
                return (
                    StatusCode::CONFLICT,
                    format!("Rule already {}", rule.status),
                )
                    .into_response();
            }
            match state.db.update_temp_rule_decision(&id, Decision::Approved, "http_api") {
                Ok(true) => {
                    info!("Temp rule {id} approved via HTTP API");
                    (StatusCode::OK, "Approved").into_response()
                }
                Ok(false) => (StatusCode::CONFLICT, "Rule already decided").into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn deny_temp_rule(
    State(state): State<AppState>,
    Path((id, nonce)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.db.get_temp_rule(&id) {
        Ok(Some(rule)) => {
            if rule.nonce != nonce {
                return (StatusCode::FORBIDDEN, "Invalid nonce").into_response();
            }
            if rule.status != "pending" {
                return (
                    StatusCode::CONFLICT,
                    format!("Rule already {}", rule.status),
                )
                    .into_response();
            }
            match state.db.update_temp_rule_decision(&id, Decision::Denied, "http_api") {
                Ok(true) => {
                    info!("Temp rule {id} denied via HTTP API");
                    (StatusCode::OK, "Denied").into_response()
                }
                Ok(false) => (StatusCode::CONFLICT, "Rule already decided").into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
