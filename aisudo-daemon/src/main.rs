mod bw_session;
mod config;
mod db;
mod notification;
mod scrub;
mod socket;
mod sudoers;
mod web;
mod web_auth;

use anyhow::Result;
use dashmap::DashMap;
use notification::telegram::TelegramBackend;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("aisudo=info".parse()?))
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/aisudo/aisudo.toml".to_string());

    info!("Loading config from: {config_path}");
    let config_holder = Arc::new(config::ConfigHolder::new(&config_path)?);
    let config = config_holder.config();

    info!("Opening database: {}", config.db_path.display());
    let db = Arc::new(db::Database::open(&config.db_path)?);

    // Set up notification backend
    let backend: Arc<dyn notification::NotificationBackend> =
        if let Some(ref tg_config) = config.telegram {
            if tg_config.chat_id == 0 {
                warn!("Telegram chat_id is 0 — this is almost certainly wrong. Set chat_id in config.");
            }
            let mut tg = TelegramBackend::new(
                tg_config.bot_token.clone(),
                tg_config.chat_id,
                config.timeout_seconds,
                config.limits.stdin_preview_bytes,
                tg_config.poll_timeout_seconds,
                Arc::clone(&config_holder),
            );
            tg.set_db(Arc::clone(&db));
            let telegram = Arc::new(tg);
            telegram.validate_bot_token().await;
            telegram.start_polling();
            info!("Telegram notification backend enabled (chat_id: {})", tg_config.chat_id);
            telegram
        } else {
            anyhow::bail!("No approval mechanism configured. Set [telegram] in config.");
        };

    // Set up BW session manager (if configured)
    let bw_session = if let Some(ref bw_config) = config.bitwarden {
        if bw_config.enabled {
            let mgr = Arc::new(bw_session::BwSessionManager::new(
                bw_config.bw_binary.clone(),
                bw_config.auto_lock_timeout,
            ));

            // Spawn auto-lock timer
            let mgr_autolock = Arc::clone(&mgr);
            let db_autolock = Arc::clone(&db);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    if mgr_autolock.check_auto_lock().await {
                        db_autolock
                            .log_bw_session_event("auto_lock", "idle timeout")
                            .ok();
                        info!("BW session auto-locked due to idle timeout");
                    }
                }
            });

            info!("Bitwarden integration enabled");
            Some(mgr)
        } else {
            info!("Bitwarden integration disabled in config");
            None
        }
    } else {
        None
    };

    // Shared pending-unlock channels (web UI -> socket handler signaling)
    let pending_unlocks = Arc::new(DashMap::new());

    // Web access codes/sessions shared between the web UI and the locked-request
    // notification path. Created unconditionally (cheap); link delivery is only
    // enabled when web_external_url is set.
    let web_auth = {
        let bw = config.bitwarden.as_ref();
        if bw.is_some() && bw.and_then(|b| b.web_external_url.as_ref()).is_none() {
            warn!("Bitwarden web UI: web_external_url is unset — Telegram unlock links are disabled (set it to your https Tailscale URL).");
        }
        Arc::new(web_auth::WebAuth::new(
            bw.and_then(|b| b.web_external_url.clone()),
            bw.map(|b| b.code_ttl_seconds).unwrap_or(600),
            bw.map(|b| b.session_ttl_seconds).unwrap_or(900),
            bw.map(|b| b.code_request_cooldown_seconds).unwrap_or(30),
        ))
    };

    // Start web UI if bitwarden is enabled
    if let Some(ref bw_session_ref) = bw_session {
        if let Some(ref bw_config) = config.bitwarden {
            let web_state = web::WebState::new(
                Arc::clone(bw_session_ref),
                Arc::clone(&db),
                Arc::clone(&pending_unlocks),
                bw_config.max_password_attempts,
                Arc::clone(&web_auth),
                Arc::clone(&backend),
            );
            let port = bw_config.web_ui_port;
            tokio::spawn(async move {
                web::run_web_server(web_state, port).await;
            });
            info!("Web UI spawned on port {}", bw_config.web_ui_port);

            // Spawn the credential scrubber: periodically redact released secrets
            // from the session logs and drop the retained plaintext from the DB.
            let db_scrub = Arc::clone(&db);
            let backend_scrub = Arc::clone(&backend);
            let scrub_interval = bw_config.scrub_interval.max(1) as u64;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(scrub_interval)).await;
                    if let Err(e) = run_scrub_pass(&db_scrub, backend_scrub.as_ref()).await {
                        error!("Scrub pass error: {e:#}");
                    }
                }
            });
            info!("Credential scrubber spawned (interval: {}s)", scrub_interval);
        }
    }

    // Spawn timeout expiry task
    let db_timeout = Arc::clone(&db);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            match db_timeout.expire_timed_out_requests() {
                Ok(expired) => {
                    for id in expired {
                        info!("Request {id} expired (timeout)");
                    }
                }
                Err(e) => error!("Timeout check error: {e}"),
            }
            match db_timeout.expire_temp_rules() {
                Ok(expired) => {
                    for id in &expired {
                        info!("Temp rule {id} expired");
                    }
                }
                Err(e) => error!("Temp rule expiry error: {e}"),
            }
        }
    });

    // Run socket listener (blocks)
    socket::run_socket_listener(config_holder, db, backend, bw_session, pending_unlocks, web_auth).await?;

    Ok(())
}

/// One scrubber iteration: redact due credentials from the session logs and
/// clear the retained plaintext. Deferred with backoff on failure, with a hard
/// retry cap after which the plaintext is dropped regardless.
async fn run_scrub_pass(
    db: &Arc<db::Database>,
    backend: &dyn notification::NotificationBackend,
) -> Result<()> {
    const MAX_RETRIES: i32 = 5;
    const RETRY_BACKOFF_SECS: u32 = 60;

    let now = chrono::Utc::now();
    for entry in db.get_pending_scrubs()? {
        // Only act once the scrub delay has elapsed (unparseable time = treat as due).
        let due = db::parse_datetime(&entry.scrub_at)
            .map(|t| t <= now)
            .unwrap_or(true);
        if !due {
            continue;
        }

        db.update_scrub_status(&entry.id, "in_progress").ok();

        match scrub::redact_session_files(&entry.session_files, &entry.credential_value) {
            Ok(n) => {
                db.complete_scrub(&entry.id)?;
                info!(
                    "Scrubbed credential for request {} ({} file(s) redacted)",
                    entry.request_id, n
                );
                // Best-effort completion notification.
                if let Ok(Some(req)) = db.get_bw_request(&entry.request_id) {
                    let item = req.resolved_item_name.unwrap_or(req.item_name);
                    if let Err(e) = backend.send_scrub_complete(&entry.request_id, &item).await {
                        warn!("Scrub-complete notification failed for {}: {e}", entry.request_id);
                    }
                }
            }
            Err(e) => {
                let attempts = entry.retry_count + 1;
                if attempts >= MAX_RETRIES {
                    error!(
                        "Giving up scrubbing request {} after {} attempts (dropping retained plaintext): {e}",
                        entry.request_id, attempts
                    );
                    db.fail_scrub(&entry.id)?;
                } else {
                    warn!(
                        "Scrub failed for request {} (attempt {}, will retry): {e}",
                        entry.request_id, attempts
                    );
                    db.defer_scrub(&entry.id, RETRY_BACKOFF_SECS)?;
                }
            }
        }
    }
    Ok(())
}
