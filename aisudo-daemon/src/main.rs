mod bw_session;
mod config;
mod db;
mod notification;
mod socket;
mod sudoers;
mod web;

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
            let tg = TelegramBackend::new(
                tg_config.bot_token.clone(),
                tg_config.chat_id,
                config.timeout_seconds,
                config.limits.stdin_preview_bytes,
                tg_config.poll_timeout_seconds,
                Arc::clone(&config_holder),
            );
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

    // Start web UI if bitwarden is enabled
    if let Some(ref bw_session_ref) = bw_session {
        if let Some(ref bw_config) = config.bitwarden {
            let web_state = web::WebState::new(
                Arc::clone(bw_session_ref),
                Arc::clone(&db),
                Arc::clone(&pending_unlocks),
                bw_config.max_password_attempts,
            );
            let port = bw_config.web_ui_port;
            tokio::spawn(async move {
                web::run_web_server(web_state, port).await;
            });
            info!("Web UI spawned on port {}", bw_config.web_ui_port);
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
    socket::run_socket_listener(config_holder, db, backend, bw_session, pending_unlocks).await?;

    Ok(())
}
