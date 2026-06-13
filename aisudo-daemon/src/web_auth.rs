//! Short-lived access codes and sessions gating the Bitwarden web UI.
//!
//! The UI is fronted by a code delivered over Telegram (the channel only the
//! operator controls). Tapping the link redeems the single-use code for a
//! short-lived session cookie; all real UI routes require a valid session.
//!
//! Codes and session ids are 122-bit random UUIDs looked up by key, so a plain
//! map lookup is sufficient — no constant-time compare is needed.

use dashmap::DashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Sliding window and cap for the global "send code" rate limit (anti-spam for
/// the operator's Telegram; access is never granted by issuing a code).
const GLOBAL_WINDOW: Duration = Duration::from_secs(60);
const GLOBAL_MAX_PER_WINDOW: usize = 10;

struct CodeEntry {
    expires_at: Instant,
    request_id: Option<String>,
}

pub struct WebAuth {
    /// Public base URL (no trailing slash) used to build unlock links. None
    /// disables link delivery.
    base_url: Option<String>,
    code_ttl: Duration,
    session_ttl: Duration,
    cooldown: Duration,
    codes: DashMap<String, CodeEntry>,
    /// session_id -> expiry.
    sessions: DashMap<String, Instant>,
    /// caller identity -> last code-request time (per-identity cooldown).
    last_request: DashMap<String, Instant>,
    /// recent code-request times for the global cap.
    global_requests: Mutex<Vec<Instant>>,
}

impl WebAuth {
    pub fn new(
        base_url: Option<String>,
        code_ttl_seconds: u32,
        session_ttl_seconds: u32,
        cooldown_seconds: u32,
    ) -> Self {
        Self {
            base_url: base_url.map(|u| u.trim_end_matches('/').to_string()),
            code_ttl: Duration::from_secs(code_ttl_seconds as u64),
            session_ttl: Duration::from_secs(session_ttl_seconds as u64),
            cooldown: Duration::from_secs(cooldown_seconds as u64),
            codes: DashMap::new(),
            sessions: DashMap::new(),
            last_request: DashMap::new(),
            global_requests: Mutex::new(Vec::new()),
        }
    }

    /// Whether tappable links can be built (i.e. a base URL is configured).
    pub fn link_delivery_enabled(&self) -> bool {
        self.base_url.is_some()
    }

    /// Session lifetime in seconds (for the cookie Max-Age).
    pub fn session_max_age(&self) -> u64 {
        self.session_ttl.as_secs()
    }

    /// Mint a single-use code and return the tappable unlock URL, or None when no
    /// base URL is configured. `request_id`, if given, is carried through redemption
    /// so the unlock page can target a specific pending request.
    pub fn issue_link(&self, request_id: Option<&str>) -> Option<String> {
        let base = self.base_url.as_ref()?;
        self.sweep_codes();
        let code = Uuid::new_v4().simple().to_string();
        self.codes.insert(
            code.clone(),
            CodeEntry {
                expires_at: Instant::now() + self.code_ttl,
                request_id: request_id.map(|s| s.to_string()),
            },
        );
        let mut url = format!("{base}/aibw/unlock?c={code}");
        if let Some(req) = request_id {
            url.push_str("&request=");
            url.push_str(req);
        }
        Some(url)
    }

    /// Validate and consume a code; on success mint a session and return
    /// (session_id, associated request_id).
    pub fn redeem(&self, code: &str) -> Option<(String, Option<String>)> {
        let (_, entry) = self.codes.remove(code)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        let session_id = Uuid::new_v4().simple().to_string();
        self.sessions
            .insert(session_id.clone(), Instant::now() + self.session_ttl);
        Some((session_id, entry.request_id))
    }

    /// Whether the given session id is present and unexpired.
    pub fn is_session_valid(&self, session_id: &str) -> bool {
        let now = Instant::now();
        // The Ref from `get` is dropped at the end of this statement, before any remove.
        let valid = self
            .sessions
            .get(session_id)
            .map(|e| *e.value() > now)
            .unwrap_or(false);
        if !valid {
            self.sessions.remove(session_id);
        }
        valid
    }

    /// Whether a "send access code" request from `identity` is allowed now. On
    /// success it records the request (consuming the per-identity cooldown slot and
    /// a global-window slot). Returns false if within the per-identity cooldown or
    /// over the global cap.
    pub fn allow_code_request(&self, identity: &str) -> bool {
        let now = Instant::now();

        if let Some(last) = self.last_request.get(identity) {
            if now.duration_since(*last.value()) < self.cooldown {
                return false;
            }
        }

        {
            let mut g = self.global_requests.lock().unwrap();
            g.retain(|t| now.duration_since(*t) < GLOBAL_WINDOW);
            if g.len() >= GLOBAL_MAX_PER_WINDOW {
                return false;
            }
            g.push(now);
        }

        self.last_request.insert(identity.to_string(), now);
        true
    }

    fn sweep_codes(&self) {
        let now = Instant::now();
        self.codes.retain(|_, e| e.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> WebAuth {
        WebAuth::new(Some("https://host.example/".to_string()), 600, 900, 30)
    }

    #[test]
    fn no_base_url_disables_links() {
        let a = WebAuth::new(None, 600, 900, 30);
        assert!(!a.link_delivery_enabled());
        assert!(a.issue_link(None).is_none());
    }

    #[test]
    fn issue_link_builds_url_and_strips_trailing_slash() {
        let a = auth();
        let url = a.issue_link(Some("req-1")).unwrap();
        assert!(url.starts_with("https://host.example/aibw/unlock?c="));
        assert!(url.contains("&request=req-1"));
        assert!(!url.contains("//aibw")); // trailing slash on base was trimmed
    }

    #[test]
    fn code_redeems_exactly_once() {
        let a = auth();
        let url = a.issue_link(Some("req-7")).unwrap();
        let code = url
            .split("c=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();

        let (session, req) = a.redeem(&code).expect("first redeem works");
        assert_eq!(req.as_deref(), Some("req-7"));
        assert!(a.is_session_valid(&session));

        // Second use of the same code fails (single-use).
        assert!(a.redeem(&code).is_none());
    }

    #[test]
    fn unknown_code_and_session_rejected() {
        let a = auth();
        assert!(a.redeem("nope").is_none());
        assert!(!a.is_session_valid("nope"));
    }

    #[test]
    fn expired_code_is_rejected() {
        let a = WebAuth::new(Some("https://h".to_string()), 0, 900, 30);
        let url = a.issue_link(None).unwrap();
        let code = url.split("c=").nth(1).unwrap().to_string();
        // TTL of 0 => expires_at == issue time, which is <= now at redeem.
        assert!(a.redeem(&code).is_none());
    }

    #[test]
    fn expired_session_is_invalid() {
        let a = WebAuth::new(Some("https://h".to_string()), 600, 0, 30);
        let url = a.issue_link(None).unwrap();
        let code = url.split("c=").nth(1).unwrap().to_string();
        let (session, _) = a.redeem(&code).unwrap();
        assert!(!a.is_session_valid(&session));
    }

    #[test]
    fn per_identity_cooldown() {
        let a = auth(); // cooldown 30s
        assert!(a.allow_code_request("alice"));
        // Immediate retry is blocked by the cooldown.
        assert!(!a.allow_code_request("alice"));
        // A different identity is independent.
        assert!(a.allow_code_request("bob"));
    }

    #[test]
    fn global_cap_blocks_after_window_max() {
        // No per-identity cooldown so only the global cap applies.
        let a = WebAuth::new(Some("https://h".to_string()), 600, 900, 0);
        for i in 0..GLOBAL_MAX_PER_WINDOW {
            assert!(
                a.allow_code_request(&format!("id-{i}")),
                "request {i} should be allowed"
            );
        }
        assert!(
            !a.allow_code_request("id-overflow"),
            "global cap should block"
        );
    }
}
