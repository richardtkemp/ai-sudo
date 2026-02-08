use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub struct BwSessionManager {
    /// BW session key (from `bw unlock`), zeroized on drop.
    session_key: Mutex<Option<Zeroizing<String>>>,
    /// Last time the session was used (for auto-lock).
    last_used: Mutex<Option<Instant>>,
    /// When the session was locked (for status reporting).
    locked_since: Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    /// Auto-lock timeout from config.
    auto_lock_timeout: Duration,
    /// Path to `bw` binary.
    bw_binary: PathBuf,
}

impl BwSessionManager {
    pub fn new(bw_binary: PathBuf, auto_lock_timeout_secs: u32) -> Self {
        Self {
            session_key: Mutex::new(None),
            last_used: Mutex::new(None),
            locked_since: Mutex::new(Some(chrono::Utc::now())),
            auto_lock_timeout: Duration::from_secs(auto_lock_timeout_secs as u64),
            bw_binary,
        }
    }

    /// Check if vault is unlocked and session is still valid.
    pub async fn is_session_active(&self) -> bool {
        let key = self.session_key.lock().await;
        if key.is_none() {
            return false;
        }
        !self.is_auto_lock_expired().await
    }

    /// Return the timestamp when the session was locked (for status).
    pub async fn locked_since(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        *self.locked_since.lock().await
    }

    /// Return the last-used timestamp (for status).
    pub async fn last_used_time(&self) -> Option<String> {
        // We track Instant internally but report wall-clock approximation.
        let last = self.last_used.lock().await;
        last.map(|inst| {
            let elapsed = inst.elapsed();
            let wall = chrono::Utc::now() - chrono::Duration::from_std(elapsed).unwrap_or_default();
            wall.to_rfc3339()
        })
    }

    /// Unlock the vault with the given master password.
    /// Uses --passwordenv: sets BW_PASSWORD in child process environment (H2).
    pub async fn unlock(&self, password: &str) -> Result<()> {
        let password = Zeroizing::new(password.to_string());
        let mut cmd = tokio::process::Command::new(&self.bw_binary);
        cmd.args(["unlock", "--raw", "--passwordenv", "BW_PASSWORD"]);
        cmd.env("BW_PASSWORD", password.as_str());
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.spawn()?.wait_with_output().await?;
        // password is zeroized when dropped

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("bw unlock failed: {}", stderr);
            return Err(anyhow!("bw unlock failed"));
        }

        // With --raw, the session key is the entire stdout (no "export BW_SESSION=..." wrapper)
        let session_key = String::from_utf8(output.stdout)
            .map_err(|_| anyhow!("bw unlock returned non-UTF8 output"))?
            .trim()
            .to_string();

        if session_key.is_empty() {
            return Err(anyhow!("bw unlock returned empty session key"));
        }

        *self.session_key.lock().await = Some(Zeroizing::new(session_key));
        *self.locked_since.lock().await = None;
        self.touch().await;
        info!("BW vault unlocked");
        Ok(())
    }

    /// Retrieve a vault item by name. Returns the full BW item JSON.
    /// Session key passed via BW_SESSION env var (C1), not CLI arg.
    /// Item name validated before use (H1).
    pub async fn get_item_raw(&self, item_name: &str) -> Result<serde_json::Value> {
        validate_item_name(item_name)?;

        let output = self.run_bw_command(&["get", "item", item_name]).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't distinguish "not found" from "access denied" to prevent enumeration
            if stderr.contains("Not found") {
                return Err(anyhow!("item not found"));
            }
            return Err(anyhow!("bw get failed"));
        }

        let item: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| anyhow!("bw returned invalid JSON"))?;

        self.touch().await;
        Ok(item)
    }

    /// Extract a specific field from a BW item JSON response (M4).
    /// Only the requested field is returned; caller should zeroize the full JSON.
    pub fn extract_field(item_json: &serde_json::Value, field: &str) -> Result<String> {
        let value = match field {
            "password" => item_json
                .get("login")
                .and_then(|l| l.get("password"))
                .and_then(|v| v.as_str()),
            "username" => item_json
                .get("login")
                .and_then(|l| l.get("username"))
                .and_then(|v| v.as_str()),
            "totp" => item_json
                .get("login")
                .and_then(|l| l.get("totp"))
                .and_then(|v| v.as_str()),
            "notes" => item_json.get("notes").and_then(|v| v.as_str()),
            "uri" => item_json
                .get("login")
                .and_then(|l| l.get("uris"))
                .and_then(|u| u.as_array())
                .and_then(|arr| arr.first())
                .and_then(|u| u.get("uri"))
                .and_then(|v| v.as_str()),
            _ => return Err(anyhow!("unknown field: {field}")),
        };
        value
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("field '{field}' not found in item"))
    }

    /// Extract the item name from BW item JSON (for resolved name comparison).
    pub fn extract_item_name(item_json: &serde_json::Value) -> Option<String> {
        item_json.get("name").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    /// Lock the vault, clearing the session key (zeroized).
    pub async fn lock(&self) -> Result<()> {
        let mut key = self.session_key.lock().await;
        // Zeroizing<String> zeroes memory on drop
        *key = None;
        *self.locked_since.lock().await = Some(chrono::Utc::now());
        info!("BW vault locked");
        Ok(())
    }

    /// Touch the last-used timestamp.
    async fn touch(&self) {
        *self.last_used.lock().await = Some(Instant::now());
    }

    /// Check if auto-lock timeout has expired.
    async fn is_auto_lock_expired(&self) -> bool {
        let last = self.last_used.lock().await;
        match *last {
            Some(instant) => instant.elapsed() > self.auto_lock_timeout,
            None => false,
        }
    }

    /// Auto-lock if idle timeout expired. Returns true if locked.
    pub async fn check_auto_lock(&self) -> bool {
        if self.is_auto_lock_expired().await {
            let key = self.session_key.lock().await;
            if key.is_some() {
                drop(key);
                self.lock().await.ok();
                return true;
            }
        }
        false
    }

    /// Run a bw CLI command with session key in env (C1).
    async fn run_bw_command(&self, args: &[&str]) -> Result<std::process::Output> {
        let session_key = self.session_key.lock().await;
        if session_key.is_none() {
            return Err(anyhow!("vault is locked"));
        }
        let mut cmd = tokio::process::Command::new(&self.bw_binary);
        cmd.args(args);
        if let Some(ref key) = *session_key {
            cmd.env("BW_SESSION", key.as_str());
        }
        // No shell — direct exec (H1)
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn().map_err(|e| anyhow!("failed to spawn bw: {e}"))?;
        drop(session_key); // release mutex while waiting
        child.wait_with_output().await.map_err(Into::into)
    }
}

/// Validate an item name before passing to bw CLI (H1).
/// Rejects control characters, null bytes, and excessive length.
pub fn validate_item_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("item name cannot be empty"));
    }
    if name.len() > 256 {
        return Err(anyhow!("item name too long (max 256 characters)"));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(anyhow!("item name contains invalid characters"));
    }
    Ok(())
}

/// Compute SHA-256 hash of a credential for audit/scrub correlation.
pub fn credential_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(&result[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_item_name_valid() {
        assert!(validate_item_name("GitHub Token").is_ok());
        assert!(validate_item_name("a").is_ok());
        assert!(validate_item_name(&"x".repeat(256)).is_ok());
    }

    #[test]
    fn validate_item_name_empty() {
        assert!(validate_item_name("").is_err());
    }

    #[test]
    fn validate_item_name_too_long() {
        assert!(validate_item_name(&"x".repeat(257)).is_err());
    }

    #[test]
    fn validate_item_name_control_chars() {
        assert!(validate_item_name("foo\x00bar").is_err());
        assert!(validate_item_name("foo\nbar").is_err());
        assert!(validate_item_name("foo\tbar").is_err());
        assert!(validate_item_name("\x7fDEL").is_err());
    }

    #[test]
    fn extract_field_password() {
        let json: serde_json::Value = serde_json::json!({
            "name": "Test Item",
            "login": {
                "username": "user@example.com",
                "password": "secret123",
                "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{"uri": "https://example.com"}]
            },
            "notes": "some notes"
        });
        assert_eq!(
            BwSessionManager::extract_field(&json, "password").unwrap(),
            "secret123"
        );
        assert_eq!(
            BwSessionManager::extract_field(&json, "username").unwrap(),
            "user@example.com"
        );
        assert_eq!(
            BwSessionManager::extract_field(&json, "totp").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        assert_eq!(
            BwSessionManager::extract_field(&json, "notes").unwrap(),
            "some notes"
        );
        assert_eq!(
            BwSessionManager::extract_field(&json, "uri").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn extract_field_unknown() {
        let json = serde_json::json!({"login": {"password": "x"}});
        assert!(BwSessionManager::extract_field(&json, "unknown").is_err());
    }

    #[test]
    fn extract_field_missing() {
        let json = serde_json::json!({"login": {}});
        assert!(BwSessionManager::extract_field(&json, "password").is_err());
    }

    #[test]
    fn extract_item_name_present() {
        let json = serde_json::json!({"name": "GitHub Token", "login": {}});
        assert_eq!(
            BwSessionManager::extract_item_name(&json),
            Some("GitHub Token".to_string())
        );
    }

    #[test]
    fn extract_item_name_missing() {
        let json = serde_json::json!({"login": {}});
        assert_eq!(BwSessionManager::extract_item_name(&json), None);
    }

    #[test]
    fn credential_hash_deterministic() {
        let h1 = credential_hash("secret123");
        let h2 = credential_hash("secret123");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn credential_hash_different_inputs() {
        let h1 = credential_hash("secret123");
        let h2 = credential_hash("secret456");
        assert_ne!(h1, h2);
    }
}
