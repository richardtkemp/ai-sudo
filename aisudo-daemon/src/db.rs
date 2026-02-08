use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct BwRequestRow {
    pub id: String,
    pub user: String,
    pub item_name: String,
    pub field: String,
    pub timestamp: String,
    pub status: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub nonce: String,
    pub resolved_item_name: Option<String>,
    pub credential_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScrubQueueEntry {
    pub id: String,
    pub request_id: String,
    pub credential_hash: String,
    pub credential_value: String,
    pub scrub_at: String,
    pub session_files: Vec<String>,
    pub status: String,
    pub completed_at: Option<String>,
    pub retry_count: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TempRuleRow {
    pub id: String,
    pub user: String,
    pub patterns: String,
    pub duration_seconds: u32,
    pub requested_at: String,
    pub expires_at: String,
    pub status: String,
    pub nonce: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
}

/// Parse a datetime string that may be RFC3339 or SQLite's `datetime('now')` format.
fn parse_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(naive.and_utc());
    }
    None
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                user TEXT NOT NULL,
                command TEXT NOT NULL,
                cwd TEXT,
                pid INTEGER,
                timestamp TEXT DEFAULT (datetime('now')),
                status TEXT DEFAULT 'pending',
                timeout_seconds INTEGER DEFAULT 60,
                decided_at TEXT,
                decided_by TEXT,
                nonce TEXT NOT NULL,
                stdin_bytes INTEGER
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                event TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS temp_rules (
                id TEXT PRIMARY KEY,
                user TEXT NOT NULL,
                patterns TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                nonce TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS bw_requests (
                id TEXT PRIMARY KEY,
                user TEXT NOT NULL,
                item_name TEXT NOT NULL,
                field TEXT NOT NULL DEFAULT 'password',
                timestamp TEXT DEFAULT (datetime('now')),
                status TEXT DEFAULT 'pending',
                decided_at TEXT,
                decided_by TEXT,
                nonce TEXT NOT NULL,
                resolved_item_name TEXT,
                credential_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS bw_scrub_queue (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                credential_hash TEXT NOT NULL,
                credential_value TEXT NOT NULL,
                scrub_at TEXT NOT NULL,
                session_files TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                completed_at TEXT,
                retry_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS bw_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                timestamp TEXT DEFAULT (datetime('now')),
                details TEXT
            );
            ",
        )?;
        // Migration: add stdin_bytes column to existing databases
        let _ = conn.execute_batch("ALTER TABLE requests ADD COLUMN stdin_bytes INTEGER;");
        Ok(())
    }

    pub fn insert_request(&self, record: &SudoRequestRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO requests (id, user, command, cwd, pid, timestamp, status, timeout_seconds, nonce, stdin_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.id,
                record.user,
                record.command,
                record.cwd,
                record.pid,
                record.timestamp.to_rfc3339(),
                record.status.as_str(),
                record.timeout_seconds,
                record.nonce,
                record.stdin_bytes.map(|n| n as i64),
            ],
        )?;
        drop(conn); // Release mutex before audit_log (which also locks it)
        let stdin_info = match record.stdin_bytes {
            Some(n) => format!(" stdin_bytes={n}"),
            None => String::new(),
        };
        self.audit_log(&record.id, "request_created", &format!("user={} command={}{}", record.user, record.command, stdin_info))?;
        Ok(())
    }

    pub fn update_decision(
        &self,
        request_id: &str,
        decision: Decision,
        decided_by: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE requests SET status = ?1, decided_at = datetime('now'), decided_by = ?2
             WHERE id = ?3 AND status = 'pending'",
            params![decision.as_str(), decided_by, request_id],
        )?;
        if changed > 0 {
            drop(conn);
            self.audit_log(
                request_id,
                &format!("decision_{}", decision.as_str()),
                &format!("by={}", decided_by),
            )?;
        }
        Ok(changed > 0)
    }

    pub fn get_request(&self, request_id: &str) -> Result<Option<SudoRequestRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, command, cwd, pid, timestamp, status, timeout_seconds, nonce, decided_at, decided_by, stdin_bytes
             FROM requests WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![request_id])?;
        if let Some(row) = rows.next()? {
            let status_str: String = row.get(6)?;
            let ts_str: String = row.get(5)?;
            let decided_at_str: Option<String> = row.get(9)?;
            let stdin_bytes: Option<i64> = row.get(11)?;
            Ok(Some(SudoRequestRecord {
                id: row.get(0)?,
                user: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                pid: row.get(4)?,
                timestamp: parse_datetime(&ts_str).unwrap_or_default(),
                status: Decision::from_str(&status_str).unwrap_or(Decision::Pending),
                timeout_seconds: row.get(7)?,
                nonce: row.get(8)?,
                decided_at: decided_at_str.and_then(|s| parse_datetime(&s)),
                decided_by: row.get(10)?,
                reason: None,
                stdin: None, // Not stored in DB
                stdin_bytes: stdin_bytes.map(|n| n as usize),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_pending_requests(&self) -> Result<Vec<SudoRequestRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, command, cwd, pid, timestamp, status, timeout_seconds, nonce, decided_at, decided_by, stdin_bytes
             FROM requests WHERE status = 'pending' ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let status_str: String = row.get(6)?;
            let ts_str: String = row.get(5)?;
            let decided_at_str: Option<String> = row.get(9)?;
            let stdin_bytes: Option<i64> = row.get(11)?;
            Ok(SudoRequestRecord {
                id: row.get(0)?,
                user: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                pid: row.get(4)?,
                timestamp: parse_datetime(&ts_str).unwrap_or_default(),
                status: Decision::from_str(&status_str).unwrap_or(Decision::Pending),
                timeout_seconds: row.get(7)?,
                nonce: row.get(8)?,
                decided_at: decided_at_str.and_then(|s| parse_datetime(&s)),
                decided_by: row.get(10)?,
                reason: None,
                stdin: None, // Not stored in DB
                stdin_bytes: stdin_bytes.map(|n| n as usize),
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn expire_timed_out_requests(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests
             WHERE status = 'pending'
             AND datetime(replace(timestamp, 'T', ' '), '+' || timeout_seconds || ' seconds') < datetime('now')",
        )?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        for id in &ids {
            conn.execute(
                "UPDATE requests SET status = 'timeout', decided_at = datetime('now'), decided_by = 'system'
                 WHERE id = ?1 AND status = 'pending'",
                params![id],
            )?;
        }
        drop(conn);

        for id in &ids {
            self.audit_log(id, "decision_timeout", "auto-expired")?;
        }

        Ok(ids)
    }

    pub fn insert_temp_rule(
        &self,
        id: &str,
        user: &str,
        patterns_json: &str,
        duration_seconds: u32,
        requested_at: &str,
        expires_at: &str,
        nonce: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO temp_rules (id, user, patterns, duration_seconds, requested_at, expires_at, nonce, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, user, patterns_json, duration_seconds, requested_at, expires_at, nonce, reason],
        )?;
        drop(conn);
        self.audit_log(id, "temp_rule_created", &format!("user={user} patterns={patterns_json} duration={duration_seconds}s"))?;
        Ok(())
    }

    pub fn update_temp_rule_decision(
        &self,
        id: &str,
        decision: Decision,
        decided_by: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE temp_rules SET status = ?1, decided_at = datetime('now'), decided_by = ?2
             WHERE id = ?3 AND status = 'pending'",
            params![decision.as_str(), decided_by, id],
        )?;
        if changed > 0 {
            drop(conn);
            self.audit_log(
                id,
                &format!("temp_rule_{}", decision.as_str()),
                &format!("by={decided_by}"),
            )?;
        }
        Ok(changed > 0)
    }

    pub fn get_temp_rule(&self, id: &str) -> Result<Option<TempRuleRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, patterns, duration_seconds, requested_at, expires_at, status, nonce, decided_at, decided_by, reason
             FROM temp_rules WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(TempRuleRow {
                id: row.get(0)?,
                user: row.get(1)?,
                patterns: row.get(2)?,
                duration_seconds: row.get(3)?,
                requested_at: row.get(4)?,
                expires_at: row.get(5)?,
                status: row.get(6)?,
                nonce: row.get(7)?,
                decided_at: row.get(8)?,
                decided_by: row.get(9)?,
                reason: row.get(10)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_active_temp_rules(&self, user: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT patterns FROM temp_rules
             WHERE user = ?1 AND status = 'approved'
             AND datetime(replace(substr(expires_at, 1, 19), 'T', ' ')) > datetime('now')",
        )?;
        let rows = stmt
            .query_map(params![user], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Get active temp rules with their patterns and expiry time (for --list-rules).
    pub fn get_active_temp_rules_detailed(&self, user: &str) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT patterns, expires_at FROM temp_rules
             WHERE user = ?1 AND status = 'approved'
             AND datetime(replace(substr(expires_at, 1, 19), 'T', ' ')) > datetime('now')",
        )?;
        let rows = stmt
            .query_map(params![user], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_all_temp_rules(&self) -> Result<Vec<TempRuleRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, patterns, duration_seconds, requested_at, expires_at, status, nonce, decided_at, decided_by, reason
             FROM temp_rules ORDER BY requested_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(TempRuleRow {
                    id: row.get(0)?,
                    user: row.get(1)?,
                    patterns: row.get(2)?,
                    duration_seconds: row.get(3)?,
                    requested_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    status: row.get(6)?,
                    nonce: row.get(7)?,
                    decided_at: row.get(8)?,
                    decided_by: row.get(9)?,
                    reason: row.get(10)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn expire_temp_rules(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM temp_rules
             WHERE status = 'approved'
             AND datetime(replace(substr(expires_at, 1, 19), 'T', ' ')) <= datetime('now')",
        )?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        for id in &ids {
            conn.execute(
                "UPDATE temp_rules SET status = 'expired', decided_at = datetime('now'), decided_by = 'system'
                 WHERE id = ?1 AND status = 'approved'",
                params![id],
            )?;
        }
        drop(conn);

        for id in &ids {
            self.audit_log(id, "temp_rule_expired", "auto-expired")?;
        }

        Ok(ids)
    }

    fn audit_log(&self, request_id: &str, event: &str, details: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (request_id, event, details) VALUES (?1, ?2, ?3)",
            params![request_id, event, details],
        )?;
        Ok(())
    }

    // --- Bitwarden request methods ---

    pub fn insert_bw_request(
        &self,
        id: &str,
        user: &str,
        item_name: &str,
        field: &str,
        nonce: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO bw_requests (id, user, item_name, field, nonce)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, user, item_name, field, nonce],
        )?;
        drop(conn);
        self.audit_log(id, "bw_request_created", &format!("user={user} item={item_name} field={field}"))?;
        Ok(())
    }

    pub fn update_bw_request_status(
        &self,
        id: &str,
        status: &str,
        decided_by: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE bw_requests SET status = ?1, decided_at = datetime('now'), decided_by = ?2
             WHERE id = ?3",
            params![status, decided_by, id],
        )?;
        if changed > 0 {
            drop(conn);
            self.audit_log(id, &format!("bw_request_{status}"), &format!("by={decided_by}"))?;
        }
        Ok(changed > 0)
    }

    pub fn set_bw_resolved_name(&self, id: &str, resolved_name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE bw_requests SET resolved_item_name = ?1 WHERE id = ?2",
            params![resolved_name, id],
        )?;
        Ok(())
    }

    pub fn set_bw_credential_hash(&self, id: &str, credential_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE bw_requests SET credential_hash = ?1 WHERE id = ?2",
            params![credential_hash, id],
        )?;
        Ok(())
    }

    pub fn get_bw_request(&self, id: &str) -> Result<Option<BwRequestRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, item_name, field, timestamp, status, decided_at, decided_by, nonce, resolved_item_name, credential_hash
             FROM bw_requests WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(BwRequestRow {
                id: row.get(0)?,
                user: row.get(1)?,
                item_name: row.get(2)?,
                field: row.get(3)?,
                timestamp: row.get(4)?,
                status: row.get(5)?,
                decided_at: row.get(6)?,
                decided_by: row.get(7)?,
                nonce: row.get(8)?,
                resolved_item_name: row.get(9)?,
                credential_hash: row.get(10)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get all pending BW requests (for the web dashboard).
    pub fn get_pending_bw_requests(&self) -> Result<Vec<BwRequestRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, item_name, field, timestamp, status, decided_at, decided_by, nonce, resolved_item_name, credential_hash
             FROM bw_requests WHERE status = 'pending' ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BwRequestRow {
                id: row.get(0)?,
                user: row.get(1)?,
                item_name: row.get(2)?,
                field: row.get(3)?,
                timestamp: row.get(4)?,
                status: row.get(5)?,
                decided_at: row.get(6)?,
                decided_by: row.get(7)?,
                nonce: row.get(8)?,
                resolved_item_name: row.get(9)?,
                credential_hash: row.get(10)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Get recently decided BW requests (for the web dashboard history).
    pub fn get_recent_bw_requests(&self, limit: u32) -> Result<Vec<BwRequestRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, item_name, field, timestamp, status, decided_at, decided_by, nonce, resolved_item_name, credential_hash
             FROM bw_requests WHERE status != 'pending' ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(BwRequestRow {
                id: row.get(0)?,
                user: row.get(1)?,
                item_name: row.get(2)?,
                field: row.get(3)?,
                timestamp: row.get(4)?,
                status: row.get(5)?,
                decided_at: row.get(6)?,
                decided_by: row.get(7)?,
                nonce: row.get(8)?,
                resolved_item_name: row.get(9)?,
                credential_hash: row.get(10)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    // --- Scrub queue methods ---

    pub fn insert_scrub_entry(
        &self,
        id: &str,
        request_id: &str,
        credential_hash: &str,
        credential_value: &str,
        scrub_at: &str,
        session_files: &[String],
    ) -> Result<()> {
        let files_json = serde_json::to_string(session_files)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO bw_scrub_queue (id, request_id, credential_hash, credential_value, scrub_at, session_files)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, request_id, credential_hash, credential_value, scrub_at, files_json],
        )?;
        drop(conn);
        self.audit_log(
            request_id,
            "bw_scrub_scheduled",
            &format!("hash={credential_hash} scrub_at={scrub_at} files={}", session_files.len()),
        )?;
        Ok(())
    }

    pub fn get_pending_scrubs(&self) -> Result<Vec<ScrubQueueEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, request_id, credential_hash, credential_value, scrub_at, session_files, status, completed_at, retry_count
             FROM bw_scrub_queue WHERE status IN ('pending', 'in_progress') ORDER BY scrub_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let files_json: String = row.get(5)?;
            let session_files: Vec<String> =
                serde_json::from_str(&files_json).unwrap_or_default();
            Ok(ScrubQueueEntry {
                id: row.get(0)?,
                request_id: row.get(1)?,
                credential_hash: row.get(2)?,
                credential_value: row.get(3)?,
                scrub_at: row.get(4)?,
                session_files,
                status: row.get(6)?,
                completed_at: row.get(7)?,
                retry_count: row.get(8)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn update_scrub_status(&self, id: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE bw_scrub_queue SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    pub fn complete_scrub(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE bw_scrub_queue SET status = 'completed', completed_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn defer_scrub(&self, id: &str, delay_secs: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE bw_scrub_queue SET status = 'pending', scrub_at = datetime('now', '+' || ?1 || ' seconds'), retry_count = retry_count + 1 WHERE id = ?2",
            params![delay_secs, id],
        )?;
        Ok(())
    }

    /// Extend scrub timer for existing entry with matching credential_hash.
    /// Returns true if an existing entry was extended.
    pub fn extend_scrub_timer(&self, credential_hash: &str, new_scrub_at: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE bw_scrub_queue SET scrub_at = ?1 WHERE credential_hash = ?2 AND status IN ('pending', 'in_progress')",
            params![new_scrub_at, credential_hash],
        )?;
        Ok(changed > 0)
    }

    // --- Session event logging ---

    pub fn log_bw_session_event(&self, event: &str, details: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO bw_session_events (event, details) VALUES (?1, ?2)",
            params![event, details],
        )?;
        Ok(())
    }

    /// Rate limit check for BW requests (separate from sudo rate limit).
    pub fn check_bw_rate_limit(&self, user: &str, max_per_minute: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM bw_requests
             WHERE user = ?1 AND datetime(replace(timestamp, 'T', ' ')) > datetime('now', '-1 minute')",
            params![user],
            |row| row.get(0),
        )?;
        Ok(count < max_per_minute)
    }

    pub fn check_rate_limit(&self, user: &str, max_per_minute: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM requests
             WHERE user = ?1 AND datetime(replace(timestamp, 'T', ' ')) > datetime('now', '-1 minute')",
            params![user],
            |row| row.get(0),
        )?;
        Ok(count < max_per_minute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db() -> (TempDir, Database) {
        let dir = TempDir::new().unwrap();
        let db = Database::open(&dir.path().join("test.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn insert_and_get_temp_rule() {
        let (_dir, db) = test_db();
        let now = chrono::Utc::now();
        let expires = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install", "apt list"]).unwrap();

        db.insert_temp_rule(
            "rule-1", "alice", &patterns, 3600,
            &now.to_rfc3339(), &expires, "nonce-1", Some("need deps"),
        ).unwrap();

        let rule = db.get_temp_rule("rule-1").unwrap().unwrap();
        assert_eq!(rule.user, "alice");
        assert_eq!(rule.status, "pending");
        assert_eq!(rule.reason.as_deref(), Some("need deps"));
    }

    #[test]
    fn get_active_temp_rules_only_approved_and_not_expired() {
        let (_dir, db) = test_db();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let past = (now - chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install"]).unwrap();

        // Approved, not expired — should be returned
        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        // Pending — should NOT be returned
        db.insert_temp_rule("r2", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n2", None).unwrap();

        // Denied — should NOT be returned
        db.insert_temp_rule("r3", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n3", None).unwrap();
        db.update_temp_rule_decision("r3", Decision::Denied, "test").unwrap();

        // Approved but expired — should NOT be returned
        db.insert_temp_rule("r4", "alice", &patterns, 3600, &now.to_rfc3339(), &past, "n4", None).unwrap();
        db.update_temp_rule_decision("r4", Decision::Approved, "test").unwrap();

        // Different user — should NOT be returned
        db.insert_temp_rule("r5", "bob", &patterns, 3600, &now.to_rfc3339(), &future, "n5", None).unwrap();
        db.update_temp_rule_decision("r5", Decision::Approved, "test").unwrap();

        let active = db.get_active_temp_rules("alice").unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], patterns);
    }

    #[test]
    fn update_temp_rule_decision_only_updates_pending() {
        let (_dir, db) = test_db();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install"]).unwrap();

        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();

        // First update should succeed
        assert!(db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap());

        // Second update should fail (no longer pending)
        assert!(!db.update_temp_rule_decision("r1", Decision::Denied, "test").unwrap());

        let rule = db.get_temp_rule("r1").unwrap().unwrap();
        assert_eq!(rule.status, "approved");
    }

    #[test]
    fn insert_and_get_request() {
        let (_dir, db) = test_db();
        let req = aisudo_common::SudoRequest {
            user: "alice".to_string(),
            command: "ls -la".to_string(),
            cwd: "/home/alice".to_string(),
            pid: 1234,
            mode: aisudo_common::RequestMode::Exec,
            reason: Some("testing".to_string()),
            stdin: Some("aGVsbG8=".to_string()),
            skip_nopasswd: false,
        };
        let record = aisudo_common::SudoRequestRecord::new(req, 60);
        let id = record.id.clone();

        db.insert_request(&record).unwrap();

        let fetched = db.get_request(&id).unwrap().unwrap();
        assert_eq!(fetched.user, "alice");
        assert_eq!(fetched.command, "ls -la");
        assert_eq!(fetched.cwd, "/home/alice");
        assert_eq!(fetched.pid, 1234);
        assert_eq!(fetched.status, Decision::Pending);
        assert_eq!(fetched.timeout_seconds, 60);
        assert_eq!(fetched.stdin_bytes, Some(6));
        assert!(fetched.decided_at.is_none());
        assert!(fetched.decided_by.is_none());
    }

    #[test]
    fn insert_request_without_stdin() {
        let (_dir, db) = test_db();
        let req = aisudo_common::SudoRequest {
            user: "alice".to_string(),
            command: "ls".to_string(),
            cwd: "/".to_string(),
            pid: 1,
            mode: aisudo_common::RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        };
        let record = aisudo_common::SudoRequestRecord::new(req, 60);
        let id = record.id.clone();
        db.insert_request(&record).unwrap();

        let fetched = db.get_request(&id).unwrap().unwrap();
        assert!(fetched.stdin_bytes.is_none());
    }

    #[test]
    fn get_request_not_found() {
        let (_dir, db) = test_db();
        assert!(db.get_request("nonexistent").unwrap().is_none());
    }

    #[test]
    fn update_decision_and_get() {
        let (_dir, db) = test_db();
        let req = aisudo_common::SudoRequest {
            user: "alice".to_string(),
            command: "ls".to_string(),
            cwd: "/".to_string(),
            pid: 1,
            mode: aisudo_common::RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        };
        let record = aisudo_common::SudoRequestRecord::new(req, 60);
        let id = record.id.clone();
        db.insert_request(&record).unwrap();

        assert!(db.update_decision(&id, Decision::Approved, "tester").unwrap());

        let fetched = db.get_request(&id).unwrap().unwrap();
        assert_eq!(fetched.status, Decision::Approved);
        assert!(fetched.decided_at.is_some());
        assert_eq!(fetched.decided_by.as_deref(), Some("tester"));
    }

    #[test]
    fn update_decision_only_updates_pending() {
        let (_dir, db) = test_db();
        let req = aisudo_common::SudoRequest {
            user: "alice".to_string(),
            command: "ls".to_string(),
            cwd: "/".to_string(),
            pid: 1,
            mode: aisudo_common::RequestMode::Pam,
            reason: None,
            stdin: None,
            skip_nopasswd: false,
        };
        let record = aisudo_common::SudoRequestRecord::new(req, 60);
        let id = record.id.clone();
        db.insert_request(&record).unwrap();

        assert!(db.update_decision(&id, Decision::Approved, "first").unwrap());
        assert!(!db.update_decision(&id, Decision::Denied, "second").unwrap());

        let fetched = db.get_request(&id).unwrap().unwrap();
        assert_eq!(fetched.status, Decision::Approved);
    }

    #[test]
    fn get_pending_requests_filters_correctly() {
        let (_dir, db) = test_db();
        for i in 0..3 {
            let req = aisudo_common::SudoRequest {
                user: "alice".to_string(),
                command: format!("cmd-{i}"),
                cwd: "/".to_string(),
                pid: i as u32,
                mode: aisudo_common::RequestMode::Pam,
                reason: None,
                stdin: None,
                skip_nopasswd: false,
            };
            let record = aisudo_common::SudoRequestRecord::new(req, 60);
            let id = record.id.clone();
            db.insert_request(&record).unwrap();
            if i == 2 {
                db.update_decision(&id, Decision::Approved, "test").unwrap();
            }
        }

        let pending = db.get_pending_requests().unwrap();
        assert_eq!(pending.len(), 2);
        for r in &pending {
            assert_eq!(r.status, Decision::Pending);
        }
    }

    #[test]
    fn get_all_temp_rules_returns_all() {
        let (_dir, db) = test_db();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install"]).unwrap();

        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.insert_temp_rule("r2", "bob", &patterns, 7200, &now.to_rfc3339(), &future, "n2", Some("testing")).unwrap();

        let all = db.get_all_temp_rules().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn get_active_temp_rules_detailed_returns_patterns_and_expiry() {
        let (_dir, db) = test_db();
        let now = chrono::Utc::now();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install", "apt list"]).unwrap();

        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        let detailed = db.get_active_temp_rules_detailed("alice").unwrap();
        assert_eq!(detailed.len(), 1);
        assert_eq!(detailed[0].0, patterns);
    }

    #[test]
    fn check_rate_limit_under_limit() {
        let (_dir, db) = test_db();
        assert!(db.check_rate_limit("alice", 5).unwrap());
    }

    #[test]
    fn check_rate_limit_at_limit() {
        let (_dir, db) = test_db();
        for i in 0..5 {
            let req = aisudo_common::SudoRequest {
                user: "alice".to_string(),
                command: format!("cmd-{i}"),
                cwd: "/".to_string(),
                pid: i as u32,
                mode: aisudo_common::RequestMode::Pam,
                reason: None,
                stdin: None,
                skip_nopasswd: false,
            };
            let record = aisudo_common::SudoRequestRecord::new(req, 60);
            db.insert_request(&record).unwrap();
        }
        assert!(!db.check_rate_limit("alice", 5).unwrap());
        // Different user still under limit
        assert!(db.check_rate_limit("bob", 5).unwrap());
    }

    #[test]
    fn expire_temp_rules_marks_expired() {
        let (_dir, db) = test_db();
        let now = chrono::Utc::now();
        let past = (now - chrono::Duration::seconds(10)).to_rfc3339();
        let future = (now + chrono::Duration::seconds(3600)).to_rfc3339();
        let patterns = serde_json::to_string(&vec!["apt install"]).unwrap();

        // Approved and expired
        db.insert_temp_rule("r1", "alice", &patterns, 3600, &now.to_rfc3339(), &past, "n1", None).unwrap();
        db.update_temp_rule_decision("r1", Decision::Approved, "test").unwrap();

        // Approved but not expired yet
        db.insert_temp_rule("r2", "alice", &patterns, 3600, &now.to_rfc3339(), &future, "n2", None).unwrap();
        db.update_temp_rule_decision("r2", Decision::Approved, "test").unwrap();

        let expired = db.expire_temp_rules().unwrap();
        assert_eq!(expired, vec!["r1"]);

        let rule = db.get_temp_rule("r1").unwrap().unwrap();
        assert_eq!(rule.status, "expired");

        // r2 should still be approved
        let rule = db.get_temp_rule("r2").unwrap().unwrap();
        assert_eq!(rule.status, "approved");
    }

    // --- Bitwarden DB tests ---

    #[test]
    fn insert_and_get_bw_request() {
        let (_dir, db) = test_db();
        db.insert_bw_request("bw-1", "alice", "GitHub Token", "password", "nonce-1").unwrap();

        let req = db.get_bw_request("bw-1").unwrap().unwrap();
        assert_eq!(req.user, "alice");
        assert_eq!(req.item_name, "GitHub Token");
        assert_eq!(req.field, "password");
        assert_eq!(req.status, "pending");
        assert_eq!(req.nonce, "nonce-1");
        assert!(req.resolved_item_name.is_none());
        assert!(req.credential_hash.is_none());
    }

    #[test]
    fn get_bw_request_not_found() {
        let (_dir, db) = test_db();
        assert!(db.get_bw_request("nonexistent").unwrap().is_none());
    }

    #[test]
    fn update_bw_request_status_and_get() {
        let (_dir, db) = test_db();
        db.insert_bw_request("bw-1", "alice", "Token", "password", "n1").unwrap();
        assert!(db.update_bw_request_status("bw-1", "approved", "telegram").unwrap());

        let req = db.get_bw_request("bw-1").unwrap().unwrap();
        assert_eq!(req.status, "approved");
        assert!(req.decided_at.is_some());
        assert_eq!(req.decided_by.as_deref(), Some("telegram"));
    }

    #[test]
    fn set_bw_resolved_name() {
        let (_dir, db) = test_db();
        db.insert_bw_request("bw-1", "alice", "Token", "password", "n1").unwrap();
        db.set_bw_resolved_name("bw-1", "GitHub Personal Access Token").unwrap();

        let req = db.get_bw_request("bw-1").unwrap().unwrap();
        assert_eq!(req.resolved_item_name.as_deref(), Some("GitHub Personal Access Token"));
    }

    #[test]
    fn set_bw_credential_hash() {
        let (_dir, db) = test_db();
        db.insert_bw_request("bw-1", "alice", "Token", "password", "n1").unwrap();
        db.set_bw_credential_hash("bw-1", "sha256:abc12345").unwrap();

        let req = db.get_bw_request("bw-1").unwrap().unwrap();
        assert_eq!(req.credential_hash.as_deref(), Some("sha256:abc12345"));
    }

    #[test]
    fn insert_and_get_scrub_entry() {
        let (_dir, db) = test_db();
        let files = vec!["/tmp/session1.jsonl".to_string(), "/tmp/session2.jsonl".to_string()];
        db.insert_scrub_entry("scrub-1", "bw-1", "sha256:abc", "secret123", "2026-02-08T12:00:00Z", &files).unwrap();

        let pending = db.get_pending_scrubs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "scrub-1");
        assert_eq!(pending[0].request_id, "bw-1");
        assert_eq!(pending[0].credential_hash, "sha256:abc");
        assert_eq!(pending[0].credential_value, "secret123");
        assert_eq!(pending[0].session_files.len(), 2);
        assert_eq!(pending[0].status, "pending");
    }

    #[test]
    fn complete_scrub_removes_from_pending() {
        let (_dir, db) = test_db();
        let files = vec!["/tmp/session.jsonl".to_string()];
        db.insert_scrub_entry("scrub-1", "bw-1", "sha256:abc", "secret", "2026-02-08T12:00:00Z", &files).unwrap();

        db.complete_scrub("scrub-1").unwrap();

        let pending = db.get_pending_scrubs().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn defer_scrub_increments_retry() {
        let (_dir, db) = test_db();
        let files = vec!["/tmp/session.jsonl".to_string()];
        db.insert_scrub_entry("scrub-1", "bw-1", "sha256:abc", "secret", "2026-02-08T12:00:00Z", &files).unwrap();
        db.update_scrub_status("scrub-1", "in_progress").unwrap();

        db.defer_scrub("scrub-1", 30).unwrap();

        let pending = db.get_pending_scrubs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, "pending");
        assert_eq!(pending[0].retry_count, 1);
    }

    #[test]
    fn extend_scrub_timer_existing() {
        let (_dir, db) = test_db();
        let files = vec!["/tmp/session.jsonl".to_string()];
        db.insert_scrub_entry("scrub-1", "bw-1", "sha256:abc", "secret", "2026-02-08T12:00:00Z", &files).unwrap();

        assert!(db.extend_scrub_timer("sha256:abc", "2026-02-08T13:00:00Z").unwrap());

        let pending = db.get_pending_scrubs().unwrap();
        assert_eq!(pending[0].scrub_at, "2026-02-08T13:00:00Z");
    }

    #[test]
    fn extend_scrub_timer_no_match() {
        let (_dir, db) = test_db();
        assert!(!db.extend_scrub_timer("sha256:nonexistent", "2026-02-08T13:00:00Z").unwrap());
    }

    #[test]
    fn log_bw_session_event() {
        let (_dir, db) = test_db();
        // Should not error
        db.log_bw_session_event("unlock", "via web_ui").unwrap();
        db.log_bw_session_event("lock", "manual").unwrap();
    }

    #[test]
    fn check_bw_rate_limit_under_limit() {
        let (_dir, db) = test_db();
        assert!(db.check_bw_rate_limit("alice", 10).unwrap());
    }

    #[test]
    fn check_bw_rate_limit_at_limit() {
        let (_dir, db) = test_db();
        for i in 0..10 {
            db.insert_bw_request(&format!("bw-{i}"), "alice", "Token", "password", &format!("n{i}")).unwrap();
        }
        assert!(!db.check_bw_rate_limit("alice", 10).unwrap());
        // Different user still under limit
        assert!(db.check_bw_rate_limit("bob", 10).unwrap());
    }
}
