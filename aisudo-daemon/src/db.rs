use aisudo_common::{Decision, SudoRequestRecord};
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

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
                nonce TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                event TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                details TEXT
            );
            ",
        )?;
        Ok(())
    }

    pub fn insert_request(&self, record: &SudoRequestRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO requests (id, user, command, cwd, pid, timestamp, status, timeout_seconds, nonce)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
            ],
        )?;
        drop(conn); // Release mutex before audit_log (which also locks it)
        self.audit_log(&record.id, "request_created", &format!("user={} command={}", record.user, record.command))?;
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
            "SELECT id, user, command, cwd, pid, timestamp, status, timeout_seconds, nonce, decided_at, decided_by
             FROM requests WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![request_id])?;
        if let Some(row) = rows.next()? {
            let status_str: String = row.get(6)?;
            let ts_str: String = row.get(5)?;
            let decided_at_str: Option<String> = row.get(9)?;
            Ok(Some(SudoRequestRecord {
                id: row.get(0)?,
                user: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                pid: row.get(4)?,
                timestamp: chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .unwrap_or_default()
                    .with_timezone(&chrono::Utc),
                status: Decision::from_str(&status_str).unwrap_or(Decision::Pending),
                timeout_seconds: row.get(7)?,
                nonce: row.get(8)?,
                decided_at: decided_at_str.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&chrono::Utc))
                }),
                decided_by: row.get(10)?,
                reason: None,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_pending_requests(&self) -> Result<Vec<SudoRequestRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user, command, cwd, pid, timestamp, status, timeout_seconds, nonce, decided_at, decided_by
             FROM requests WHERE status = 'pending' ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let status_str: String = row.get(6)?;
            let ts_str: String = row.get(5)?;
            let decided_at_str: Option<String> = row.get(9)?;
            Ok(SudoRequestRecord {
                id: row.get(0)?,
                user: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                pid: row.get(4)?,
                timestamp: chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .unwrap_or_default()
                    .with_timezone(&chrono::Utc),
                status: Decision::from_str(&status_str).unwrap_or(Decision::Pending),
                timeout_seconds: row.get(7)?,
                nonce: row.get(8)?,
                decided_at: decided_at_str.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&chrono::Utc))
                }),
                decided_by: row.get(10)?,
                reason: None,
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
             AND datetime(timestamp, '+' || timeout_seconds || ' seconds') < datetime('now')",
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

    fn audit_log(&self, request_id: &str, event: &str, details: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (request_id, event, details) VALUES (?1, ?2, ?3)",
            params![request_id, event, details],
        )?;
        Ok(())
    }

    pub fn check_rate_limit(&self, user: &str, max_per_minute: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM requests
             WHERE user = ?1 AND timestamp > datetime('now', '-1 minute')",
            params![user],
            |row| row.get(0),
        )?;
        Ok(count < max_per_minute)
    }
}
