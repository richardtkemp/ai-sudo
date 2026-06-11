//! Session-log credential redaction for the Bitwarden integration.
//!
//! When a credential is released, it may have been written into the agent's
//! session `.jsonl` logs. After a delay, the scrubber worker (in `main.rs`)
//! rewrites those logs to remove the secret. This module provides the pure
//! redaction step; it never logs or returns the plaintext.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// What the secret is replaced with in the logs.
pub const REDACTION_PLACEHOLDER: &str = "***REDACTED***";

/// Replace every occurrence of `plaintext` in each file with the redaction
/// placeholder, writing the result back atomically (temp file in the same
/// directory + `rename`) while preserving the original file's permissions.
///
/// Missing files are skipped. Returns the number of files actually modified.
/// On an I/O or decode error the caller should retry/defer — the original file
/// is left untouched (the rename is atomic, so a partial write is never visible).
pub fn redact_session_files(files: &[String], plaintext: &str) -> std::io::Result<usize> {
    if plaintext.is_empty() {
        return Ok(0);
    }

    let mut modified = 0usize;
    for file in files {
        let path = Path::new(file);

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            // A log that no longer exists needs no redaction.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };

        if !content.contains(plaintext) {
            continue;
        }

        let redacted = content.replace(plaintext, REDACTION_PLACEHOLDER);

        // Preserve the original mode on the replacement; fall back to 0600.
        let mode = fs::metadata(path).map(|m| m.permissions().mode()).unwrap_or(0o600);

        // Temp file in the SAME directory so `rename` is atomic on one filesystem.
        // The name is hidden and does not end in `.jsonl`, so the log-discovery
        // filter will not pick it up if the daemon is interrupted mid-write.
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("session");
        let tmp = dir.join(format!(".{base}.scrub.tmp"));

        {
            let mut f = fs::File::create(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
            f.write_all(redacted.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        modified += 1;
    }

    Ok(modified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn tmpdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        // Unique-ish without Math.random/time: use the test thread name.
        let uniq = std::thread::current().name().unwrap_or("scrub").replace("::", "_");
        p.push(format!("aisudo_scrub_test_{uniq}"));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn redacts_secret_and_preserves_other_content() {
        let dir = tmpdir();
        let file = dir.join("session1.jsonl");
        fs::write(&file, "{\"line\":1}\nsecret-value-123 appears here\n{\"line\":3}\n").unwrap();

        let n = redact_session_files(&[file.to_string_lossy().to_string()], "secret-value-123").unwrap();
        assert_eq!(n, 1);

        let mut out = String::new();
        fs::File::open(&file).unwrap().read_to_string(&mut out).unwrap();
        assert!(!out.contains("secret-value-123"));
        assert!(out.contains(REDACTION_PLACEHOLDER));
        assert!(out.contains("{\"line\":1}"));
        assert!(out.contains("{\"line\":3}"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn preserves_file_permissions() {
        let dir = tmpdir();
        let file = dir.join("session2.jsonl");
        fs::write(&file, "topsecret here").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();

        redact_session_files(&[file.to_string_lossy().to_string()], "topsecret").unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "mode should be preserved across redaction");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn idempotent_and_skips_files_without_secret() {
        let dir = tmpdir();
        let file = dir.join("session3.jsonl");
        fs::write(&file, "no secret here").unwrap();

        // No occurrence -> 0 files modified.
        let n = redact_session_files(&[file.to_string_lossy().to_string()], "absent").unwrap();
        assert_eq!(n, 0);

        // Second pass after a successful redaction is a no-op.
        fs::write(&file, "secretX").unwrap();
        assert_eq!(redact_session_files(&[file.to_string_lossy().to_string()], "secretX").unwrap(), 1);
        assert_eq!(redact_session_files(&[file.to_string_lossy().to_string()], "secretX").unwrap(), 0);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_files_are_skipped() {
        let n = redact_session_files(&["/nonexistent/aisudo/none.jsonl".to_string()], "x").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn empty_plaintext_is_noop() {
        let n = redact_session_files(&["/whatever.jsonl".to_string()], "").unwrap();
        assert_eq!(n, 0);
    }
}
