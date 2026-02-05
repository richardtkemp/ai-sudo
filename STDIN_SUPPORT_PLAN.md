# Implementation Plan: stdin Support for aisudo

**Date:** 2026-02-05  
**Goal:** Enable heredocs, pipes, and stdin redirection to work with aisudo  
**Status:** Planning phase

---

## Problem Statement

Currently, commands like this don't work:

```bash
aisudo tee /etc/file << 'EOF'
content here
EOF

echo "data" | aisudo tee /etc/file
```

**Why:** The CLI doesn't capture stdin, and the daemon doesn't forward it to the child process.

---

## Design Goals

1. ✅ **Transparency:** User should be able to pipe data to aisudo naturally
2. ✅ **Security:** Show stdin preview in Telegram approval for transparency
3. ✅ **Practical limits:** Reasonable size caps to prevent abuse/memory issues
4. ✅ **Graceful degradation:** Binary data and huge inputs handled safely
5. ❌ **Non-goal:** Interactive stdin (like `passwd`) - not supported (would need PTY)

---

## Architecture Overview

```
User: echo "data" | aisudo tee /etc/file
              │
              ↓
┌─────────────────────────────────────────┐
│  CLI (aisudo-cli/src/main.rs)           │
│  1. Detect stdin available (!isatty)    │
│  2. Read stdin (up to MAX_STDIN_SIZE)   │
│  3. Base64-encode                        │
│  4. Add to SudoRequest                   │
└─────────────────┬───────────────────────┘
                  │ Unix socket
                  ↓
┌─────────────────────────────────────────┐
│  Daemon (aisudo-daemon/src/socket.rs)   │
│  1. Receive SudoRequest with stdin      │
│  2. Generate Telegram notification:     │
│     - Show command                       │
│     - Show stdin preview (truncated)    │
│  3. Wait for approval                    │
│  4. If approved:                         │
│     - Decode stdin                       │
│     - Configure child .stdin(piped())   │
│     - Write stdin to child process      │
│     - Stream stdout/stderr back         │
└─────────────────────────────────────────┘
```

---

## Protocol Changes

### 1. Modify `SudoRequest` (aisudo-common/src/lib.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoRequest {
    pub user: String,
    pub command: String,
    pub cwd: String,
    pub pid: u32,
    #[serde(default = "default_mode")]
    pub mode: RequestMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    
    // NEW: stdin data, base64-encoded
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
}
```

**Why base64?**
- JSON-safe encoding for arbitrary bytes
- Handles binary data without corruption
- Easy to decode server-side

**Alternatives considered:**
- Raw bytes as Vec<u8>: Not JSON-friendly, harder to debug
- Hex encoding: 2x size overhead vs base64's 1.33x

---

## CLI Changes (aisudo-cli/src/main.rs)

### Location: After parsing args, before creating SudoRequest

```rust
// NEW: Capture stdin if available
let stdin_data = capture_stdin()?;

let request = SudoRequest {
    user: user.clone(),
    command: command.clone(),
    cwd,
    pid,
    mode: RequestMode::Exec,
    reason,
    stdin: stdin_data,  // NEW
};
```

### New function: `capture_stdin()`

```rust
use std::io::{self, IsTerminal, Read};
use base64::Engine as _;

const MAX_STDIN_SIZE: usize = 10 * 1024 * 1024; // 10 MB

fn capture_stdin() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    
    // Don't capture if stdin is a terminal (user typing interactively)
    if stdin.is_terminal() {
        return Ok(None);
    }
    
    let mut buffer = Vec::new();
    let mut handle = stdin.lock();
    
    // Read with size limit
    let bytes_read = handle.take(MAX_STDIN_SIZE as u64).read_to_end(&mut buffer)?;
    
    if bytes_read == MAX_STDIN_SIZE {
        eprintln!("aisudo: warning: stdin truncated at {} bytes", MAX_STDIN_SIZE);
    }
    
    if buffer.is_empty() {
        return Ok(None);
    }
    
    // Base64-encode
    let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
    Ok(Some(encoded))
}
```

**Edge cases handled:**
- ✅ No stdin (terminal): Returns None
- ✅ Empty stdin: Returns None
- ✅ Large stdin: Truncates at 10MB with warning
- ✅ Binary data: Base64 handles safely

---

## Daemon Changes

### 1. Decode stdin (aisudo-daemon/src/socket.rs)

```rust
async fn handle_request(
    // ... existing params ...
) -> Result<()> {
    // ... existing code ...
    
    let request: SudoRequest = serde_json::from_str(line)?;
    
    // NEW: Decode stdin if present
    let stdin_bytes = if let Some(ref stdin_b64) = request.stdin {
        Some(base64::engine::general_purpose::STANDARD.decode(stdin_b64)?)
    } else {
        None
    };
    
    // ... rest of function ...
}
```

### 2. Show stdin in Telegram notification (aisudo-daemon/src/notification/telegram.rs)

```rust
async fn send_and_wait(&self, record: &SudoRequestRecord) -> Result<Decision> {
    let mut message = format!(
        "🔐 *sudo request*\n\n\
         User: `{}`\n\
         Command: `{}`\n\
         CWD: `{}`\n\
         Reason: {}",
        record.user,
        record.command,
        record.cwd,
        record.reason.as_deref().unwrap_or("_none_")
    );
    
    // NEW: Add stdin preview if present
    if let Some(ref stdin_b64) = record.stdin {
        let stdin_preview = format_stdin_preview(stdin_b64);
        message.push_str(&format!("\n\nStdin:\n```\n{}\n```", stdin_preview));
    }
    
    // ... rest of function ...
}

fn format_stdin_preview(stdin_b64: &str) -> String {
    const PREVIEW_SIZE: usize = 2048; // 2 KB preview
    
    let decoded = match base64::engine::general_purpose::STANDARD.decode(stdin_b64) {
        Ok(bytes) => bytes,
        Err(_) => return "[invalid base64]".to_string(),
    };
    
    // Check if binary
    if is_likely_binary(&decoded) {
        return format!("[binary data, {} bytes]", decoded.len());
    }
    
    // Convert to UTF-8 (lossy)
    let text = String::from_utf8_lossy(&decoded);
    
    if text.len() <= PREVIEW_SIZE {
        text.to_string()
    } else {
        format!("{}... ({} bytes total, truncated)", 
                &text[..PREVIEW_SIZE], 
                decoded.len())
    }
}

fn is_likely_binary(data: &[u8]) -> bool {
    // Heuristic: if >5% of first 512 bytes are non-printable, it's binary
    let sample_size = data.len().min(512);
    let sample = &data[..sample_size];
    
    let non_printable_count = sample.iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    
    (non_printable_count as f32 / sample_size as f32) > 0.05
}
```

### 3. Forward stdin to child process (aisudo-daemon/src/socket.rs)

```rust
async fn exec_command(
    command: &str,
    cwd: &str,
    stdin_bytes: Option<Vec<u8>>,  // NEW parameter
    writer: &mut tokio::net::unix::OwnedWriteHalf,
) -> Result<()> {
    use tokio::process::Command;
    use tokio::io::AsyncWriteExt;

    info!("Executing command: {command}");

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(if stdin_bytes.is_some() {
            std::process::Stdio::piped()  // NEW
        } else {
            std::process::Stdio::null()
        })
        .spawn()?;

    // NEW: Write stdin to child if present
    if let Some(data) = stdin_bytes {
        if let Some(mut stdin_pipe) = child.stdin.take() {
            tokio::spawn(async move {
                if let Err(e) = stdin_pipe.write_all(&data).await {
                    error!("Failed to write stdin to child: {e}");
                }
                // Close stdin pipe after writing
                drop(stdin_pipe);
            });
        }
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // ... rest of existing stdout/stderr streaming code ...
}
```

**Why spawn for stdin write:**
- Prevents blocking the main task
- Allows stdout/stderr streaming to start immediately
- stdin pipe closes automatically when task completes

---

## Size Limits & Configuration

### Add to aisudo.toml

```toml
[limits]
max_stdin_bytes = 10485760  # 10 MB default
stdin_preview_bytes = 2048  # 2 KB preview in Telegram
```

### Add to Config struct (aisudo-daemon/src/config.rs)

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    // ... existing fields ...
    
    #[serde(default = "default_limits")]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_stdin")]
    pub max_stdin_bytes: usize,
    
    #[serde(default = "default_preview_size")]
    pub stdin_preview_bytes: usize,
}

fn default_max_stdin() -> usize { 10 * 1024 * 1024 }
fn default_preview_size() -> usize { 2048 }
fn default_limits() -> LimitsConfig {
    LimitsConfig {
        max_stdin_bytes: default_max_stdin(),
        stdin_preview_bytes: default_preview_size(),
    }
}
```

---

## Edge Cases & Handling

### 1. Interactive stdin (e.g., `aisudo passwd`)

**Problem:** Commands that expect terminal input (like `passwd` prompting for password).

**Solution:** **Not supported** - these require a PTY, which is a much larger architectural change.

**Detection:** Already handled - `stdin.is_terminal()` returns false for pipes/heredocs, true for interactive terminals. We only capture non-terminal stdin.

**Error message:** If user tries: `aisudo passwd` (with terminal stdin), it will just execute without stdin, and the command will fail naturally with "stdin not a terminal" or similar.

### 2. Binary data

**Handling:**
- ✅ Base64 encoding in transit (safe)
- ✅ Detection via heuristic in `is_likely_binary()`
- ✅ Telegram shows "[binary data, X bytes]" instead of garbled text

**Example:**
```bash
cat image.png | aisudo tee /var/www/logo.png
# Telegram shows: "[binary data, 45823 bytes]"
```

### 3. Very large stdin (>10MB)

**CLI behavior:**
- Reads up to 10MB
- If stdin exceeds limit: **REJECT with error**
- Prints error: "aisudo: error: stdin exceeds limit (10485760 bytes)"
- Exit with code 1

**Rationale:**
- Explicit failure better than silent truncation
- Prevents data loss/corruption
- User can split large inputs or use alternative methods

**Implementation:**
```rust
if bytes_read == MAX_STDIN_SIZE {
    eprintln!("aisudo: error: stdin exceeds limit ({} bytes)", MAX_STDIN_SIZE);
    return Err("stdin too large".into());
}
```

### 4. Empty stdin

**Handling:**
- ✅ CLI returns `None` for stdin field
- ✅ Daemon doesn't configure child stdin pipe
- ✅ Child gets `/dev/null` as stdin (existing behavior)

### 5. Malformed base64

**Handling:**
- Daemon decode fails with error
- Request denied with error message: "invalid stdin encoding"
- Logged to audit trail

---

## Testing Strategy

### Unit Tests

**CLI (aisudo-cli/src/main.rs):**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capture_stdin_with_data() {
        // Mock stdin with test data
        // Verify base64 encoding
    }
    
    #[test]
    fn test_capture_stdin_empty() {
        // Mock empty stdin
        // Verify returns None
    }
    
    #[test]
    fn test_capture_stdin_size_limit() {
        // Mock 15MB stdin
        // Verify truncates at 10MB
        // Verify warning printed
    }
}
```

**Daemon (aisudo-daemon/src/socket.rs):**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_stdin_preview_text() {
        // Small text data
        // Verify full preview
    }
    
    #[test]
    fn test_format_stdin_preview_large() {
        // 5KB text
        // Verify truncation at 2KB
    }
    
    #[test]
    fn test_format_stdin_preview_binary() {
        // Binary data (e.g., PNG header)
        // Verify shows "[binary data, X bytes]"
    }
    
    #[test]
    fn test_is_likely_binary() {
        // Test with text, binary, mixed data
    }
}
```

### Integration Tests

**Test 1: Heredoc**
```bash
aisudo tee /tmp/test.txt << 'EOF'
Hello World
Multi-line
EOF

# Verify: file created with correct content
cat /tmp/test.txt
```

**Test 2: Pipe**
```bash
echo "test data" | aisudo tee /tmp/test2.txt

# Verify: file created
cat /tmp/test2.txt
```

**Test 3: Large stdin**
```bash
dd if=/dev/zero bs=1M count=15 | aisudo cat > /tmp/test3.bin

# Verify: file is 10MB (truncated)
ls -lh /tmp/test3.bin
```

**Test 4: Binary data**
```bash
cat /bin/ls | aisudo tee /tmp/ls-copy

# Verify: Telegram shows "[binary data, X bytes]"
# Verify: files are identical (binary preserved)
diff /bin/ls /tmp/ls-copy
```

**Test 5: Command with no stdin**
```bash
aisudo ls -la

# Verify: works as before (no regression)
```

---

## Migration & Compatibility

### Backwards Compatibility

**Protocol change:** Adding optional `stdin` field is backwards-compatible:
- Old CLI → New daemon: Works (stdin=None)
- New CLI → Old daemon: Fails (daemon doesn't understand stdin field)

**Solution:** Version both components together. Document that upgrading requires:
```bash
# Stop daemon
sudo systemctl stop aisudo-daemon

# Build & install new version
cargo build --release
sudo bash setup.sh

# Restart daemon
sudo systemctl start aisudo-daemon
```

---

## Implementation Checklist

### Phase 1: Protocol & CLI
- [ ] Add `stdin: Option<String>` to `SudoRequest` in `aisudo-common/src/lib.rs`
- [ ] Implement `capture_stdin()` in `aisudo-cli/src/main.rs`
- [ ] Add stdin capture to main flow in CLI
- [ ] Add unit tests for CLI stdin capture
- [ ] Update CLI help text to mention stdin support

### Phase 2: Daemon Execution
- [ ] Add stdin decode logic in `aisudo-daemon/src/socket.rs`
- [ ] Modify `exec_command()` to accept `stdin_bytes: Option<Vec<u8>>`
- [ ] Configure child process `.stdin(Stdio::piped())` when stdin present
- [ ] Implement stdin write task (tokio::spawn)
- [ ] Update all `exec_command()` call sites to pass stdin

### Phase 3: Telegram Notification
- [ ] Implement `format_stdin_preview()` in `aisudo-daemon/src/notification/telegram.rs`
- [ ] Implement `is_likely_binary()` helper
- [ ] Add stdin preview to Telegram message format
- [ ] Add unit tests for preview formatting

### Phase 4: Configuration
- [ ] Add `LimitsConfig` struct to `aisudo-daemon/src/config.rs`
- [ ] Add `[limits]` section to `aisudo.toml.example`
- [ ] Pass limits to stdin handling code

### Phase 5: Testing
- [ ] Write unit tests for all new functions
- [ ] Manual integration testing with heredocs, pipes, binary data
- [ ] Test with large stdin (verify truncation)
- [ ] Test Telegram preview display

### Phase 6: Documentation
- [ ] Update README.md with stdin support examples
- [ ] Update TOOLS.md (remove aisudo heredoc limitation)
- [ ] Add CHANGELOG entry
- [ ] Update `aisudo --help` output

---

## Open Questions

1. **Should we reject instead of truncate large stdin?**
   - Current plan: Truncate at 10MB with warning
   - Alternative: Return error "stdin exceeds limit"
   - Recommendation: Start with truncate, can make stricter later

2. **Should stdin size limit be per-user configurable?**
   - Current plan: Global config in aisudo.toml
   - Alternative: Per-user limits in database
   - Recommendation: Global is simpler, sufficient for now

3. **Should we log stdin content to audit database?**
   - Pro: Complete audit trail
   - Con: Could be huge, sensitive data
   - **DECIDED:** Log presence + size, not content
     - Add `stdin_bytes: Option<usize>` to SudoRequestRecord
     - This provides audit trail without bloating database

4. **Interactive stdin detection - should we explicitly reject?**
   - Current: Silently doesn't capture (command fails naturally)
   - Alternative: Detect and print error "aisudo: interactive stdin not supported"
   - Recommendation: Add explicit error message for better UX

---

## Timeline Estimate

**Development:** ~6-8 hours
- Phase 1 (Protocol & CLI): 2 hours
- Phase 2 (Daemon execution): 2 hours
- Phase 3 (Telegram): 1 hour
- Phase 4 (Config): 1 hour
- Phase 5 (Testing): 1-2 hours
- Phase 6 (Docs): 1 hour

**Assumes:** Familiarity with Rust, tokio, and the existing codebase.

---

## Success Criteria

✅ Heredocs work: `aisudo tee /etc/file << 'EOF'`  
✅ Pipes work: `echo "data" | aisudo tee /etc/file`  
✅ Binary data preserved correctly  
✅ Large stdin handled gracefully (truncated with warning)  
✅ Telegram shows stdin preview (truncated for large/binary)  
✅ No regression in existing functionality  
✅ Clear error messages for unsupported cases  
✅ Complete test coverage  

---

## Approved Changes (2026-02-05)

✅ **Decision 1:** Reject oversize payloads (>10MB) instead of truncating  
✅ **Decision 2:** Binary data shows "[binary data, X bytes]" in Telegram (already in plan)  
✅ **Change 1:** Explicit "interactive stdin not supported" error message  
✅ **Change 2:** Log stdin size in audit DB (`stdin_bytes: Option<usize>`)  

**Next Steps:**
1. ~~Review this plan with Dick~~ ✅ Approved
2. ~~Get approval on design decisions~~ ✅ Approved
3. Implement in phases (delegated to Claude)
4. Test thoroughly before deploying to production

**Author:** Clutch  
**Date:** 2026-02-05  
**Status:** Approved, ready for implementation
