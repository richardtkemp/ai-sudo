# Security Fixes Applied

## 1. Shell Injection via Allowlist Bypass (CRITICAL)

**Files:** `aisudo-daemon/src/socket.rs` - `is_allowed()` and `is_temp_rule_allowed()`

**Before:** `starts_with()` allowed `apt list; rm -rf /` to match `apt list`

**After:** Requires exact match OR prefix followed by a space character. Blocks `;`, `&&`, `$()`, tab, and other metacharacter injection.

## 2. User Identity Spoofing (CRITICAL)

**Files:** `aisudo-daemon/src/socket.rs`, `aisudo-cli/src/main.rs`

**Before:** Daemon trusted the `user` field from the client, which came from `$USER` env var (trivially spoofable).

**After:**
- Daemon extracts real UID via `stream.peer_cred()` (SO_PEERCRED, kernel-provided, cannot be spoofed)
- Resolves UID to username via `nix::unistd::User::from_uid()`
- Overrides client-supplied user field; logs warning on mismatch
- CLI now uses `libc::getuid()` + `libc::getpwuid()` instead of `$USER`

## 3. Telegram Callback Sender Validation (HIGH)

**File:** `aisudo-daemon/src/notification/telegram.rs`

**Before:** `CallbackQuery` struct didn't deserialize the `from` field. Anyone in a group chat could approve/deny.

**After:**
- Added `from: CallbackUser` field with `id: i64`
- `handle_callback()` rejects callbacks where `from.id != self.chat_id`

## 4. Error Message Sanitization (LOW)

**File:** `aisudo-daemon/src/socket.rs`

**Before:** Internal errors like JSON parse details and notification backend errors were sent to the client.

**After:** Client sees generic messages (`"request failed"`, `"notification error"`, `"invalid request"`). Full details still logged server-side via tracing.

## Not Addressed (Requires Non-Code Action)

- **Telegram bot token in git history** - Rotate via @BotFather immediately
- **Privilege dropping (setuid)** - Significant architectural change for future work
- **STDIN preview scrubbing** - Design decision needed
- **SQLite encryption** - Requires different build configuration

## Test Results

All 90 tests pass: `cargo test --workspace`
