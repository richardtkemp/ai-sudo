# aibw - Bitwarden Integration for AI Agent

## Overview

Extend aisudo to support Bitwarden credential retrieval with human approval. The agent can request specific vault items; the human approves via Telegram and provides master password when needed.

## Core Requirements

### 1. Credential Retrieval
- Agent requests specific Bitwarden vault items by name
- Human approves/denies each request via Telegram
- On approval (if session active): credential returned immediately
- On approval (if session inactive): human enters master password via web UI
- Credential returned to agent for use

### 2. Session Management
- Vault session key persists after first unlock (avoid re-entering password every time)
- Session key stored securely (root-only access)
- Manual lock command: `aibw lock`
- Auto-lock after configurable idle timeout
- Daemon verifies session is still active before sending simple approve/deny notification
- If session expired/inactive, send link to password entry page instead of buttons

### 3. Credential Scrubbing
- Credentials returned to agent are automatically scrubbed from session logs after configurable delay
- Default scrub delay: 10 minutes
- Scrub respects active processing (checks for `.jsonl.lock` file, retries if present)
- Repeated requests for same credential extend scrub timer
- Scrubber uses actual credential value to find and replace all occurrences

### 4. Security & Access Control
- Daemon runs as root (like aisudo)
- All access attempts logged (audit trail)
- Rate limiting on requests
- Web UI for password entry accessible only via Tailscale

### 5. Audit Logging
- Log all requests: timestamp, item requested, approved/denied, by whom
- Log all scrub operations: what was scrubbed, when, from which files
- Log session lock/unlock events

## Environment Details

### Agent Session Logs Location
```
/home/rich/git/openclaw/config/agents/main/sessions/
├── sessions.json                              # Session index/metadata
├── <session-uuid>.jsonl                       # Conversation history (JSONL format)
├── <session-uuid>.jsonl.lock                  # Lock file during active processing
```

Lock file format:
```json
{
  "pid": 1420134,
  "createdAt": "2026-02-08T15:24:06.570Z"
}
```

Lock file exists only while agent is actively processing. Scrubber must check for lock and defer if present.

### Existing aisudo Architecture
- Rust daemon running as root via systemd
- Unix socket for client communication
- Telegram bot integration for approval notifications
- SQLite database for audit logging
- Rate limiting already implemented

### Bitwarden CLI
- Installed at: `/usr/bin/bw` (or check `which bw`)
- Login: `bw login --apikey` (uses BW_CLIENTID, BW_CLIENTSECRET env vars)
- Unlock: `bw unlock --passwordenv BW_PASSWORD` or `bw unlock --passwordfile <path>`
- Get item: `bw get item <name-or-id> --session <session_key>`
- Lock: `bw lock`
- Session key returned by unlock command

### Network Access
- Password entry web UI must be accessible via Tailscale only
- NUC Tailscale hostname: `nuc.brown-ordinal.ts.net`
- Can reuse existing Tailscale Serve configuration or add new route

## CLI Interface

```bash
# Request a credential (triggers approval flow)
aibw get "GitHub Token"
aibw get "OpenRouter API Key"

# Lock the session manually
aibw lock

# Check session status
aibw status
```

## Telegram Notification Flow

### If session is active (unlocked):
```
🔐 Bitwarden Request

Agent requests: "GitHub Token"
Session: active

[Approve] [Deny]
```

### If session is inactive (locked):
```
🔐 Bitwarden Request

Agent requests: "GitHub Token"
Session: locked

Unlock vault to approve:
https://nuc.brown-ordinal.ts.net/aibw/unlock?request=<request-id>
```

## Web UI for Password Entry

Simple page accessible via Tailscale:
- Shows what credential is being requested
- Password input field
- Submit button
- On success: unlocks vault, approves request, returns credential to waiting agent
- On failure: shows error, allows retry

## Scrub Queue

Daemon maintains scrub queue:
```json
{
  "pending": [
    {
      "credential_hash": "sha256:...",  // For identification only
      "credential_value": "ghp_xxx...", // Actual value for scrubbing
      "scrub_at": "2026-02-08T15:40:00Z",
      "session_files": ["/path/to/session.jsonl"],
      "request_id": "uuid"
    }
  ]
}
```

Scrub process:
1. Check if scrub_at has passed
2. For each session file, check for .lock file
3. If locked, defer scrub by 30 seconds
4. If unlocked, replace all occurrences of credential_value with `[REDACTED:aibw]`
5. Remove entry from queue
6. Log scrub operation

## Integration Points with aisudo

- Reuse: Telegram bot, SQLite audit logging, rate limiting, systemd service, Unix socket IPC
- Add: Bitwarden session management, web server for password entry, scrub scheduler
- Extend: CLI with `aibw` subcommand or separate binary
