# aibw Security Review: Remote Attacker Threat Model

This review assesses the aibw system from the perspective of a **remote attacker** — someone not on the machine, attacking over the network. This complements the original security review which focused on a compromised local AI agent.

---

## Threat Model

**Attacker profile**: External adversary with no initial access to the NUC. Capabilities range from passive network observer to active attacker with control of adjacent systems.

**Attacker goals**:
1. Steal Bitwarden credentials in transit or at rest
2. Trick the human into approving credential retrieval for the attacker
3. Unlock the vault without authorization
4. Intercept or replay approval messages
5. Compromise the daemon to gain persistent access

**System topology**:
```
[Agent on NUC] → Unix socket → [aisudo-daemon on NUC]
                                    ↕ HTTPS (Telegram Bot API)
                                [Telegram servers]
                                    ↕ HTTPS (Telegram client)
                                [Human's phone/desktop]

[Human's device] → Tailscale → [NUC:8377 via Tailscale Serve]
                                    ↕ localhost
                                [aisudo-daemon web UI]
```

---

## CRITICAL Findings

### RC1: Telegram Bot Token Compromise Grants Full Approval Authority

**Severity**: CRITICAL

The Telegram bot token is stored in `/etc/aisudo/aisudo.toml` in plaintext. If an attacker obtains this token, they can:

1. **Receive all getUpdates** — see every pending approval request (item names, users, request IDs)
2. **Send callback queries** — approve or deny any request by constructing the right `callback_data` (e.g., `approve_bw:<request-id>`)
3. **Race the legitimate polling loop** — call `getUpdates` with a higher offset to steal updates before the daemon sees them

The bot token is the single secret that controls the entire approval channel. Compromise vectors:
- Config file backup leaked (e.g., in a git repo, a tarball, a cloud backup)
- Log file containing the token (e.g., if tracing logs the config at startup at DEBUG level)
- Process environment if the token is passed via env var
- Memory dump of the daemon process

**Impact**: Attacker can silently approve any credential request without the human ever seeing the notification. The human wouldn't know — the attacker's `getUpdates` call with a higher offset consumes the update, and the daemon's poll never sees the callback.

**Remediation**:
- **Callback sender validation already exists** (`from.id == chat_id`), but this checks the `from` field in the callback, which is set by Telegram based on who pressed the button. An attacker using the bot API directly cannot forge `from.id` — they would need to use `answerCallbackQuery`, not create fake callbacks. **However**, an attacker with the bot token can call `getUpdates` and steal the legitimate user's callback before the daemon processes it. They can then fabricate the response.
- Actually, re-examining: an attacker with the bot token **cannot** forge callback queries. Callbacks are user-initiated via button presses in the Telegram UI. The attacker can only *read* them by racing `getUpdates`. But the attacker **can** send messages to the chat impersonating the bot (e.g., phishing the human with a fake "unlock vault" link).
- **Real risk**: Token leak allows the attacker to (a) read all approval requests (credential names, users), (b) race to consume callbacks and prevent the daemon from seeing approvals (DoS), (c) send phishing messages via the bot.
- **Mitigation**: Treat the bot token as a high-value secret. Ensure it's not logged. Consider using a separate bot token for aibw vs. aisudo. Rotate periodically.

### RC2: Telegram Messages Are Not End-to-End Encrypted

**Severity**: CRITICAL

Telegram Bot API messages use HTTPS transport encryption (TLS) to Telegram's servers, but messages are **readable by Telegram** (the company). This means:

1. Telegram (the company or a compromised employee) can read every approval notification, including:
   - Item names being requested ("Production Database Password")
   - Request IDs (needed for web UI unlock URLs)
   - Approval/denial decisions and timing
2. If compelled by a government or court order, Telegram must provide this data
3. A compromised Telegram infrastructure node sees all traffic

The **credential values themselves are never sent via Telegram** (they go over the local Unix socket), so this is a metadata exposure issue, not a direct credential leak.

**Impact**: An adversary with access to Telegram's servers knows exactly which credentials are being requested and when, enabling targeted attacks.

**Remediation**:
- This is an inherent limitation of the Telegram Bot API (bots cannot use Telegram's "Secret Chats" E2E encryption).
- Accept this risk for the current single-user personal-server threat model.
- If credential names are sensitive, consider using opaque identifiers in Telegram messages and showing the real name only in the web UI.
- For a higher-security deployment, replace Telegram with a self-hosted notification system (e.g., Signal, Matrix with Olm E2E, or a custom push notification system).

---

## HIGH Findings

### RH1: Web UI Unlock URL Sent Via Telegram — Phishable

**Severity**: HIGH

When the BW session is locked, the Telegram message contains a URL like:
```
https://nuc.brown-ordinal.ts.net/aibw/unlock?request=<uuid>
```

An attacker who can send messages in the Telegram chat (e.g., via a compromised bot token per RC1, or by being added to a group chat) can send a **fake unlock URL** pointing to their own server:
```
https://nuc.brown-ordinal.ts.net.evil.com/aibw/unlock?request=<uuid>
```

The human clicks the fake link, enters their BW master password on the attacker's page, and the attacker captures it.

**Impact**: BW master password stolen → full vault compromise.

**Remediation**:
- Train the user to verify the URL domain before entering the password (weak mitigation — humans are bad at this).
- Use Tailscale Serve with a verified HTTPS certificate for the `.ts.net` domain. The user can check for the Tailscale certificate.
- Consider not putting the URL in the Telegram message at all. Instead, just show "Session locked — unlock via web UI" and have the user navigate to a bookmarked URL. The web UI can show all pending requests.
- **Best**: Add a persistent dashboard page at `https://nuc.brown-ordinal.ts.net/aibw/` that shows pending requests. The Telegram message says "unlock needed" but doesn't include a clickable URL. Human navigates to bookmarked URL.

### RH2: Web UI Has No Authentication Beyond Request ID

**Severity**: HIGH

The web UI at `/aibw/unlock?request=<uuid>` has no authentication. Anyone who can reach the URL (via Tailscale) and knows/guesses the request UUID can:
1. View what credential is being requested
2. Submit a password to unlock the vault

Tailscale provides network-level authentication (only devices on the tailnet can connect), but:
- If any device on the tailnet is compromised, it can access the web UI
- Tailscale Serve by default doesn't require the connecting device to authenticate further (no Tailscale identity headers unless configured with `--set-header`)
- A compromised phone on the tailnet (e.g., malware on the same phone that receives Telegram notifications) has full access

**Impact**: Any compromised tailnet device can submit passwords to the unlock endpoint.

**Remediation**:
- Enable Tailscale Serve identity headers (`Tailscale-User-Login`, `Tailscale-User-Name`) and validate that the connecting user matches an authorized list in the daemon config.
- Add HTTP basic auth as an additional layer (username/password stored in config).
- The request UUID is already unguessable (UUID v4), so the risk is primarily from tailnet-level compromise.

### RH3: Bitwarden API Key Credentials Stored on Disk

**Severity**: HIGH

The `bw` CLI requires `BW_CLIENTID` and `BW_CLIENTSECRET` environment variables (or interactive login) to authenticate with Bitwarden servers. These are likely stored somewhere on the NUC — either:
- In `/root/.config/Bitwarden CLI/data.json` (BW CLI's config)
- In the systemd service file as `Environment=` directives
- In the aisudo config file
- In a `.env` file

If a remote attacker gains any file read on the NUC (e.g., via a different service vulnerability, a path traversal bug, a backup leak), they can steal the BW API credentials and use them to:
1. Log in to Bitwarden from their own machine
2. Unlock the vault (if they also have the master password, or can brute-force it)

**Impact**: Bitwarden vault fully compromised if API credentials + master password are both obtained.

**Remediation**:
- Ensure BW API credentials are stored with `0600 root:root` permissions.
- Don't store them in the aisudo config file — keep them separate.
- Monitor Bitwarden login activity for unexpected logins.
- Enable Bitwarden 2FA (which protects against API key + master password compromise).

### RH4: bw CLI Communicates with Bitwarden Servers Over HTTPS

**Severity**: HIGH (if TLS is compromised)

The `bw` CLI calls `vault.bitwarden.com` over HTTPS to retrieve vault data. Attack vectors:

1. **TLS interception**: If the NUC's CA certificate store is compromised (rogue CA added), a MITM attacker on the network path could intercept `bw` CLI traffic.
2. **DNS poisoning**: If the NUC's DNS resolver is compromised, `vault.bitwarden.com` could resolve to an attacker-controlled server.
3. **Bitwarden server compromise**: If Bitwarden's infrastructure is compromised, vault data could be exfiltrated (though BW uses zero-knowledge encryption — the server never sees decrypted data).

**Impact**: Vault data encryption keys are derived from the master password (PBKDF2/Argon2). Even with a MITM on the BW API, the attacker gets encrypted vault data that they'd need the master password to decrypt.

**Remediation**:
- Ensure the NUC uses a trusted DNS resolver (e.g., Tailscale DNS, systemd-resolved with DNSSEC).
- Don't add custom CA certificates unless necessary.
- This is largely an accepted risk — BW's zero-knowledge architecture provides defense-in-depth.

---

## MEDIUM Findings

### RM1: Telegram Bot Polling Denial-of-Service

**Severity**: MEDIUM

An attacker with the bot token (or who compromises the Telegram Bot API) can call `getUpdates` with a very high offset, causing all pending callback updates to be marked as "seen" by Telegram. The daemon's polling loop would never receive them.

**Effect**: All approval buttons become non-functional. The human presses "Approve" but the daemon never receives the callback. Requests time out.

**Remediation**:
- Monitor for unexpected approval timeouts. If many requests time out despite the human approving, the bot token may be compromised.
- The web UI path (entering the password directly) still works as a fallback since it doesn't depend on Telegram callbacks.
- Rotate the bot token if compromise is suspected.

### RM2: Tailscale Network Trust Boundary

**Severity**: MEDIUM

The web UI is accessible to **any device on the Tailscale network**. The security of the web UI depends entirely on the security of the tailnet. Risks:
- If one device on the tailnet is compromised, it can reach the web UI
- If Tailscale ACLs are not configured, all devices have equal access
- Shared tailnets (e.g., family plans) expose the web UI to all members

**Remediation**:
- Configure Tailscale ACLs to restrict which devices can reach port 8377 on the NUC.
- Use Tailscale Serve's identity verification to restrict to specific users.
- Audit tailnet membership regularly.

### RM3: Web UI Password Brute-Force Over Tailscale

**Severity**: MEDIUM

The web UI accepts the BW master password. An attacker on the tailnet can:
1. Observe a request ID from a Telegram message (if they have bot token access)
2. Send repeated POST requests to `/aibw/unlock` with different passwords

The plan includes rate limiting (5 attempts/minute per request ID), but:
- The attacker can create multiple request IDs by making `aibw get` requests (if they have local access) or by waiting for legitimate requests
- 5 attempts/minute = 300/hour = 7200/day — still meaningful for targeted attacks on weak passwords
- Rate limiting is per request ID, not per source IP

**Remediation**:
- Rate limit by source IP (Tailscale identity) in addition to request ID.
- Lock out the request ID permanently after N failures (e.g., 10 total attempts).
- Implement exponential backoff on failures (double the delay after each failure).
- Log all failed password attempts with source IP for monitoring.

### RM4: Replay Attack on Telegram Callbacks

**Severity**: MEDIUM

Telegram callback queries include a `callback_query_id` and `data` field. The daemon processes the `data` field (e.g., `approve_bw:<request-id>`) and delivers the decision. If an attacker could replay a callback:

1. Capture a legitimate `approve_bw:<id>` callback
2. Wait for a new request with a known or guessed ID
3. Replay the old callback with the new request ID

**Analysis**: This is mitigated because:
- Telegram callbacks are generated by button presses in the Telegram UI, not by API calls
- Each callback has a unique `callback_query_id` that Telegram tracks
- The daemon validates `from.id == chat_id`
- Request IDs are UUID v4 (unguessable)

**Residual risk**: If the attacker has the bot token, they can observe callbacks via `getUpdates` but cannot forge new ones. This is covered by RC1.

**Remediation**: No additional action needed beyond RC1 mitigations.

### RM5: DNS Rebinding Attack on Web UI

**Severity**: MEDIUM

The web UI binds to `127.0.0.1:8377`. Tailscale Serve proxies external connections to this localhost port. However, if a DNS rebinding attack is used:

1. Attacker hosts a web page at `https://evil.com`
2. The human visits `evil.com` on a device that's on the tailnet
3. `evil.com`'s DNS first resolves to the attacker's server, then switches to the NUC's Tailscale IP
4. JavaScript on the page makes requests to the NUC's web UI, bypassing same-origin policy

This could allow the attacker to probe the web UI or submit password attempts from the human's browser context.

**Remediation**:
- The web UI should validate the `Host` header and reject requests where `Host` doesn't match the expected Tailscale hostname.
- Axum can add middleware to check `Host: nuc.brown-ordinal.ts.net` and reject others.
- This is a defense-in-depth measure; the attacker still needs the request UUID and the password.

### RM6: Credential Exfiltration via Bitwarden Sync

**Severity**: MEDIUM

The `bw` CLI syncs vault data from Bitwarden servers. If the attacker compromises the BW account (via stolen API keys + master password, or social engineering of BW support), they can:
1. Add a new vault item with a known password
2. Wait for the agent to request it (or request it themselves if they have local access)
3. This is more relevant to BW account security than to aibw itself

Additionally, if the attacker can modify vault items:
- They could change "GitHub Token" to contain a malicious value (e.g., a different token that logs usage to the attacker)
- The two-phase approval (H4) would show the resolved item name, but the human wouldn't notice if the item name matches but the value changed

**Remediation**:
- This is a Bitwarden account security issue, not an aibw issue.
- Enable BW 2FA.
- Monitor BW audit log for unexpected item modifications.

---

## LOW Findings

### RL1: Timing Attacks on Web UI Password Verification

**Severity**: LOW

`bw unlock` may take different amounts of time depending on whether the password is correct (runs full vault decryption) vs incorrect (fails faster). An attacker can measure response times to determine if a password attempt was "close" to correct.

**Remediation**: Not a practical concern — BW uses PBKDF2/Argon2 for key derivation, which takes a fixed amount of time regardless of password correctness. The timing difference, if any, would be in the vault decryption step (not the key derivation), and would be in the noise over a network connection.

### RL2: Web UI Error Messages May Leak State

**Severity**: LOW

Different error messages for "request not found" vs "request expired" vs "request already approved" could help an attacker map the state of the system.

**Remediation**: Return a generic "invalid request" for all failure cases on the web UI.

### RL3: Tailscale Serve TLS Certificate Pinning

**Severity**: LOW

Tailscale Serve uses Let's Encrypt certificates for `.ts.net` domains. If Let's Encrypt is compromised or an attacker obtains a fraudulent certificate for `nuc.brown-ordinal.ts.net`, they could MITM the web UI.

**Remediation**: This is a general TLS PKI risk. Tailscale domains are managed by Tailscale, making fraudulent cert issuance very unlikely. HSTS headers can be added as defense-in-depth.

### RL4: Daemon Log File Exposure

**Severity**: LOW

The daemon logs (via `tracing`) may contain:
- Item names requested
- User names
- Request IDs
- Error details from `bw` CLI

If log files are readable by non-root users or backed up insecurely, this metadata could leak.

**Remediation**: Ensure systemd journal permissions restrict access to root. Don't log credential values (this is already the plan — only credential hashes are logged).

---

## Network Architecture Assessment

### Tailscale Trust Model

The system relies on Tailscale for:
1. **Web UI access control** — only tailnet devices can reach the unlock page
2. **TLS termination** — Tailscale Serve provides HTTPS
3. **Identity** (optional) — Tailscale can provide connecting user identity

**Assessment**: Tailscale is a reasonable trust boundary for a single-user personal server. The main risk is tailnet device compromise (if the human's phone or laptop is compromised, the attacker has tailnet access). This is consistent with the general threat model — if the human's device is compromised, all bets are off regardless.

### Telegram Channel Trust Model

The system relies on Telegram for:
1. **Notification delivery** — sending approval requests to the human
2. **Approval collection** — receiving button presses via callback queries
3. **Confidentiality** — item names are visible to Telegram

**Assessment**: Telegram provides transport encryption but not E2E encryption for bot messages. This is acceptable for a personal-server threat model but would be unacceptable for a multi-tenant or enterprise deployment. The main risks are bot token compromise (RC1) and phishing via the bot chat (RH1).

### End-to-End Data Flow Security

```
Credential value path:
  BW servers →(TLS)→ bw CLI →(stdout)→ daemon memory →(Unix socket)→ aibw CLI →(stdout)→ agent

Credential NEVER passes through:
  - Telegram (only item names, no values)
  - The web UI (only master password, not vault item values)
  - Network (Unix socket is local only)
  - Disk (held in memory, scrubbed from session files after delay)

Master password path:
  Human →(Tailscale TLS)→ web UI →(env var)→ bw CLI →(local only)→ BW vault
```

**Assessment**: The credential value never transits an external network, which is good. The master password transits the Tailscale tunnel (TLS-encrypted), which is acceptable. The main network exposure is metadata (item names, approval decisions) via Telegram.

---

## Summary

| ID | Severity | Finding | Remediation |
|---|---|---|---|
| RC1 | CRITICAL | Bot token compromise grants approval visibility and DoS | Protect token; can't fully mitigate within Telegram model |
| RC2 | CRITICAL | Telegram messages readable by Telegram (no E2E) | Accept for personal use; metadata only, not credentials |
| RH1 | HIGH | Phishable unlock URL in Telegram messages | Use bookmarked URL instead of links in messages |
| RH2 | HIGH | Web UI has no auth beyond Tailscale + request UUID | Add Tailscale identity headers; consider basic auth |
| RH3 | HIGH | BW API credentials stored on disk | Restrict permissions; enable BW 2FA |
| RH4 | HIGH | bw CLI HTTPS could be MITMed if CA/DNS compromised | Use trusted DNS; BW zero-knowledge mitigates |
| RM1 | MEDIUM | Telegram polling DoS via stolen bot token | Monitor timeouts; web UI fallback |
| RM2 | MEDIUM | Tailscale network trust boundary | Configure ACLs; restrict device access |
| RM3 | MEDIUM | Password brute-force over Tailscale | Per-IP rate limiting; lockout after N failures |
| RM4 | MEDIUM | Telegram callback replay | Already mitigated by design |
| RM5 | MEDIUM | DNS rebinding on web UI | Validate Host header |
| RM6 | MEDIUM | Credential exfiltration via BW account compromise | BW 2FA; audit log monitoring |
| RL1 | LOW | Timing attacks on password verification | Not practical; BW uses constant-time KDF |
| RL2 | LOW | Web UI error messages leak state | Generic error messages |
| RL3 | LOW | Tailscale TLS certificate pinning | Unlikely; add HSTS |
| RL4 | LOW | Daemon log metadata exposure | Restrict journal permissions |

### Key Takeaways

1. **The biggest remote risk is Telegram bot token compromise.** This is the single most valuable secret in the remote attack surface. It doesn't directly expose credentials (those never transit Telegram), but it enables approval visibility, DoS of the approval channel, and phishing via bot messages.

2. **Credential values never transit an external network.** The architecture correctly keeps credentials on the local machine (Unix socket, process memory). Remote attackers cannot intercept credential values without first gaining local access.

3. **The web UI is the second most sensitive remote surface.** It accepts the BW master password, and its security depends on Tailscale network access control. Adding Tailscale identity verification and the bookmarked-URL approach (instead of clickable links in Telegram) would significantly reduce risk.

4. **Telegram metadata exposure is an inherent limitation.** Item names visible to Telegram servers is an accepted tradeoff for the convenience of Telegram-based approval. For a personal server, this is reasonable.

### Recommended Priority Actions for Remote Threats

1. **Protect the bot token** — ensure it's not logged, not in backups, file permissions 0600
2. **Don't put clickable unlock URLs in Telegram messages** — use a bookmarked dashboard instead
3. **Enable Tailscale identity verification** on the web UI via Serve identity headers
4. **Validate Host header** on web UI requests (defense against DNS rebinding)
5. **Per-IP rate limiting** on password attempts with permanent lockout
6. **Enable Bitwarden 2FA** to protect against API key + master password compromise
