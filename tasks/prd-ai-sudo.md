# PRD: ai-sudo - Secure Remote Sudo Approval

## Introduction
ai-sudo is a self-hosted PAM-based sudo approval system that enables remote human-in-the-loop authorization for AI assistants. When an AI needs elevated privileges, users receive **end-to-end encrypted** push notifications on their phone to approve or deny requests.

**Security Requirement:** All notification channels must provide end-to-end encryption. Telegram and other non-E2E channels are explicitly rejected.

## Goals
- Create a secure, auditable workflow for AI assistants to request sudo access
- Enable remote approval without physical presence or blanket sudo access
- Provide rich context (command, user, PID, cwd) for informed decisions
- Support only E2E encrypted notification backends (Signal, custom apps)
- Implement security best practices (E2E encryption, nonces, rate limiting, replay prevention)

## User Stories

### US-001: PAM Module Interception
**Description:** As the system, I need to intercept sudo requests and communicate with the aisudo daemon so that privileged commands can be gated behind human approval.

**Acceptance Criteria:**
- PAM module written in C using OpenPAM API
- Extract command, user, PID, and working directory from PAM handle
- Communicate with daemon via Unix socket
- Allow or block based on daemon response
- Typecheck passes

### US-002: Daemon Setup and Socket Communication
**Description:** As the daemon, I need to listen for PAM requests via Unix socket and manage the approval state so that I can orchestrate the approval workflow.

**Acceptance Criteria:**
- Rust daemon with Tokio async runtime
- Listen on Unix socket for PAM module connections
- Deserialize request JSON from socket
- Return approval/deny response
- Typecheck passes

### US-003: Request State Persistence
**Description:** As the system, I need to persist pending requests in SQLite so that approval state survives daemon restarts and timeouts can be enforced.

**Acceptance Criteria:**
- Create SQLite database with requests and audit_log tables
- Store request_id, user, command, cwd, pid, timestamp, status, timeout_seconds
- Mark requests as pending/approved/denied/timeout
- Typecheck passes

### US-004: Notification Backend Interface
**Description:** As the system, I need a pluggable E2E notification backend interface so that different E2E encrypted notification channels can be supported.

**Acceptance Criteria:**
- Define E2ENotificationBackend trait in Rust
- Interface includes register(), send_request(), receive_response() methods
- Concrete implementations for Signal Bot, Custom Apps
- Typecheck passes

### US-005: E2E Encrypted Notification via Signal
**Description:** As a privacy-conscious user, I want to receive sudo request notifications via Signal so that my approval workflow is protected by Signal's proven end-to-end encryption.

**Acceptance Criteria:**
- Implement E2ENotificationBackend for Signal Bot API (via signald)
- Encrypt notification payload with user's Signal public key
- Send encrypted notification with request_id, command, user, timeout
- Include rich context (command, user, PID, cwd)
- Typecheck passes

**Security Requirements:**
- Use Signal Protocol for E2E encryption
- Generate and store encryption keys securely
- Validate nonces to prevent replay attacks

### US-006: Custom Mobile App with App-Level E2E
**Description:** As a security-conscious user, I want a dedicated mobile app with app-level E2E encryption for sudo approvals so that I have full control over the encryption implementation.

**Acceptance Criteria:**
- Build native iOS app with CryptoKit encryption
- Build native Android app with libsodium encryption
- Encrypt notifications via APNs (iOS) and FCM (Android)
- Implement secure key generation and storage
- Typecheck passes

**Security Requirements:**
- Private keys never leave device
- Encryption keys stored in platform secure storage (Keychain/Keystore)
- Forward secrecy (optional future enhancement)

### US-008: HTTP API for Approval
**Description:** As the notification backend, I need HTTP endpoints to receive approval/deny responses so that users can interact with requests from their phone.

**Acceptance Criteria:**
- Implement /approve/<request_id>/<nonce> endpoint
- Implement /deny/<request_id>/<nonce> endpoint
- Validate nonce before processing approval/deny
- Update request status in SQLite
- Return confirmation response
- Typecheck passes

### US-009: Timeout Handling
**Description:** As the system, I need to auto-deny requests after a configurable timeout so that commands don't hang indefinitely waiting for approval.

**Acceptance Criteria:**
- Track timeout per request (default 30 seconds)
- Spawn async timeout task for each pending request
- Mark request as timeout status on expiry
- Send timeout notification to user
- Typecheck passes

### US-010: Audit Logging
**Description:** As a security-conscious user, I want a complete audit trail of all requests and decisions so that I can review security events.

**Acceptance Criteria:**
- Log all requests to audit_log table
- Log approval/deny/timeout decisions with timestamp and decision source
- Log encryption key registration events
- Provide CLI command to view audit log
- Typecheck passes

### US-011: Rate Limiting
**Description:** As a security-conscious user, I want to prevent denial-of-service attacks through rapid sudo requests so that the system remains responsive.

**Acceptance Criteria:**
- Track requests per user with time windows
- Reject requests exceeding limit (e.g., 10/minute)
- Return error to PAM module for fallback to password
- Typecheck passes

### US-012: Nonce-Based Response Validation
**Description:** As a security-conscious user, I want to prevent replay attacks on approval responses so that old or intercepted responses can't be reused.

**Acceptance Criteria:**
- Generate cryptographic nonce for each request
- Include nonce in notification and require in response
- Validate nonce before processing approval/deny
- Typecheck passes

### US-013: Encryption Key Management
**Description:** As the system, I need to manage E2E encryption keys for users so that notifications can be securely encrypted.

**Acceptance Criteria:**
- Generate Curve25519 keypairs for users
- Store public keys in database (user_keys table)
- Provide secure key exchange mechanism
- Support key rotation (future)
- Typecheck passes

### US-014: PAM Configuration
**Description:** As a user, I want to configure PAM to use ai-sudo so that the system can intercept sudo requests.

**Acceptance Criteria:**
- Document PAM configuration for /etc/pam.d/sudo
- Support configurable timeout option
- Support optional allowed_users allowlist
- Typecheck passes

### US-015: Daemon Installation and Service
**Description:** As a user, I want to install ai-sudo as a system service so that the daemon runs automatically on boot.

**Acceptance Criteria:**
- Create systemd service file for Linux
- Create launchd plist for macOS
- Support enable/disable on boot
- Typecheck passes

### US-016: macOS OpenPAM Compatibility
**Description:** As a macOS user, I want ai-sudo to work with OpenPAM so that the system functions correctly on my platform.

**Acceptance Criteria:**
- Use OpenPAM headers and API (not Linux PAM)
- Compile successfully on macOS with clang
- Test PAM module integration on macOS
- Typecheck passes

### US-017: CLI Tool for Local Testing
**Description:** As a developer, I want a CLI tool to test the approval workflow locally so that I can debug without triggering actual sudo.

**Acceptance Criteria:**
- Create aisudo CLI that simulates PAM module
- Send test request to daemon
- Print notification status
- Typecheck passes

### US-018: Signal Communication Channel Research
**Description:** As a security-conscious developer, I need to understand Signal's communication options so that we can make an informed decision about notification delivery.

**Acceptance Criteria:**
- Research whether Signal has an official Bot API
- Research signald status (maintenance, security)
- Research signal-cli approach (puppet account)
- Document puppet account security concerns
- Make and document decision for MVP
- Typecheck passes (documentation only)

#### Signal API Reality Check

**Critical Finding:** Signal does NOT offer an official Bot API. All approaches require "puppeting" a real user account.

> **From signald README (archived):**
> "Signal does not offer any sort of official API. Unlike traditional messaging applications, the Signal server expects the client software to perform encryption and key management."

#### Communication Channel Options

| Option | Status | E2E Secure | Effort | Risk |
|--------|--------|------------|--------|------|
| **signal-cli (Java)** | ✅ Active | ✅ Yes | Medium | Low |
| **signal-cli (JSON-RPC)** | ✅ Active | ✅ Yes | Medium | Low |
| **signald (Go)** | ❌ Abandoned | ⚠️ "Not nearly as secure" | Low | **High** |
| **libsignal + custom** | ⚠️ Complex | ✅ Yes | Very High | Medium |
| **Custom Mobile App** | 🔬 Future | ✅ Yes | Very High | Low |

**Option A: signal-cli (Java/Python)**
- **What:** Command-line interface for Signal, provides JSON-RPC server
- **Status:** Active (2024), maintained by AsamK
- **Repo:** https://github.com/AsamK/signal-cli
- **How it works:** Runs as a local daemon, connects to Signal servers as a registered user
- **E2E:** ✅ Yes - uses Signal Protocol correctly
- **Effort:** 2-3 weeks to integrate
- **Pros:** Mature, well-tested, E2E secure
- **Cons:** Requires Java runtime, needs dedicated phone number

**Option B: signald (Go)**
- **What:** Daemon that exposes Signal via Unix socket
- **Status:** ❌ **ABANDONED** - README says "no longer actively maintained"
- **Security Warning:** Official README states "not nearly as secure as the real Signal clients"
- **Recommendation:** ❌ DO NOT USE for security-critical applications
- **Repo:** https://gitlab.com/signald/signald

**Option C: libsignal + Custom Rust Client**
- **What:** Build our own Signal client using libsignal protocol library
- **Status:** Signal publishes libsignal (Rust, Java, Swift)
- **Repo:** https://github.com/signalapp/libsignal
- **Effort:** 3-6 months (full Signal client implementation)
- **Pros:** Maximum control, Rust-native
- **Cons:** Massive effort, reimplementing Signal's key management

**Option D: Custom Mobile App (Future v2)**
- **What:** Build a proper Signal client as a mobile app
- **Uses:** libsignal for iOS/Android
- **Effort:** 6+ months
- **Pros:** Best user experience, proper E2E
- **Cons:** Highest effort

#### Puppet Account Concerns

All Signal API approaches require a **puppet account** - a real Signal phone number that acts as the sender.

| Concern | Impact | Mitigation |
|---------|--------|------------|
| **Account ownership** | Need dedicated phone number | Use VoIP number (Google Voice, etc.) |
| **Rate limiting** | Signal may block high-volume sending | Limit request frequency, respect quotas |
| **Session management** | Need to link device to Signal | Initial QR code or PIN setup |
| **Security of credentials** | Recovery phrases must be stored | Encrypt at rest, use hardware key |
| **Account recovery** | Losing recovery phrase = losing access | Backup recovery phrase securely |
| **ToS compliance** | Signal ToS prohibits automated messaging | ⚠️ **Potential risk** |

**ToS Concern:** Signal's Terms of Service may prohibit automated messaging. This is an unquantified risk.

#### Recommendation for MVP

**Signal-cli (JSON-RPC) is the only viable option for MVP.**

Despite the puppet account concerns, signal-cli is:
- ✅ Actively maintained
- ✅ E2E secure (uses Signal Protocol correctly)
- ✅ Provides JSON-RPC interface for integration
- ✅ Better security posture than abandoned signald

**Risk Acceptance:**
- We accept puppet account risk for MVP
- Recovery phrase stored encrypted on server
- Rate limiting enforced by ai-sudo daemon
- Clear ToS risk documented

**Future (v2):** Build custom mobile app with libsignal for proper Signal client experience.

#### References
- signal-cli: https://github.com/AsamK/signal-cli (⭐ ~2.5k stars, active)
- libsignal: https://github.com/signalapp/libsignal (official Signal repo)
- signald: https://gitlab.com/signald/signald (abandoned, security concerns)

### US-019: Rust PAM Module Technology Decision
**Description:** As a senior developer, I want to evaluate Rust PAM crate options so that we can choose the best approach for ai-sudo's PAM module.

**Acceptance Criteria:**
- Research nonstick crate (modern, trait-based, OpenPAM support)
- Research pamsm crate (lightweight, focused on Service Modules)
- Research pam-sys / libpam-sys crate (raw FFI, Tailscale approach)
- Create comparison table with effort estimates
- Make and document decision for MVP
- Typecheck passes (documentation only)

#### Rust PAM Crate Comparison

| Crate | Approach | macOS/OpenPAM | Maintenance | Effort | Risk |
|-------|----------|---------------|-------------|--------|------|
| **nonstick** | Trait-based wrapper | ✅ Explicit support | Active (2024) | Low | Low |
| **pamsm** | Service Module focus | ✅ Should work | Stable (older) | Low | Low |
| **pam-sys** | Raw FFI bindings | ⚠️ Linux-focused | Active | High | Medium |

**Option 1: nonstick** (⭐ Recommended)
- Modern, trait-based approach (PamModule trait)
- Handles extern "C" boilerplate with `pam_export!` macro
- Cross-platform: Linux-PAM + OpenPAM/macOS
- Type-safe wrapper reduces PAM memory safety issues
- ~1-2 weeks for MVP module

**Option 2: pamsm**
- Lightweight, specifically for Service Modules
- Older but stable, minimal overhead
- Macro for module entry points
- ~1-2 weeks for MVP module

**Option 3: pam-sys + manual**
- Raw FFI bindings for maximum control
- Used by Tailscale's pam_tailscale
- More boilerplate, less abstraction
- ~3-4 weeks for MVP module

**Recommendation:** **nonstick** for MVP
- Best balance of ease-of-use and type safety
- Explicit macOS/OpenPAM support
- Modern Rust patterns (traits, macros)
- Reduces boilerplate while maintaining safety

## Non-Goals
- Biometric authentication - future enhancement
- YubiKey/FIDO2 integration - future enhancement
- Multi-user approval workflows - future enhancement
- Non-E2E notification channels (Telegram, SMS, email) - explicitly rejected

## Technical Considerations
- PAM module written in Rust using nonstick crate (cross-platform: Linux-PAM + OpenPAM/macOS)
- Daemon written in Rust for memory safety and async performance
- Use libsodium/sodiumoxide for E2E encryption (Curve25519, XSalsa20)
- Use sqlx or rusqlite for SQLite database
- Notification backends are pluggable via E2ENotificationBackend trait
- Unix socket for fast local IPC with PAM module
- HTTP API for receiving responses from notification backends
- All notification channels must provide E2E encryption (non-negotiable)

## Out of Scope
- Command preview/dry-run feature
- Batch approval for multiple commands
- Integration with enterprise SSO providers
- Non-E2E notification channels

## E2E Notification Backend Decision

See [agents/ARCHITECTURE.md](agents/ARCHITECTURE.md) for detailed analysis of E2E encrypted notification options.

### Current Recommendation for MVP

| Backend | Status | Rationale |
|---------|--------|-----------|
| signal-cli (JSON-RPC) | ✅ Approved | Only viable option, E2E secure |
| Custom Apps | 🔬 Future v2 | Best UX, but highest effort |

### Communication Channel Research Summary

**Critical Finding:** Signal does NOT provide an official Bot API. All approaches require puppeting a real user account.

| Option | Status | Security | Notes |
|--------|--------|----------|-------|
| signal-cli | ✅ Active | ✅ Secure | **MVP Choice** - Java-based, JSON-RPC |
| signald | ❌ Abandoned | ⚠️ Risky | "Not nearly as secure" - DO NOT USE |
| libsignal + custom | 🔬 Complex | ✅ Secure | Future v2 - massive effort |
| Custom Mobile App | 🔬 Future | ✅ Secure | Best UX, requires full client |

### Puppet Account Requirements

- Dedicated phone number (VoIP acceptable)
- Recovery phrase must be stored securely
- Rate limiting must be enforced
- Signal ToS compliance is an unquantified risk

### Rejected Options

| Backend | Reason for Rejection |
|---------|---------------------|
| Telegram | No native E2E encryption |
| Clawdbot iOS Node | Not publicly available (closed infrastructure) |
| signald | Abandoned project, security concerns |
| SMS | No encryption, SIM hijacking risks |
| Email | No E2E, prone to interception |
| Plain webhooks | No encryption |
