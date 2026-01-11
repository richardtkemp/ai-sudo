# PRD: ai-sudo - Secure Remote Sudo Approval

## Introduction
ai-sudo is a self-hosted PAM-based sudo approval system that enables remote human-in-the-loop authorization for AI assistants. When an AI needs elevated privileges, users receive **end-to-end encrypted** push notifications on their phone to approve or deny requests.

**Security Requirement:** All notification channels must provide end-to-end encryption. Telegram and other non-E2E channels are explicitly rejected.

## Goals
- Create a secure, auditable workflow for AI assistants to request sudo access
- Enable remote approval without physical presence or blanket sudo access
- Provide rich context (command, user, PID, cwd) for informed decisions
- Support only E2E encrypted notification backends (Signal, custom apps, Clawdbot iOS node with encryption)
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
- Concrete implementations for Signal Bot, Clawdbot iOS node (with E2E), Custom Apps
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

### US-006: Clawdbot iOS Node with Custom E2E
**Description:** As a Clawdbot user, I want to receive sudo request notifications via the Clawdbot iOS node with custom end-to-end encryption so that I can approve requests using my existing infrastructure.

**Acceptance Criteria:**
- Extend Clawdbot nodes API with E2E encryption layer
- Generate Curve25519 keypair on iOS device
- Encrypt notifications before sending via nodes API
- Decrypt and display notifications on iOS device
- Typecheck passes

**Security Requirements:**
- Keys stored in iOS Keychain
- Secure key exchange mechanism (QR code during setup)
- Revocation mechanism for compromised devices

### US-007: Custom Mobile App with App-Level E2E
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

### US-018: E2E Notification Backend Decision
**Description:** As a project stakeholder, I want to evaluate and decide on the E2E encrypted notification backend(s) to use so that we can implement a secure and practical solution.

**Acceptance Criteria:**
- Research Signal Bot API (signald)
- Research Custom iOS/Android apps with E2E
- Research Clawdbot iOS node with E2E
- Research WebRTC-based notifications
- Document pros/cons of each option
- Make and document decision for MVP
- Typecheck passes (documentation only)

## Non-Goals
- Biometric authentication - future enhancement
- YubiKey/FIDO2 integration - future enhancement
- Multi-user approval workflows - future enhancement
- Non-E2E notification channels (Telegram, SMS, email) - explicitly rejected

## Technical Considerations
- PAM module must be written in C due to OpenPAM API requirements
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
| Signal Bot | ✅ Approved | Proven E2E encryption, moderate effort |
| Custom Apps | 🔬 Researching | High effort, best UX (future v2) |
| Clawdbot iOS | 🔬 Researching | Leverages existing infrastructure |

### Rejected Options

| Backend | Reason for Rejection |
|---------|---------------------|
| Telegram | No native E2E encryption |
| SMS | No encryption, SIM hijacking risks |
| Email | No E2E, prone to interception |
| Plain webhooks | No encryption |
