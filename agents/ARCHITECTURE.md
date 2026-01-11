# ai-sudo Architecture & Implementation Guide

This document provides a comprehensive technical guide for implementing ai-sudo.

## Architecture Components

### 1. PAM Module (`pam_aisudo`)

The core interception layer that integrates with the system's authentication stack.

**Responsibilities:**
- Intercept sudo authentication requests
- Extract command, user, and context information
- Communicate with the local aisudo daemon
- Allow or block based on daemon response

**Technical Details:**
- Written in C (required for PAM modules)
- Uses OpenPAM API (macOS/BSD compatible)
- Pluggable into `/etc/pam.d/sudo`
- Thread-safe implementation

**Configuration:**
```c
// pam_aisudo.h
#define PAM_EXAMPLE_MODULE_NAME "pam_aisudo"

typedef struct {
    int debug;
    int timeout;
    char *socket_path;
    char *allowed_users;
} pam_aisudo_options_t;
```

### 2. AISudo Daemon (`aisudo-daemon`)

The central service that manages approval workflow.

**Responsibilities:**
- Listen for PAM module requests via Unix socket
- Encrypt and send push notifications to mobile devices
- Manage approval state and timeouts
- Provide HTTP API for approval queries
- Log all events for audit

**Technical Details:**
- Written in Rust (memory safety, async performance)
- Uses Tokio async runtime
- Unix socket communication with PAM module
- SQLite for request state persistence
- libsodium for encryption operations

**Architecture:**
```
┌───────────────────────────────────────────────────────────────────────┐
│                          aisudo-daemon                                 │
├───────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ Socket      │  │ State       │  │ Encryption  │  │ HTTP API    │  │
│  │ Listener    │  │ Manager     │  │ Engine      │  │ Server      │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │
│         │                │                │                │          │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐  │
│  │ Request     │  │ SQLite      │  │ libsodium   │  │ /approve    │  │
│  │ Queue       │  │ Database    │  │ E2E Enc     │  │ /deny       │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  │ /status     │  │
│                                                      └─────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ E2E Encrypted Notification Backends (Pluggable)                 │  │
│  │ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐    │  │
│  │ │ Signal Bot  │ │ Clawdbot    │ │ Custom App (TBD)        │    │  │
│  │ │ (Approved)  │ │ iOS Node    │ │ iOS/Android with E2E    │    │  │
│  │ └─────────────┘ │ (TBD)       │ └─────────────────────────┘    │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

### 3. E2E Encryption Engine

All notifications must be encrypted end-to-end using libsodium.

**Encryption Requirements:**
- Use NaCl/libsodium for all encryption
- Curve25519 for key exchange
- XSalsa20 for symmetric encryption
- Poly1305 for authentication tags

**Key Exchange Flow:**
```
User's Device                    AISudo Daemon
     │                                │
     │  1. Generate keypair           │
     │◄───────────────────────────────│
     │                                │
     │  2. Send public key            │
     │───────────────────────────────▶│
     │                                │
     │  3. Encrypt notification       │
     │◄───────────────────────────────│
     │    with shared secret          │
     │                                │
     │  4. Decrypt and display        │
     │                                │
```

### 4. Notification Backend

**Interface:**
```rust
trait E2ENotificationBackend {
    /// Initialize the backend with user's public key
    async fn register(&self, user_id: &str, public_key: &[u8]) -> Result<(), Error>;
    
    /// Send encrypted notification
    async fn send_request(&self, encrypted_payload: &[u8], metadata: &RequestMetadata) -> Result<(), Error>;
    
    /// Receive and validate approval response
    async fn receive_response(&self) -> Result<ApprovalResponse, Error>;
}
```

**Approved Backends:**
1. **Signal Bot** - Native E2E encryption via Signal protocol

**Backends Under Evaluation:**
2. **Clawdbot iOS Node** - Custom E2E encryption layer
3. **Custom Mobile Apps** - App-level E2E with APNs/FCM

---

## E2E Encrypted Notification Options

### Status: To Be Decided

We are evaluating the following E2E encrypted notification channels. Each option is being researched for security, usability, and implementation effort.

### Option A: Signal Bot API ✅ Approved

**Status:** Approved - Recommended for MVP

**Description:**
Use Signal's bot API to send encrypted notifications. Signal provides native E2E encryption using the Signal Protocol.

**Implementation Options:**

| Option | Pros | Cons | Effort |
|--------|------|------|--------|
| signal-cli (Java) | Mature, well-documented | Requires Java runtime | Medium |
| signald (Go) | Fast, socket-based | Requires running signald | Medium |
| signal-web-api | No local server | Weaker security model | Low |

**Recommended: signald**

signald runs as a local daemon and communicates with Signal servers. It provides a socket-based API that ai-sudo can use.

**Architecture with signald:**
```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│ aisudo      │────▶│ signald     │────▶│ Signal Server   │
│ daemon      │     │ (local)     │     │ (relay only)    │
└─────────────┘     └─────────────┘     └────────┬────────┘
                                                  │
                                                  ▼
                                           ┌─────────────┐
                                           │ Signal App  │
                                           │ (decrypts)  │
                                           └─────────────┘
```

**Security Properties:**
- Signal Protocol provides forward secrecy
- Native E2E encryption
- No access to message content on Signal servers

**Implementation:**
```rust
struct SignalBackend {
    socket_path: PathBuf,
    phone_number: String,
}

impl E2ENotificationBackend for SignalBackend {
    async fn send_request(&self, encrypted: &[u8], metadata: &RequestMetadata) -> Result<()> {
        let message = hex::encode(encrypted);
        signald_send(&self.socket_path, &self.phone_number, &message).await?;
        Ok(())
    }
}
```

**Pros:**
- ✅ Proven E2E encryption
- ✅ Cross-platform (iOS, Android, desktop)
- ✅ Large user base
- ✅ No custom app development needed

**Cons:**
- ⚠️ Requires linked device (phone number or QR)
- ⚠️ signald needs to run as a separate service
- ⚠️ Signal ToS may prohibit automated messaging

---

### Option B: Custom iOS/Android Apps 🔬 Researching

**Status:** Researching - Requires significant effort

**Description:**
Build native iOS and Android apps that implement custom E2E encryption and communicate with ai-sudo via push notification services.

**Architecture:**
```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│ aisudo      │────▶│ APNs (iOS)       │────▶│ Custom App  │
│ daemon      │     │ or FCM (Android) │     │ (decrypts)  │
└─────────────┘     └──────────────────┘     └─────────────┘
                          │
                          ▼ Encrypt payload
                     ┌─────────────┐
                     │ Apple/      │
                     │ Google      │
                     │ (can't read)│
                     └─────────────┘
```

**Security Model:**
1. App generates Curve25519 keypair on first launch
2. Public key sent to ai-sudo daemon (via secure channel)
3. All notifications encrypted with app's public key
4. APNs/FCM only sees encrypted blob
5. App decrypts locally with private key

**Technical Requirements:**

**iOS:**
- Apple Push Notification service (APNs)
- CryptoKit for encryption (or libsodium via swift-nacl)
- Background fetch for timely delivery
- Keychain for secure key storage

**Android:**
- Firebase Cloud Messaging (FCM)
- libsodium/jna for encryption
- WorkManager for background processing
- Keystore for secure key storage

**Push Notification Payload (Encrypted):**
```json
{
  "aps": {
    "alert": {
      "title": "Sudo Request",
      "body": "Encrypted notification"
    },
    "content-available": 1
  },
  "encrypted_payload": "<base64-encoded encrypted data>",
  "request_id": "uuid",
  "nonce": "base64"
}
```

**Pros:**
- ✅ Full control over encryption
- ✅ No third-party service dependencies
- ✅ Best user experience
- ✅ Future: biometric authentication possible

**Cons:**
- ⚠️ High development effort (two native apps)
- ⚠️ Need to distribute apps (App Store, Play Store)
- ⚠️ Maintenance burden
- ⚠️ Certificate/credential management

**Estimated Effort:**
- iOS App: 2-3 months
- Android App: 2-3 months
- Backend API: 1 month

---

### Option C: Clawdbot iOS Node with E2E 🔬 Researching

**Status:** Researching - Leverages existing infrastructure

**Description:**
Extend the existing Clawdbot iOS node infrastructure with custom E2E encryption for sudo notifications.

**Architecture:**
```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│ aisudo      │────▶│ Clawdbot Gateway │────▶│ Clawdbot    │
│ daemon      │     │ (encrypted)      │     │ iOS Node    │
└─────────────┘     └──────────────────┘     └─────────────┘
```

**Implementation Strategy:**
1. Use existing nodes API for notification delivery
2. Add encryption layer using libsodium
3. Generate keypair on iOS device
4. Store public key in daemon's trusted store
5. Encrypt all notifications before sending

**Encryption Flow:**
```rust
// Daemon side
let shared_secret = x25519_dh(
    daemon_private_key,
    device_public_key
);
let encrypted = encrypt_xsalsa20(
    &shared_secret,
    nonce,
    plaintext.as_bytes()
);

// iOS side
let shared_secret = x25519_dh(
    device_private_key,
    daemon_public_key
);
let plaintext = decrypt_xsalsa20(
    &shared_secret,
    nonce,
    encrypted.as_bytes()
);
```

**Security Considerations:**
- Keys must be stored securely (iOS Keychain)
- Need secure key exchange mechanism (QR code? initial setup?)
- Revocation mechanism if device is compromised

**Pros:**
- ✅ Leverages existing Clawdbot infrastructure
- ✅ Single codebase to maintain
- ✅ Direct device notification
- ✅ Can use Clawdbot's existing auth

**Cons:**
- ⚠️ Need to implement encryption layer
- ⚠️ iOS node dependency
- ⚠️ Limited to Clawdbot users

---

### Option D: WebRTC for Signaling 🔬 Researching

**Status:** Researching - Most complex but most secure

**Description:**
Use WebRTC for direct peer-to-peer communication with E2E encryption via DTLS/SRTP.

**Architecture:**
```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│ aisudo      │────▶│ STUN/TURN Server │────▶│ Browser/    │
│ daemon      │     │ (relay)          │     │ PWA         │
└─────────────┘     └──────────────────┘     └─────────────┘
                            │
                            ▼ WebRTC Data Channel (DTLS/SRTP)
                     ┌──────────────────┐
                     │ Direct P2P       │
                     │ (encrypted)      │
                     └──────────────────┘
```

**How It Works:**
1. Open WebRTC data channel between daemon and browser/PWA
2. DTLS provides E2E encryption (certificate-based)
3. SRTP for media (if voice/video added later)
4. Use Web Push API for waking sleeping devices

**Pros:**
- ✅ Native E2E encryption via DTLS
- ✅ No push notification service dependency
- ✅ Can work offline (once established)
- ✅ Cross-platform (web-based)

**Cons:**
- ⚠️ Complex implementation
- ⚠️ Requires TURN server for NAT traversal
- ⚠️ Browser must be open (or use Web Push)
- ⚠️ Limited mobile support for data channels

---

### Recommendation Summary

| Option | Security | Effort | Maturity | Recommendation |
|--------|----------|--------|----------|----------------|
| Signal Bot | ⭐⭐⭐⭐⭐ | Medium | High | **MVP Choice** |
| Custom Apps | ⭐⭐⭐⭐⭐ | High | Low | Future v2 |
| Clawdbot iOS | ⭐⭐⭐⭐ | Medium | Medium | Alternative |
| WebRTC | ⭐⭐⭐⭐⭐ | Very High | Low | Research only |

**MVP Recommendation:** Start with **Signal Bot** (signald) as it provides proven E2E encryption with moderate implementation effort.

**Future Enhancement:** Build custom iOS/Android apps for a polished, self-contained experience.

---

## Technology Recommendations

### Language Selection

| Component | Language | Rationale |
|-----------|----------|-----------|
| PAM Module | C | Required by PAM API; OpenPAM on macOS |
| Daemon | Rust | Memory safety, async performance, good crypto libs |
| Mobile App (future) | Swift (iOS) / Kotlin (Android) | Native platform support |

### Key Libraries

**Rust (Daemon):**
- `tokio` - Async runtime
- `sqlx` - SQLite with async
- `rusqlite` - SQLite bindings
- `sodiumoxide` / `libsodium` - Encryption
- `uuid` - Request tracking
- `serde`/`serde_json` - Serialization

**C (PAM Module):**
- OpenPAM headers (`<security/pam_modules.h>`)
- Darwin/macOS syslog

### Database Schema

```sql
CREATE TABLE requests (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    command TEXT NOT NULL,
    cwd TEXT,
    pid INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending', -- pending, approved, denied, timeout
    timeout_seconds INTEGER DEFAULT 30,
    decided_at DATETIME,
    decided_by TEXT,
    nonce TEXT NOT NULL,
    audit_log TEXT
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    event TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

CREATE TABLE user_keys (
    user_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    key_type TEXT DEFAULT 'x25519',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Implementation Steps

### Phase 1: Core Infrastructure

#### Step 1.1: Set up Rust Project Structure
```bash
cargo new aisudo-daemon
cd aisudo-daemon
cargo add tokio rusqlite sqlx uuid serde serde_json sodiumoxide
```

#### Step 1.2: Create PAM Module Skeleton
```c
// pam_aisudo.c
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Extract command and user info
    // Send to daemon socket
    // Wait for response
    return PAM_SUCCESS; // or PAM_AUTH_ERR
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

#### Step 1.3: Implement Unix Socket Communication

**Daemon side (Rust):**
```rust
use std::os::unix::net::UnixListener;

async fn handle_connection(stream: UnixStream) {
    let request: Request = deserialize_from_stream(stream).await?;
    let request_id = process_request(request).await;
    send_encrypted_notification(request_id).await;
}
```

**PAM module side (C):**
```c
int send_to_daemon(const char *socket_path, const char *json_data, char *response, size_t response_size) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(sock, socket_path, sizeof(sockaddr_un));
    write(sock, json_data, strlen(json_data));
    read(sock, response, response_size);
    close(sock);
    return 0;
}
```

### Phase 2: E2E Encryption

#### Step 2.1: Key Generation and Exchange

```rust
// Generate keypair
let (public_key, private_key) = x25519::gen_keypair();

// Store public key for user
save_user_public_key(user_id, &public_key).await;

// During notification, encrypt with user's public key
let nonce = gen_nonce();
let encrypted = seal(plaintext, &nonce, &user_public_key);
```

#### Step 2.2: libsodium Integration

```rust
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::box_;

fn encrypt_for_user(plaintext: &[u8], user_public_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (nonce, key) = derive_shared_key(user_public_key);
    let encrypted = secretbox::seal(plaintext, &nonce, &key);
    (nonce.into_vec(), encrypted)
}
```

### Phase 3: Notification Integration (Signal Bot)

#### Step 3.1: signald Integration

```rust
struct SignalBackend {
    socket_path: PathBuf,
    phone_number: String,
    identity_key: [u8; 32],
}

impl SignalBackend {
    async fn connect(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path).await?;
        Ok(stream)
    }
    
    async fn send_message(&self, message: &str) -> Result<()> {
        let request = json!({
            "type": "send",
            "recipient": {"number": self.phone_number},
            "messageBody": message
        });
        self.send_json(&request).await?;
        Ok(())
    }
}
```

### Phase 4: Approval Workflow

#### Step 4.1: HTTP API Endpoints

```rust
#[get("/approve/<request_id>/<nonce>")]
async fn approve(request_id: PathBuf, nonce: PathBuf) -> impl Responder {
    validate_nonce(&request_id, &nonce)?;
    state.mark_approved(&request_id, "mobile").await;
    HttpResponse::Ok().body("✅ Approved")
}

#[get("/deny/<request_id>/<nonce>")]
async fn deny(request_id: PathBuf, nonce: PathBuf) -> impl Responder {
    validate_nonce(&request_id, &nonce)?;
    state.mark_denied(&request_id, "mobile").await;
    HttpResponse::Ok().body("🚫 Denied")
}
```

#### Step 4.2: Timeout Handling

```rust
async fn handle_timeout(request_id: &str) {
    let mut state = state.lock().await;
    if state.get_status(request_id) == Status::Pending {
        state.mark_timeout(request_id).await;
        send_notification_timeout(request_id).await;
    }
}
```

### Phase 5: Security Hardening

#### Step 5.1: Nonce-Based Response Validation

```rust
struct ApprovalRequest {
    request_id: String,
    nonce: String,  // Cryptographic random
    timestamp: u64,
}

struct ApprovalResponse {
    request_id: String,
    nonce: String,
    decision: Decision,  // approve/deny
}
```

#### Step 5.2: Rate Limiting

```rust
struct RateLimiter {
    requests_per_minute: usize,
}

impl RateLimiter {
    async fn check(&self, user: &str) -> Result<(), Error> {
        let count = self.get_count(user).await;
        if count >= self.requests_per_minute {
            return Err(Error::RateLimited);
        }
        self.increment(user).await;
        Ok(())
    }
}
```

### Phase 6: Testing

#### Unit Tests
```bash
# Test Rust daemon
cargo test

# Test C module
gcc -Wall -Wextra -o pam_aisudo_test pam_aisudo.c -lcunit
```

#### Integration Tests
```bash
# Test full flow with mock notification
./scripts/integration_test.sh --mock-notifications

# Test encryption/decryption
./scripts/integration_test.sh --test-encryption

# Test timeout behavior
./scripts/integration_test.sh --test-timeout=5s
```

## Deployment

### Installation
```bash
# Install PAM module
sudo cp pam_aisudo.so /usr/lib/pam/
sudo chmod 755 /usr/lib/pam/pam_aisudo.so

# Configure PAM
echo "auth sufficient pam_aisudo.so timeout=30" | sudo tee /etc/pam.d/sudo

# Install daemon
cargo install --path aisudo-daemon
sudo cp aisudo-daemon.service /etc/systemd/system/
sudo systemctl enable aisudo-daemon
sudo systemctl start aisudo-daemon
```

### macOS Notes
- Uses OpenPAM (BSD-style PAM)
- PAM config location: `/etc/pam.d/sudo`
- Daemon should run as launchd agent
- Code signing required for PAM modules

## Future Enhancements

- [ ] Native iOS/Android apps (Option B)
- [ ] Biometric authentication on mobile
- [ ] Command preview (dry run before execution)
- [ ] Batch approval for multiple similar commands
- [ ] Integration with YubiKey/FIDO2
- [ ] Multi-user approval workflows
- [ ] WebRTC-based notifications (Option D)
