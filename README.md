# ai-sudo

**Secure remote sudo approval for AI assistants — with end-to-end encrypted notifications**

A self-hosted sudo approval system that sends E2E encrypted push notifications to your phone when an AI assistant (like Clawdbot) needs elevated privileges. Approve or deny requests remotely without giving blanket sudo access, with full privacy guarantees.

## What It Is

ai-sudo is a PAM (Pluggable Authentication Module) based system that intercepts sudo requests and routes them through a mobile approval workflow. When an AI needs to run a privileged command, you get a notification on your phone showing:

- The command being requested
- Which AI/process is requesting it
- The working directory and context

You can then tap **Approve** or **Deny** from anywhere. The decision is communicated back to your machine, which either allows or blocks the command.

**Security Requirement:** All notification channels must provide end-to-end encryption. We do not use Telegram or any channel without E2E encryption.

## Why It Should Be Built

AI assistants are becoming integral parts of our workflows, but they face a fundamental security constraint: they often need to run administrative commands but can't type passwords. This creates a dangerous tradeoff:

| Current Options | Problem |
|-----------------|---------|
| Grant full sudo | Complete security failure - AI can do anything |
| Physical presence | Defeats the purpose of remote AI assistance |
| Pre-approved commands | Inflexible - breaks when commands vary |

ai-sudo bridges this gap by adding a **human-in-the-loop** approval step. The AI can request privileges, but a human must explicitly approve each sensitive operation. This transforms AI + sudo from a security liability into a secure, auditable workflow.

## Security-First Design

### End-to-End Encryption Requirement

**All notification channels must provide E2E encryption.** This is non-negotiable because:

1. **Sudo requests contain sensitive information** - commands, paths, usernames
2. **Notifications travel through external servers** - we cannot trust notification providers
3. **Compromised notification channels = compromised system** - attackers could approve malicious commands

### Approved Notification Channels

| Channel | E2E Encryption | Status |
|---------|----------------|--------|
| Signal Bot | ✅ Native Signal E2E | ✅ MVP - Approved |
| Custom iOS/Android App | ✅ App-level E2E | 🔬 Future v2 |

### Rejected Notification Channels

| Channel | Reason for Rejection |
|---------|---------------------|
| Telegram | No native E2E encryption (MTProto is server-client, not E2E) |
| Clawdbot iOS Node | Not publicly available (closed infrastructure) |
| SMS | No encryption, SIM hijacking risks |
| Email | No E2E, prone to interception |
| Plain webhooks | No encryption |

## Solution Overview

ai-sudo implements a **human-gated sudo** pattern:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ sudo cmd    │────▶│ PAM Module   │────▶│ aisudo      │
│ (terminal)  │     │ (pam_aisudo) │     │ daemon      │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                   E2E Encrypted Notification    │
                                                ▼
                                         ┌─────────────┐
                                         │ Phone App   │
                                         │ (E2E Enc.)  │
                                         └─────────────┘
```

### How It Works

1. **Intercept** - A user or AI runs `sudo <command>`
2. **Pause** - The PAM module intercepts the request and notifies the daemon
3. **Encrypt & Notify** - The daemon encrypts notification payload and sends via E2E channel
4. **Approve/Deny** - Human reviews and responds via encrypted channel
5. **Execute** - PAM receives the decision (with nonce validation) and allows/blocks

### Key Features

- **E2E Encryption** - All notifications are encrypted end-to-end
- **Timeout support** - Auto-deny after configurable seconds (prevents hanging)
- **Rich context** - Shows command, user, process, working directory
- **Audit logging** - Complete trail of all requests and decisions
- **Optional allowlist** - Auto-approve known-safe commands (e.g., `brew upgrade`)
- **Fallback mode** - If the service is down, fall back to local password
- **Replay attack prevention** - Cryptographic nonces ensure fresh responses

## Getting Started

See [agents/ARCHITECTURE.md](agents/ARCHITECTURE.md) for implementation details.

## Security Considerations

- Notification channel must be authenticated (prevent spoofing)
- Nonce-based responses prevent replay attacks
- Rate limiting prevents denial-of-service
- All decisions are logged for audit
- Encryption keys are never stored on notification servers

## Notification Backend Decisions

See [agents/ARCHITECTURE.md](agents/ARCHITECTURE.md) for detailed analysis of E2E encrypted notification options.

**Current Strategy:**
- **MVP (v1):** Signal Bot API (proven E2E, available now)
- **Future (v2):** Custom iOS/Android apps with app-level E2E

## License

MIT
