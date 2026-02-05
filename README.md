# ai-sudo

**Remote sudo approval for AI assistants via Telegram.**

When an AI assistant needs to run a privileged command, it sends you a Telegram notification with Approve/Deny buttons. No blanket sudo access, no passwords, full audit trail.

## How It Works

```
AI runs `aisudo whoami`
        │
        ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  aisudo CLI  │────▶│  aisudo      │────▶│  Telegram    │
│  (wrapper)   │     │  daemon      │     │  (your phone)│
└──────────────┘     └──────────────┘     └──────┬───────┘
                            ▲                     │
                            │    Approve / Deny   │
                            └─────────────────────┘
```

1. AI runs `aisudo <command>` instead of `sudo`
2. Daemon checks the allowlist — auto-approves safe commands (e.g. `df`, `journalctl`)
3. For other commands, sends a Telegram notification with command details
4. You tap **Approve** or **Deny** on your phone
5. If approved, the daemon executes the command as root and streams output back

## Features

- **CLI wrapper** — `aisudo` drop-in, no PAM configuration needed
- **Reason flag** — `aisudo -r "why I need this" <command>` shows context in the notification
- **Command allowlist** — auto-approve safe commands without notification
- **Configurable timeout** — requests expire after a set time (default: 60s, configurable)
- **Rate limiting** — 10 requests per minute per user
- **Audit logging** — all requests and decisions stored in SQLite
- **PAM module** — optional `--pam` install for intercepting all sudo (not default)

## Quick Start

### Prerequisites

- Rust toolchain (`cargo`)
- A Telegram bot (create via [@BotFather](https://t.me/BotFather))
- Your Telegram chat ID (get from [@userinfobot](https://t.me/userinfobot))

### Build & Install

```bash
git clone https://github.com/richardtkemp/ai-sudo.git
cd ai-sudo
cargo build --release

# Install daemon + CLI (default)
sudo bash setup.sh

# Or with PAM module too
sudo bash setup.sh --pam
```

### Configure

Edit `/etc/aisudo/aisudo.toml`:

```toml
socket_path = "/var/run/aisudo/aisudo.sock"
db_path = "/var/lib/aisudo/aisudo.db"
timeout_seconds = 900  # 15 minutes

# Commands that auto-approve without notification
allowlist = [
    "systemctl status",
    "journalctl",
    "df",
    "du",
    "apt list",
    # ... see aisudo.toml for full list
]

[telegram]
bot_token = "your-bot-token"
chat_id = 123456789
```

### Usage

```bash
# Basic
aisudo apt update

# With reason (shown in Telegram notification)
aisudo -r "checking disk health" smartctl -a /dev/sda

# Allowlisted commands run immediately
aisudo df -h          # no notification needed
aisudo journalctl -n 50
```

## Shell Operators in Auto-Approved Commands

Auto-approved commands (via allowlist or temp rules) support shell operators like pipes and chaining. Each sub-command is validated individually against the allowlist — all must match for the command to be auto-approved.

```bash
# Both 'apt list' and 'grep' must be in the allowlist:
aisudo 'apt list --installed | grep vim'

# Sequential execution — both must be allowed:
aisudo 'apt list ; dpkg -l'

# Conditional chains:
aisudo 'apt list && echo ok || echo fail'
```

**Supported operators:** `;` (sequential), `&&` (and), `||` (or), `|` (pipe)

**Rejected syntax** (denied immediately if found unquoted):
- `$`, `` ` `` — variable expansion, command substitution
- `(`, `)` — subshells
- `>`, `<` — redirections
- Bare `&` — background execution

Quoting (single or double) suppresses operator detection, so `echo "hello; world"` is treated as a single command.

Commands approved via Telegram (human-approved) continue to use `sh -c` and support all shell syntax — this restriction only applies to auto-approved commands.

## Architecture

- **`aisudo-cli`** — CLI wrapper, connects to daemon via Unix socket
- **`aisudo-daemon`** — Runs as root, handles approvals, executes commands
- **`aisudo-common`** — Shared types and protocol
- **`aisudo-pam`** — Optional PAM module for intercepting native `sudo`

The daemon runs as a systemd service (`aisudo-daemon.service`) and communicates with the CLI over a Unix socket (`/var/run/aisudo/aisudo.sock`). Users must be in the `aisudo` group to connect.

## OpenClaw Integration

If you're using [OpenClaw](https://github.com/openclaw/openclaw), add this to your `TOOLS.md` so your agent knows to use `aisudo` instead of `sudo`:

    ## aisudo — Remote Sudo Approval

    **NEVER use plain `sudo`. Always use `aisudo` instead.**

    `aisudo` sends a Telegram notification to your human with approve/deny buttons.
    Without approval, the command won't run. This is the only way to run privileged commands.

    ```bash
    # Basic usage
    aisudo apt update

    # With reason (shows WHY in the Telegram notification)
    aisudo -r "need to check disk health" smartctl -a /dev/sda
    ```

    **Always include `-r "reason"` for non-obvious commands.** Your human is much more
    likely to approve if they know why.

    **Allowlisted commands** (auto-approved, no Telegram prompt):
    systemctl status/restart, journalctl, apt search/install/list/show, du, df, lsblk,
    ss, lsof, cat /etc/*, tail /var/log/*, dmesg, smartctl, and more.
    See `/etc/aisudo/aisudo.toml` for the full list.

    **Config:** `/etc/aisudo/aisudo.toml` | **Socket:** `/var/run/aisudo/aisudo.sock`

## Security Notes

- Daemon runs as root — it executes approved commands directly
- Unix socket is `root:aisudo 0660` — only group members can request
- All requests and decisions are logged to SQLite for audit
- Telegram notifications are not E2E encrypted — suitable for personal servers, not high-security environments
- Rate limiting prevents abuse (10 requests/minute/user)

## License

MIT

## Credits

Forked from [codemonument/ai-sudo](https://github.com/codemonument/ai-sudo). Substantially rewritten with CLI wrapper mode, Telegram backend, and command execution.
