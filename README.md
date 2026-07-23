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
- **macOS only:** Xcode Command Line Tools (`xcode-select --install`). A clean
  Mac cannot `cargo build` without the linker and `Security.framework`
  (reqwest's default native-tls links against it). This is the first thing
  that fails on a fresh machine.

### Build & Install

```bash
git clone https://github.com/richardtkemp/ai-sudo.git
cd ai-sudo
cp aisudo.toml.example aisudo.toml   # then uncomment [telegram] and fill in your bot token + chat ID

# Build + install. Run via sudo from your normal user account: setup.sh compiles
# as you (unprivileged) and only the install steps run as root. It refuses to
# build from a world-writable source tree. Works on Linux (systemd) and macOS
# (launchd); setup.sh dispatches on `uname -s`.
sudo ./setup.sh
```

The build uses `cargo build --release --locked` as the invoking user, then root
installs the binaries (`/usr/local/bin`, `0755 root:root` on Linux /
`root:wheel` on macOS), config (`/etc/aisudo/aisudo.toml`, `0600`), the `aisudo`
group, and the systemd unit (Linux) or launchd plist (macOS).

**Adding yourself to the `aisudo` group** (required to connect to the daemon):

```bash
# Linux
sudo usermod -aG aisudo $USER       # then log out and back in

# macOS
sudo dseditgroup -o edit -a $USER -t user aisudo
# new group membership needs a fresh login shell: sg aisudo -l, or open a new terminal
```

### macOS notes

- **State location:** the daemon uses `/var/db/aisudo/aisudo.db` on macOS (not
  `/var/lib/`, which doesn't exist by default on Darwin). The default is
  `cfg`-gated in `aisudo-daemon/src/config.rs`; you don't need to set
  `db_path` in config.
- **Logs:** `launchd` writes stdout/stderr to `/var/log/aisudo.log` (rotated by
  `newsyslog` via a drop-in `setup.sh` installs). Use `tail -f
  /var/log/aisudo.log` instead of `journalctl -u aisudo-daemon`.
- **Service management:**
  ```bash
  sudo launchctl print system/ai.sudo.daemon       # status
  sudo launchctl kickstart -k system/ai.sudo.daemon  # restart
  ```
- **Socket dir after reboot:** `/private/var/run` is wiped on every boot and
  launchd has no equivalent of systemd's `RuntimeDirectory=`. The daemon
  recreates `/var/run/aisudo` itself at startup with mode `0750 root:aisudo`
  (cfg-gated macOS block in `socket.rs`). If the CLI ever can't connect after
  a reboot, check that dir's ownership and mode first.
- **`SystemCallArchitectures=native` is intentionally not paralleled** on macOS.
  The threat it defends against (32-bit syscall ABI exploit portability) does
  not exist on Darwin — Apple removed 32-bit app support in Catalina (10.15,
  2019). See [`agents/decisions/002-systemcallarchitectures-macos.md`](agents/decisions/002-systemcallarchitectures-macos.md).
- **askgw path caveat:** the `[askgw]` example uses bare `/run/foci/askgw.sock`,
  which does not exist on macOS (only `/var/run` does). If you route approvals
  through askgw on macOS, set the socket path under `/var/run/...` on the foci
  side.

### Configure

Edit `/etc/aisudo/aisudo.toml`:

```toml
socket_path = "/var/run/aisudo/aisudo.sock"
db_path = "/var/lib/aisudo/aisudo.db"
timeout_seconds = 900  # 15 minutes

# Commands that auto-approve without notification.
# Only list commands that cannot execute arbitrary code or write arbitrary
# files as root. Do NOT auto-approve `apt install` (runs maintainer scripts /
# local .deb as root) or other code-executing commands — route those through
# Telegram approval.
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

# Alternative to [telegram]: route approvals through foci's interactive button
# surface over a local Unix socket. Takes precedence over [telegram] when set.
# [askgw]
# socket_path = "/run/foci/askgw.sock"
# gateway_uid = "foci"   # socket owner, as username or numeric uid (fail-closed check)
# agent = "clutch"       # optional: route asks to a specific agent

# Alternative to both: same askgw approval flow, but over the network instead
# of a local socket — for a REMOTE host (e.g. a Mac) that can't reach foci's
# socket without ssh-forwarding it. Takes precedence over [telegram], but
# [askgw] wins if both are set. Requires foci's [askgw] http_enabled = true.
# [askgw_http]
# endpoint = "https://foci.example.ts.net"  # foci's HTTP server base URL
# api_key = "your-foci-http-api-key"        # same value as foci's http.api_key
# agent = "clutch"                          # optional: route asks to a specific agent
# poll_wait_seconds = 20                    # long-poll GET wait
# request_timeout_seconds = 30              # HTTP client timeout per request

[limits]
check_binary_ownership = "auto"  # "off", "auto" (allowlist/temp rules only), or "all" (including Telegram-approved)
allowed_binary_owners = []       # additional trusted UIDs beyond root (default: root only)
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

## Shell Operators

Commands support chaining operators like pipes and `&&`. For auto-approved
commands, each sub-command is validated individually against the allowlist — all
must match.

```bash
# Both 'apt list' and 'grep' must be in the allowlist:
aisudo 'apt list --installed | grep vim'

# Sequential execution — both must be allowed:
aisudo 'apt list ; dpkg -l'

# Conditional chains:
aisudo 'apt list && echo ok || echo fail'
```

**Supported operators:** `;` (sequential), `&&` (and), `||` (or), `|` (pipe)

**Rejected syntax** (the request is denied immediately if found unquoted, for
**both** auto-approved and human-approved commands):
- `$`, `` ` `` — variable expansion, command substitution
- `(`, `)` — subshells
- `>`, `<` — redirections
- Bare `&` — background execution

This is a hard rule: a command with unquoted metacharacters never runs, even if
you would approve it — it can't reach a shell, which closes a class of bypasses
where a denylisted command is slipped through by appending e.g. `$(true)`.

To run a genuine shell one-liner (redirects, substitutions, subshells), wrap it
explicitly so the metacharacters are quoted — it then parses as a single command
and the full text is shown in the approval prompt:

```bash
aisudo bash -c 'echo "deb …" > /etc/apt/sources.list.d/foo.list'
aisudo bash -c 'kill $(pidof nginx)'
```

Quoting (single or double) suppresses operator detection, so `echo "hello; world"`
is treated as a single command.

## Hot-Reload

Set `hot_reload = true` in `aisudo.toml` to pick up config changes without restarting the daemon. On each incoming connection, the daemon checks file modification times (main config + `conf.d/` drop-ins) and re-parses if anything changed. If the new config is invalid, the old config is kept.

**Reloads at runtime:** `allowlist`, `timeout_seconds`, `max_stdin_bytes`

**Requires daemon restart:** `socket_path`, `db_path`, Telegram settings

## Architecture

- **`aisudo-cli`** — CLI wrapper, connects to daemon via Unix socket
- **`aisudo-daemon`** — Runs as root, handles approvals, executes commands
- **`aisudo-common`** — Shared types and protocol
- **`aisudo-pam`** — Optional PAM module for intercepting native `sudo`

The daemon runs as a systemd service on Linux (`aisudo-daemon.service`) or a launchd daemon on macOS (`ai.sudo.daemon.plist`), and communicates with the CLI over a Unix socket (`/var/run/aisudo/aisudo.sock`). Users must be in the `aisudo` group to connect.

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
    systemctl status, journalctl, apt search/list/show, du, df, lsblk,
    ss, lsof, cat /etc/*, tail /var/log/*, dmesg, smartctl, and more.
    (Code-executing commands like `apt install` and `systemctl restart` are NOT
    auto-approved by default — they require a Telegram prompt.)
    See `/etc/aisudo/aisudo.toml` for the full list.

    **Config:** `/etc/aisudo/aisudo.toml` | **Socket:** `/var/run/aisudo/aisudo.sock`

## Security Notes

- Daemon runs as root — it executes approved commands directly
- Unix socket is `root:aisudo 0660` — only group members can request
- All requests and decisions are logged to SQLite for audit
- Telegram notifications are not E2E encrypted — suitable for personal servers, not high-security environments
- `[askgw_http]` (network askgw) is gated by a single bearer token (foci's `http.api_key`) — a materially weaker gate than `[askgw]`'s local-socket SO_PEERCRED UID check. Only use it for a host that genuinely can't reach the socket (e.g. over Tailscale/HTTPS to a trusted foci instance), not as a drop-in upgrade for a host that could use the socket instead.
- Rate limiting prevents abuse (10 requests/minute/user)
- **Single root process (no privilege separation):** splitting into an unprivileged front-end + a minimal root executor was evaluated and judged not worth the complexity here. The front-end *is* the approval authority, so compromising it already lets an attacker authorize arbitrary root execution regardless of any split — privsep would only shrink the blast radius of memory-safety/dependency bugs, a modest gain in a Rust codebase for this personal-server threat model.

## Bitwarden Web Unlock (optional)

The optional Bitwarden integration exposes a small web UI to unlock the vault. It
is gated by a **single-use access code delivered over Telegram** — only the
configured `chat_id` ever receives codes:

- A credential request that finds the vault locked sends a Telegram notification
  containing a tappable unlock link.
- You can also request a link any time via the dashboard's **Send access code**
  button (rate-limited per caller).

Tapping a link redeems the code for a short-lived session cookie (the code is
stripped from the URL), then you enter the Bitwarden master password to unlock.
Releasing a specific credential always requires an explicit Telegram
**Approve/Cancel** — unlocking the vault is not the same as approving a release.

Set `web_external_url` in `[bitwarden]` to your UI's public https URL (e.g. behind
`tailscale serve`) so the daemon can build the links. See `aisudo.toml.example`.

## Limitations

**Interactive apps like `vim`, `nano`, `less`, `htop` don't work** — no pseudo-terminal (PTY) is allocated. Commands run via pipes with unidirectional output streaming, and stdin is captured upfront (for piped input only), not forwarded interactively. Use `sudo` directly for interactive applications, or non-interactive alternatives like `sed -i` for file edits.

## Binary Ownership Validation

Commands can be checked for binary ownership before execution. The daemon resolves the command binary via PATH and rejects it if:

- The binary is not owned by root (or an explicitly allowed owner)
- The binary is world-writable or group-writable
- The binary is a symlink to an untrusted target (follows symlinks)

This prevents privilege escalation where an attacker replaces a whitelisted binary with a malicious one.

Three levels are available:

| Level | Description |
|-------|-------------|
| `"off"` | No ownership checking |
| `"auto"` | Check only auto-approved commands (allowlist/temp rules) **(default)** |
| `"all"` | Check all commands, including human-approved (Telegram) ones |

Configure in `aisudo.toml`:

```toml
[limits]
check_binary_ownership = "auto"  # "off", "auto", or "all"
allowed_binary_owners = [1000]   # additional trusted UIDs beyond root
```

For backward compatibility, `true` is treated as `"auto"` and `false` as `"off"`.

## License

MIT

## Credits

Forked from [codemonument/ai-sudo](https://github.com/codemonument/ai-sudo). Substantially rewritten with CLI wrapper mode, Telegram backend, and command execution.
