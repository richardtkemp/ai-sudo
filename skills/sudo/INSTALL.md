# sudo Installation Guide

Complete guide to installing and configuring sudo from scratch.

---

## Prerequisites

### Required
- **Rust toolchain** (cargo)
- **An approval transport.** The daemon picks ONE backend, by precedence:
  `[askgw]` > `[askgw_http]` > a direct bot transport. This host uses `[askgw]`,
  which needs a running foci gateway exposing an askgw unix socket.
- **Root access** (for installation)

### System Requirements
- Linux (tested on Linux Mint 22 / Ubuntu-based)
- systemd
- SQLite3
- OpenSSL

---

## Step 1: Install Rust (if needed)

```bash
# Check if already installed
cargo --version

# If not installed:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

---

## Step 2: Set up the approval transport (askgw)

The daemon does not talk to a chat platform itself. It hands the question to foci over a
unix socket, and foci posts it into a chat with approve/deny buttons.

1. **Enable askgw in foci's config** (`~/config/foci.toml`):
   ```toml
   [askgw]
   enabled = true
   socket_path = "/home/foci/data/askgw.sock"
   allowed_uids = ["root"]     # aisudo-daemon runs as root
   default_agent = "clutch"    # which agent's chat unrouted asks land in
   ```

2. **Confirm the socket exists and foci is listening on it:**
   ```bash
   ls -l /home/foci/data/askgw.sock
   ss -lx | grep askgw
   ```

3. **Note which chat `default_agent` resolves to.** foci presents the question on that
   agent's *primary* connection. If the agent has several transports configured, the
   question follows the primary one — which is not necessarily the one you actually read.
   The daemon-side `agent` key (Step 5) overrides the routing per install.

---

## Step 3: Clone Repository

```bash
cd ~/git
git clone https://github.com/richardtkemp/ai-sudo.git
cd ai-sudo
```

---

## Step 4: Configure

```bash
# Copy example config
cp aisudo.toml.example aisudo.toml

# Edit config
nano aisudo.toml
```

**Minimum required config:**

```toml
# ai-sudo daemon configuration

socket_path = "/var/run/aisudo/aisudo.sock"
db_path = "/var/lib/aisudo/aisudo.db"
timeout_seconds = 7200  # 2 hours

allowlist = [
    # Add commands that should auto-approve
    "systemctl status",
    "journalctl",
    "df",
    "du",
    # ... see aisudo.toml.example for full list
]

[askgw]
socket_path = "/home/foci/data/askgw.sock"
gateway_uid = "foci"   # username or numeric uid; the daemon stats the socket and
                       # refuses to connect if the owner does not match (protocol 3.2)
# agent = "clutch"     # OPTIONAL: route asks to a named agent. Unset means the
                       # gateway uses its own default_agent routing.
```

**Set `agent` explicitly if more than one agent exists.** With it unset the gateway falls
back to `default_agent`, then `master_agent`, then the first agent in config order — three
layers of implicit choice, and a question delivered to the wrong chat still reports success
to the daemon, which then blocks for the full approval window with nothing visible anywhere.

**Do not add `http_bind` or `http_enable_not_recommended`.** This guide used to list
`http_bind = "127.0.0.1:7654"` here. The HTTP API was removed in `86599f9` (2026-02-05)
and neither key is a field on the config struct any more. There is no
`deny_unknown_fields`, so serde ignores them silently — a config that sets them looks
configured and does nothing. The NUC's live config had exactly that dead key in it until
`793581d`.

**Important:**
- Replace `YOUR_BOT_TOKEN_HERE` with your actual bot token
- Replace `YOUR_CHAT_ID_HERE` with your numeric chat ID
- Keep quotes around bot_token, but NOT around chat_id

---

## Step 5: Build & Install

```bash
# Still in ~/git/ai-sudo directory
sudo bash setup.sh
```

**What setup.sh does:**
1. Builds release binaries (`cargo build --release`)
2. Installs binaries to `/usr/local/bin/`
3. Copies config to `/etc/aisudo/` — but ONLY if a local `aisudo.toml` exists in the
   repo. There is none, so an existing `/etc/aisudo/aisudo.toml` is left alone.
4. Creates the `aisudo` system group
5. Creates runtime directories
6. Installs systemd service
7. Enables and starts daemon

**Output should show:**
```
[✓] Building ai-sudo (release)...
[✓] Installing daemon binary...
[✓] Installing CLI wrapper...
[✓] Installing config...
[✓] Creating sudo service group...
[✓] Creating runtime directories...
[✓] Installing systemd service...
[✓] Enabling and starting aisudo-daemon...
[✓] aisudo-daemon is running!

═══════════════════════════════════════════════════
  ai-sudo setup complete!
═══════════════════════════════════════════════════
```

---

## Step 6: Add User to the aisudo Group

The group is `aisudo`, NOT `sudo`. `sudo` is the real, unrelated system group that
grants unrestricted root (gid 27 on a Debian/Ubuntu box). Adding yourself to it does
not give you aisudo access and does give you something you did not ask for.

```bash
# Add yourself
sudo usermod -aG aisudo $USER

# Verify. Match the whole word — 'grep sudo' also matches 'aisudo' and proves nothing.
groups | tr ' ' '\n' | grep -x aisudo

# Log out and back in for group changes to take effect
# OR: newgrp sudo
```

**Why?** Only members of the `sudo` group can connect to the Unix socket.

---

## Step 7: Test Installation

### Test 1: Simple command

```bash
sudo whoami
```

**Expected:**
1. CLI shows: `sudo: requesting approval for: whoami`
2. An approval request appears in the routed agent's chat
3. Click **[Approve]**
4. CLI shows: `root` (output of whoami as root)

### Test 2: Allowlisted command (auto-approved)

```bash
sudo df -h
```

**Expected:**
- No approval request (auto-approved)
- Output shows immediately

### Test 3: Denied request

```bash
sudo whoami
```

**Then:** Click **[Deny]**

**Expected:**
```
sudo: request denied by user
```

---

## Troubleshooting

### Build fails

```bash
# Check Rust version
rustc --version  # Should be 1.70+

# Update if needed
rustup update stable

# Clean and rebuild
cargo clean
cargo build --release
```

### Daemon won't start

```bash
# Check status
systemctl status aisudo-daemon

# View logs
journalctl -u aisudo-daemon -n 50

# Common issues:
# 1. Config syntax error
sudo cat /etc/aisudo/aisudo.toml

# 2. Socket directory missing — mode and group are NOT arbitrary
sudo install -d -o root -g aisudo -m 750 /var/run/aisudo

# 3. Database directory missing — root only, it holds the DB and transient credentials
sudo install -d -o root -g root -m 700 /var/lib/aisudo
```

### "Connection refused"

```bash
# Check socket exists
ls -l /var/run/aisudo/aisudo.sock

# Check permissions
ls -ld /var/run/aisudo/

# Under systemd this shows drwxr-xr-x root root: RuntimeDirectory in the unit file
# recreates the directory as 0755 root:root on every start, overriding what setup.sh
# made. Both are fine — group-traversable is all that is needed. What matters is that
# it is NOT group-writable, or aisudo members could unlink and replace the socket.

# Check you're in the group. Match the WHOLE word: 'grep sudo' also matches 'aisudo'
# and tells you nothing.
groups | tr ' ' '\n' | grep -x aisudo

# If not, add yourself and re-login
sudo usermod -aG aisudo $USER
```

### Approval requests never arrive

Confirm which backend is actually live before checking anything — the daemon picks one by
precedence, and checks against a backend that is not in use run cleanly and return empty,
which reads as "nothing wrong here".

```bash
# Which backend did the daemon choose? It names it at startup.
journalctl -u aisudo-daemon | grep 'backend enabled'

# askgw: is the socket there, and is the daemon connected to it?
ls -l /home/foci/data/askgw.sock
ss -xp | grep askgw          # want ESTAB, with foci-gw's pid on the other end

# Is a request actually queued? Also a live round-trip probe of the socket.
aisudo --status              # "Pending requests: 1" = daemon is blocked waiting
```

`Received sudo request` in the daemon log with nothing after it means the daemon is still
waiting — it logs nothing on a successful send, so silence is not an error.

**A delivery can succeed and still be invisible.** foci returns "unavailable" only when it
has no connection at all; if it has one, the send succeeds and the daemon waits out the
full window. So "no error anywhere, and no prompt" points at ROUTING — the question went to
a real chat that nobody reads. Check `default_agent` and the `agent` key (Step 5), not the
transport.

---

## Updating an existing install

`sudo make -C /home/rich/git/ai-sudo update` (= `sudo ./setup.sh`). It builds release as the
**invoking** user — never root — then installs, reloads and restarts.

**A bad daemon binary locks you out of sudo, and setup.sh has no rollback.** So, in order:

1. **Preserve.** `cp -p /usr/local/bin/aisudo /usr/local/bin/aisudo-daemon` somewhere you own,
   with a note giving the restore commands. Copying needs no privilege; restoring does — so write
   it down for a human who may have no working sudo.
2. **Boot the new daemon before installing it**, on a throwaway config (`socket_path`/`db_path`
   under /tmp, a small `allowlist`). If it starts and serves one request, it will start under
   systemd.
3. Then update.

**`make update`'s exit code means nothing.** The install is forked into a transient systemd unit
so it survives the daemon restart; make returns immediately and the unit is gone by the time you
look. Verify instead with `/var/log/aisudo-setup.log` (ends in a completion line),
`systemctl show aisudo-daemon -p ActiveEnterTimestamp,NRestarts` (`NRestarts=0` = came up first
try, not crash-looping), and `sha256sum /usr/local/bin/aisudo target/release/aisudo`.

**Config is preserved** unless a local `aisudo.toml` exists in the repo — there is none, so
`/etc/aisudo/` and its `conf.d/` drop-ins survive. Confirm rather than assume.

**Gates that abort before installing anything** (so, harmless): a world-writable file in the tree,
or `cargo` missing from the build user's **login** shell (`bash -lc`, not your current PATH).

## Uninstall

```bash
# Stop and disable service
sudo systemctl stop aisudo-daemon
sudo systemctl disable aisudo-daemon

# Remove binaries
sudo rm /usr/local/bin/aisudo
sudo rm /usr/local/bin/aisudo-daemon
# ...and any per-agent shim pointing at it, e.g. /home/foci/bin/sudo

# Remove service file
sudo rm /etc/systemd/system/aisudo-daemon.service
sudo systemctl daemon-reload

# Remove config and data (optional)
sudo rm -rf /etc/aisudo      # includes conf.d/ — check for drop-ins you want to keep
sudo rm -rf /var/lib/aisudo  # the audit database lives here
sudo rm -rf /var/run/aisudo

# Remove group (optional)
sudo groupdel aisudo

# Remove user from group
sudo gpasswd -d $USER sudo
```

---

## Advanced Configuration

### Custom allowlist

Edit `/etc/aisudo/aisudo.toml`:

```toml
allowlist = [
    # File operations (read-only)
    "cat /var/log",
    "tail -f /var/log",
    
    # System info
    "systemctl status",
    "journalctl",
    
    # Network
    "ss -tunlp",
    "netstat -tunlp",
    
    # Custom app commands
    "myapp status",
    "myapp logs",
]
```

**After editing:**
```bash
sudo systemctl restart aisudo-daemon
```

### Adjust timeout

```toml
timeout_seconds = 3600  # 1 hour
```

### Multiple chat IDs (future feature)

Currently supports one chat_id. For multiple admins, create separate deployments or use the HTTP API.

---

## PAM Mode — not implemented

This section previously described `sudo bash setup.sh --pam`, a PAM module at
`/usr/lib/security/pam_sudo.so`, and an edit to `/etc/pam.d/sudo`. **None of that
exists.** Verified 2026-09-01:

- `setup.sh` accepts only `--gid N` and `-h|--help`, and rejects anything else with
  "Unknown argument".
- The cargo workspace has four members — `aisudo-common`, `aisudo-daemon`, `aisudo-cli`,
  `aibw-cli`. There is no PAM crate and nothing builds a `.so`.

It was built and then deleted. `agents/decisions/001-rust-pam-module.md` (ADR-001,
2026-01-12) chose the nonstick crate; an `aisudo-pam` crate existed; commit `86599f9`
(2026-02-05, "Remove HTTP API and PAM module") deleted `aisudo-pam/src/lib.rs` and its
Cargo.toml with the reason "neither was needed". The ADR is still marked DECIDED, which
is what kept this page describing a shipped feature.

`RequestMode::Pam` does still exist on the wire, but it no longer means PAM. It is what
the CLI sends for `--dry-run` (`aisudo-cli/src/main.rs`): decide, and do not execute.

Interception is CLI-only, and deliberately so: `sudo` on your PATH is the aisudo client,
which shadows `/usr/bin/sudo`.

---

## Security Notes

- Daemon runs as root - it has full system access when executing commands
- With `[askgw]` the request never leaves the machine, but the question text is posted
  into a chat — treat it as visible to anything with access to that chat
- Rate limiting prevents spam but not targeted abuse
- Audit logs in SQLite can grow large - consider rotation
- Socket permissions are critical - only `sudo` group members can connect

**Recommendations:**
- Use for personal/development servers only
- Don't put passwords or secrets in commands (the full command line is shown for approval)
- Review audit logs periodically
- Consider VPN or Tailscale for remote access instead of exposing sudo

---

## Files Installed

| File | Purpose |
|------|---------|
| `/usr/local/bin/aisudo` | CLI wrapper. There is no `/usr/local/bin/sudo` — the `sudo` you type is a per-agent symlink (e.g. `/home/foci/bin/sudo -> /usr/local/bin/aisudo`) earlier on PATH, created outside setup.sh |
| `/usr/local/bin/aisudo-daemon` | Daemon binary |
| `/etc/aisudo/aisudo.toml` | Base configuration |
| `/etc/aisudo/conf.d/*.toml` | Drop-in overrides, merged over the base at startup. Not created or touched by setup.sh, and not mentioned anywhere else in this guide — but this is where most real configuration lives (9 drop-ins on the NUC as of 2026-09-01). Only `.toml` is loaded, so `.bak` siblings are ignored. The daemon logs each one it loads at INFO on startup |
| `/etc/systemd/system/aisudo-daemon.service` | Systemd unit |
| `/var/run/aisudo/aisudo.sock` | Unix socket |
| `/var/lib/aisudo/aisudo.db` | SQLite audit database |

---

## Next Steps

After installation:
1. ✅ Test basic commands
2. ✅ Add commonly-used commands to allowlist
3. ✅ Integrate with OpenClaw (add to TOOLS.md)
4. ✅ Review audit logs occasionally
5. ✅ Keep backups of `/etc/aisudo/aisudo.toml`

---

## Support

- Repository: https://github.com/richardtkemp/ai-sudo
- Issues: https://github.com/richardtkemp/ai-sudo/issues
- Skill docs: `~/shared/skills/sudo/SKILL.md` (see also `command-forms.md`, `allowlist.md`, `troubleshooting.md`)
