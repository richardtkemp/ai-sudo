---
owner: clutch
name: sudo
description: Remote sudo approval routed to a human approver through foci. Run privileged commands with human approval.
---

# sudo — remote sudo approval via aisudo

**Never call `/usr/bin/sudo` directly.** `sudo` on your PATH is `/home/foci/bin/sudo`, the aisudo client — it shadows the real binary, so a plain `sudo foo` already goes through the approval path. Do not reach past it.

sudo sends an approval request to the approver with approve/deny buttons. On this host it travels over the
`[askgw]` backend — a unix socket to foci, which posts the question into the approver's chat. Without
approval, commands won't run. This is the only way to run privileged commands in this environment.

**Approval is asynchronous.** The approver may not be at their phone. Always set a LONG timeout on sudo exec calls and be patient — don't retry or assume failure if approval takes minutes.

> **Claude Code Bash tool: `timeout` is MILLISECONDS, capped at 600000 (10 min).** So `timeout: 7200` means 7.2 **seconds** — use `timeout: 600000`, or `run_in_background: true`.
>
> **If the aisudo client ever errors, the command may still have run.** Once the approver approves, the aisudo-DAEMON launches the command as root, independently of your client. Before reporting failure, check for the live process: `ps -eo pid,ppid,etimes,user,args | grep '[f]oo'` (guarded pattern avoids self-match). Bitten 2026-07-18 running `/root/bin/disk-report.sh` — told the approver "it never ran" while it had been running ~9 min.

---

## Quick Reference

### Basic Usage

```bash
# Simple command
sudo apt update

# With reason (ALWAYS include for non-obvious commands)
sudo -r "checking disk health" smartctl -a /dev/sda

# Multi-word commands
sudo systemctl restart aisudo-daemon
```

### Before Running Commands

**Verify syntax before using sudo:**

```bash
# Check command help first (without sudo)
timeshift --help | grep -A5 -- --create

# Then run with sudo
sudo -r "reason" timeshift --create --comments "snapshot name"
```

This prevents sending bad syntax to the approver for approval.

**If a command fails and you retry:**

Include what changed in the `-r` reason:

```bash
# First attempt failed
sudo -r "creating snapshot" timeshift --create --comments "bad syntax"
# (fails)

# ❌ BAD - same reason, the approver can't tell what's different
sudo -r "creating snapshot" timeshift --create --comments "Post-cleanup"

# ✅ GOOD - explains what changed
sudo -r "creating snapshot (fixed: escaped quotes in comments)" timeshift --create --comments "Post-cleanup"
```

### When to Wait vs Poll

**Wait synchronously when:**
- ✅ In active conversation with the approver
- ✅ Command is quick (<30 seconds expected)
- ✅ Next steps depend on this command's success

**Background + poll when:**
- ✅ Running autonomously (heartbeat, cron job)
- ✅ Command might take a while
- ✅ You're doing other work in parallel

```bash
# Wait (default - just run the command)
sudo systemctl restart nginx
# <blocks until approved/denied>

# Background + poll (rarely needed for sudo)
sudo -r "reason" long-running-command &
# Check later with process monitoring
```

---

## The `-r` Flag (Reason)

**Always include `-r "reason"` for non-obvious commands.**

The approver is much more likely to approve if they know WHY you need elevated privileges.

```bash
# ❌ BAD - no context
sudo apt install ripgrep

# ✅ GOOD - explains why
sudo -r "ripgrep is faster for log scanning in healthcheck" apt install ripgrep

# ❌ BAD
sudo cp /tmp/config /etc/myapp/config

# ✅ GOOD
sudo -r "deploying updated config after validation" cp /tmp/config /etc/myapp/config
```

**Reason shows in the approval request:**
```
🔐 sudo request

User: rich
Command: apt install ripgrep
Reason: ripgrep is faster for log scanning in healthcheck

[Approve] [Deny]
```

---

## Sub-files

| File | Read it when |
|---|---|
| **`command-forms.md`** | Writing the command line — heredocs, compound commands, pipes, and why prepending `bash`/`sh` breaks allowlist matching. |
| **`allowlist.md`** | What auto-approves and how to change it — checking with `sudo -n` before you run, permanent `conf.d` drop-ins, temporary rules. |
| **`troubleshooting.md`** | The daemon or the approval path itself is broken — socket, permissions, approval delivery, timeouts, rate limits, config recovery. |
| **`INSTALL.md`** | Installing or reconfiguring ai-sudo from scratch. |

## Installation & Setup

See [INSTALL.md](./INSTALL.md) for detailed setup instructions.

**Quick summary:**
1. Clone: `git clone https://github.com/richardtkemp/ai-sudo.git ~/git/ai-sudo`
2. Configure: `cp aisudo.toml.example aisudo.toml`, then add an approval backend —
   `[askgw]` with `socket_path` + `gateway_uid` is what this host uses.
3. Build & install: `sudo ./setup.sh`
4. Add user to group: `sudo usermod -aG aisudo rich`

**`aisudo`, not `sudo`, in steps 2 and 4.** `sudo` is a real unrelated system group granting
unrestricted root; joining it gives you root and does NOT give you aisudo access.

---

## See Also

- Installation guide: [INSTALL.md](./INSTALL.md)
- Repository: `~/git/ai-sudo`
- Approval transport: `[askgw]` — see `troubleshooting.md` for how to confirm which backend is live
