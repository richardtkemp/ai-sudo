# sudo — the allowlist and temporary rules

What runs without paging the approver, and how to change that. For writing the command line itself
see `command-forms.md`; a command that is on the allowlist but phrased wrong still asks.

## Check before you run — `sudo -n`

`sudo -n <cmd>` (`--dry-run`) reports whether the command would be approved **without
requesting anything**. It prints one of `sudo: command would be auto-approved` or
`sudo: command would require approval` and returns immediately. Nothing is recorded,
nothing is executed, and no approval request is sent.

Use it before running anything that shells out to sudo **in a loop** — a script, a build
target, a deploy. A headless `make dry-run` against the dotfiles repo sent the approver three
approval prompts and then timed out, because it probes paths with `sudo test -d /etc/...`
once per path. `-n` on one representative command would have shown that in advance.

`journalctl -u aisudo-daemon` shows requests as they arrive, if you want to watch what a
run is actually asking for.

## Allowlist (Auto-Approved Commands)

Many safe commands are **auto-approved** without asking the approver at all:

### System Info (read-only)
- `systemctl status`
- `systemctl is-active`
- `journalctl`
- `df`, `du`, `lsblk`, `fdisk -l`
- `free`, `ss`, `netstat`, `lsof`
- `dmesg`, `lspci`, `lsusb`
- `smartctl`

### Package Info (not remove)
- `apt search`
- `apt list`
- `apt show`
- `apt-cache`

### File Reading
- `cat /etc/*`
- `tail /var/log/*`
- `ls /root`, `cat /root/*`

**List all active rules:**
```bash
sudo -l
```

**Full list (config file):** `/etc/aisudo/aisudo.toml` (allowlist section)

**Check if a specific command is allowlisted:**
```bash
# Ask without requesting anything — prints "would be auto-approved" or "would require approval"
sudo -n journalctl -n 50
```

---
## Adding Allowlist Rules

**Use drop-in files in `/etc/aisudo/conf.d/`** — don't edit the main config.

Each `.toml` file in `conf.d/` is merged with the main config. This keeps changes modular and avoids editing the master file.

### Adding a new allowlist entry

```bash
# 1. Write a drop-in file to /tmp
cat > /tmp/my-rules.toml << 'EOF'
allowlist = [
    "/path/to/my/script.sh",
    "some-command",
]
EOF

# 2. Copy to conf.d (needs sudo approval)
sudo cp /tmp/my-rules.toml /etc/aisudo/conf.d/my-rules.toml
# No restart needed — aisudo hot-reloads config on each request
```

### Existing drop-in files

```bash
ls /etc/aisudo/conf.d/
```
## Temporary Rules

Request a time-limited allowlist rule, approved the same way as any other request:

```bash
# Request a temp rule for 1 hour (3600 seconds)
sudo --request-rule --duration 3600 -r "need timeshift access for disk cleanup" timeshift

# Request for 24 hours
sudo --request-rule --duration 86400 -r "debugging network" tcpdump
```

The approver gets an approval button in their chat. If approved, the pattern is allowlisted for the specified duration. No config files or restarts needed.

**Check active temp rules:**
```bash
sudo -l  # shows both permanent and temp rules
```

### Current Development Rules

These are already allowlisted for sudo development:

```toml
# sudo development (updating after build)
"systemctl stop aisudo-daemon"
"systemctl start aisudo-daemon"
"systemctl daemon-reload"
"cp /home/rich/git/ai-sudo/target/release/aisudo-daemon /usr/local/bin/aisudo-daemon"
"cp /home/rich/git/ai-sudo/target/release/sudo /usr/local/bin/sudo"
"chmod 755 /usr/local/bin/aisudo-daemon"
"chmod 755 /usr/local/bin/sudo"

# sudo config management
"cp /etc/aisudo/aisudo.toml.backup"
"ls /etc/aisudo"
"cat /etc/aisudo/aisudo.toml"
```

---
