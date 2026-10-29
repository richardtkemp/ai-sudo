# sudo — when the daemon or the approval path is not working

Diagnosis and recovery for the sudo machinery itself. If the command runs but is not
auto-approved, that is `allowlist.md`; if it is rejected or mangled, that is
`command-forms.md`.

## Troubleshooting

### "Connection refused" or "daemon not running"

```bash
# Check daemon status
systemctl status aisudo-daemon

# Check logs
journalctl -u aisudo-daemon -n 50

# Restart daemon
sudo systemctl restart aisudo-daemon
```

### "Permission denied" connecting to socket

```bash
# Check you're in the aisudo group. Grep for the exact name: `grep sudo`
# also matches "aisudo", so it passes whether or not you are in it.
id -nG | tr ' ' '\n' | grep -qx aisudo && echo yes || echo no

# Add yourself if missing. NOT `-aG sudo` — that is a different, real system
# group granting unrestricted root, and it gives no aisudo access.
sudo usermod -aG aisudo $USER
# Then log out and back in (or `newgrp aisudo`)
```

### Approval never arrives

**This host uses `[askgw]`** — a unix socket to foci, which posts the question into the approver's
chat. Confirm it rather than assuming: the daemon picks one backend by precedence
(`[askgw]` > `[askgw_http]` > a direct bot transport), and checks against a backend that
is not live all run cleanly and return empty, which reads as "nothing wrong here".

```bash
grep -rn '^\[askgw' /etc/aisudo/aisudo.toml /etc/aisudo/conf.d/*.toml
journalctl -u aisudo-daemon | grep -i 'backend enabled'   # names it at startup

aisudo --status          # pending count + approval rate; also a live socket probe
ss -xp | grep askgw      # daemon<->gateway conn should be ESTAB, with foci-gw's pid
```

`Received sudo request` with nothing after it in the daemon log means it is still
blocked waiting — the daemon logs only on backend ERROR, so silence is normal.

**foci logs nothing when an ask arrives or is presented** (only `answered` and
`notify for unknown or expired`). An empty foci.log at the incident minute is NOT
evidence the ask never got there. Tracked in #1837.

### Command gets "Timeout" response

Default timeout is 7200 seconds (2 hours). If you didn't approve in time:

```bash
# Check audit log for the request
sudo sqlite3 /var/lib/aisudo/aisudo.db \
  "SELECT * FROM requests ORDER BY timestamp DESC LIMIT 5;"
```

### "Rate limit exceeded" error

**Rate limit:** 30 non-allowlisted requests per minute per user (allowlisted commands don't count toward the limit).

If you hit the rate limit:
- **Wait 60 seconds** before retrying
- Rate limit window is rolling (not fixed intervals)
- Check if command can be added to allowlist instead (if safe)

```bash
# If you see this error:
sudo: rate limit exceeded

# Wait 60 seconds, then retry
sleep 60 && sudo your-command

# Or add to allowlist if it's a safe read-only command
# Edit /etc/aisudo/aisudo.toml and add to [allowlist.commands]
```

**Why rate limiting?**
- Prevents accidental DOS from scripts
- Protects the approver's attention from a script that pages them once per loop iteration
- Allowlisted commands bypass the limit (they're pre-approved as safe)

**Pro tip:** Batch similar operations together or add frequently-used commands to the allowlist.

---
## Emergency Recovery

If sudo breaks:

```bash
# Restore previous config
sudo cp /etc/aisudo/aisudo.toml.backup-YYYYMMDD-HHMMSS /etc/aisudo/aisudo.toml
sudo systemctl restart aisudo-daemon
```

---
