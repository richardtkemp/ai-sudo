# sudo — when the daemon or the approval path does not work

Diagnosis and recovery for the sudo machinery itself. If the command runs but does not
auto-approve, read `allowlist.md`. If the daemon rejects or changes the command, read
`command-forms.md`. Paths and service commands per OS are in the **Platforms** table in
`SKILL.md`; run `uname -s` first.

## "Connection refused" or "daemon not running"

| | Linux | macOS |
|---|---|---|
| status | `systemctl status aisudo-daemon` | `launchctl print system/ai.sudo.daemon` |
| logs | `journalctl -u aisudo-daemon -n 50` | `tail -50 /var/log/aisudo.log` |
| restart | `sudo systemctl restart aisudo-daemon` | `sudo launchctl kickstart -k system/ai.sudo.daemon` |

**macOS restart:** `kickstart -k` kills the daemon that serves your request. So the client
exits 1 although the restart worked. Read `/var/log/aisudo.log` for the new startup lines
before you report a failure.

If the daemon is down, aisudo cannot restart it. A human must use the real `/usr/bin/sudo`.

**macOS after a reboot:** `/var/run` is empty after every boot. The daemon recreates
`/var/run/aisudo` itself at startup (mode `0750 root:aisudo`). If the client cannot connect
after a reboot, check that directory's owner and mode first.

## "Permission denied" on the socket

Only members of the group `aisudo` can connect. **Not `sudo`**: on Linux that is a real,
unrelated group that grants unrestricted root and no aisudo access.

```bash
# Both OSes. Match the whole word: 'grep sudo' also matches 'aisudo'.
id -nG | tr ' ' '\n' | grep -qx aisudo && echo yes || echo no
```

| | Linux | macOS |
|---|---|---|
| add | `sudo usermod -aG aisudo $USER` | `sudo dseditgroup -o edit -a $USER -t user aisudo` |
| check membership in the directory | `getent group aisudo` | `dseditgroup -o checkmember -m $USER aisudo` |
| takes effect | new login (or `newgrp aisudo`) | new login session only |

A running process (foci, its agents) keeps its old groups. After an add, restart that process.

## Approval never arrives

All hosts use `[askgw]`. Confirm it: the daemon picks one backend by precedence
(`[askgw]` > `[askgw_http]` > a direct bot transport). A check against a backend that is not
live returns empty, and empty reads as "nothing wrong".

```bash
grep -rn '^\[askgw' /etc/aisudo/aisudo.toml /etc/aisudo/conf.d/*.toml
aisudo --status        # pending count; also a live round trip over the daemon socket
```

| check | Linux | macOS |
|---|---|---|
| backend chosen at startup | `journalctl -u aisudo-daemon \| grep 'backend enabled'` | `grep 'backend enabled' /var/log/aisudo.log` |
| daemon connected to foci | `ss -xp \| grep askgw` (want ESTAB, foci-gw pid on the far end) | `grep 'askgw connected' /var/log/aisudo.log`, or `lsof -U \| grep askgw` |
| request reached daemon | `journalctl -u aisudo-daemon \| grep 'Received sudo request'` | `grep 'Received sudo request' /var/log/aisudo.log` |

`Received sudo request` with nothing after it means the daemon still waits. It logs only on a
backend ERROR, so silence there is normal.

**foci logs each ask.** grep the foci log (Platforms table) for `[askgw]`:

- `ask arrived id=… agent=…` — foci received it from the daemon.
- `ask posted id=… session=…` — foci put it into that chat.
- `ask unavailable … no chat session for agent` / `ask present failed` — delivery failed.
- `ask answered` / `ask timed out` / `ask abandoned` — the end of the ask.

`ask posted` with no answer means routing: the ask went to a real chat that nobody reads.
Check the `agent` key in `[askgw]` (daemon side) and `default_agent` (foci side).

## Command gets "Timeout"

`timeout_seconds` is 7200 (2 h) on both hosts. Look up the request in the audit DB
(path in the Platforms table):

```bash
sudo sqlite3 <db_path> "SELECT id,user,command,status,timestamp FROM requests ORDER BY timestamp DESC LIMIT 5;"
```

## "Rate limit exceeded"

Default: 30 requests that need a human per 60 s, per user (`rate_limit_requests`,
`rate_limit_window_seconds`). Auto-approved commands do not count, unless
`rate_limit_count_allowlisted = true`. The window rolls.

- Wait 60 s, then retry.
- Batch the work into fewer requests.
- If the command is safe and frequent, it may belong on the allowlist. A human installs that
  drop-in (see `allowlist.md`). You do not edit `aisudo.toml`.

## Emergency recovery

**A failed install rolls back by itself.** Before it changes anything, `setup.sh` copies each
file it will overwrite to `/var/backups/aisudo/<YYYYMMDD-HHMMSS>.<pid>/`, in the same layout,
with a `MANIFEST` listing the paths. It keeps the last 5. If any step fails, or the new daemon
does not answer `aisudo --status` within 10 s, a trap copies every MANIFEST path back, restarts
the daemon and checks it again. The log says which result you got:

- `Rolled back. The previous daemon is answering on its socket again.` — safe; the new build
  stays in `target/release/` for debugging.
- `ROLLED BACK, BUT THE RESTORED DAEMON IS NOT ANSWERING.` — a human must recover with the
  real `/usr/bin/sudo`.
- `no previous install to restore` — expected on a first install.

Where to read it: Linux `/var/log/aisudo-setup.log`; macOS the terminal that ran `setup.sh`.

Files in the backup: both binaries and `/etc/aisudo/aisudo.toml` on both OSes; plus
`/etc/systemd/system/aisudo-daemon.service` (Linux), or the LaunchDaemon plist and
`/etc/newsyslog.d/aisudo.conf` (macOS). **`conf.d/` drop-ins are not in the backup.**

**Restore by hand.** Run this in a root shell. If aisudo is down, a human opens one with the real `/usr/bin/sudo -i`.

```bash
B=/var/backups/aisudo/<dir>           # root-only (mode 700); newest: sudo ls -1t /var/backups/aisudo
cat "$B/MANIFEST"
while read -r p; do cp -p "$B$p" "$p"; done < "$B/MANIFEST"
# then restart the daemon (Platforms table) and run: aisudo --status
```
