---
owner: clutch
name: sudo
description: Remote sudo approval routed to a human approver through foci. Run privileged commands with human approval.
---

# sudo — remote sudo approval via aisudo

**Never call `/usr/bin/sudo` directly.** `sudo` on your PATH is a symlink to
`/usr/local/bin/aisudo`, the aisudo client. It shadows the real binary, so a plain
`sudo foo` already goes through the approval path.

The client sends the command to the aisudo daemon. The daemon either auto-approves it
(allowlist) or asks the approver. The ask goes over the `[askgw]` backend: a unix socket to
the local foci, which posts approve/deny buttons into the agent's chat. Without approval,
the command does not run.

**Approval is asynchronous.** The approver may not be at their phone. Set a long timeout and
wait. Do not retry, and do not assume failure, while approval is pending.

> **Claude Code Bash tool: `timeout` is MILLISECONDS, capped at 600000 (10 min).**
> `timeout: 7200` is 7.2 seconds. Use `timeout: 600000` or `run_in_background: true`.
>
> **If the client errors, the command may still have run.** After approval the DAEMON runs
> the command as root, independently of your client. Before you report failure, look for the
> live process: `ps -eo pid,ppid,etime,user,args | grep '[f]oo'` (works on both OSes).

## Platforms

Find your OS with `uname -s`. The sub-files refer to this table.

| | Linux (`Linux`, the NUC) | macOS (`Darwin`, the work Mac) |
|---|---|---|
| foci user | `foci` | `richardkemp` (foci `HOME` is `~/foci`) |
| `sudo` shim | `/home/foci/bin/sudo` | `/Users/richardkemp/foci/bin/sudo` |
| service | systemd unit `aisudo-daemon` | LaunchDaemon `system/ai.sudo.daemon` |
| status | `systemctl status aisudo-daemon` | `launchctl print system/ai.sudo.daemon` |
| restart | `sudo systemctl restart aisudo-daemon` | `sudo launchctl kickstart -k system/ai.sudo.daemon` (see `troubleshooting.md`) |
| daemon log | `journalctl -u aisudo-daemon` | `/var/log/aisudo.log` (no journald) |
| audit DB | `/var/lib/aisudo/aisudo.db` | `/var/db/aisudo/aisudo.db` |
| askgw socket | `/home/foci/data/askgw.sock` | `/Users/richardkemp/foci/data/askgw.sock` |
| foci log | `/home/foci/logs/foci.log` | `/Users/richardkemp/foci/logs/foci.log` |
| socket peers | `ss -xp \| grep askgw` | `lsof -U \| grep askgw` (no `ss`) |
| repo | `/home/rich/git/ai-sudo` | `/Users/richardkemp/git/ai-sudo` |

Same on both: client `/usr/local/bin/aisudo`, daemon `/usr/local/bin/aisudo-daemon`,
config `/etc/aisudo/aisudo.toml` plus drop-ins `/etc/aisudo/conf.d/*.toml`,
`hot_reload = true`, `timeout_seconds = 7200` (2 h).

The allowlist is **different on each host**. Never assume a command auto-approves here
because it did on the other host. Check with `sudo -n <cmd>` (see `allowlist.md`).

## Basic usage

```bash
sudo whoami
sudo -r "checking disk health" smartctl -a /dev/sda   # -r = reason, shown to the approver
sudo -n journalctl -n 50                              # dry run: would it auto-approve?
sudo -l                                               # list permanent and temp rules
sudo df -h                                            # -h after the command name passes through
```

**Always give `-r "reason"` for a command that is not obvious.** The approver sees it in the
request. On a retry, say what changed: `-r "create snapshot (fixed: quoting in --comments)"`.

**Check the syntax before you ask.** Run `<cmd> --help` without sudo first. A bad command
line costs the approver a tap and gets you nothing.

## Wait or background?

- **Wait** (plain call) when you talk with the approver now, the command is quick, and your
  next step depends on it.
- **Background** (`run_in_background: true`) when you run unattended (cron, heartbeat), or the
  command is slow, or you have other work to do.

## Sub-files

| File | Read it when |
|---|---|
| `command-forms.md` | You write the command line: heredocs, compound commands, pipes, why `bash -c` breaks allowlist matching. |
| `allowlist.md` | You need to know what auto-approves, or to change it: `sudo -n`, `conf.d` drop-ins, temporary rules. |
| `troubleshooting.md` | The daemon or the approval path is broken: socket, group, approval delivery, timeouts, rate limit, recovery. |
| `INSTALL.md` | You install, update or remove ai-sudo. |
