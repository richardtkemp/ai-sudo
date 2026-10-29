# sudo — the allowlist and temporary rules

What runs without asking the approver, and how that changes. For the command line itself,
read `command-forms.md`: an allowlisted command in the wrong form still asks.

## Each host has its own allowlist

The rules live in `/etc/aisudo/aisudo.toml` (`allowlist = [...]`, often empty) and in the
drop-ins `/etc/aisudo/conf.d/*.toml`. The daemon merges every `.toml` drop-in over the base.
Other suffixes (`.bak`, `~`) do not load. **The two hosts have different drop-ins.** A command
that auto-approves on one host can ask on the other. So do not trust a list from memory or
from a doc. Ask the host:

```bash
sudo -l                     # every permanent and temporary rule the daemon has now
ls /etc/aisudo/conf.d/      # which drop-ins exist (filenames show the topic)
sudo -n <cmd>               # would THIS command auto-approve?
```

## Check before you run — `sudo -n`

`sudo -n <cmd>` (`--dry-run`) prints `sudo: command would be auto-approved` or
`sudo: command would require approval` and returns at once. It runs nothing, records nothing
and sends no ask.

Use it before anything that calls sudo **in a loop**: a script, a build target, a deploy.
A headless dotfiles `make dry-run` once sent the approver three asks and then timed out,
because it probed paths with `sudo test -d /etc/...` once per path. One `-n` on a sample
command would have shown that first.

To watch what a run asks for, follow the daemon log (Platforms table in `SKILL.md`).

## Permanent rules — the human installs them

A permanent rule is a drop-in file in `/etc/aisudo/conf.d/`. The key is `allowlist`:

```toml
# /etc/aisudo/conf.d/<topic>.toml
allowlist = [
    "/path/to/my/script.sh",
    "some-command --with-fixed-args",
]
```

`hot_reload = true` on both hosts, so a new or changed drop-in applies on the next request.
No restart.

**You cannot install a drop-in yourself, even with an approval tap.** Claude Code's auto-mode
classifier sees a write into `conf.d` as a security weakening and denies the tool call before
aisudo sees it. The denial is silent to the approver. So:

1. Write the proposed file in `/tmp` and check its TOML.
2. Send it to the human with the reason and the exact install command, for example
   `sudo install -o 0 -g 0 -m 644 /tmp/<topic>.toml /etc/aisudo/conf.d/<topic>.toml`
   (`-g 0`, not `-g root`: macOS has no group named `root`).
3. After the human installs it, confirm with `sudo -n <cmd>`.

**Linux (NUC): most drop-ins come from the dotfiles repo.** A file with the header
`Managed by dotfiles` is a rendered template (`assets/aisudo/templates/conf.d/` in
`/home/rich/git/dotfiles`). Propose the change to the template, not to the installed copy:
a dotfiles run overwrites a hand edit. Check with `grep -l 'Managed by dotfiles' /etc/aisudo/conf.d/*.toml`.

Keep each entry narrow. Matching is a prefix match on the whole command string, so
`"systemctl"` allows every `systemctl` subcommand. Do not allowlist a command that can run
arbitrary code or write arbitrary files as root (`apt install`, `cp` to any path, an
interpreter).

## Temporary rules

A time-limited rule. The approver approves it like any other request:

```bash
sudo --request-rule --duration 3600 -r "timeshift access for disk cleanup" timeshift
sudo --request-rule --duration 86400 -r "network debugging" tcpdump
```

If approved, the pattern auto-approves for that many seconds (the daemon caps it with
`max_temp_rule_duration_seconds`). No file and no restart. `sudo -l` shows active temp rules.
