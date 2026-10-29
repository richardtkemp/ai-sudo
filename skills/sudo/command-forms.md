# sudo — writing the command line

aisudo matches your command against the allowlist as a literal argv, so how you phrase a
command decides both whether it runs and whether it auto-approves. These are the forms
that do not survive the trip.

## ❌ Heredocs Don't Work

Shell features like heredocs, pipes, and redirections don't work with sudo because stdin isn't captured:

```bash
# ❌ WRONG - doesn't work
sudo tee /etc/file << 'EOF'
content here
EOF

# ✅ RIGHT - create file in /tmp first
cat > /tmp/file << 'EOF'
content here
EOF
sudo cp /tmp/file /etc/file
```

**Why:** sudo executes commands remotely and doesn't forward stdin. Always create files in `/tmp` first, then use sudo to copy them to protected locations.

**Future:** stdin support is planned (see STDIN_SUPPORT_PLAN.md in ~/git/ai-sudo)

## Compound Commands (&&, ||, pipes)

Single-quote the entire command string:

```bash
# ✅ RIGHT - single-quoted compound command
sudo 'chgrp -R rich-readers /home/rich/git/ && chmod -R g+rwX /home/rich/git/'

# ❌ WRONG - bash -c wrapper breaks argument parsing AND allowlist matching
sudo bash -c 'chgrp -R rich-readers /home/rich/git/ && chmod -R g+rwX /home/rich/git/'
```

**Why:** the compound MUST arrive as a *single* argument (one shell-quoted blob). The CLI
forwards a lone positional arg verbatim, so the daemon's chain parser sees the operators
*unquoted*, splits the command into segments (`;`, `&&`, `||`, `|`), validates **each segment**
against approval, and executes with real shell semantics (`&&` runs the next only on success).
Operators passed as their *own* args (`sudo cp a b '&&' chown x b`) get escaped to literals and
will NOT chain — keep the whole compound inside one quoted blob. `bash -c` also breaks: it splits
arguments wrong and defeats allowlist matching.

Rejected even when quoted-as-blob: unquoted `$`, backtick, `(` `)`, `<` `>`, bare `&`, newline —
the daemon refuses these. Use the multi-arg form (`sudo echo '$HOME'`) when you need them literal.

(Fixed in CLI commit `ac7350a`, Jun 2026 — before that, a single-quoted compound failed with a
baffling "not found" because the CLI re-quoted the blob and the parser skipped quoted operators.)

## ⚠️ Never Prepend `bash` / `sh` — It Breaks Allowlist Matching

Some allowlisted commands use **prefix matching** (e.g. `"systemctl status"` matches `"systemctl status nginx"`). Prepending `bash` or `sh` means the allowlist sees `bash ...` instead of the actual command, and prefix matching fails:

```bash
# ❌ WRONG - allowlist sees "bash -c systemctl status nginx"
sudo bash -c 'systemctl status nginx'

# ❌ WRONG - allowlist sees "bash /path/to/script.sh"
sudo bash /path/to/script.sh

# ✅ RIGHT - allowlist sees "systemctl status nginx"
sudo 'systemctl status nginx'

# ✅ RIGHT - scripts have shebangs, just run them directly
sudo /path/to/script.sh
```

**Never prepend `bash`, `sh`, or any shell wrapper.** Pass commands directly. Scripts have appropriate shebangs — run them by path.

### ⚠️ The daemon's own error message tells you to do this. Ignore it.

Reject an unquoted `>`/`|`/`$`, and the currently-deployed daemon replies:

```
unsupported shell syntax (<reason>); wrap in bash -c '...' to run as a shell
```

**Following that is strictly worse than ignoring it.** Prefix matching runs on the whole command string, and `strip_shell_prefix` is `false` by default *and* unset in this host's `/etc/aisudo/aisudo.toml` — so a wrapped command reaches the allowlist as `bash …` and can never match an entry written for the real command. Every wrapped call escalates to the approver's phone, **even when the underlying command is allowlisted and would have auto-approved.**

Do what the section above says instead: keep the pipe/redirect outside the call.

One genuine exception: if the **redirect itself needs root** (writing into a root-only path), a root shell really is required and `bash -c '...'` is the only answer — accept that it won't auto-approve.

Fixed in ai-sudo `8eced8e` (2026-07-31), which leads with the cheap fix and names the escalation cost of the wrapper. **Not yet deployed** — until the daemon is rebuilt and restarted, you will still see the misleading text above.

## Pipes Break Allowlist Matching

Pipes and redirects inside the sudo command change the command string, breaking prefix matching against the allowlist:

```bash
# ❌ WRONG - pipe is inside sudo, "iotop -b -n 1 | head" doesn't match "iotop"
sudo 'iotop -b -n 1 | head -5'

# ✅ RIGHT - pipe is outside sudo, aisudo only sees "iotop -b -n 1"
sudo 'iotop -b -n 1' | head -5
```

**Why:** Allowlist uses prefix matching on the full command string. Keep pipes/redirects outside the sudo call so only the actual command is matched.

---
