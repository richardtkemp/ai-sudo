# sudo — writing the command line

aisudo matches your command against the allowlist as a string. So the form of the command
decides if it runs and if it auto-approves. This file applies to both OSes.

## Piped stdin and heredocs work; interactive input does not

The client reads piped or redirected stdin **before** it sends the request (up to 10 MB,
`max_stdin_bytes`), and the daemon feeds it to the command. So this works:

```bash
sudo tee /etc/myapp/config >/dev/null <<'EOF'
content here
EOF
```

Checked 2026-10-29: `printf 'x\n' | sudo cat /etc -` printed `x`. The redirect `>/dev/null` is
outside the sudo call, so it runs as you. That is correct here: `tee` writes the file as root.

What does not work: anything interactive (`vim`, `nano`, `less`, `htop`, a password prompt).
The daemon allocates no terminal and does not forward stdin while the command runs.

The `/tmp` copy is still the better form when the target path has an allowlist entry for
`cp` or `install`:

```bash
cat > /tmp/file <<'EOF'
content here
EOF
sudo install -o 0 -g 0 -m 644 /tmp/file /etc/myapp/config   # -g 0: macOS has no group 'root'
```

## Compound commands (`&&`, `||`, `;`, `|`)

Put the whole compound in **one** single-quoted argument:

```bash
# ✅ one quoted argument
sudo 'chgrp -R staff /srv/data && chmod -R g+rwX /srv/data'

# ❌ bash -c breaks argument parsing AND allowlist matching
sudo bash -c 'chgrp -R staff /srv/data && chmod -R g+rwX /srv/data'
```

The client sends a lone argument as it is. The daemon parses the operators, splits the command
into segments, checks **each segment** against the allowlist, and runs them with real shell
semantics (`&&` runs the next segment only on success). If you pass an operator as its own
argument (`sudo cp a b '&&' chown x b`), the client escapes it to a literal, and it does not
chain.

The daemon rejects these characters even inside the quoted argument: unquoted `$`, backtick,
`(`, `)`, `<`, `>`, a bare `&`, newline. If you need one as a literal, use the multi-argument
form (`sudo echo '$HOME'`).

## Never prepend `bash` / `sh`

The allowlist uses prefix matching on whole words (`"systemctl status"` matches
`systemctl status nginx`). A shell wrapper changes the first word, so the match fails:

```bash
# ❌ the allowlist sees "bash -c systemctl status nginx"
sudo bash -c 'systemctl status nginx'

# ❌ the allowlist sees "bash /path/to/script.sh"
sudo bash /path/to/script.sh

# ✅
sudo systemctl status nginx
sudo /path/to/script.sh          # the script has a shebang; run it by path
```

`strip_shell_prefix` (off by default) would remove the wrapper before matching. Do not depend
on it. Check the live config: `grep -rn strip_shell_prefix /etc/aisudo/`.

When you send an unquoted `>`, `|` or `$`, the daemon's error tells you to keep the
pipe or redirect OUTSIDE the call. Do that. It also says that `bash -c '...'` will NOT
auto-approve. Use `bash -c` only when the redirect itself needs root (a write into a root-only
path), and accept that it asks the approver. Often `tee` with piped stdin (above) avoids it.

## Keep pipes and redirects outside the call

```bash
# ❌ "iotop -b -n 1 | head -5" is checked as two segments; head may not be allowlisted
sudo 'iotop -b -n 1 | head -5'

# ✅ only "iotop -b -n 1" goes through aisudo; head runs as you
sudo iotop -b -n 1 | head -5
```

## Flags

aisudo flags (`-r`, `-n`, `-l`, `--status`, `--request-rule`) go **before** the command name.
After the command name, every argument belongs to the command. So `sudo df -h` passes `-h` to
`df` (fixed in ai-sudo `c48a519`).
