# sudo — install, update, remove

How to install ai-sudo on Linux or macOS, keep it current, and remove it. Run `uname -s`
first. Paths per OS are in the **Platforms** table in `SKILL.md`. The repo `README.md` has
more detail, including a "macOS notes" section.

**`aisudo`, not `sudo`, is the group.** On Linux, `sudo` is a real, unrelated system group that
grants unrestricted root. Joining it gives no aisudo access.

---

## Prerequisites

| | Linux | macOS |
|---|---|---|
| init system | systemd | launchd |
| compiler | Rust (`cargo`), from rustup or the distro | Xcode Command Line Tools (`xcode-select --install`) and `brew install rust` |
| first install | a human with root | a human with the real admin password |
| approval transport | a running foci with askgw enabled | same |

`cargo` must be on the build user's **login** PATH (`bash -lc 'command -v cargo'`). `setup.sh`
builds as the user who ran `sudo`, never as root, and stops if it cannot find cargo.

---

## Step 1: enable askgw in foci

The daemon does not talk to a chat platform. It sends the ask to foci over a unix socket, and
foci posts it into a chat. In foci's config (`<foci home>/config/foci.toml`):

```toml
[askgw]
enabled = true
allowed_uids = ["root"]     # aisudo-daemon runs as root
default_agent = "<agent>"   # chat where unrouted asks land (clutch on the NUC, cam on the Mac)
# socket_path is optional; the default is <foci data dir>/askgw.sock
```

Check that foci listens:

| | Linux | macOS |
|---|---|---|
| socket | `ls -l /home/foci/data/askgw.sock` | `ls -l /Users/richardkemp/foci/data/askgw.sock` |
| listener | `ss -lx \| grep askgw` | `lsof -U \| grep askgw` |

---

## Step 2: clone and configure

```bash
git clone https://github.com/richardtkemp/ai-sudo.git ~/git/ai-sudo
```

`setup.sh` copies a config to `/etc/aisudo/aisudo.toml` only if `aisudo.toml` exists in the
repo root. To write a first config, copy `aisudo.toml.example` to `aisudo.toml` and edit it.
Then the minimum is:

```toml
socket_path = "/var/run/aisudo/aisudo.sock"
# db_path: leave unset. The default is /var/lib/aisudo/aisudo.db on Linux
# and /var/db/aisudo/aisudo.db on macOS.
timeout_seconds = 7200
hot_reload = true          # serde default is false; without it conf.d edits need a restart
allowlist = []             # put rules in /etc/aisudo/conf.d/*.toml instead

[askgw]
socket_path = "<foci data dir>/askgw.sock"   # Step 1 table
gateway_uid = "<foci user>"                  # foci on Linux, richardkemp on macOS
agent = "<agent>"                            # set it; see below
```

`gateway_uid` takes a user name or a numeric uid. The daemon checks the socket owner and
refuses to connect on a mismatch.

**Set `agent` if more than one agent exists.** Without it, foci falls back to `default_agent`,
then `master_agent`, then the first agent in config order. An ask that goes to the wrong chat
still reports success to the daemon, which then waits the full 2 h with nothing visible.

**Do not add `http_bind` or `http_enable_not_recommended`.** The HTTP API was removed in
`86599f9`. The config has no `deny_unknown_fields`, so serde ignores these keys silently.

On an existing install, leave the repo without `aisudo.toml`. Then `setup.sh` does not touch
`/etc/aisudo/` and its `conf.d/` drop-ins.

---

## Step 3: build and install (first install)

A human runs this in a terminal, from the repo:

```bash
cd ~/git/ai-sudo && sudo ./setup.sh     # the real sudo: aisudo does not exist yet
```

| `setup.sh` does | Linux | macOS |
|---|---|---|
| build (as the invoking user) | `cargo build --release --locked` | same |
| back up files it overwrites | `/var/backups/aisudo/<ts>.<pid>/` + `MANIFEST` | same |
| create group `aisudo` | `groupadd --system` (or `--gid N`) | `dseditgroup -o create` |
| install service | `/etc/systemd/system/aisudo-daemon.service` | `/Library/LaunchDaemons/ai.sudo.daemon.plist` (starts at boot) |
| log | journald; install log `/var/log/aisudo-setup.log` | `/var/log/aisudo.log`, rotated by `/etc/newsyslog.d/aisudo.conf` |
| run the install | in a transient `systemd-run` unit (survives the daemon restart) | inline |
| health gate | `aisudo --status` round trip, 10 tries; on failure it rolls back | same |

The rollback is described in `troubleshooting.md`, "Emergency recovery".

---

## Step 4: add the foci user to the group, and the shim

| | Linux | macOS |
|---|---|---|
| add | `sudo usermod -aG aisudo foci` | `sudo dseditgroup -o edit -a richardkemp -t user aisudo` |
| check | `id -nG foci \| tr ' ' '\n' \| grep -x aisudo` | `dseditgroup -o checkmember -m richardkemp aisudo` |
| shim | `ln -s /usr/local/bin/aisudo /home/foci/bin/sudo` | `ln -s /usr/local/bin/aisudo /Users/richardkemp/foci/bin/sudo` |

The shim directory must come before `/usr/bin` on the agent's PATH. `setup.sh` does not make
the shim.

A new group membership applies only to a new login session. Restart foci after the add.

---

## Step 5: test

```bash
sudo -n whoami     # "would require approval" (no ask is sent)
sudo whoami        # an ask appears in the agent's chat; approve -> prints "root"
sudo whoami        # deny this one -> "request denied"
aisudo --status    # pending count; proves the socket round trip
```

Pick a command for the auto-approve test from `sudo -l`. The allowlist is per host.

---

## Updating an existing install

### Linux

```bash
make -C /home/rich/git/ai-sudo update      # NO leading sudo
```

The target runs `sudo ./setup.sh` itself. An outer `sudo` makes `SUDO_USER` root, and
`setup.sh` refuses to build as root. The install then runs in a transient `systemd-run` unit,
so make returns before the install ends. **Exit 0 proves nothing.** Verify:

```bash
stat -c %y /usr/local/bin/aisudo-daemon /usr/local/bin/aisudo     # newer than your start
systemctl show aisudo-daemon -p ActiveEnterTimestamp,NRestarts     # new start; NRestarts=0
tail -5 /var/log/aisudo-setup.log      # want "=== aisudo setup completed at", no "Install failed"
```

### macOS

**Do not run `setup.sh` through aisudo.** It restarts the daemon that runs it. A full update
(daemon, plist) needs a human in a terminal with the real password:
`cd ~/git/ai-sudo && sudo ./setup.sh`.

For a change to the client only, build and install the client:

```bash
cargo build --release --locked -p aisudo-cli
sudo install -o 0 -g 0 -m 755 target/release/aisudo /usr/local/bin/aisudo
```

Use `-g 0`, not `-g root`: macOS has no group named `root` (gid 0 is `wheel`).
Verify with `stat -f %Sm /usr/local/bin/aisudo` and one `sudo -n whoami`.

### Both

Config survives an update when the repo has no `aisudo.toml`. Confirm it: `ls /etc/aisudo/conf.d/`
before and after. Gates that stop before anything is installed (harmless): a world-writable
file in the tree, or no `cargo` on the build user's login PATH.

---

## Uninstall

Run as root (a human with the real `/usr/bin/sudo`; aisudo goes away during these steps).

| step | Linux | macOS |
|---|---|---|
| stop service | `systemctl disable --now aisudo-daemon` | `launchctl bootout system /Library/LaunchDaemons/ai.sudo.daemon.plist` |
| remove service file | `rm /etc/systemd/system/aisudo-daemon.service && systemctl daemon-reload` | `rm /Library/LaunchDaemons/ai.sudo.daemon.plist /etc/newsyslog.d/aisudo.conf` |
| remove binaries | `rm /usr/local/bin/aisudo /usr/local/bin/aisudo-daemon` | same |
| remove shim | `rm /home/foci/bin/sudo` | `rm /Users/richardkemp/foci/bin/sudo` |
| remove data (optional) | `rm -rf /var/lib/aisudo /var/run/aisudo` | `rm -rf /var/db/aisudo /var/run/aisudo /var/log/aisudo.log` |
| remove config (optional) | `rm -rf /etc/aisudo` (check `conf.d/` first) | same |
| remove group (optional) | `groupdel aisudo` | `dseditgroup -o delete aisudo` |

---

## Security notes

- The daemon runs as root and runs approved commands as root.
- With `[askgw]` the request stays on the machine, but the question text goes into a chat.
  Do not put secrets in a command line.
- Only members of `aisudo` can connect to `/var/run/aisudo/aisudo.sock`. The socket
  directory must not be group-writable.
- The audit DB keeps history for `history_retention_days` (default 365).

## Files installed

| File | Purpose |
|---|---|
| `/usr/local/bin/aisudo` | client; the per-agent `sudo` shim points here |
| `/usr/local/bin/aisudo-daemon` | daemon |
| `/etc/aisudo/aisudo.toml` | base config |
| `/etc/aisudo/conf.d/*.toml` | drop-ins merged over the base; most real config lives here. Not created by `setup.sh` |
| systemd unit / LaunchDaemon plist | see Step 3 table |
| `/var/run/aisudo/aisudo.sock` | client socket |
| audit DB | Platforms table in `SKILL.md` |
| `/var/backups/aisudo/` | install backups, last 5 |

## PAM mode does not exist

Older docs described `setup.sh --pam` and a `pam_sudo.so`. Commit `86599f9` (2026-02-05)
removed the PAM module. `setup.sh` accepts only `--gid N` and `-h`. `RequestMode::Pam` still
exists on the wire, but it means `--dry-run` (decide, do not run).
