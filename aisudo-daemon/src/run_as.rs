//! Run an approved command as a user other than root (`sudo -u <user>`, #2799).
//!
//! The account is resolved once, before any rule is checked, so the rules, the approver
//! and the exec all see the same one. A rule cannot match one account and the exec run
//! another, and a rename while a request waits for a human changes nothing.

use anyhow::Result;
use nix::libc;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;

/// The daemon's variables a target user keeps. Everything else is cleared: the daemon's
/// environment belongs to a root service and is not the target's to read.
const KEPT_ENV: &[&str] = &["PATH", "LANG", "LC_ALL"];

/// More groups than any real account has. Reaching it means the lookup is broken.
const MAX_GROUP_LOOKUP: usize = 65536;

/// The account a command runs as.
#[derive(Debug, Clone)]
pub struct RunAsTarget {
    /// The name from the passwd database, not the one the client typed. macOS looks
    /// names up case-insensitively, and rule matching must not depend on that.
    pub name: String,
    uid: u32,
    gid: u32,
    home: OsString,
    shell: OsString,
    groups: Vec<libc::gid_t>,
}

impl RunAsTarget {
    /// Resolve a `-u` argument. `Ok(None)` means the account IS root, which is exactly a
    /// request with no `-u`. Only the account named root collapses: another uid-0 name
    /// (`toor`) stays a named target, so root's rules do not cover it.
    pub fn resolve(name: &str) -> std::result::Result<Option<Self>, String> {
        let user = match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => user,
            Ok(None) => return Err(format!("unknown user '{name}'")),
            Err(e) => return Err(format!("could not look up user '{name}': {e}")),
        };
        if user.uid.is_root() && user.name == "root" {
            return Ok(None);
        }
        let groups = group_list(&user.name, user.gid.as_raw())
            .map_err(|e| format!("could not read the groups of '{name}': {e}"))?;
        Ok(Some(Self {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir.into_os_string(),
            shell: user.shell.into_os_string(),
            groups,
            name: user.name,
        }))
    }

    #[cfg(test)]
    pub fn groups_for_test(&self) -> &[libc::gid_t] {
        &self.groups
    }

    /// Make `cmd` run as this account, in `cwd`.
    ///
    /// The child enters `cwd` AFTER it drops privileges, not as root. The client supplies
    /// that path, so entering it as root would hand the target a working directory inside
    /// a tree it cannot reach. If the target cannot enter it, the command does not run.
    /// It does not fall back to another directory: `rm foo` must not mean `rm /foo`.
    pub fn apply(&self, cmd: &mut tokio::process::Command, cwd: &str) -> Result<()> {
        let cwd = CString::new(cwd)?;

        cmd.env_clear();
        for key in KEPT_ENV {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        cmd.env("HOME", &self.home)
            .env("USER", &self.name)
            .env("LOGNAME", &self.name)
            .env("SHELL", &self.shell);

        let (uid, gid, groups) = (self.uid, self.gid, self.groups.clone());
        // SAFETY: the closure runs between fork and exec, so it must only make
        // async-signal-safe calls and must not allocate. getgrouplist, which is neither,
        // ran in resolve(). The Err arm builds an io::Error from errno, which does not
        // allocate. Order matters: groups and gid need root, so uid goes last.
        unsafe {
            cmd.pre_exec(move || {
                drop_privileges(uid, gid, &groups)?;
                check(libc::chdir(cwd.as_ptr()))?;
                mark_inherited_fds_cloexec();
                Ok(())
            });
        }
        Ok(())
    }
}

/// Become `uid`, for good. Runs in the forked child.
///
/// # Safety
/// Only call between fork and exec.
unsafe fn drop_privileges(uid: u32, gid: u32, groups: &[libc::gid_t]) -> std::io::Result<()> {
    // setgroups needs root. A daemon that is not root skips it, and the setgid or setuid
    // below then fails unless the target is the daemon's own user, where nothing changes.
    if libc::geteuid() == 0 {
        check(libc::setgroups(groups.len() as _, groups.as_ptr()))?;
    }
    check(libc::setgid(gid))?;
    check(libc::setuid(uid))?;
    if libc::getuid() != uid || libc::geteuid() != uid {
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

fn check(rc: libc::c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Stop any descriptor the daemon left inheritable from reaching the target. The pipes
/// of a concurrent root pipeline are one (`nix::unistd::pipe` does not set CLOEXEC), and
/// they would let this user read that command's output. Marked, not closed: std's
/// exec-error pipe is among them and must survive to the exec.
fn mark_inherited_fds_cloexec() {
    // SAFETY: sysconf and fcntl are async-signal-safe. A bad descriptor returns EBADF.
    unsafe {
        let max = libc::sysconf(libc::_SC_OPEN_MAX);
        let max = if max > 0 { max as libc::c_int } else { 1024 };
        for fd in 3..max {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
}

/// The target's groups, primary first, as `initgroups` would set them. Read here because
/// `initgroups` itself is not safe between fork and exec.
fn group_list(name: &str, gid: u32) -> std::result::Result<Vec<libc::gid_t>, String> {
    let c_name = CString::new(OsString::from(name).into_vec()).map_err(|e| e.to_string())?;
    let mut capacity = 64usize;
    let mut groups = loop {
        let mut buf: Vec<libc::gid_t> = vec![0; capacity];
        let mut count = capacity as libc::c_int;
        // SAFETY: buf holds `count` entries. The casts cover macOS, which declares these
        // arguments as c_int where Linux has gid_t. The two have the same size.
        let rc = unsafe {
            libc::getgrouplist(
                c_name.as_ptr(),
                gid as _,
                buf.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if rc >= 0 {
            buf.truncate(count as usize);
            break buf;
        }
        if capacity >= MAX_GROUP_LOOKUP {
            return Err(format!("more than {MAX_GROUP_LOOKUP} groups"));
        }
        capacity = (capacity * 2).max(count.max(0) as usize);
    };
    groups.retain(|g| *g != gid);
    groups.insert(0, gid);
    // setgroups(2) on macOS refuses more than NGROUPS_MAX (16). Dropping the extras is
    // what initgroups(3) does there.
    #[cfg(target_vendor = "apple")]
    groups.truncate(16);
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_resolves_to_no_target() {
        assert!(RunAsTarget::resolve("root").unwrap().is_none());
    }

    #[test]
    fn unknown_and_unrepresentable_names_are_errors() {
        for name in ["no-such-user-2799", "", "nobody\n", "a\0b"] {
            let err = RunAsTarget::resolve(name).unwrap_err();
            assert!(err.contains("unknown user"), "{name:?}: {err}");
        }
    }

    #[test]
    fn a_real_account_resolves_with_its_primary_group_first() {
        let target = RunAsTarget::resolve("nobody").unwrap().unwrap();
        let passwd = nix::unistd::User::from_name("nobody").unwrap().unwrap();
        assert_eq!(target.name, "nobody");
        assert_eq!(target.uid, passwd.uid.as_raw());
        assert_eq!(target.gid, passwd.gid.as_raw());
        assert_eq!(target.groups.first(), Some(&passwd.gid.as_raw()));
    }
}
