//! `sudo -u <user>` through the real connection handler (#2799).
//!
//! The rule tests use dry runs, so they run unprivileged. The tests marked `#[ignore]`
//! need root, because only root can change user:
//!   sudo <test binary> run_as_root --ignored --test-threads=1

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

/// Stands in for the approver: answers with `decision` and keeps what it was shown.
struct Approver {
    decision: Decision,
    asked: Mutex<Vec<SudoRequestRecord>>,
}

impl Approver {
    fn new(decision: Decision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            asked: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl NotificationBackend for Approver {
    async fn send_and_wait(&self, record: &SudoRequestRecord) -> anyhow::Result<Decision> {
        self.asked.lock().unwrap().push(record.clone());
        Ok(self.decision)
    }
    async fn send_temp_rule_and_wait(&self, _: &TempRuleRecord) -> anyhow::Result<Decision> {
        anyhow::bail!("not used")
    }
    async fn send_bw_request_and_wait(&self, _: &BwRequestRecord) -> anyhow::Result<Decision> {
        anyhow::bail!("not used")
    }
    async fn send_bw_confirm_and_wait(&self, _: &BwConfirmRecord) -> anyhow::Result<Decision> {
        anyhow::bail!("not used")
    }
    async fn send_bw_locked_notification(&self, _: &BwRequestRecord) -> anyhow::Result<()> {
        Ok(())
    }
    async fn send_access_link(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn send_scrub_complete(&self, _: &str, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn update_completion_status(&self, _: &crate::notification::CompletionInfo) {}
    fn name(&self) -> &'static str {
        "approver"
    }
}

fn limits() -> LimitsConfig {
    LimitsConfig {
        max_stdin_bytes: 1024,
        stdin_preview_bytes: 64,
        max_temp_rule_duration_seconds: 3600,
        rate_limit_requests: 1000,
        rate_limit_window_seconds: 60,
        rate_limit_count_allowlisted: false,
        rate_limit_mode: RateLimitMode::PerUser,
        check_binary_ownership: BinaryOwnershipCheck::Off,
        allowed_binary_owners: Vec::new(),
        strip_shell_prefix: false,
        history_retention_days: 365,
    }
}

fn me() -> String {
    resolve_username(nix::unistd::getuid().as_raw()).unwrap()
}

#[derive(Default, Clone)]
struct Rules {
    allowlist: Vec<String>,
    denylist: Vec<String>,
    per_user: HashMap<String, Vec<String>>,
    run_as: HashMap<String, Vec<String>>,
}

fn request(command: &str, run_as: Option<&str>, dry_run: bool) -> SudoRequest {
    SudoRequest {
        user: me(),
        command: command.to_string(),
        cwd: "/".to_string(),
        pid: 1,
        mode: if run_as.is_some() {
            RequestMode::ExecAs
        } else {
            RequestMode::Exec
        },
        reason: None,
        stdin: None,
        skip_nopasswd: false,
        timeout_seconds: None,
        dry_run,
        wants_status: false,
        run_as: run_as.map(str::to_string),
    }
}

struct Daemon {
    db: Arc<Database>,
    approver: Arc<Approver>,
    sudoers: Arc<SudoersCache>,
    rules: Rules,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn new(rules: Rules, decision: Decision) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Database::open(&dir.path().join("t.db")).unwrap());
        Self {
            db,
            approver: Approver::new(decision),
            sudoers: Arc::new(SudoersCache::new(3600)),
            rules,
            _dir: dir,
        }
    }

    /// Send one request and return every line the daemon wrote.
    async fn send(&self, req: &SudoRequest) -> Vec<String> {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (db, approver, sudoers, rules) = (
            Arc::clone(&self.db),
            Arc::clone(&self.approver),
            Arc::clone(&self.sudoers),
            self.rules.clone(),
        );
        let handler = tokio::spawn(async move {
            handle_connection(
                server,
                db,
                approver,
                sudoers,
                60,
                &rules.allowlist,
                &rules.denylist,
                &rules.per_user,
                &AllowlistArgs::new(),
                &rules.run_as,
                limits(),
                None,
            )
            .await
        });
        let (reader, mut writer) = client.into_split();
        let mut json = serde_json::to_string(req).unwrap();
        json.push('\n');
        writer.write_all(json.as_bytes()).await.unwrap();
        let mut raw = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            BufReader::new(reader).read_to_string(&mut raw),
        )
        .await
        .expect("daemon did not finish")
        .unwrap();
        drop(writer);
        let _ = handler.await;
        raw.lines().map(str::to_string).collect()
    }

    /// What a dry run decides for this request.
    async fn decide(&self, command: &str, run_as: Option<&str>) -> SudoResponse {
        let lines = self.send(&request(command, run_as, true)).await;
        serde_json::from_str(lines.last().expect("no reply")).unwrap()
    }

    fn asked(&self) -> Vec<SudoRequestRecord> {
        self.approver.asked.lock().unwrap().clone()
    }
}

/// Auto-approved by the daemon, with no human involved.
fn auto(resp: &SudoResponse) -> bool {
    matches!(resp.decision, Decision::Approved | Decision::UseSudo)
}

fn would_ask(resp: &SudoResponse) -> bool {
    resp.decision == Decision::Denied
        && resp.error.as_deref() == Some("dry-run: would require approval")
}

fn one_rule(user: &str, pattern: &str) -> HashMap<String, Vec<String>> {
    HashMap::from([(user.to_string(), vec![pattern.to_string()])])
}

// ---- requirement 3: -u cannot bypass the allowlist ------------------------------------

#[tokio::test]
async fn a_root_allowlist_entry_does_not_approve_another_user() {
    let d = Daemon::new(
        Rules {
            allowlist: vec!["apt list".into()],
            ..Rules::default()
        },
        Decision::Denied,
    );
    assert!(auto(&d.decide("apt list", None).await), "control: root");
    let resp = d.decide("apt list", Some("nobody")).await;
    assert!(would_ask(&resp), "{resp:?}");
}

#[tokio::test]
async fn a_per_user_allowlist_entry_does_not_approve_another_user() {
    let d = Daemon::new(
        Rules {
            per_user: one_rule(&me(), "apt list"),
            ..Rules::default()
        },
        Decision::Denied,
    );
    assert!(auto(&d.decide("apt list", None).await), "control: root");
    let resp = d.decide("apt list", Some("nobody")).await;
    assert!(would_ask(&resp), "{resp:?}");
}

#[tokio::test]
async fn a_run_as_rule_covers_exactly_its_user() {
    let d = Daemon::new(
        Rules {
            run_as: one_rule("nobody", "apt list"),
            ..Rules::default()
        },
        Decision::Denied,
    );
    let yes = d.decide("apt list --installed", Some("nobody")).await;
    assert_eq!(
        yes.decision,
        Decision::Approved,
        "the rule says so: {yes:?}"
    );

    // The reverse direction: not as root, spelled either way.
    let root = d.decide("apt list", None).await;
    assert!(would_ask(&root), "as root: {root:?}");
    let root = d.decide("apt list", Some("root")).await;
    assert!(would_ask(&root), "as -u root: {root:?}");
    // Not as a third user, and not as the requester.
    let other = d.decide("apt list", Some("daemon")).await;
    assert!(would_ask(&other), "as daemon: {other:?}");
    if me() != "nobody" {
        let requester = d.decide("apt list", Some(&me())).await;
        assert!(would_ask(&requester), "as the requester: {requester:?}");
    }
    // The pattern still has to match.
    let wrong = d.decide("apt install vim", Some("nobody")).await;
    assert!(would_ask(&wrong), "other command: {wrong:?}");
}

#[tokio::test]
async fn a_temp_rule_does_not_approve_another_user() {
    let d = Daemon::new(Rules::default(), Decision::Denied);
    let now = chrono::Utc::now();
    d.db.insert_temp_rule(
        "r1",
        &me(),
        &serde_json::to_string(&["apt list"]).unwrap(),
        3600,
        &now.to_rfc3339(),
        &(now + chrono::Duration::seconds(3600)).to_rfc3339(),
        "n1",
        None,
    )
    .unwrap();
    d.db.update_temp_rule_decision("r1", Decision::Approved, "test")
        .unwrap();
    assert!(auto(&d.decide("apt list", None).await), "control: root");
    let resp = d.decide("apt list", Some("nobody")).await;
    assert!(would_ask(&resp), "{resp:?}");
}

#[tokio::test]
async fn a_nopasswd_rule_does_not_approve_another_user() {
    let d = Daemon::new(Rules::default(), Decision::Denied);
    d.sudoers.seed_for_test(&me(), "ALL");
    let root = d.decide("apt list", None).await;
    assert_eq!(root.decision, Decision::UseSudo, "control: {root:?}");
    let resp = d.decide("apt list", Some("nobody")).await;
    assert!(would_ask(&resp), "{resp:?}");
}

#[tokio::test]
async fn the_denylist_beats_a_run_as_rule() {
    let d = Daemon::new(
        Rules {
            denylist: vec!["apt list".into()],
            run_as: one_rule("nobody", "apt list"),
            ..Rules::default()
        },
        Decision::Approved,
    );
    let resp = d.decide("apt list", Some("nobody")).await;
    assert_eq!(resp.decision, Decision::Denied);
    assert_eq!(resp.error.as_deref(), Some("command is on denylist"));
}

#[tokio::test]
async fn dash_u_root_is_a_plain_root_request() {
    let d = Daemon::new(
        Rules {
            allowlist: vec!["apt list".into()],
            ..Rules::default()
        },
        Decision::Denied,
    );
    assert_eq!(
        d.decide("apt list", Some("root")).await.decision,
        Decision::Approved
    );
}

#[tokio::test]
async fn an_unknown_user_is_refused_without_asking_anyone() {
    let d = Daemon::new(Rules::default(), Decision::Approved);
    let lines = d
        .send(&request("apt list", Some("no-such-user-2799"), false))
        .await;
    let resp: SudoResponse = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(resp.decision, Decision::Denied);
    assert!(resp.error.unwrap().contains("unknown user"));
    assert!(d.asked().is_empty());
}

#[tokio::test]
async fn exec_as_without_a_target_is_refused_rather_than_run_as_root() {
    let d = Daemon::new(
        Rules {
            allowlist: vec!["apt list".into()],
            ..Rules::default()
        },
        Decision::Approved,
    );
    let mut req = request("apt list", None, false);
    req.mode = RequestMode::ExecAs;
    let lines = d.send(&req).await;
    let resp: SudoResponse = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(resp.decision, Decision::Denied);
    assert!(resp.error.unwrap().contains("exec-as"));
}

// ---- requirement 2: the approver and the audit DB see the target ----------------------

#[tokio::test]
async fn the_approver_and_the_audit_db_see_the_target() {
    // Denied, so nothing runs and the test needs no privilege.
    let d = Daemon::new(Rules::default(), Decision::Denied);
    d.send(&request("touch /x", Some("nobody"), false)).await;

    let asked = d.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].run_as.as_deref(), Some("nobody"));
    let question = crate::notification::askgw_sudo_question(&asked[0]);
    assert!(question.starts_with("Run as nobody?"), "{question}");

    let row = d.db.get_request(&asked[0].id).unwrap().unwrap();
    assert_eq!(row.run_as.as_deref(), Some("nobody"));
    let history = d.db.get_history(&me(), 10).unwrap();
    assert_eq!(history[0].run_as.as_deref(), Some("nobody"));
    assert_eq!(d.db.audit_details_for_test(&asked[0].id).len(), 2);
    assert!(d.db.audit_details_for_test(&asked[0].id)[0].contains(" run_as=nobody "));
}

#[tokio::test]
async fn the_audit_db_sees_the_target_on_the_auto_approved_path_too() {
    let d = Daemon::new(
        Rules {
            run_as: one_rule(&me(), "true"),
            ..Rules::default()
        },
        Decision::Denied,
    );
    if nix::unistd::geteuid().is_root() {
        return; // me() is root, so -u collapses to a root request.
    }
    d.send(&request("true", Some(&me()), false)).await;
    let history = d.db.get_history(&me(), 10).unwrap();
    assert_eq!(history[0].run_as.as_deref(), Some(me().as_str()));
    assert_eq!(history[0].decided_by.as_deref(), Some("allowlist"));
}

#[tokio::test]
async fn a_root_request_records_no_target() {
    let d = Daemon::new(Rules::default(), Decision::Denied);
    d.send(&request("touch /x", None, false)).await;
    let asked = d.asked();
    assert_eq!(asked[0].run_as, None);
    assert!(crate::notification::askgw_sudo_question(&asked[0]).starts_with("Run as root?"));
    assert_eq!(
        d.db.get_request(&asked[0].id).unwrap().unwrap().run_as,
        None
    );
    assert!(!d.db.audit_details_for_test(&asked[0].id)[0].contains("run_as"));
}

// ---- requirement 1: what the child actually is ----------------------------------------

/// Split the daemon's frames into (stdout, stderr, exit code).
fn frames(lines: &[String]) -> (String, String, Option<i32>) {
    let (mut out, mut err, mut code) = (String::new(), String::new(), None);
    for frame in lines
        .iter()
        .filter_map(|l| serde_json::from_str::<ExecOutput>(l).ok())
    {
        match frame.stream.as_str() {
            "stdout" => out.push_str(&frame.data),
            "stderr" => err.push_str(&frame.data),
            "exit" => code = frame.exit_code,
            _ => {}
        }
    }
    (out, err, code)
}

/// As a user the daemon cannot become, the command must not run at all. It must not fall
/// through and run as the daemon's own user, and the client must be told.
#[tokio::test]
async fn a_failed_user_change_runs_nothing_and_says_why() {
    if nix::unistd::geteuid().is_root() {
        return; // Root can become anyone: run_as_root_* covers that.
    }
    let dir = tempfile::TempDir::new().unwrap();
    let marker = dir.path().join("ran");
    let command = format!("touch {}", marker.display());
    for (rules, decision, what) in [
        (
            Rules {
                run_as: one_rule("nobody", "touch"),
                ..Rules::default()
            },
            Decision::Denied,
            "auto-approved path",
        ),
        (Rules::default(), Decision::Approved, "human-approved path"),
    ] {
        let d = Daemon::new(rules, decision);
        let lines = d.send(&request(&command, Some("nobody"), false)).await;
        let (_, err, code) = frames(&lines);
        assert!(!marker.exists(), "{what}: the command ran");
        assert!(err.contains("could not start"), "{what}: {err:?}");
        assert_ne!(code, Some(0), "{what}");
    }
}

/// The target's identity variables, and none of the daemon's other environment.
#[tokio::test]
async fn the_child_gets_the_targets_environment_not_the_daemons() {
    if nix::unistd::geteuid().is_root() {
        return; // me() is root, so -u collapses to a root request.
    }
    let d = Daemon::new(
        Rules {
            allowlist: vec!["env".into()],
            run_as: one_rule(&me(), "env"),
            ..Rules::default()
        },
        Decision::Denied,
    );
    // cargo sets this for the test process. It stands in for the daemon's environment.
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let (root, _, _) = frames(&d.send(&request("env", None, false)).await);
    assert!(root.contains("CARGO_MANIFEST_DIR="), "control: {root}");

    let (out, _, code) = frames(&d.send(&request("env", Some(&me()), false)).await);
    assert_eq!(code, Some(0));
    let vars: HashMap<&str, &str> = out.lines().filter_map(|l| l.split_once('=')).collect();
    let account = nix::unistd::User::from_name(&me()).unwrap().unwrap();
    assert_eq!(vars["USER"], me());
    assert_eq!(vars["LOGNAME"], me());
    assert_eq!(vars["HOME"], account.dir.to_str().unwrap());
    assert_eq!(vars["SUDO_USER"], me());
    assert!(!out.contains("CARGO_MANIFEST_DIR="), "{out}");
}

/// A descriptor the daemon left inheritable must not reach the target.
#[tokio::test]
async fn the_child_inherits_no_stray_descriptor() {
    if nix::unistd::geteuid().is_root() {
        return; // me() is root, so -u collapses to a root request.
    }
    let d = Daemon::new(
        Rules {
            allowlist: vec!["ls".into()],
            run_as: one_rule(&me(), "ls"),
            ..Rules::default()
        },
        Decision::Denied,
    );
    const STRAY: i32 = 200;
    let (r, _w) = nix::unistd::pipe().unwrap();
    // SAFETY: dup2 onto a number nothing else in this test binary reaches. dup2 clears
    // CLOEXEC, as the daemon's pipeline pipes never have it set.
    assert_eq!(
        unsafe { nix::libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&r), STRAY) },
        STRAY
    );
    let (root, _, _) = frames(&d.send(&request("ls /dev/fd/", None, false)).await);
    let (target, _, code) = frames(&d.send(&request("ls /dev/fd/", Some(&me()), false)).await);
    unsafe { nix::libc::close(STRAY) };
    assert!(root.lines().any(|l| l == "200"), "control: {root}");
    assert_eq!(code, Some(0));
    assert!(!target.lines().any(|l| l == "200"), "{target}");
}

#[tokio::test]
async fn a_directory_the_target_cannot_enter_stops_the_command() {
    if nix::unistd::geteuid().is_root() {
        return; // Root enters anything: run_as_root_* covers that.
    }
    let d = Daemon::new(
        Rules {
            run_as: one_rule(&me(), "true"),
            ..Rules::default()
        },
        Decision::Denied,
    );
    let mut req = request("true", Some(&me()), false);
    req.cwd = "/nonexistent-2799".to_string();
    let (_, err, code) = frames(&d.send(&req).await);
    assert!(err.contains("could not start"), "{err}");
    assert_ne!(code, Some(0));
}

// ---- needs root ------------------------------------------------------------------------

/// The user whose identity the root tests check. Set AISUDO_TEST_TARGET to a user with
/// supplementary groups to exercise those too.
fn root_test_target() -> nix::unistd::User {
    let name = std::env::var("AISUDO_TEST_TARGET").unwrap_or_else(|_| "nobody".to_string());
    nix::unistd::User::from_name(&name).unwrap().unwrap()
}

fn sorted_groups(text: &str) -> Vec<u32> {
    let mut groups: Vec<u32> = text
        .split_whitespace()
        .map(|g| g.parse().unwrap())
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}

fn expected_groups(user: &nix::unistd::User) -> Vec<u32> {
    let target = RunAsTarget::resolve(&user.name).unwrap().unwrap();
    let mut groups = target.groups_for_test().to_vec();
    groups.sort_unstable();
    groups.dedup();
    groups
}

/// All three exec paths: argv, chain and pipeline, and the human-approved shell.
#[tokio::test]
#[ignore = "needs root"]
async fn run_as_root_changes_user_on_every_exec_path() {
    assert!(nix::unistd::geteuid().is_root(), "run this one as root");
    let user = root_test_target();
    let name = user.name.clone();
    let uid = user.uid.as_raw().to_string();

    let auto = Daemon::new(
        Rules {
            allowlist: vec!["id".into()],
            run_as: one_rule(&name, "id"),
            ..Rules::default()
        },
        Decision::Denied,
    );

    // Control: the same command without -u is root, so this test can tell them apart.
    let (out, _, _) = frames(&auto.send(&request("id -u", None, false)).await);
    assert_eq!(out.trim(), "0", "control");

    let (out, err, code) = frames(&auto.send(&request("id -u", Some(&name), false)).await);
    assert_eq!((out.trim(), code), (uid.as_str(), Some(0)), "argv: {err}");

    let (out, _, code) = frames(
        &auto
            .send(&request("id -ru ; id -g", Some(&name), false))
            .await,
    );
    let want = format!("{uid}\n{}\n", user.gid.as_raw());
    assert_eq!((out.as_str(), code), (want.as_str(), Some(0)), "chain");

    let piped = Daemon::new(
        Rules {
            run_as: HashMap::from([(name.clone(), vec!["id".into(), "cat".into()])]),
            ..Rules::default()
        },
        Decision::Denied,
    );
    let (out, _, code) = frames(
        &piped
            .send(&request("id -u | cat", Some(&name), false))
            .await,
    );
    assert_eq!((out.trim(), code), (uid.as_str(), Some(0)), "pipeline");

    let human = Daemon::new(Rules::default(), Decision::Approved);
    let (out, err, code) = frames(
        &human
            .send(&request("id -u; id -ru; id -G", Some(&name), false))
            .await,
    );
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some(uid.as_str()), "shell: {err}");
    assert_eq!(lines.next(), Some(uid.as_str()), "shell, real uid");
    assert_eq!(
        sorted_groups(lines.next().unwrap()),
        expected_groups(&user),
        "shell, groups"
    );
    assert_eq!(code, Some(0));
    assert_eq!(human.asked()[0].run_as.as_deref(), Some(name.as_str()));
}

/// Real, effective and saved ids all change, so the child cannot climb back to root.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root"]
async fn run_as_root_leaves_no_way_back() {
    assert!(nix::unistd::geteuid().is_root(), "run this one as root");
    let user = root_test_target();
    let d = Daemon::new(Rules::default(), Decision::Approved);
    let (status, _, _) = frames(
        &d.send(&request("cat /proc/self/status", Some(&user.name), false))
            .await,
    );
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let uid = user.uid.as_raw().to_string();
    let gid = user.gid.as_raw().to_string();
    assert_eq!(field("Uid:"), [uid.as_str(); 4], "{status}");
    assert_eq!(field("Gid:"), [gid.as_str(); 4], "{status}");
    assert_eq!(field("CapEff:"), ["0000000000000000"], "{status}");
    assert_eq!(field("CapPrm:"), ["0000000000000000"], "{status}");
    assert_eq!(
        sorted_groups(&field("Groups:").join(" ")),
        expected_groups(&user)
    );
}

/// The directory comes from the client. Root could enter it; the target must not get in.
#[tokio::test]
#[ignore = "needs root"]
async fn run_as_root_does_not_enter_a_directory_for_the_target() {
    use std::os::unix::fs::PermissionsExt;
    assert!(nix::unistd::geteuid().is_root(), "run this one as root");
    let user = root_test_target();
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let d = Daemon::new(Rules::default(), Decision::Approved);
    let mut req = request("id -u", Some(&user.name), false);
    req.cwd = dir.path().to_str().unwrap().to_string();
    let (out, err, code) = frames(&d.send(&req).await);
    assert_eq!(out, "", "the command ran");
    assert!(err.contains("could not start"), "{err}");
    assert_ne!(code, Some(0));

    // Control: the same directory as root works.
    let mut req = request("id -u", None, false);
    req.cwd = dir.path().to_str().unwrap().to_string();
    let (out, _, code) = frames(&d.send(&req).await);
    assert_eq!((out.trim(), code), ("0", Some(0)));
}
