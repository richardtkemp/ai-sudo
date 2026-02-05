use dashmap::DashMap;
use std::time::Instant;
use tracing::{debug, warn};

/// A parsed NOPASSWD rule from sudoers.
#[derive(Debug, Clone)]
pub struct NopasswdRule {
    /// The command spec, e.g. "/usr/bin/apt", "ALL", "/usr/bin/systemctl restart *"
    pub command_spec: String,
}

/// Caches parsed NOPASSWD rules per user with a TTL.
pub struct SudoersCache {
    /// Map from username to (fetch_time, rules).
    cache: DashMap<String, (Instant, Vec<NopasswdRule>)>,
    ttl_seconds: u64,
}

impl SudoersCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            cache: DashMap::new(),
            ttl_seconds,
        }
    }

    /// Get NOPASSWD rules for a user, refreshing cache if stale.
    fn get_rules(&self, user: &str) -> Vec<NopasswdRule> {
        if let Some(entry) = self.cache.get(user) {
            let (fetched_at, rules) = entry.value();
            if fetched_at.elapsed().as_secs() < self.ttl_seconds {
                return rules.clone();
            }
        }

        let rules = parse_sudo_l(user);
        self.cache
            .insert(user.to_string(), (Instant::now(), rules.clone()));
        rules
    }

    /// Check if a command is allowed by a NOPASSWD rule for the given user.
    pub fn is_nopasswd_allowed(&self, user: &str, command: &str) -> bool {
        let rules = self.get_rules(user);
        for rule in &rules {
            if matches_nopasswd_rule(&rule.command_spec, command) {
                debug!(
                    "NOPASSWD match for user={} command={:?} rule={:?}",
                    user, command, rule.command_spec
                );
                return true;
            }
        }
        false
    }

    /// Get the raw NOPASSWD rule specs for a user (for --list-rules display).
    pub fn get_nopasswd_rules(&self, user: &str) -> Vec<String> {
        self.get_rules(user)
            .into_iter()
            .map(|r| r.command_spec)
            .collect()
    }
}

/// Parse `sudo -l -U <user>` output, extracting NOPASSWD command specs.
///
/// Example output lines we care about:
/// ```text
///     (ALL : ALL) NOPASSWD: /usr/bin/apt, /usr/bin/dpkg
///     (root) NOPASSWD: ALL
///     (ALL : ALL) NOPASSWD: SETENV: /usr/bin/systemctl restart *
/// ```
fn parse_sudo_l(user: &str) -> Vec<NopasswdRule> {
    let output = match std::process::Command::new("sudo")
        .args(["-l", "-U", user])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to run sudo -l -U {user}: {e}");
            return Vec::new();
        }
    };

    if !output.status.success() {
        debug!(
            "sudo -l -U {user} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();

    for line in stdout.lines() {
        // sudoers privilege lines are indented with 4 spaces
        if !line.starts_with("    ") {
            continue;
        }

        // Must contain NOPASSWD
        if !line.contains("NOPASSWD:") {
            continue;
        }

        // Extract everything after the last NOPASSWD:
        let after_nopasswd = match line.rfind("NOPASSWD:") {
            Some(pos) => &line[pos + "NOPASSWD:".len()..],
            None => continue,
        };

        // Strip any remaining sudoers tags (SETENV:, NOEXEC:, etc.)
        let commands_part = strip_tags(after_nopasswd);

        // Split on commas for multiple commands
        for cmd in commands_part.split(',') {
            let cmd = cmd.trim();
            if !cmd.is_empty() {
                rules.push(NopasswdRule {
                    command_spec: cmd.to_string(),
                });
            }
        }
    }

    debug!("Parsed {} NOPASSWD rules for user {user}", rules.len());
    rules
}

/// Strip sudoers tags like SETENV:, NOEXEC:, etc. from a command spec string.
fn strip_tags(s: &str) -> String {
    let mut result = s.to_string();
    loop {
        let trimmed = result.trim_start();
        // Tags are uppercase letters followed by a colon
        if let Some(colon_pos) = trimmed.find(':') {
            let prefix = &trimmed[..colon_pos];
            if !prefix.is_empty()
                && prefix.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            {
                result = trimmed[colon_pos + 1..].to_string();
                continue;
            }
        }
        break;
    }
    result
}

/// Check if a command matches a NOPASSWD rule spec.
///
/// Rules can be:
/// - `ALL` — matches everything
/// - `/usr/bin/apt` — matches the exact binary (any args)
/// - `/usr/bin/apt install *` — matches binary + arg prefix with wildcard
/// - `/usr/bin/apt install vim` — matches exact binary + args
fn matches_nopasswd_rule(rule_spec: &str, command: &str) -> bool {
    if rule_spec == "ALL" {
        return true;
    }

    let command_parts: Vec<&str> = command.splitn(2, ' ').collect();
    let command_binary = command_parts[0];
    let command_args = command_parts.get(1).unwrap_or(&"");

    let rule_parts: Vec<&str> = rule_spec.splitn(2, ' ').collect();
    let rule_binary = rule_parts[0];
    let rule_args = rule_parts.get(1).map(|s| s.trim());

    // Resolve command binary to full path for comparison
    let resolved_binary = resolve_binary_path(command_binary);

    if resolved_binary != rule_binary {
        return false;
    }

    match rule_args {
        // No args in rule: any args allowed (sudoers semantics — bare path means any args)
        None => true,
        // Empty string means no args allowed
        Some("") => command_args.is_empty(),
        // Wildcard: any args allowed
        Some("*") => true,
        Some(rule_args_str) => {
            // Check for trailing wildcard
            if let Some(prefix) = rule_args_str.strip_suffix('*') {
                command_args.starts_with(prefix.trim_end())
            } else {
                // Exact args match
                *command_args == rule_args_str
            }
        }
    }
}

/// Resolve a binary name to its full path using `which`.
fn resolve_binary_path(binary: &str) -> String {
    // Already absolute
    if binary.starts_with('/') {
        return binary.to_string();
    }

    match std::process::Command::new("which").arg(binary).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => binary.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_tags() {
        assert_eq!(strip_tags(" SETENV: /usr/bin/apt"), " /usr/bin/apt");
        assert_eq!(
            strip_tags(" SETENV: NOEXEC: /usr/bin/apt"),
            " /usr/bin/apt"
        );
        assert_eq!(strip_tags(" /usr/bin/apt"), " /usr/bin/apt");
        assert_eq!(strip_tags(" ALL"), " ALL");
    }

    #[test]
    fn test_matches_all() {
        assert!(matches_nopasswd_rule("ALL", "apt install vim"));
        assert!(matches_nopasswd_rule("ALL", "rm -rf /"));
    }

    #[test]
    fn test_matches_exact_binary() {
        // Bare binary path means any args
        assert!(matches_nopasswd_rule("/usr/bin/apt", "/usr/bin/apt install vim"));
        assert!(matches_nopasswd_rule("/usr/bin/apt", "/usr/bin/apt"));
        assert!(!matches_nopasswd_rule("/usr/bin/apt", "/usr/bin/dpkg -l"));
    }

    #[test]
    fn test_matches_with_wildcard() {
        assert!(matches_nopasswd_rule(
            "/usr/bin/systemctl restart *",
            "/usr/bin/systemctl restart nginx"
        ));
        assert!(!matches_nopasswd_rule(
            "/usr/bin/systemctl restart *",
            "/usr/bin/systemctl stop nginx"
        ));
    }

    #[test]
    fn test_matches_exact_args() {
        assert!(matches_nopasswd_rule(
            "/usr/bin/systemctl restart nginx",
            "/usr/bin/systemctl restart nginx"
        ));
        assert!(!matches_nopasswd_rule(
            "/usr/bin/systemctl restart nginx",
            "/usr/bin/systemctl restart apache"
        ));
    }

    #[test]
    fn test_resolve_absolute_path() {
        assert_eq!(resolve_binary_path("/usr/bin/apt"), "/usr/bin/apt");
    }
}
