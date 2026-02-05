use serde::Deserialize;
use std::path::{Path, PathBuf};
use toml::Value;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    #[serde(default = "default_http_bind")]
    pub http_bind: String,

    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    #[serde(default)]
    pub allowlist: Vec<String>,

    pub telegram: Option<TelegramConfig>,

    #[serde(default = "default_limits")]
    pub limits: LimitsConfig,
}

#[derive(Debug, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: i64,

    #[serde(default = "default_poll_timeout")]
    pub poll_timeout_seconds: u32,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/aisudo/aisudo.sock")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/aisudo/aisudo.db")
}

fn default_http_bind() -> String {
    "127.0.0.1:7654".to_string()
}

fn default_timeout() -> u32 {
    60
}

fn default_poll_timeout() -> u32 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_stdin")]
    pub max_stdin_bytes: usize,

    #[serde(default = "default_stdin_preview")]
    pub stdin_preview_bytes: usize,
}

fn default_max_stdin() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_stdin_preview() -> usize {
    2048
}

fn default_limits() -> LimitsConfig {
    LimitsConfig {
        max_stdin_bytes: default_max_stdin(),
        stdin_preview_bytes: default_stdin_preview(),
    }
}

/// Recursively deep-merge two TOML values. Overlay wins for scalars.
/// For the `allowlist` key, arrays are appended and deduplicated.
fn merge_toml_values(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Table(mut base_table), Value::Table(overlay_table)) => {
            for (key, overlay_val) in overlay_table {
                let merged = if let Some(base_val) = base_table.remove(&key) {
                    if key == "allowlist" {
                        merge_allowlist(base_val, overlay_val)
                    } else {
                        merge_toml_values(base_val, overlay_val)
                    }
                } else {
                    overlay_val
                };
                base_table.insert(key, merged);
            }
            Value::Table(base_table)
        }
        (_base, overlay) => overlay,
    }
}

/// Merge two allowlist arrays: concatenate and deduplicate, preserving order.
fn merge_allowlist(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Array(mut base_arr), Value::Array(overlay_arr)) => {
            for item in overlay_arr {
                if !base_arr.contains(&item) {
                    base_arr.push(item);
                }
            }
            Value::Array(base_arr)
        }
        (_base, overlay) => overlay,
    }
}

/// Load all `*.toml` files from `conf.d/` next to the main config file.
/// Returns an empty vec if the directory does not exist.
fn load_conf_d(config_path: &Path) -> anyhow::Result<Vec<(String, Value)>> {
    let conf_d = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("conf.d");

    if !conf_d.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&conf_d)
        .map_err(|e| anyhow::anyhow!("cannot read conf.d directory '{}': {}", conf_d.display(), e))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            // Skip non-files, hidden files, and non-.toml files
            if !path.is_file() {
                return None;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || !name.ends_with(".toml") {
                return None;
            }
            Some((name, path))
        })
        .collect();

    // Sort alphabetically by filename for deterministic ordering
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut results = Vec::new();
    for (name, path) in entries {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read drop-in config '{}': {}", path.display(), e))?;
        let value: Value = content.parse()
            .map_err(|e| anyhow::anyhow!("invalid TOML in drop-in '{}': {}", name, e))?;
        results.push((name, value));
    }

    Ok(results)
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let config_path = Path::new(path);

        let content = std::fs::read_to_string(config_path)
            .map_err(|e| anyhow::anyhow!("cannot read config file '{}': {}", path, e))?;
        let mut base: Value = content.parse()
            .map_err(|e| anyhow::anyhow!("invalid config in '{}': {}", path, e))?;

        let dropins = load_conf_d(config_path)?;
        for (name, overlay) in &dropins {
            tracing::info!("loaded drop-in config: conf.d/{}", name);
            base = merge_toml_values(base, overlay.clone());
        }

        let config: Config = base.try_into()
            .map_err(|e| anyhow::anyhow!("invalid config after merging drop-ins: {}", e))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Write a main config and return its path string.
    fn write_main_config(dir: &Path, content: &str) -> String {
        let path = dir.join("aisudo.toml");
        fs::write(&path, content).unwrap();
        path.to_string_lossy().to_string()
    }

    const BASE_CONFIG: &str = r#"
socket_path = "/tmp/test.sock"
db_path = "/tmp/test.db"
http_bind = "127.0.0.1:9999"
timeout_seconds = 30
allowlist = ["apt list", "systemctl status"]

[telegram]
bot_token = "token123"
chat_id = 42

[limits]
max_stdin_bytes = 1024
"#;

    #[test]
    fn no_conf_d_directory() {
        let tmp = TempDir::new().unwrap();
        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.allowlist, vec!["apt list", "systemctl status"]);
    }

    #[test]
    fn empty_conf_d_directory() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("conf.d")).unwrap();
        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn scalar_override_from_dropin() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        fs::write(conf_d.join("override.toml"), "timeout_seconds = 120\n").unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.timeout_seconds, 120);
        // Other fields unchanged
        assert_eq!(config.http_bind, "127.0.0.1:9999");
    }

    #[test]
    fn allowlist_merge_and_dedup() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        fs::write(
            conf_d.join("allowlist.toml"),
            r#"allowlist = ["apt list", "docker ps", "ls -la"]"#,
        )
        .unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        // "apt list" appears in both but should only appear once
        assert_eq!(
            config.allowlist,
            vec!["apt list", "systemctl status", "docker ps", "ls -la"]
        );
    }

    #[test]
    fn nested_table_merge() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        // Only override chat_id within [telegram], leave bot_token intact
        fs::write(
            conf_d.join("telegram.toml"),
            "[telegram]\nchat_id = 999\n",
        )
        .unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        let tg = config.telegram.unwrap();
        assert_eq!(tg.chat_id, 999);
        assert_eq!(tg.bot_token, "token123");
    }

    #[test]
    fn sort_order_deterministic() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        // 01 sets timeout to 100, 99 overrides to 200
        fs::write(conf_d.join("01-first.toml"), "timeout_seconds = 100\n").unwrap();
        fs::write(conf_d.join("99-last.toml"), "timeout_seconds = 200\n").unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.timeout_seconds, 200);
    }

    #[test]
    fn invalid_toml_in_dropin_errors_with_filename() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        fs::write(conf_d.join("bad.toml"), "this is not valid toml {{{").unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let err = Config::load(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bad.toml"), "error should mention filename: {}", msg);
    }

    #[test]
    fn hidden_files_and_non_toml_skipped() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        // These should all be ignored
        fs::write(conf_d.join(".hidden.toml"), "timeout_seconds = 999\n").unwrap();
        fs::write(conf_d.join("readme.txt"), "timeout_seconds = 999\n").unwrap();
        fs::write(conf_d.join("notes.md"), "timeout_seconds = 999\n").unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.timeout_seconds, 30); // unchanged from base
    }

    #[test]
    fn merge_toml_values_overlay_wins_for_non_tables() {
        let base: Value = "hello".into();
        let overlay: Value = "world".into();
        assert_eq!(merge_toml_values(base, overlay), Value::String("world".into()));
    }

    #[test]
    fn limits_partial_override() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir(&conf_d).unwrap();
        fs::write(
            conf_d.join("limits.toml"),
            "[limits]\nstdin_preview_bytes = 4096\n",
        )
        .unwrap();

        let path = write_main_config(tmp.path(), BASE_CONFIG);
        let config = Config::load(&path).unwrap();
        assert_eq!(config.limits.max_stdin_bytes, 1024); // from base
        assert_eq!(config.limits.stdin_preview_bytes, 4096); // from drop-in
    }
}
