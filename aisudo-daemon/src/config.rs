use serde::Deserialize;
use std::path::PathBuf;

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

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file '{}': {}", path, e))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("invalid config in '{}': {}", path, e))?;
        Ok(config)
    }
}
