use std::{collections::HashSet, env, net::SocketAddr, path::PathBuf};
use zeroize::Zeroizing;

// Deliberately no Debug: configuration contains an OAuth client secret.
pub struct Config {
    pub bind: SocketAddr,
    pub database: PathBuf,
    pub github_client_id: String,
    pub github_client_secret: Zeroizing<String>,
    pub allowed_origins: HashSet<String>,
    pub allowed_github_ids: HashSet<String>,
    pub public_access: bool,
    pub require_https_proxy: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, &'static str> {
        let bind: SocketAddr = env::var("SYNC_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8787".into())
            .parse()
            .map_err(|_| "invalid SYNC_BIND")?;
        if !bind.ip().is_loopback() {
            return Err("SYNC_BIND must be loopback; expose only the HTTPS proxy");
        }
        let client_id =
            env::var("SYNC_GITHUB_CLIENT_ID").map_err(|_| "SYNC_GITHUB_CLIENT_ID is required")?;
        if client_id.is_empty()
            || client_id.contains("REPLACE_WITH")
            || client_id.len() > 128
            || !client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        {
            return Err("invalid SYNC_GITHUB_CLIENT_ID");
        }
        let secret = Zeroizing::new(
            env::var("SYNC_GITHUB_CLIENT_SECRET")
                .map_err(|_| "SYNC_GITHUB_CLIENT_SECRET is required")?,
        );
        if secret.len() < 20
            || secret.contains("REPLACE_WITH")
            || secret.chars().any(char::is_whitespace)
        {
            return Err("invalid SYNC_GITHUB_CLIENT_SECRET");
        }
        let allowed_github_ids = list("SYNC_ALLOWED_GITHUB_IDS");
        for id in &allowed_github_ids {
            if crate::protocol::revision(id).map_err(|_| "invalid allowed GitHub ID")? == 0 {
                return Err("invalid allowed GitHub ID");
            }
        }
        let mode = env::var("SYNC_ACCESS_MODE").unwrap_or_else(|_| "restricted".into());
        if mode != "restricted" && mode != "public" {
            return Err("invalid SYNC_ACCESS_MODE");
        }
        let development = env::var("SYNC_ALLOW_LOCAL_HTTP").unwrap_or_else(|_| "false".into());
        if development != "true" && development != "false" {
            return Err("invalid SYNC_ALLOW_LOCAL_HTTP");
        }
        let allowed_origins = list("SYNC_ALLOWED_ORIGINS");
        for origin in &allowed_origins {
            let url = reqwest::Url::parse(origin).map_err(|_| "invalid allowed Origin")?;
            if url.scheme() != "https" || url.origin().ascii_serialization() != *origin {
                return Err("Origin must be an exact HTTPS origin");
            }
        }
        Ok(Self {
            bind,
            database: env::var("SYNC_DATABASE")
                .unwrap_or_else(|_| "data/sync.db".into())
                .into(),
            github_client_id: client_id,
            github_client_secret: secret,
            allowed_origins,
            allowed_github_ids,
            public_access: mode == "public",
            require_https_proxy: development != "true",
        })
    }
}

fn list(name: &str) -> HashSet<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
