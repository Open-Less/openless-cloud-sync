#![allow(dead_code)]
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use openless_cloud_sync::{
    auth::{Account, IdentityVerifier, VerifyFuture},
    config::{Config, UsageMode},
    error::ApiError,
    protocol::{Snapshot, hash},
    server::{AppState, router},
    store::Store,
};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};
use tower::ServiceExt;

struct FakeGithub;
impl IdentityVerifier for FakeGithub {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        Box::pin(async move {
            let (id, login) = match token {
                "github-alice" => ("11", "alice"),
                "github-alice-renamed" => ("11", "new-name"),
                "github-bob" => ("22", "alice"),
                "wrong-app" => return Err(ApiError::new(StatusCode::FORBIDDEN, "wrong_oauth_app")),
                _ => return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated")),
            };
            Ok(Account {
                github_id: id.into(),
                login: login.into(),
            })
        })
    }
}
pub struct Fixture {
    pub app: Router,
    pub store: Store,
    pub dir: tempfile::TempDir,
}
impl Fixture {
    pub fn new() -> Self {
        Self::https(false)
    }
    pub fn https(require_https_proxy: bool) -> Self {
        Self::open(
            tempfile::tempdir().unwrap(),
            require_https_proxy,
            UsageMode::Enabled,
        )
    }
    pub fn reopen(self, usage_mode: UsageMode) -> Self {
        let Self { app, store, dir } = self;
        drop((app, store));
        Self::open(dir, false, usage_mode)
    }
    fn open(dir: tempfile::TempDir, require_https_proxy: bool, usage_mode: UsageMode) -> Self {
        let path = dir.path().join("sync.db");
        let store = Store::open(&path).unwrap();
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            database: path,
            github_client_id: "test-app".into(),
            github_client_secret: "fixture-secret-not-a-real-credential".to_owned().into(),
            allowed_origins: HashSet::from(["https://allowed.example".into()]),
            allowed_github_ids: HashSet::from(["11".into(), "22".into()]),
            public_access: false,
            require_https_proxy,
            usage_mode,
        };
        let app = router(Arc::new(AppState::new(
            config,
            store.clone(),
            Arc::new(FakeGithub),
        )));
        Self { app, store, dir }
    }
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(
                "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ));
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let json = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        assert_eq!(headers["cache-control"], "no-store");
        Reply {
            status,
            headers,
            body,
            json,
        }
    }
    pub async fn login(&self, github_token: &str) -> String {
        let reply = self
            .request("POST", "/v1/auth/github", Some(github_token), &[], vec![])
            .await;
        assert_eq!(reply.status, 200);
        reply.json["accessToken"].as_str().unwrap().into()
    }
    pub async fn meta(&self, token: &str) -> Reply {
        self.request("GET", "/v1/me/vault", Some(token), &[], vec![])
            .await
    }
    pub async fn put(&self, token: &str, tag: &str, value: &Value) -> Reply {
        self.request(
            "PUT",
            "/v1/me/vault/snapshot",
            Some(token),
            &[
                ("if-match", tag),
                ("idempotency-key", value["operationId"].as_str().unwrap()),
                ("content-type", "application/json"),
            ],
            serde_json::to_vec(value).unwrap(),
        )
        .await
    }
}
pub struct Reply {
    pub status: u16,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
    pub json: Value,
}
impl Reply {
    pub fn tag(&self) -> &str {
        self.headers["etag"].to_str().unwrap()
    }
    pub fn code(&self) -> &str {
        self.json["error"]["code"].as_str().unwrap()
    }
}
pub fn sample(owner: &str) -> Value {
    let ciphertext = vec![42; 65552];
    json!({"protocolVersion":1,"payloadSchemaVersion":1,"ownerGithubId":owner,
        "vaultId":uuid::Uuid::new_v4().to_string(),"keyId":uuid::Uuid::new_v4().to_string(),
        "baseRevision":"0","revision":"1","operationId":uuid::Uuid::new_v4().to_string(),"kind":"create",
        "cryptoProfile":"argon2id-xchacha20poly1305-v1",
        "kdf":{"name":"argon2id","version":19,"memoryKiB":65536,"iterations":3,"parallelism":4,"salt":URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())},
        "aead":"xchacha20poly1305-ietf","codec":"json-pad64k-v1","nonce":URL_SAFE_NO_PAD.encode([2;24]),
        "ciphertextSha256":hash(&ciphertext),"ciphertext":URL_SAFE_NO_PAD.encode(ciphertext)})
}
pub fn next(previous: &Value, nonce: u8, kind: &str) -> Value {
    let mut value = previous.clone();
    value["baseRevision"] = previous["revision"].clone();
    value["revision"] = (previous["revision"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        + 1)
    .to_string()
    .into();
    value["kind"] = kind.into();
    value["operationId"] = uuid::Uuid::new_v4().to_string().into();
    value["nonce"] = URL_SAFE_NO_PAD.encode([nonce; 24]).into();
    value
}
pub fn typed(value: &Value) -> Snapshot {
    serde_json::from_value(value.clone()).unwrap()
}

pub const FEATURE: &str = "/v1/features/service-usage";
pub const USAGE: &str = "/v1/me/vault/usage";
pub const USAGE_SNAPSHOT: &str = "/v1/me/vault/usage/snapshot";
pub const ROTATE: &str = "/v1/me/vault/usage/password-change";
pub const VAULT_SNAPSHOT: &str = "/v1/me/vault/snapshot";

impl Fixture {
    pub async fn usage_meta(&self, token: &str) -> Reply {
        self.request("GET", USAGE, Some(token), &[], vec![]).await
    }
    pub async fn usage_download(&self, token: &str, tag: &str) -> Reply {
        self.request(
            "GET",
            USAGE_SNAPSHOT,
            Some(token),
            &[("if-match", tag)],
            vec![],
        )
        .await
    }
    pub async fn usage_put(&self, token: &str, tag: &str, body: &Value) -> Reply {
        self.json_mutation(
            "PUT",
            USAGE_SNAPSHOT,
            token,
            tag,
            body["operationId"].as_str().unwrap(),
            body,
        )
        .await
    }
    pub async fn rotate(&self, token: &str, tag: &str, body: &Value) -> Reply {
        self.json_mutation(
            "PUT",
            ROTATE,
            token,
            tag,
            body["vaultSnapshot"]["operationId"].as_str().unwrap(),
            body,
        )
        .await
    }
    pub async fn operation(&self, token: &str, usage: bool, id: &Value) -> Reply {
        let prefix = if usage { USAGE } else { "/v1/me" };
        self.request(
            "GET",
            &format!("{prefix}/operations/{}", id.as_str().unwrap()),
            Some(token),
            &[],
            vec![],
        )
        .await
    }
    pub async fn json_mutation(
        &self,
        method: &str,
        path: &str,
        token: &str,
        tag: &str,
        id: &str,
        body: &Value,
    ) -> Reply {
        self.request(
            method,
            path,
            Some(token),
            &[
                ("if-match", tag),
                ("idempotency-key", id),
                ("content-type", "application/json"),
            ],
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }
}

pub fn usage_upload(vault: &Value, base: u64, nonce: u8) -> Value {
    let ciphertext = vec![87; 65_552];
    json!({"protocolVersion":1,"payloadSchemaVersion":1,"ownerGithubId":vault["ownerGithubId"],
           "vaultId":vault["vaultId"],"keyId":vault["keyId"],"baseRevision":base.to_string(),
           "revision":(base+1).to_string(),"operationId":uuid::Uuid::new_v4().to_string(),
           "aead":"xchacha20poly1305-ietf","codec":"json-pad64k-v1","nonce":URL_SAFE_NO_PAD.encode([nonce;24]),
           "ciphertextSha256":hash(&ciphertext),"ciphertext":URL_SAFE_NO_PAD.encode(ciphertext)})
}

pub fn rekey(previous: &Value, nonce: u8) -> Value {
    let mut vault = next(previous, nonce, "password_change");
    vault["keyId"] = uuid::Uuid::new_v4().to_string().into();
    vault["kdf"]["salt"] = URL_SAFE_NO_PAD
        .encode(uuid::Uuid::new_v4().as_bytes())
        .into();
    vault
}

pub fn dual(vault: &Value, usage_tag: &str, base: u64, nonce: u8) -> Value {
    let mut usage = usage_upload(vault, base, nonce);
    usage["operationId"] = vault["operationId"].clone();
    json!({"vaultSnapshot":vault,"usageIfMatch":usage_tag,"usageSnapshot":usage})
}
