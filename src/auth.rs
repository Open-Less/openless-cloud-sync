use crate::{
    error::{ApiError, Result},
    protocol,
    store::Store,
};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub github_id: String,
    pub login: String,
}

pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<Account>> + Send + 'a>>;
pub trait IdentityVerifier: Send + Sync {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a>;
}

pub struct GithubVerifier {
    client: reqwest::Client,
    client_id: String,
    client_secret: Zeroizing<String>,
    endpoint: String,
}

impl GithubVerifier {
    pub fn new(client_id: String, client_secret: Zeroizing<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .no_proxy()
            .user_agent(concat!("openless-cloud-sync/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ApiError::unavailable())?;
        let endpoint = format!("https://api.github.com/applications/{client_id}/token");
        Ok(Self {
            client,
            client_id,
            client_secret,
            endpoint,
        })
    }

    async fn check(&self, token: &str) -> Result<Account> {
        let mut response = self
            .client
            .post(&self.endpoint)
            .basic_auth(&self.client_id, Some(self.client_secret.as_str()))
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2026-03-10")
            .json(&serde_json::json!({"access_token": token}))
            .send()
            .await
            .map_err(|_| ApiError::unavailable())?;
        match response.status().as_u16() {
            200 => (),
            404 => return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated")),
            // 401 is our application credential failure, not an end-user credential failure.
            _ => return Err(ApiError::unavailable()),
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ApiError::unavailable())?
        {
            if bytes.len() + chunk.len() > 65536 {
                return Err(ApiError::unavailable());
            }
            bytes.extend_from_slice(&chunk);
        }
        let checked: CheckedToken =
            serde_json::from_slice(&bytes).map_err(|_| ApiError::unavailable())?;
        if checked.app.client_id != self.client_id {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "wrong_oauth_app"));
        }
        if checked.user.id == 0 || checked.user.login.is_empty() || checked.user.login.len() > 100 {
            return Err(ApiError::unavailable());
        }
        if let Some(expires) = checked.expires_at {
            let expires = chrono::DateTime::parse_from_rfc3339(&expires)
                .map_err(|_| ApiError::unavailable())?;
            if expires.timestamp() <= chrono::Utc::now().timestamp() {
                return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"));
            }
        }
        Ok(Account {
            github_id: checked.user.id.to_string(),
            login: checked.user.login,
        })
    }
}

impl IdentityVerifier for GithubVerifier {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        Box::pin(self.check(token))
    }
}

#[derive(Deserialize)]
struct CheckedToken {
    app: CheckedApp,
    user: CheckedUser,
    expires_at: Option<String>,
}
#[derive(Deserialize)]
struct CheckedApp {
    client_id: String,
}
#[derive(Deserialize)]
struct CheckedUser {
    id: u64,
    login: String,
}

pub async fn session(store: &Store, account: Account) -> Result<serde_json::Value> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| ApiError::unavailable())?;
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
    store
        .issue_session(
            account.github_id.clone(),
            protocol::hash(token.as_bytes()),
            chrono::Utc::now().timestamp() + 900,
        )
        .await?;
    Ok(
        serde_json::json!({"protocolVersion":1,"accessToken":token.as_str(),"tokenType":"Bearer","expiresIn":900,"account":account}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Request, response::IntoResponse};
    use serde_json::json;

    async fn verifier(
        status: u16,
        body: serde_json::Value,
    ) -> (GithubVerifier, tokio::task::JoinHandle<()>) {
        let app = Router::new().fallback(move |request: Request| {
            let body = body.clone();
            async move {
                assert_eq!(request.method(), "POST");
                assert_eq!(request.uri().path(), "/applications/test-app/token");
                assert_eq!(request.headers()["x-github-api-version"], "2026-03-10");
                let expected = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(b"test-app:test-secret")
                );
                assert_eq!(request.headers()["authorization"], expected);
                let bytes = axum::body::to_bytes(request.into_body(), 8192)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                    json!({"access_token":"github-user-token"})
                );
                (StatusCode::from_u16(status).unwrap(), Json(body)).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "http://{}/applications/test-app/token",
            listener.local_addr().unwrap()
        );
        let task = tokio::spawn(async {
            axum::serve(listener, app).await.unwrap();
        });
        let verifier = GithubVerifier {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .no_proxy()
                .build()
                .unwrap(),
            client_id: "test-app".into(),
            client_secret: "test-secret".to_owned().into(),
            endpoint,
        };
        (verifier, task)
    }

    #[tokio::test]
    async fn github_verification_uses_application_credentials_and_numeric_id() {
        let (verifier,task)=verifier(200,json!({"app":{"client_id":"test-app"},"user":{"id":9007199254740993u64,"login":"renamed"},"expires_at":null,"token":"ignored-returned-token"})).await;
        let account = verifier.verify("github-user-token").await.unwrap();
        assert_eq!(account.github_id, "9007199254740993");
        assert_eq!(account.login, "renamed");
        task.abort();
    }

    #[tokio::test]
    async fn upstream_mismatch_expiry_failure_and_redirect_fail_closed() {
        for (status, body, code) in [
            (
                200,
                json!({"app":{"client_id":"other-app"},"user":{"id":1,"login":"name"}}),
                "wrong_oauth_app",
            ),
            (
                200,
                json!({"app":{"client_id":"test-app"},"user":{"id":1,"login":"name"},"expires_at":"2020-01-01T00:00:00Z"}),
                "unauthenticated",
            ),
            (
                200,
                json!({"app":{"client_id":"test-app"},"user":{"id":0,"login":"name"}}),
                "service_unavailable",
            ),
            (404, json!({}), "unauthenticated"),
            (401, json!({}), "service_unavailable"),
            (429, json!({}), "service_unavailable"),
            (302, json!({}), "service_unavailable"),
            (200, json!({"message":"unexpected"}), "service_unavailable"),
        ] {
            let (verifier, task) = verifier(status, body).await;
            assert_eq!(
                verifier
                    .verify("github-user-token")
                    .await
                    .err()
                    .unwrap()
                    .code,
                code
            );
            task.abort();
        }
    }
}
