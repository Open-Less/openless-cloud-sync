use crate::{
    auth::{self, IdentityVerifier},
    config::Config,
    error::{ApiError, Result},
    protocol,
    store::{Mutation, Store},
};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

pub struct AppState {
    pub config: Config,
    pub store: Store,
    pub verifier: Arc<dyn IdentityVerifier>,
    in_flight: Semaphore,
}
impl AppState {
    pub fn new(config: Config, store: Store, verifier: Arc<dyn IdentityVerifier>) -> Self {
        Self {
            config,
            store,
            verifier,
            in_flight: Semaphore::new(8),
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    // A single dispatcher makes every rejection (including wrong method/path) structured JSON.
    Router::new().fallback(dispatch).with_state(state)
}

async fn dispatch(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let start = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let origin = one_header(request.headers(), "origin")
        .ok()
        .flatten()
        .map(str::to_owned);
    let allowed_origin = origin.filter(|o| state.config.allowed_origins.contains(o));
    let result = match state.in_flight.try_acquire() {
        Ok(_permit) => {
            match tokio::time::timeout(Duration::from_secs(60), handle(&state, request)).await {
                Ok(result) => result,
                Err(_) => Err(ApiError::unavailable()),
            }
        }
        Err(_) => Err(ApiError::unavailable()),
    };
    let mut response = result.unwrap_or_else(|error| error.response_with_id(request_id.clone()));
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
        .headers_mut()
        .insert("x-request-id", request_id.parse().expect("UUID header"));
    if let Some(origin) = allowed_origin {
        response.headers_mut().insert(
            "access-control-allow-origin",
            origin.parse().expect("validated origin"),
        );
        response
            .headers_mut()
            .insert("vary", HeaderValue::from_static("Origin"));
        response.headers_mut().insert(
            "access-control-expose-headers",
            HeaderValue::from_static("ETag, Idempotency-Replayed, Retry-After, X-Request-Id"),
        );
    }
    // No URI, IP, account, headers, body, or upstream error text in logs.
    tracing::info!(
        request_id,
        status = response.status().as_u16(),
        elapsed_ms = start.elapsed().as_millis() as u64
    );
    response
}

async fn handle(state: &AppState, request: Request) -> Result<Response> {
    if request.uri().query().is_some() {
        return Err(ApiError::invalid());
    }
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .ok_or_else(ApiError::unavailable)?;
    if !peer.is_loopback() {
        return Err(ApiError::invalid());
    }
    let headers = request.headers();
    let origin = one_header(headers, "origin")?;
    if origin.is_some_and(|o| !state.config.allowed_origins.contains(o)) {
        return Err(ApiError::invalid());
    }
    if path == "/healthz" && method == Method::GET {
        read_body(request, protocol::MAX_CONTROL, false).await?;
        state.store.health().await?;
        return Ok(
            Json(serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
                .into_response(),
        );
    }
    let ip = if state.config.require_https_proxy {
        if one_header(headers, "x-forwarded-proto")? != Some("https") {
            return Err(ApiError::invalid());
        }
        one_header(headers, "x-real-ip")?
            .ok_or_else(ApiError::invalid)?
            .parse::<IpAddr>()
            .map_err(|_| ApiError::invalid())?
    } else {
        peer
    };
    let now = chrono::Utc::now().timestamp();
    if method == Method::OPTIONS {
        if origin.is_none() {
            return Err(ApiError::invalid());
        }
        let requested =
            one_header(headers, "access-control-request-method")?.ok_or_else(ApiError::invalid)?;
        if !matches!(requested, "GET" | "POST" | "PUT" | "DELETE") {
            return Err(ApiError::invalid());
        }
        if let Some(names) = one_header(headers, "access-control-request-headers")?
            && !names.split(',').all(|h| {
                matches!(
                    h.trim().to_ascii_lowercase().as_str(),
                    "authorization"
                        | "content-type"
                        | "if-match"
                        | "if-none-match"
                        | "idempotency-key"
                )
            })
        {
            return Err(ApiError::invalid());
        }
        read_body(request, protocol::MAX_CONTROL, false).await?;
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, POST, PUT, DELETE"),
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            HeaderValue::from_static(
                "Authorization, Content-Type, If-Match, If-None-Match, Idempotency-Key",
            ),
        );
        return Ok(response);
    }
    if path == "/v1/capabilities" && method == Method::GET {
        state
            .store
            .rate(
                "public",
                protocol::hash(ip.to_string().as_bytes()),
                120,
                now,
            )
            .await?;
        read_body(request, protocol::MAX_CONTROL, false).await?;
        return Ok(Json(serde_json::json!({"protocolVersion":1,"cryptoProfile":protocol::PROFILE,
            "githubClientId":state.config.github_client_id,"maxHttpBodyBytes":protocol::MAX_BODY,
            "maxCiphertextBytes":protocol::MAX_CIPHERTEXT,"maxPlaintextJsonBytes":protocol::MAX_JSON,
            "idempotencyRetentionSeconds":protocol::RETENTION,"maxBackupRetentionDays":7})).into_response());
    }
    if path == "/v1/auth/github" && method == Method::POST {
        state
            .store
            .rate(
                "exchange",
                protocol::hash(ip.to_string().as_bytes()),
                20,
                now,
            )
            .await?;
        let token = Zeroizing::new(bearer(headers)?.to_owned());
        read_body(request, protocol::MAX_CONTROL, false).await?;
        let account = state.verifier.verify(&token).await?;
        if !state.config.public_access
            && !state.config.allowed_github_ids.contains(&account.github_id)
        {
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"));
        }
        return Ok(Json(auth::session(&state.store, account).await?).into_response());
    }
    let known_route = (path == "/v1/auth/session" && method == Method::DELETE)
        || (path == "/v1/me/vault" && matches!(method, Method::GET | Method::DELETE))
        || (path == "/v1/me/vault/snapshot" && matches!(method, Method::GET | Method::PUT))
        || (path.starts_with("/v1/me/operations/") && method == Method::GET);
    if !known_route {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "invalid_request"));
    }
    // Limit invalid authentication attempts independently of valid account quotas.
    let token_hash = protocol::hash(bearer(headers)?.as_bytes());
    let owner = match state.store.authenticate(token_hash.clone()).await {
        Ok(owner) => owner,
        Err(error) => {
            state
                .store
                .rate(
                    "invalid_auth",
                    protocol::hash(ip.to_string().as_bytes()),
                    120,
                    now,
                )
                .await?;
            return Err(error);
        }
    };
    if !state.config.public_access && !state.config.allowed_github_ids.contains(&owner) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"));
    }
    let write = method != Method::GET;
    state
        .store
        .rate(
            if write { "write" } else { "read" },
            owner.clone(),
            if write { 30 } else { 120 },
            now,
        )
        .await?;
    match (method.as_str(), path.as_str()) {
        ("DELETE", "/v1/auth/session") => {
            read_body(request, protocol::MAX_CONTROL, false).await?;
            state.store.revoke(token_hash).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        ("GET", "/v1/me/vault") => {
            let condition = one_header(headers, "if-none-match")?.map(str::to_owned);
            if let Some(tag) = &condition {
                protocol::etag(Some(tag))?;
            }
            read_body(request, protocol::MAX_CONTROL, false).await?;
            let metadata = state.store.metadata(owner).await?;
            let tag = metadata.etag();
            let mut response = if condition.as_ref() == Some(&tag) {
                StatusCode::NOT_MODIFIED.into_response()
            } else {
                Json(metadata).into_response()
            };
            response
                .headers_mut()
                .insert("etag", tag.parse().expect("generated ETag"));
            Ok(response)
        }
        ("GET", "/v1/me/vault/snapshot") => {
            let tag = protocol::etag(one_header(headers, "if-match")?)?.to_owned();
            read_body(request, protocol::MAX_CONTROL, false).await?;
            let bytes = state.store.download(owner, tag.clone()).await?;
            let mut response = Body::from(bytes).into_response();
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            response
                .headers_mut()
                .insert("etag", tag.parse().expect("validated ETag"));
            Ok(response)
        }
        ("PUT", "/v1/me/vault/snapshot") | ("DELETE", "/v1/me/vault") => {
            let tag = one_header(headers, "if-match")?.map(str::to_owned);
            let id = one_header(headers, "idempotency-key")?
                .ok_or_else(ApiError::invalid)?
                .to_owned();
            protocol::uuid(&id)?;
            let bytes = read_body(
                request,
                if method == Method::PUT {
                    protocol::MAX_BODY
                } else {
                    protocol::MAX_CONTROL
                },
                true,
            )
            .await?;
            let (receipt, replayed) = state
                .store
                .mutate(Mutation::new(owner, method.as_str(), &path, tag, id, bytes))
                .await?;
            let mut response = Json(receipt).into_response();
            response.headers_mut().insert(
                "idempotency-replayed",
                HeaderValue::from_static(if replayed { "true" } else { "false" }),
            );
            Ok(response)
        }
        _ => {
            let id = path
                .strip_prefix("/v1/me/operations/")
                .ok_or_else(ApiError::invalid)?
                .to_owned();
            protocol::uuid(&id)?;
            read_body(request, protocol::MAX_CONTROL, false).await?;
            Ok(Json(state.store.operation(owner, id).await?).into_response())
        }
    }
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(ApiError::invalid());
    }
    first
        .map(|v| v.to_str().map_err(|_| ApiError::invalid()))
        .transpose()
}
fn bearer(headers: &HeaderMap) -> Result<&str> {
    let header = one_header(headers, "authorization")?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"))?;
    let (scheme, token) = header
        .split_once(' ')
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"))?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.len() > 2048
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"));
    }
    Ok(token)
}
async fn read_body(request: Request, limit: usize, json: bool) -> Result<Vec<u8>> {
    if let Some(length) = one_header(request.headers(), "content-length")? {
        let length = length.parse::<u64>().map_err(|_| ApiError::invalid())?;
        if length > limit as u64 {
            return Err(ApiError::too_large());
        }
    }
    if one_header(request.headers(), "content-encoding")?.is_some_and(|e| e != "identity") {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    if json
        && !one_header(request.headers(), "content-type")?.is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let bytes = to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ApiError::too_large())?;
    if !json && !bytes.is_empty() {
        return Err(ApiError::invalid());
    }
    Ok(bytes.to_vec())
}
