use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub current_revision: Option<String>,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            current_revision: None,
            retry_after: None,
        }
    }
    pub fn invalid() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request")
    }
    pub fn unavailable() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
    }
    pub fn conflict(code: &'static str, revision: &str) -> Self {
        let status = if code == "revision_conflict" {
            StatusCode::PRECONDITION_FAILED
        } else {
            StatusCode::CONFLICT
        };
        Self {
            current_revision: Some(revision.into()),
            ..Self::new(status, code)
        }
    }
    pub fn too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
    }
    pub fn limited(seconds: u64) -> Self {
        Self {
            retry_after: Some(seconds.clamp(1, 86400)),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        }
    }
}

impl ApiError {
    pub fn response_with_id(self, request_id: String) -> Response {
        let mut error = json!({"code": self.code, "message": match self.code {
            "revision_conflict" => "Cloud snapshot changed.",
            "unauthenticated" | "session_expired" => "Authentication required.",
            "service_unavailable" => "Service temporarily unavailable.",
            "payload_too_large" => "Payload exceeds protocol limits.",
            "rate_limited" => "Request limit reached.",
            _ => "Request could not be completed."
        }, "requestId": request_id});
        if let Some(revision) = self.current_revision {
            error["currentRevision"] = revision.into();
        }
        let mut response = (self.status, Json(json!({"error": error}))).into_response();
        response
            .headers_mut()
            .insert("cache-control", "no-store".parse().expect("static header"));
        if let Some(seconds) = self.retry_after {
            response.headers_mut().insert(
                "retry-after",
                seconds.to_string().parse().expect("integer header"),
            );
        }
        response
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.response_with_id(uuid::Uuid::new_v4().to_string())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        // Never log SQL parameters, ciphertext, or database error messages.
        tracing::error!(event = "database_operation_failed");
        Self::unavailable()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
