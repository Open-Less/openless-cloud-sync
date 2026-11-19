use crate::{
    error::{ApiError, Result},
    protocol::{self, Metadata, Receipt, Snapshot},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

pub(crate) const FEATURE: &str = "/v1/features/service-usage";
pub(crate) const RESOURCE: &str = "/v1/me/vault/usage";
pub(crate) const SNAPSHOT: &str = "/v1/me/vault/usage/snapshot";
pub(crate) const ROTATE: &str = "/v1/me/vault/usage/password-change";
pub(crate) const OPERATIONS: &str = "/v1/me/vault/usage/operations/";
pub const MAX_CIPHERTEXT: usize = 1_048_592;
pub const MAX_BODY: usize = 1_572_864;
const ETAG_PREFIX: &str = "usage-v1-";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageMetadata {
    pub protocol_version: u32,
    pub state: UsageState,
    pub owner_github_id: String,
    pub vault_id: String,
    pub key_id: String,
    pub revision: String,
    pub updated_at: Option<String>,
    pub last_operation_id: Option<String>,
    pub ciphertext_sha256: Option<String>,
    pub ciphertext_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageState {
    Empty,
    Active,
}

impl UsageMetadata {
    pub(crate) fn empty(vault: &Metadata) -> Result<Self> {
        Ok(Self {
            protocol_version: 1,
            state: UsageState::Empty,
            owner_github_id: vault.owner_github_id.clone(),
            vault_id: vault.vault_id.clone().ok_or_else(ApiError::unavailable)?,
            key_id: vault.key_id.clone().ok_or_else(ApiError::unavailable)?,
            revision: "0".into(),
            updated_at: None,
            last_operation_id: None,
            ciphertext_sha256: None,
            ciphertext_bytes: 0,
        })
    }

    pub fn etag(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("usage metadata serialization");
        format!("\"{ETAG_PREFIX}{}\"", protocol::hash(&bytes))
    }
}

pub(crate) fn etag(value: Option<&str>) -> Result<&str> {
    let value = protocol::etag(value)?;
    let digest = value[1..value.len() - 1]
        .strip_prefix(ETAG_PREFIX)
        .ok_or_else(ApiError::invalid)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ApiError::invalid());
    }
    Ok(value)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageSnapshot {
    pub protocol_version: u32,
    pub payload_schema_version: u32,
    pub owner_github_id: String,
    pub vault_id: String,
    pub key_id: String,
    pub base_revision: String,
    pub revision: String,
    pub operation_id: String,
    pub aead: String,
    pub codec: String,
    pub nonce: String,
    pub ciphertext_sha256: String,
    pub ciphertext: String,
}

impl UsageSnapshot {
    pub fn validate(&self, owner: &str) -> Result<usize> {
        if self.protocol_version != 1 || self.payload_schema_version != 1 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "unsupported_protocol",
            ));
        }
        if protocol::revision(&self.owner_github_id)? == 0 {
            return Err(ApiError::invalid());
        }
        if self.owner_github_id != owner {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "owner_mismatch"));
        }
        for id in [&self.vault_id, &self.key_id, &self.operation_id] {
            protocol::uuid(id)?;
        }
        let base = protocol::revision(&self.base_revision)?;
        let next = base
            .checked_add(1)
            .ok_or_else(|| ApiError::conflict("revision_exhausted", &self.base_revision))?;
        if protocol::revision(&self.revision)? != next {
            return Err(ApiError::invalid());
        }
        let crypto_error = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_crypto_header");
        if self.aead != "xchacha20poly1305-ietf" || self.codec != "json-pad64k-v1" {
            return Err(crypto_error());
        }
        protocol::decode(&self.nonce, Some(24))?;
        if self.ciphertext.len() > (MAX_CIPHERTEXT * 4).div_ceil(3) {
            return Err(ApiError::too_large());
        }
        let ciphertext = protocol::decode(&self.ciphertext, None)?;
        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(ApiError::too_large());
        }
        if ciphertext.len() < 65_552
            || (ciphertext.len() - 16) % 65_536 != 0
            || protocol::hash(&ciphertext) != self.ciphertext_sha256
        {
            return Err(crypto_error());
        }
        Ok(ciphertext.len())
    }

    /// The server never decrypts. This is used by client interop fixtures.
    pub fn aad(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "openless-cloud-sync",
            1,
            "service-usage",
            self.owner_github_id,
            self.vault_id,
            self.key_id,
            self.base_revision,
            self.revision,
            self.operation_id,
            self.payload_schema_version,
            self.aead,
            self.codec
        ]))
        .expect("AAD serialization")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Rotation {
    pub vault_snapshot: Snapshot,
    pub usage_if_match: String,
    pub usage_snapshot: UsageSnapshot,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RotationReceipt {
    pub vault_receipt: Receipt,
    pub usage_receipt: Receipt,
}
