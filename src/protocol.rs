use crate::error::{ApiError, Result};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_BODY: usize = 25_165_824;
pub const MAX_CONTROL: usize = 8192;
pub const MAX_CIPHERTEXT: usize = 16_777_232;
pub const MAX_JSON: usize = 15_728_640;
pub const PROFILE: &str = "argon2id-xchacha20poly1305-v1";
pub const RETENTION: i64 = 604800;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Kdf {
    pub name: String,
    pub version: u32,
    #[serde(rename = "memoryKiB")]
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub protocol_version: u32,
    pub payload_schema_version: u32,
    pub owner_github_id: String,
    pub vault_id: String,
    pub key_id: String,
    pub base_revision: String,
    pub revision: String,
    pub operation_id: String,
    pub kind: UploadKind,
    pub crypto_profile: String,
    pub kdf: Kdf,
    pub aead: String,
    pub codec: String,
    pub nonce: String,
    pub ciphertext_sha256: String,
    pub ciphertext: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadKind {
    Create,
    Snapshot,
    PasswordChange,
}

impl UploadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Snapshot => "snapshot",
            Self::PasswordChange => "password_change",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteRequest {
    pub protocol_version: u32,
    pub base_revision: String,
    pub operation_id: String,
    pub expected_vault_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub protocol_version: u32,
    pub state: String,
    pub owner_github_id: String,
    pub revision: String,
    pub vault_id: Option<String>,
    pub key_id: Option<String>,
    pub updated_at: Option<String>,
    pub payload_schema_version: Option<u32>,
    pub ciphertext_bytes: usize,
    pub ciphertext_sha256: Option<String>,
    pub last_operation_id: Option<String>,
}

impl Metadata {
    pub fn empty(owner: &str) -> Self {
        Self {
            protocol_version: 1,
            state: "empty".into(),
            owner_github_id: owner.into(),
            revision: "0".into(),
            vault_id: None,
            key_id: None,
            updated_at: None,
            payload_schema_version: None,
            ciphertext_bytes: 0,
            ciphertext_sha256: None,
            last_operation_id: None,
        }
    }
    pub fn etag(&self) -> String {
        // Binds the account, state and immutable operation, even for empty vaults.
        let bytes = serde_json::to_vec(self).expect("metadata serialization");
        format!("\"{}\"", hash(&bytes))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: String,
    pub status: String,
    pub kind: String,
    pub committed_revision: String,
    pub committed_at: String,
    pub vault_id: String,
    pub ciphertext_sha256: Option<String>,
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn revision(value: &str) -> Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ApiError::invalid());
    }
    value.parse::<u64>().map_err(|_| ApiError::invalid())
}

pub fn uuid(value: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| ApiError::invalid())?;
    if id.get_version_num() != 4
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != value
    {
        return Err(ApiError::invalid());
    }
    Ok(())
}

pub fn etag(value: Option<&str>) -> Result<&str> {
    let value = value
        .ok_or_else(|| ApiError::new(StatusCode::PRECONDITION_REQUIRED, "precondition_required"))?;
    if value.len() < 3
        || value.len() > 130
        || !value.starts_with('"')
        || !value.ends_with('"')
        || !value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|b| *b == b'!' || (b'#'..=b'~').contains(b))
    {
        return Err(ApiError::invalid());
    }
    Ok(value)
}

pub fn decode(value: &str, bytes: Option<usize>) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| crypto_error())?;
    if bytes.is_some_and(|expected| decoded.len() != expected)
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(crypto_error());
    }
    Ok(decoded)
}

fn crypto_error() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_crypto_header")
}

impl Snapshot {
    pub fn validate(&self, owner: &str) -> Result<usize> {
        if self.protocol_version != 1 || self.payload_schema_version != 1 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "unsupported_protocol",
            ));
        }
        if revision(&self.owner_github_id)? == 0 {
            return Err(ApiError::invalid());
        }
        if self.owner_github_id != owner {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "owner_mismatch"));
        }
        for id in [&self.vault_id, &self.key_id, &self.operation_id] {
            uuid(id)?;
        }
        let base = revision(&self.base_revision)?;
        let next = base
            .checked_add(1)
            .ok_or_else(|| ApiError::conflict("revision_exhausted", &self.base_revision))?;
        if revision(&self.revision)? != next {
            return Err(ApiError::invalid());
        }
        if self.crypto_profile != PROFILE
            || self.aead != "xchacha20poly1305-ietf"
            || self.codec != "json-pad64k-v1"
            || self.kdf.name != "argon2id"
            || self.kdf.version != 19
            || self.kdf.memory_kib != 65536
            || self.kdf.iterations != 3
            || self.kdf.parallelism != 4
        {
            return Err(crypto_error());
        }
        decode(&self.kdf.salt, Some(16))?;
        decode(&self.nonce, Some(24))?;
        if self.ciphertext.len() > 22_369_643 {
            return Err(ApiError::too_large());
        }
        let ciphertext = decode(&self.ciphertext, None)?;
        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(ApiError::too_large());
        }
        if ciphertext.len() < 65552
            || (ciphertext.len() - 16) % 65536 != 0
            || hash(&ciphertext) != self.ciphertext_sha256
        {
            return Err(crypto_error());
        }
        Ok(ciphertext.len())
    }

    /// Canonical AAD for client interoperability fixtures; the service never decrypts.
    pub fn aad(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "openless-cloud-sync",
            1,
            "snapshot",
            self.owner_github_id,
            self.vault_id,
            self.key_id,
            self.base_revision,
            self.revision,
            self.operation_id,
            self.kind,
            self.payload_schema_version,
            self.crypto_profile,
            self.kdf.name,
            self.kdf.version,
            self.kdf.memory_kib,
            self.kdf.iterations,
            self.kdf.parallelism,
            self.kdf.salt,
            self.aead,
            self.codec
        ]))
        .expect("AAD serialization")
    }
}
