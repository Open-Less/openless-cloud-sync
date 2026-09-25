use crate::{
    error::{ApiError, Result},
    protocol::{self, DeleteRequest, Metadata, Receipt, Snapshot, UploadKind},
};
use axum::http::StatusCode;
use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
pub struct Store(Arc<Mutex<Connection>>);

#[derive(Clone)]
pub struct Mutation {
    pub owner: String,
    pub method: String,
    pub path: String,
    pub if_match: Option<String>,
    pub operation_id: String,
    pub body: Vec<u8>,
}

impl Mutation {
    pub fn new(
        owner: String,
        method: &str,
        path: &str,
        if_match: Option<String>,
        operation_id: String,
        body: Vec<u8>,
    ) -> Self {
        Self {
            owner,
            method: method.into(),
            path: path.into(),
            if_match,
            operation_id,
            body,
        }
    }
    fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(
            serde_json::to_vec(&(&self.method, &self.path, &self.if_match))
                .expect("fingerprint header"),
        );
        digest.update([0]);
        digest.update(&self.body);
        format!("{digest:x}", digest = digest.finalize())
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(10))?;
        // DELETE journal and secure_delete avoid retaining old ciphertext in WAL/free pages.
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;")?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 1 {
            return Err(ApiError::unavailable());
        }
        if version == 0 {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(include_str!("../migrations/001_initial.sql"))?;
            tx.commit()?;
        }
        Ok(Self(Arc::new(Mutex::new(db))))
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let db = self.0.clone();
        // A cancelled HTTP response cannot cancel a partially executed transaction.
        tokio::task::spawn_blocking(move || {
            let mut connection = db.lock().map_err(|_| ApiError::unavailable())?;
            f(&mut connection)
        })
        .await
        .map_err(|_| ApiError::unavailable())?
    }

    pub async fn health(&self) -> Result<()> {
        self.run(|db| {
            db.query_row("SELECT 1", [], |_| Ok(()))?;
            Ok(())
        })
        .await
    }

    pub async fn metadata(&self, owner: String) -> Result<Metadata> {
        self.run(move |db| read_metadata(db, &owner)).await
    }

    pub async fn download(&self, owner: String, tag: String) -> Result<Vec<u8>> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let meta = read_metadata(&tx, &owner)?;
            if tag != meta.etag() {
                return Err(ApiError::conflict("revision_conflict", &meta.revision));
            }
            if meta.state != "active" {
                return Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    if meta.state == "empty" {
                        "vault_empty"
                    } else {
                        "vault_deleted"
                    },
                ));
            }
            let bytes = tx.query_row(
                "SELECT snapshot FROM vaults WHERE owner=?1",
                [&owner],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(bytes)
        })
        .await
    }

    pub async fn operation(&self, owner: String, id: String) -> Result<Receipt> {
        self.run(move |db| {
            let receipt: Option<String> = db.query_row("SELECT receipt FROM operations WHERE owner=?1 AND operation_id=?2 AND committed_at>=?3",
                params![owner, id, Utc::now().timestamp()-protocol::RETENTION], |r| r.get(0)).optional()?;
            receipt.map(|r| from_db(&r)).unwrap_or_else(|| Err(ApiError::new(StatusCode::NOT_FOUND, "operation_not_found")))
        }).await
    }

    pub async fn mutate(&self, request: Mutation) -> Result<(Receipt, bool)> {
        self.run(move |db| {
            let limit = if request.method == "PUT" { protocol::MAX_BODY } else { protocol::MAX_CONTROL };
            if request.body.len() > limit { return Err(ApiError::too_large()); }
            protocol::uuid(&request.operation_id)?;
            let fingerprint = request.fingerprint();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = Utc::now();
            let prior: Option<(String, String)> = tx.query_row(
                "SELECT fingerprint, receipt FROM operations WHERE owner=?1 AND operation_id=?2 AND committed_at>=?3",
                params![request.owner, request.operation_id, now.timestamp()-protocol::RETENTION], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            if let Some((original, receipt)) = prior {
                if fingerprint != original { return Err(ApiError::new(StatusCode::CONFLICT, "idempotency_key_reused")); }
                return Ok((from_db(&receipt)?, true));
            }
            let tag = protocol::etag(request.if_match.as_deref())?;
            let old = read_metadata(&tx, &request.owner)?;
            let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
            let (meta, receipt, snapshot) = match (request.method.as_str(), request.path.as_str()) {
                ("PUT", "/v1/me/vault/snapshot") => {
                    let upload: Snapshot = serde_json::from_slice(&request.body).map_err(|_| ApiError::invalid())?;
                    let size = upload.validate(&request.owner)?;
                    if upload.operation_id != request.operation_id { return Err(ApiError::invalid()); }
                    if old.state == "active" && upload.kind == UploadKind::Snapshot && old.key_id.as_ref() != Some(&upload.key_id) {
                        return Err(ApiError::conflict("key_epoch_changed", &old.revision));
                    }
                    check_cas(&old, tag, &upload.base_revision)?;
                    match upload.kind {
                        UploadKind::Create => {
                            if old.state == "active" { return Err(ApiError::conflict("vault_exists", &old.revision)); }
                            remember(&tx, &request.owner, "vault", &upload.vault_id, "invalid_crypto_header")?;
                            remember_epoch(&tx, &request.owner, &upload)?;
                        }
                        UploadKind::Snapshot | UploadKind::PasswordChange => {
                            if old.state != "active" { return Err(state_conflict(&old)); }
                            if old.vault_id.as_ref() != Some(&upload.vault_id) { return Err(ApiError::conflict("revision_conflict", &old.revision)); }
                            let prior: Vec<u8> = tx.query_row("SELECT snapshot FROM vaults WHERE owner=?1", [&request.owner], |r| r.get(0))?;
                            let prior: Snapshot = serde_json::from_slice(&prior).map_err(|_| ApiError::unavailable())?;
                            if upload.kind == UploadKind::Snapshot {
                                if upload.kdf.salt != prior.kdf.salt { return Err(ApiError::conflict("key_epoch_changed", &old.revision)); }
                            } else {
                                if upload.key_id == prior.key_id || upload.kdf.salt == prior.kdf.salt {
                                    return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_crypto_header"));
                                }
                                remember_epoch(&tx, &request.owner, &upload)?;
                            }
                        }
                    }
                    remember(&tx, &request.owner, &format!("nonce:{}", upload.key_id), &upload.nonce, "invalid_crypto_header")?;
                    let meta = Metadata {
                        protocol_version: 1, state: "active".into(), owner_github_id: request.owner.clone(), revision: upload.revision.clone(),
                        vault_id: Some(upload.vault_id.clone()), key_id: Some(upload.key_id), updated_at: Some(timestamp.clone()),
                        payload_schema_version: Some(1), ciphertext_bytes: size, ciphertext_sha256: Some(upload.ciphertext_sha256.clone()),
                        last_operation_id: Some(request.operation_id.clone()),
                    };
                    let receipt = Receipt { operation_id: request.operation_id.clone(), status: "committed".into(), kind: upload.kind.as_str().into(),
                        committed_revision: upload.revision, committed_at: timestamp, vault_id: upload.vault_id,
                        ciphertext_sha256: Some(upload.ciphertext_sha256) };
                    (meta, receipt, Some(request.body))
                }
                ("DELETE", "/v1/me/vault") => {
                    let delete: DeleteRequest = serde_json::from_slice(&request.body).map_err(|_| ApiError::invalid())?;
                    if delete.protocol_version != 1 { return Err(ApiError::new(StatusCode::BAD_REQUEST, "unsupported_protocol")); }
                    protocol::uuid(&delete.expected_vault_id)?;
                    protocol::uuid(&delete.operation_id)?;
                    protocol::revision(&delete.base_revision)?;
                    if delete.operation_id != request.operation_id { return Err(ApiError::invalid()); }
                    check_cas(&old, tag, &delete.base_revision)?;
                    if old.state != "active" { return Err(state_conflict(&old)); }
                    if old.vault_id.as_ref() != Some(&delete.expected_vault_id) { return Err(ApiError::conflict("revision_conflict", &old.revision)); }
                    let next = protocol::revision(&old.revision)?.checked_add(1).ok_or_else(|| ApiError::conflict("revision_exhausted", &old.revision))?.to_string();
                    let meta = Metadata { protocol_version: 1, state: "deleted".into(), owner_github_id: request.owner.clone(), revision: next.clone(),
                        vault_id: old.vault_id, key_id: None, updated_at: Some(timestamp.clone()), payload_schema_version: None,
                        ciphertext_bytes: 0, ciphertext_sha256: None, last_operation_id: Some(request.operation_id.clone()) };
                    let receipt = Receipt { operation_id: request.operation_id.clone(), status: "committed".into(), kind: "delete".into(),
                        committed_revision: next, committed_at: timestamp, vault_id: delete.expected_vault_id, ciphertext_sha256: None };
                    (meta, receipt, None)
                }
                _ => return Err(ApiError::invalid()),
            };
            tx.execute("INSERT INTO vaults(owner, metadata, snapshot) VALUES(?1,?2,?3) ON CONFLICT(owner) DO UPDATE SET metadata=excluded.metadata,snapshot=excluded.snapshot",
                params![request.owner, serde_json::to_string(&meta).map_err(|_| ApiError::unavailable())?, snapshot])?;
            tx.execute("INSERT INTO operations(owner,operation_id,fingerprint,receipt,committed_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(owner,operation_id) DO UPDATE SET fingerprint=excluded.fingerprint,receipt=excluded.receipt,committed_at=excluded.committed_at",
                params![request.owner, request.operation_id, fingerprint, serde_json::to_string(&receipt).map_err(|_| ApiError::unavailable())?, now.timestamp()])?;
            tx.commit()?;
            Ok((receipt, false))
        }).await
    }

    pub async fn issue_session(
        &self,
        owner: String,
        token_hash: String,
        expires_at: i64,
    ) -> Result<()> {
        self.run(move |db| {
            db.execute(
                "INSERT INTO sessions(token_hash,owner,expires_at) VALUES(?1,?2,?3)",
                params![token_hash, owner, expires_at],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn authenticate(&self, token_hash: String) -> Result<String> {
        self.run(move |db| {
            let row: Option<(String, i64)> = db
                .query_row(
                    "SELECT owner,expires_at FROM sessions WHERE token_hash=?1",
                    [token_hash],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                Some((owner, expires)) if expires > Utc::now().timestamp() => Ok(owner),
                Some(_) => Err(ApiError::new(StatusCode::UNAUTHORIZED, "session_expired")),
                None => Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated")),
            }
        })
        .await
    }

    pub async fn revoke(&self, token_hash: String) -> Result<()> {
        self.run(move |db| {
            let changed = db.execute(
                "DELETE FROM sessions WHERE token_hash=?1 AND expires_at>?2",
                params![token_hash, Utc::now().timestamp()],
            )?;
            if changed != 1 {
                return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"));
            }
            Ok(())
        })
        .await
    }

    pub async fn rate(
        &self,
        bucket: &'static str,
        identity: String,
        limit: u32,
        now: i64,
    ) -> Result<()> {
        self.run(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("DELETE FROM rate_events WHERE occurred_at<=?1", [now - 60])?;
            let (count, earliest): (u32, Option<i64>) = tx.query_row(
                "SELECT COUNT(*),MIN(occurred_at) FROM rate_events WHERE bucket=?1 AND identity=?2",
                params![bucket, identity],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if count >= limit {
                return Err(ApiError::limited(
                    u64::try_from(earliest.unwrap_or(now) + 60 - now).unwrap_or(60),
                ));
            }
            tx.execute(
                "INSERT INTO rate_events(bucket,identity,occurred_at) VALUES(?1,?2,?3)",
                params![bucket, identity, now],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn maintain(&self) -> Result<()> {
        self.run(|db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = Utc::now().timestamp();
            tx.execute(
                "DELETE FROM operations WHERE committed_at<?1",
                [now - protocol::RETENTION],
            )?;
            tx.execute("DELETE FROM sessions WHERE expires_at<?1", [now - 900])?;
            tx.execute("DELETE FROM rate_events WHERE occurred_at<=?1", [now - 60])?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
}

fn from_db<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| ApiError::unavailable())
}
fn read_metadata(db: &Connection, owner: &str) -> Result<Metadata> {
    let value: Option<String> = db
        .query_row("SELECT metadata FROM vaults WHERE owner=?1", [owner], |r| {
            r.get(0)
        })
        .optional()?;
    value
        .map(|s| from_db(&s))
        .unwrap_or_else(|| Ok(Metadata::empty(owner)))
}
fn check_cas(meta: &Metadata, tag: &str, base: &str) -> Result<()> {
    if tag != meta.etag() || base != meta.revision {
        return Err(ApiError::conflict("revision_conflict", &meta.revision));
    }
    Ok(())
}
fn state_conflict(meta: &Metadata) -> ApiError {
    ApiError::conflict(
        if meta.state == "deleted" {
            "vault_deleted"
        } else {
            "vault_empty"
        },
        &meta.revision,
    )
}
fn remember(
    db: &Connection,
    owner: &str,
    scope: &str,
    value: &str,
    error: &'static str,
) -> Result<()> {
    let changed = db.execute(
        "INSERT OR IGNORE INTO used_values(owner,scope,digest) VALUES(?1,?2,?3)",
        params![owner, scope, protocol::hash(value.as_bytes())],
    )?;
    if changed != 1 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, error));
    }
    Ok(())
}
fn remember_epoch(db: &Connection, owner: &str, upload: &Snapshot) -> Result<()> {
    remember(db, owner, "key", &upload.key_id, "invalid_crypto_header")?;
    remember(db, owner, "salt", &upload.kdf.salt, "invalid_crypto_header")
}
