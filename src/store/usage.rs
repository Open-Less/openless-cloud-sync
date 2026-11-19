use super::{
    Mutation, OperationRoute, Store, from_db, operation, prepare_vault_upload, read_metadata,
    remember_nonce, replay, state_conflict, to_db, write_operation, write_vault,
};
use crate::{
    clock,
    config::UsageMode,
    error::{ApiError, Result},
    protocol::{self, Metadata, Receipt, UploadKind},
    usage::{self, Rotation, RotationReceipt, UsageMetadata, UsageSnapshot, UsageState},
};
use axum::http::StatusCode;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

impl Store {
    pub(crate) async fn usage_metadata(&self, owner: String) -> Result<UsageMetadata> {
        self.run(move |db| {
            let tx = db.transaction()?;
            read_usage(&tx, &read_metadata(&tx, &owner)?)
        })
        .await
    }

    pub(crate) async fn usage_download(&self, owner: String, tag: String) -> Result<Vec<u8>> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let meta = read_usage(&tx, &read_metadata(&tx, &owner)?)?;
            check_usage_cas(&meta, &tag, &meta.revision)?;
            if meta.state == UsageState::Empty {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "usage_empty"));
            }
            Ok(tx.query_row(
                "SELECT snapshot FROM service_usage WHERE owner=?1",
                [&owner],
                |r| r.get(0),
            )?)
        })
        .await
    }

    pub(crate) async fn usage_operation(&self, owner: String, id: String) -> Result<Receipt> {
        self.run(move |db| operation(db, OperationRoute::Usage, &owner, &id))
            .await
    }

    pub(crate) async fn usage_mutate(
        &self,
        request: Mutation,
        mode: UsageMode,
    ) -> Result<(Receipt, bool)> {
        self.run(move |db| {
            if request.body.len() > usage::MAX_BODY {
                return Err(ApiError::too_large());
            }
            let fingerprint = request.fingerprint();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = clock::now();
            if let Some(prior) = replay(&tx, &request, &fingerprint, now)? {
                return Ok((prior.usage.ok_or_else(ApiError::unavailable)?, true));
            }
            if mode == UsageMode::Rescue {
                return Err(ApiError::unavailable());
            }
            let tag = usage::etag(request.if_match.as_deref())?;
            let upload: UsageSnapshot =
                serde_json::from_slice(&request.body).map_err(|_| ApiError::invalid())?;
            let size = upload.validate(&request.owner)?;
            if upload.operation_id != request.operation_id {
                return Err(ApiError::invalid());
            }
            let vault = read_metadata(&tx, &request.owner)?;
            if vault.state != "active" {
                return Err(state_conflict(&vault));
            }
            let old = read_usage(&tx, &vault)?;
            if upload.vault_id != old.vault_id {
                return Err(ApiError::conflict("revision_conflict", &old.revision));
            }
            if upload.key_id != old.key_id {
                return Err(ApiError::conflict("key_epoch_changed", &old.revision));
            }
            check_usage_cas(&old, tag, &upload.base_revision)?;
            let timestamp = clock::wire_timestamp(now)?;
            let receipt = write_usage(
                &tx,
                &upload,
                size,
                &request.body,
                &timestamp,
                UploadKind::Snapshot,
            )?;
            write_operation(
                &tx,
                OperationRoute::Usage,
                &request.owner,
                &fingerprint,
                &receipt,
                now,
            )?;
            tx.commit()?;
            Ok((receipt, false))
        })
        .await
    }

    pub(crate) async fn rotate_usage(&self, request: Mutation) -> Result<(RotationReceipt, bool)> {
        self.run(move |db| {
            if request.body.len() > protocol::MAX_BODY {
                return Err(ApiError::too_large());
            }
            let fingerprint = request.fingerprint();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = clock::now();
            if let Some(prior) = replay(&tx, &request, &fingerprint, now)? {
                let vault_receipt = prior.vault.ok_or_else(ApiError::unavailable)?;
                let usage_receipt = prior.usage.ok_or_else(ApiError::unavailable)?;
                return Ok((
                    RotationReceipt {
                        vault_receipt,
                        usage_receipt,
                    },
                    true,
                ));
            }
            let tag = protocol::etag(request.if_match.as_deref())?;
            let rotation: Rotation =
                serde_json::from_slice(&request.body).map_err(|_| ApiError::invalid())?;
            let usage_tag = usage::etag(Some(&rotation.usage_if_match))?;
            let upload = rotation.vault_snapshot;
            let usage_upload = rotation.usage_snapshot;
            if upload.kind != UploadKind::PasswordChange
                || upload.vault_id != usage_upload.vault_id
                || upload.key_id != usage_upload.key_id
                || usage_upload.operation_id != request.operation_id
            {
                return Err(ApiError::invalid());
            }
            let size = usage_upload.validate(&request.owner)?;
            let old = read_metadata(&tx, &request.owner)?;
            let timestamp = clock::wire_timestamp(now)?;
            // V1 validation and nonce reservation share a transaction with Usage CAS and data.
            let (meta, vault_receipt) =
                prepare_vault_upload(&tx, &request, &old, tag, &upload, &timestamp, true)?;
            let old_usage = read_usage(&tx, &old)?;
            check_usage_cas(&old_usage, usage_tag, &usage_upload.base_revision)?;
            if old_usage.state == UsageState::Empty {
                return Err(ApiError::conflict("usage_empty", &old_usage.revision));
            }
            write_vault(&tx, &meta, Some(to_db(&upload)?.as_bytes()))?;
            let usage_receipt = write_usage(
                &tx,
                &usage_upload,
                size,
                to_db(&usage_upload)?.as_bytes(),
                &timestamp,
                UploadKind::PasswordChange,
            )?;
            write_operation(
                &tx,
                OperationRoute::Vault,
                &request.owner,
                &fingerprint,
                &vault_receipt,
                now,
            )?;
            write_operation(
                &tx,
                OperationRoute::Usage,
                &request.owner,
                &fingerprint,
                &usage_receipt,
                now,
            )?;
            tx.commit()?;
            Ok((
                RotationReceipt {
                    vault_receipt,
                    usage_receipt,
                },
                false,
            ))
        })
        .await
    }
}

pub(super) fn has_snapshot(db: &Connection, owner: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM service_usage WHERE owner=?1)",
        [owner],
        |r| r.get(0),
    )?)
}

fn read_usage(db: &Connection, vault: &Metadata) -> Result<UsageMetadata> {
    if vault.state != "active" {
        let error = state_conflict(vault);
        return Err(ApiError::new(StatusCode::NOT_FOUND, error.code));
    }
    let stored: Option<String> = db
        .query_row(
            "SELECT metadata FROM service_usage WHERE owner=?1",
            [&vault.owner_github_id],
            |r| r.get(0),
        )
        .optional()?;
    let empty = UsageMetadata::empty(vault)?;
    let Some(stored) = stored else {
        return Ok(empty);
    };
    let meta: UsageMetadata = from_db(&stored)?;
    if meta.vault_id != empty.vault_id
        || meta.key_id != empty.key_id
        || meta.state != UsageState::Active
    {
        return Err(ApiError::unavailable());
    }
    Ok(meta)
}

fn check_usage_cas(meta: &UsageMetadata, tag: &str, base: &str) -> Result<()> {
    if tag != meta.etag() || base != meta.revision {
        return Err(ApiError::conflict("revision_conflict", &meta.revision));
    }
    Ok(())
}

fn write_usage(
    db: &Connection,
    upload: &UsageSnapshot,
    size: usize,
    body: &[u8],
    timestamp: &str,
    kind: UploadKind,
) -> Result<Receipt> {
    remember_nonce(db, &upload.owner_github_id, &upload.key_id, &upload.nonce)?;
    let meta = UsageMetadata {
        protocol_version: 1,
        state: UsageState::Active,
        owner_github_id: upload.owner_github_id.clone(),
        vault_id: upload.vault_id.clone(),
        key_id: upload.key_id.clone(),
        revision: upload.revision.clone(),
        updated_at: Some(timestamp.into()),
        last_operation_id: Some(upload.operation_id.clone()),
        ciphertext_sha256: Some(upload.ciphertext_sha256.clone()),
        ciphertext_bytes: size,
    };
    let receipt = Receipt {
        operation_id: upload.operation_id.clone(),
        status: "committed".into(),
        kind: kind.as_str().into(),
        committed_revision: upload.revision.clone(),
        committed_at: timestamp.into(),
        vault_id: upload.vault_id.clone(),
        ciphertext_sha256: Some(upload.ciphertext_sha256.clone()),
    };
    db.execute(
        "INSERT INTO service_usage(owner,metadata,snapshot) VALUES(?1,?2,?3) ON CONFLICT(owner) DO UPDATE SET metadata=excluded.metadata,snapshot=excluded.snapshot",
        params![upload.owner_github_id, to_db(&meta)?, body],
    )?;
    Ok(receipt)
}
