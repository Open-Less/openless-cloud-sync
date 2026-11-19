use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openless_cloud_sync::{
    protocol::{Metadata, Snapshot, hash},
    store::{Mutation, Store},
};
use serde_json::{Value, json};

fn sample(owner: &str) -> Vec<u8> {
    let ciphertext = vec![42; 65552];
    serde_json::to_vec(&json!({
        "protocolVersion": 1, "payloadSchemaVersion": 1, "ownerGithubId": owner,
        "vaultId": uuid::Uuid::new_v4().to_string(), "keyId": uuid::Uuid::new_v4().to_string(),
        "baseRevision": "0", "revision": "1", "operationId": uuid::Uuid::new_v4().to_string(),
        "kind": "create", "cryptoProfile": "argon2id-xchacha20poly1305-v1",
        "kdf": {"name":"argon2id","version":19,"memoryKiB":65536,"iterations":3,"parallelism":4,"salt":URL_SAFE_NO_PAD.encode([1;16])},
        "aead":"xchacha20poly1305-ietf", "codec":"json-pad64k-v1", "nonce":URL_SAFE_NO_PAD.encode([2;24]),
        "ciphertextSha256":hash(&ciphertext), "ciphertext":URL_SAFE_NO_PAD.encode(ciphertext)
    })).unwrap()
}

#[tokio::test]
async fn current_client_envelope_round_trips_as_opaque_ciphertext() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let store = Store::open(&path).unwrap();
    let fixture: Value = serde_json::from_str(include_str!("vectors/v1.json")).unwrap();
    let value = fixture["vectors"][0]["snapshot"].clone();
    let body = serde_json::to_vec(&value).unwrap();
    let snapshot: Snapshot = serde_json::from_value(value.clone()).unwrap();
    let owner = snapshot.owner_github_id.clone();
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&snapshot.ciphertext)
        .unwrap();
    let prior = Metadata {
        protocol_version: 1,
        state: "active".into(),
        owner_github_id: owner.clone(),
        revision: snapshot.base_revision.clone(),
        vault_id: Some(snapshot.vault_id.clone()),
        key_id: Some(snapshot.key_id.clone()),
        updated_at: Some("2026-09-23T00:00:00Z".into()),
        payload_schema_version: Some(snapshot.payload_schema_version),
        ciphertext_bytes: ciphertext.len(),
        ciphertext_sha256: Some(snapshot.ciphertext_sha256.clone()),
        last_operation_id: Some(uuid::Uuid::new_v4().to_string()),
    };
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "INSERT INTO vaults(owner,metadata,snapshot) VALUES(?1,?2,?3)",
        rusqlite::params![owner, serde_json::to_string(&prior).unwrap(), body.clone()],
    )
    .unwrap();

    let request = Mutation::new(
        snapshot.owner_github_id.clone(),
        "PUT",
        "/v1/me/vault/snapshot",
        Some(prior.etag()),
        snapshot.operation_id.clone(),
        body.clone(),
    );
    let (_, replayed) = store.mutate(request).await.unwrap();
    assert!(!replayed);
    let metadata = store.metadata(snapshot.owner_github_id).await.unwrap();
    let downloaded = store.download(owner, metadata.etag()).await.unwrap();
    assert_eq!(downloaded, body);
    assert_eq!(serde_json::from_slice::<Value>(&downloaded).unwrap(), value);
}

#[tokio::test]
async fn replay_precedes_cas_and_is_scoped_to_account() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path().join("test.db")).unwrap();
    let etag = store.metadata("11".into()).await.unwrap().etag();
    let bytes = sample("11");
    let s: Snapshot = serde_json::from_slice(&bytes).unwrap();
    let request = Mutation::new(
        "11".into(),
        "PUT",
        "/v1/me/vault/snapshot",
        Some(etag.clone()),
        s.operation_id.clone(),
        bytes.clone(),
    );
    let (receipt, replay) = store.mutate(request.clone()).await.unwrap();
    assert!(!replay);
    assert_eq!(receipt.committed_revision, "1");
    assert!(store.mutate(request.clone()).await.unwrap().1);
    assert_eq!(store.metadata("11".into()).await.unwrap().revision, "1");
    assert_eq!(
        store
            .operation("22".into(), s.operation_id.clone())
            .await
            .unwrap_err()
            .code,
        "operation_not_found"
    );
    let mut altered = request;
    altered.body.push(b' ');
    assert_eq!(
        store.mutate(altered).await.unwrap_err().code,
        "idempotency_key_reused"
    );
    assert_eq!(
        store.download("11".into(), etag).await.unwrap_err().code,
        "revision_conflict"
    );
    assert_eq!(store.metadata("22".into()).await.unwrap().state, "empty");
    drop(store);
    let reopened = Store::open(temp.path().join("test.db")).unwrap();
    assert_eq!(
        reopened
            .operation("11".into(), s.operation_id)
            .await
            .unwrap()
            .committed_revision,
        "1"
    );
}

#[tokio::test]
async fn concurrent_creates_have_exactly_one_winner() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let a = Store::open(&path).unwrap();
    let b = Store::open(&path).unwrap();
    let tag = a.metadata("11".into()).await.unwrap().etag();
    let request = |body: Vec<u8>| {
        let s: Snapshot = serde_json::from_slice(&body).unwrap();
        Mutation::new(
            "11".into(),
            "PUT",
            "/v1/me/vault/snapshot",
            Some(tag.clone()),
            s.operation_id,
            body,
        )
    };
    let (a, b) = tokio::join!(
        a.mutate(request(sample("11"))),
        b.mutate(request(sample("11")))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
}

#[tokio::test]
async fn receipt_failure_rolls_back_snapshot_and_nonce_and_retry_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let store = Store::open(&path).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    let tag = store.metadata("11".into()).await.unwrap().etag();
    let bytes = sample("11");
    let s: Snapshot = serde_json::from_slice(&bytes).unwrap();
    let request = Mutation::new(
        "11".into(),
        "PUT",
        "/v1/me/vault/snapshot",
        Some(tag),
        s.operation_id.clone(),
        bytes,
    );
    assert!(store.mutate(request.clone()).await.is_err());
    assert_eq!(store.metadata("11".into()).await.unwrap().state, "empty");
    assert_eq!(
        store
            .operation("11".into(), s.operation_id)
            .await
            .unwrap_err()
            .code,
        "operation_not_found"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM used_values", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER fail_receipt;").unwrap();
    assert_eq!(
        store.mutate(request).await.unwrap().0.committed_revision,
        "1"
    );
}

#[tokio::test]
async fn revisions_use_full_uint64_and_never_wrap() {
    use openless_cloud_sync::protocol::Metadata;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let store = Store::open(&path).unwrap();
    let mut metadata = Metadata::empty("11");
    metadata.state = "deleted".into();
    metadata.revision = (u64::MAX - 1).to_string();
    metadata.vault_id = Some(uuid::Uuid::new_v4().to_string());
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "INSERT INTO vaults(owner,metadata) VALUES(?1,?2)",
        rusqlite::params!["11", serde_json::to_string(&metadata).unwrap()],
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&sample("11")).unwrap();
    value["baseRevision"] = (u64::MAX - 1).to_string().into();
    value["revision"] = u64::MAX.to_string().into();
    let request = Mutation::new(
        "11".into(),
        "PUT",
        "/v1/me/vault/snapshot",
        Some(metadata.etag()),
        value["operationId"].as_str().unwrap().into(),
        serde_json::to_vec(&value).unwrap(),
    );
    assert_eq!(
        store.mutate(request).await.unwrap().0.committed_revision,
        u64::MAX.to_string()
    );
    let metadata = store.metadata("11".into()).await.unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let body=serde_json::to_vec(&json!({"protocolVersion":1,"baseRevision":u64::MAX.to_string(),"operationId":id,"expectedVaultId":metadata.vault_id})).unwrap();
    let error = store
        .mutate(Mutation::new(
            "11".into(),
            "DELETE",
            "/v1/me/vault",
            Some(metadata.etag()),
            id,
            body,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code, "revision_exhausted");
    assert_eq!(store.metadata("11".into()).await.unwrap().state, "active");
}

#[tokio::test]
async fn rolling_rate_limit_and_retention_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let store = Store::open(&path).unwrap();
    store.rate("test", "11".into(), 2, 100).await.unwrap();
    store.rate("test", "11".into(), 2, 120).await.unwrap();
    let next = Store::open(&path).unwrap();
    assert_eq!(
        next.rate("test", "11".into(), 2, 159)
            .await
            .unwrap_err()
            .retry_after,
        Some(1)
    );
    next.rate("test", "11".into(), 2, 160).await.unwrap();
    assert_eq!(
        next.rate("test", "11".into(), 2, 160)
            .await
            .unwrap_err()
            .retry_after,
        Some(20)
    );
    let bytes = sample("11");
    let s: Snapshot = serde_json::from_slice(&bytes).unwrap();
    let tag = store.metadata("11".into()).await.unwrap().etag();
    store
        .mutate(Mutation::new(
            "11".into(),
            "PUT",
            "/v1/me/vault/snapshot",
            Some(tag),
            s.operation_id.clone(),
            bytes,
        ))
        .await
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE operations SET committed_at=?1",
        [time::OffsetDateTime::now_utc().unix_timestamp() - 604801],
    )
    .unwrap();
    assert_eq!(
        store
            .operation("11".into(), s.operation_id)
            .await
            .unwrap_err()
            .code,
        "operation_not_found"
    );
    store.maintain().await.unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM operations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(store.metadata("11".into()).await.unwrap().revision, "1");
}

#[tokio::test]
async fn v1_upgrade_is_atomic_and_keeps_live_snapshot_and_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("v1.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(include_str!("../migrations/001_initial.sql"))
        .unwrap();
    let old_body = sample("11");
    let upload: Snapshot = serde_json::from_slice(&old_body).unwrap();
    let metadata = Metadata {
        protocol_version: 1,
        state: "active".into(),
        owner_github_id: "11".into(),
        revision: "1".into(),
        vault_id: Some(upload.vault_id.clone()),
        key_id: Some(upload.key_id.clone()),
        updated_at: Some("2026-09-23T00:00:00Z".into()),
        payload_schema_version: Some(1),
        ciphertext_bytes: 65_552,
        ciphertext_sha256: Some(upload.ciphertext_sha256.clone()),
        last_operation_id: Some(upload.operation_id.clone()),
    };
    db.execute(
        "INSERT INTO vaults VALUES('11',?1,?2)",
        rusqlite::params![serde_json::to_string(&metadata).unwrap(), old_body],
    )
    .unwrap();
    let receipt = json!({"operationId":upload.operation_id,"status":"committed","kind":"create","committedRevision":"1","committedAt":"2026-09-23T00:00:00Z","vaultId":upload.vault_id,"ciphertextSha256":upload.ciphertext_sha256});
    db.execute(
        "INSERT INTO operations VALUES('11',?1,'fixture',?2,?3)",
        rusqlite::params![
            upload.operation_id,
            receipt.to_string(),
            time::OffsetDateTime::now_utc().unix_timestamp()
        ],
    )
    .unwrap();
    db.execute_batch("CREATE INDEX service_usage_operations_expiry ON operations(owner);")
        .unwrap();
    assert!(Store::open(&path).is_err());
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('service_usage','service_usage_operations')", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
    db.execute_batch("DROP INDEX service_usage_operations_expiry;")
        .unwrap();
    let migrated = Store::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        migrated
            .download("11".into(), metadata.etag())
            .await
            .unwrap(),
        old_body
    );
    let after = migrated
        .operation("11".into(), upload.operation_id)
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(after).unwrap(), receipt);
}
