use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openless_cloud_sync::{
    protocol::{Snapshot, hash},
    store::{Mutation, Store},
};
use serde_json::json;

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
        [chrono::Utc::now().timestamp() - 604801],
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
