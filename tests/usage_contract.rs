mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::*;
use openless_cloud_sync::{
    config::UsageMode,
    protocol::{MAX_BODY, MAX_CIPHERTEXT, hash},
    usage,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use uuid::Uuid;

async fn create(f: &Fixture, token: &str) -> Value {
    let v1 = sample("11");
    assert_eq!(
        f.put(token, f.meta(token).await.tag(), &v1).await.status,
        200
    );
    v1
}

#[tokio::test]
async fn probe_legacy_reads_writes_and_numeric_account_isolation() {
    let f = Fixture::https(true);
    let probe = f.request("GET", FEATURE, None, &[], vec![]).await;
    assert_eq!(probe.status, 400);
    let proxy = [("x-forwarded-proto", "https"), ("x-real-ip", "192.0.2.1")];
    let probe = f.request("GET", FEATURE, None, &proxy, vec![]).await;
    assert_eq!(
        probe.json,
        json!({"protocolVersion":1,"maxCiphertextBytes":1048592,"maxBodyBytes":1572864})
    );

    let f = Fixture::new();
    let capabilities = f
        .request("GET", "/v1/capabilities", None, &[], vec![])
        .await
        .json;
    assert_eq!(capabilities.as_object().unwrap().len(), 8);
    assert_eq!(capabilities["maxHttpBodyBytes"], MAX_BODY);
    let token = f.login("github-alice").await;
    let renamed = f.login("github-alice-renamed").await;
    let other = f.login("github-bob").await;
    assert_eq!(f.request("GET", USAGE, None, &[], vec![]).await.status, 401);
    assert_eq!(f.usage_meta(&token).await.code(), "vault_empty");
    let initial = create(&f, &token).await;
    let empty = f.usage_meta(&token).await;
    assert_eq!(empty.json["revision"], "0");
    assert_eq!(empty.json["state"], "empty");
    assert_eq!(
        f.usage_download(&token, empty.tag()).await.code(),
        "usage_empty"
    );
    let v1 = f.meta(&token).await;
    assert_ne!(v1.tag(), empty.tag());
    assert_eq!(f.usage_download(&token, v1.tag()).await.status, 400);
    assert_eq!(
        f.request(
            "GET",
            USAGE,
            Some(&token),
            &[("if-none-match", empty.tag())],
            vec![]
        )
        .await
        .status,
        304
    );

    let usage = usage_upload(&initial, 0, 3);
    let committed = f.usage_put(&token, empty.tag(), &usage).await;
    assert_eq!(committed.status, 200);
    assert_eq!(committed.headers["idempotency-replayed"], "false");
    assert_eq!(f.meta(&token).await.tag(), v1.tag());
    let old_write = next(&initial, 4, "snapshot");
    assert_eq!(f.put(&token, v1.tag(), &old_write).await.status, 200);
    let old_meta = f.meta(&token).await;
    let download_legacy = f
        .request(
            "GET",
            VAULT_SNAPSHOT,
            Some(&token),
            &[("if-match", old_meta.tag())],
            vec![],
        )
        .await;
    assert_eq!(
        download_legacy.body,
        serde_json::to_vec(&old_write).unwrap()
    );
    let active = f.usage_meta(&renamed).await;
    assert_eq!(active.json["revision"], "1");
    assert_eq!(f.usage_download(&renamed, active.tag()).await.json, usage);
    assert_eq!(f.usage_meta(&other).await.code(), "vault_empty");
    assert_eq!(f.usage_put(&other, empty.tag(), &usage).await.status, 403);
    assert_eq!(
        f.operation(&other, true, &usage["operationId"])
            .await
            .code(),
        "operation_not_found"
    );
    assert_eq!(
        f.operation(&token, false, &usage["operationId"])
            .await
            .code(),
        "operation_not_found"
    );
    assert_eq!(
        f.operation(&token, true, &usage["operationId"]).await.json,
        committed.json
    );
}

#[tokio::test]
async fn competing_usage_writers_and_lost_ack_are_not_double_commits() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let vault = create(&f, &token).await;
    let empty = f.usage_meta(&token).await;
    let a = usage_upload(&vault, 0, 5);
    let b = usage_upload(&vault, 0, 6);
    let (aa, bb) = tokio::join!(
        f.usage_put(&token, empty.tag(), &a),
        f.usage_put(&token, empty.tag(), &b)
    );
    let (winner, lost_ack, loser) = if aa.status == 200 {
        (a, aa, bb)
    } else {
        (b, bb, aa)
    };
    assert_eq!(lost_ack.status, 200);
    assert_eq!(loser.status, 412);
    assert_eq!(loser.json["error"]["currentRevision"], "1");
    let op = &winner["operationId"];
    assert_eq!(f.operation(&token, true, op).await.json, lost_ack.json);
    let replay = f.usage_put(&token, empty.tag(), &winner).await;
    assert_eq!(replay.headers["idempotency-replayed"], "true");
    assert_eq!(replay.json, lost_ack.json);
    let active = f.usage_meta(&token).await;
    assert_eq!(active.json["revision"], "1");
    assert_eq!(f.usage_download(&token, empty.tag()).await.status, 412);
    assert_eq!(
        f.usage_put(&token, active.tag(), &winner).await.code(),
        "idempotency_key_reused"
    );
    let mut legacy = next(&vault, 7, "snapshot");
    legacy["operationId"] = op.clone();
    assert_eq!(
        f.put(&token, f.meta(&token).await.tag(), &legacy)
            .await
            .code(),
        "idempotency_key_reused"
    );
    let mut reused_by_usage = usage_upload(&vault, 1, 8);
    reused_by_usage["operationId"] = vault["operationId"].clone();
    assert_eq!(
        f.usage_put(&token, active.tag(), &reused_by_usage)
            .await
            .code(),
        "idempotency_key_reused"
    );
    let db = Connection::open(f.dir.path().join("sync.db")).unwrap();
    db.execute(
        "UPDATE service_usage_operations SET committed_at=?1",
        [time::OffsetDateTime::now_utc().unix_timestamp() - 604801],
    )
    .unwrap();
    f.store.maintain().await.unwrap();
    assert_eq!(
        f.operation(&token, true, op).await.code(),
        "operation_not_found"
    );
    assert_eq!(f.usage_download(&token, active.tag()).await.json, winner);
}

#[tokio::test]
async fn legacy_rotation_is_guarded_only_for_present_usage_and_dual_recovers_atomically() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let first = create(&f, &token).await;
    let before = f.usage_meta(&token).await;
    let vault = rekey(&first, 9);
    let empty_rotation = dual(&vault, before.tag(), 0, 10);
    let first_meta = f.meta(&token).await;
    assert_eq!(
        f.rotate(&token, first_meta.tag(), &empty_rotation)
            .await
            .code(),
        "usage_empty"
    );
    assert_eq!(f.put(&token, first_meta.tag(), &vault).await.status, 200);
    let empty = f.usage_meta(&token).await;
    assert_ne!(before.tag(), empty.tag());
    assert_eq!(empty.json["revision"], "0");
    assert_eq!(
        f.usage_put(&token, before.tag(), &usage_upload(&first, 0, 10))
            .await
            .code(),
        "key_epoch_changed"
    );
    let usage_1 = usage_upload(&vault, 0, 10);
    assert_eq!(f.usage_put(&token, empty.tag(), &usage_1).await.status, 200);
    let old_usage = f.usage_meta(&token).await;
    let old_vault = f.meta(&token).await;
    let new_vault = rekey(&vault, 11);
    assert_eq!(
        f.put(&token, old_vault.tag(), &new_vault).await.code(),
        "key_epoch_changed"
    );
    assert_eq!(f.meta(&token).await.tag(), old_vault.tag());
    assert_eq!(f.usage_meta(&token).await.tag(), old_usage.tag());

    let usage_2 = usage_upload(&vault, 1, 12);
    assert_eq!(
        f.usage_put(&token, old_usage.tag(), &usage_2).await.status,
        200
    );
    let stale = dual(&new_vault, old_usage.tag(), 1, 13);
    assert_eq!(f.rotate(&token, old_vault.tag(), &stale).await.status, 412);
    assert_eq!(f.meta(&token).await.tag(), old_vault.tag());
    let new_head = f.usage_meta(&token).await;
    let racing_vault = next(&vault, 14, "snapshot");
    assert_eq!(
        f.put(&token, old_vault.tag(), &racing_vault).await.status,
        200
    );
    let superseded = dual(&new_vault, new_head.tag(), 2, 13);
    assert_eq!(
        f.rotate(&token, old_vault.tag(), &superseded).await.status,
        412
    );
    let vault_meta = f.meta(&token).await;
    let mut new_vault = new_vault;
    new_vault["baseRevision"] = "3".into();
    new_vault["revision"] = "4".into();
    let nonce_collision = dual(&new_vault, new_head.tag(), 2, 11);
    assert_eq!(
        f.rotate(&token, vault_meta.tag(), &nonce_collision)
            .await
            .code(),
        "invalid_crypto_header"
    );
    assert_eq!(f.meta(&token).await.tag(), vault_meta.tag());

    let dual = dual(&new_vault, new_head.tag(), 2, 13);
    let op = &new_vault["operationId"];
    let db = Connection::open(f.dir.path().join("sync.db")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_usage_receipt BEFORE INSERT ON service_usage_operations BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert_eq!(f.rotate(&token, vault_meta.tag(), &dual).await.status, 503);
    assert_eq!(f.meta(&token).await.tag(), vault_meta.tag());
    assert_eq!(f.usage_meta(&token).await.tag(), new_head.tag());
    assert_eq!(f.operation(&token, false, op).await.status, 404);
    assert_eq!(f.operation(&token, true, op).await.status, 404);
    db.execute_batch("DROP TRIGGER fail_usage_receipt;")
        .unwrap();
    let result = f.rotate(&token, vault_meta.tag(), &dual).await;
    assert_eq!(result.status, 200);
    assert_eq!(result.json["vaultReceipt"]["committedRevision"], "4");
    assert_eq!(result.json["usageReceipt"]["committedRevision"], "3");
    assert_eq!(
        f.operation(&token, false, op).await.json,
        result.json["vaultReceipt"]
    );
    assert_eq!(
        f.operation(&token, true, op).await.json,
        result.json["usageReceipt"]
    );
    assert_eq!(
        f.put(&token, vault_meta.tag(), &new_vault).await.code(),
        "idempotency_key_reused"
    );
    let replay = f.rotate(&token, vault_meta.tag(), &dual).await;
    assert_eq!(replay.json, result.json);
    assert_eq!(replay.headers["idempotency-replayed"], "true");
    let after = f.usage_meta(&token).await;
    assert_eq!(after.json["keyId"], new_vault["keyId"]);
    assert_eq!(
        f.usage_download(&token, after.tag()).await.json,
        dual["usageSnapshot"]
    );
    assert_eq!(
        f.usage_put(&token, new_head.tag(), &usage_upload(&vault, 2, 15))
            .await
            .code(),
        "key_epoch_changed"
    );
}

#[tokio::test]
async fn forward_rescue_preserves_accepted_writes_and_legacy_delete_cannot_resurrect_usage() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let vault = create(&f, &token).await;
    let empty = f.usage_meta(&token).await;
    let usage = usage_upload(&vault, 0, 15);
    let receipt = f.usage_put(&token, empty.tag(), &usage).await.json;
    let old = f.usage_meta(&token).await;
    let f = f.reopen(UsageMode::Rescue);
    assert_eq!(f.usage_meta(&token).await.tag(), old.tag());
    assert_eq!(f.usage_download(&token, old.tag()).await.json, usage);
    assert_eq!(f.usage_put(&token, empty.tag(), &usage).await.json, receipt);
    assert_eq!(
        f.usage_put(&token, old.tag(), &usage_upload(&vault, 1, 16))
            .await
            .status,
        503
    );
    let prior = f.meta(&token).await;
    let legacy = next(&vault, 16, "snapshot");
    assert_eq!(f.put(&token, prior.tag(), &legacy).await.status, 200);
    let before = f.meta(&token).await;
    let rotated = rekey(&legacy, 17);
    let dual = dual(&rotated, old.tag(), 1, 18);
    assert_eq!(
        f.put(&token, before.tag(), &rotated).await.code(),
        "key_epoch_changed"
    );
    assert_eq!(f.rotate(&token, before.tag(), &dual).await.status, 200);
    let f = f.reopen(UsageMode::Enabled);
    let active = f.usage_meta(&token).await;
    assert_eq!(
        f.usage_download(&token, active.tag()).await.json,
        dual["usageSnapshot"]
    );
    let before_deleted = f.meta(&token).await;
    let delete = json!({"protocolVersion":1,"baseRevision":"3","operationId":Uuid::new_v4().to_string(),"expectedVaultId":vault["vaultId"]});
    let delete_id = delete["operationId"].as_str().unwrap();
    let response = f
        .json_mutation(
            "DELETE",
            "/v1/me/vault",
            &token,
            before_deleted.tag(),
            delete_id,
            &delete,
        )
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(f.usage_meta(&token).await.code(), "vault_deleted");
    assert_eq!(
        f.usage_download(&token, active.tag()).await.code(),
        "vault_deleted"
    );
    let db = Connection::open(f.dir.path().join("sync.db")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM service_usage", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let mut recreate = sample("11");
    recreate["baseRevision"] = "4".into();
    recreate["revision"] = "5".into();
    assert_eq!(
        f.put(&token, f.meta(&token).await.tag(), &recreate)
            .await
            .status,
        200
    );
    let fresh = f.usage_meta(&token).await;
    assert_eq!(fresh.json["revision"], "0");
    assert_ne!(fresh.tag(), empty.tag());
    assert_eq!(
        f.usage_put(&token, active.tag(), &usage_upload(&rotated, 2, 19))
            .await
            .status,
        412
    );
    assert_eq!(f.usage_put(&token, empty.tag(), &usage).await.json, receipt);
    let replay = f
        .json_mutation(
            "DELETE",
            "/v1/me/vault",
            &token,
            before_deleted.tag(),
            delete_id,
            &delete,
        )
        .await;
    assert_eq!(replay.headers["idempotency-replayed"], "true");
    assert_eq!(f.usage_meta(&token).await.tag(), fresh.tag());
}

#[tokio::test]
async fn sizes_headers_strict_json_and_shared_nonces_are_enforced() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let vault = create(&f, &token).await;
    let empty = f.usage_meta(&token).await;
    let bad = usage_upload(&vault, 0, 2);
    assert_eq!(
        f.usage_put(&token, empty.tag(), &bad).await.code(),
        "invalid_crypto_header"
    );
    let mut valid = usage_upload(&vault, 0, 20);
    let mut extra = valid.clone();
    extra["records"] = json!([]);
    assert_eq!(
        f.usage_put(&token, empty.tag(), &extra).await.code(),
        "invalid_request"
    );
    let id = valid["operationId"].as_str().unwrap().to_owned();
    let ct = [
        ("content-type", "application/json"),
        ("idempotency-key", id.as_str()),
    ];
    let body = serde_json::to_vec(&valid).unwrap();
    assert_eq!(
        f.request("PUT", USAGE_SNAPSHOT, Some(&token), &ct, body)
            .await
            .status,
        428
    );
    let tag = empty.tag();
    let headers = [ct[0], ct[1], ("if-match", tag)];
    let mut duplicate = serde_json::to_string(&valid).unwrap();
    duplicate.insert_str(1, "\"protocolVersion\":1,");
    assert_eq!(
        f.request(
            "PUT",
            USAGE_SNAPSHOT,
            Some(&token),
            &headers,
            duplicate.into_bytes()
        )
        .await
        .status,
        400
    );
    assert_eq!(
        f.request(
            "PUT",
            USAGE_SNAPSHOT,
            Some(&token),
            &headers,
            vec![b' '; usage::MAX_BODY + 1]
        )
        .await
        .status,
        413
    );
    let mut padded = valid.clone();
    padded["ciphertext"] = format!("{}=", padded["ciphertext"].as_str().unwrap()).into();
    assert_eq!(
        f.usage_put(&token, empty.tag(), &padded).await.code(),
        "invalid_crypto_header"
    );
    set_ciphertext_size(&mut valid, usage::MAX_CIPHERTEXT + 65_536);
    assert_eq!(f.usage_put(&token, empty.tag(), &valid).await.status, 413);
    set_ciphertext_size(&mut valid, usage::MAX_CIPHERTEXT);
    assert_eq!(f.usage_put(&token, empty.tag(), &valid).await.status, 200);
    let old = f.meta(&token).await;
    assert_eq!(
        f.put(&token, old.tag(), &next(&vault, 20, "snapshot"))
            .await
            .code(),
        "invalid_crypto_header"
    );
    let mut rotation = dual(&rekey(&vault, 21), f.usage_meta(&token).await.tag(), 1, 22);
    set_ciphertext_size(&mut rotation["vaultSnapshot"], MAX_CIPHERTEXT);
    set_ciphertext_size(&mut rotation["usageSnapshot"], usage::MAX_CIPHERTEXT);
    assert_eq!(f.rotate(&token, old.tag(), &rotation).await.status, 200);
}

fn set_ciphertext_size(snapshot: &mut Value, bytes: usize) {
    let ciphertext = vec![47; bytes];
    snapshot["ciphertextSha256"] = hash(&ciphertext).into();
    snapshot["ciphertext"] = URL_SAFE_NO_PAD.encode(ciphertext).into();
}

// This synthetic peer fixture exercises the real HTTP and AEAD boundary, not shipped clients.
#[tokio::test]
async fn encrypted_two_peer_join_has_no_echo_and_rotates_under_new_key() {
    let f = Fixture::new();
    let a = f.login("github-alice").await;
    let b = f.login("github-alice-renamed").await;
    let vault = create(&f, &a).await;
    let key = [54; 32];
    let old = f.usage_meta(&a).await;
    let record = |n| {
        json!({"id": Uuid::new_v4().to_string(), "occurredAtMs": 1795104000000i64,
        "kind":"llm", "purpose":"dictationPostprocess", "outcome":"succeeded", "inputTokens": n})
    };
    let mut a_local = vec![record(10)];
    let mut b_local = vec![record(7)];
    let b_pending = encrypted_usage(usage_upload(&vault, 0, 30), &key, &b_local);
    let a_pending = encrypted_usage(usage_upload(&vault, 0, 31), &key, &a_local);
    let a_commit = f.usage_put(&a, old.tag(), &a_pending).await;
    assert_eq!(a_commit.status, 200);
    assert_eq!(f.usage_put(&b, old.tag(), &b_pending).await.status, 412);
    let (_, b_commit) = sync_test_peer(&f, &b, &vault, &key, &b_local, 32).await;
    assert_eq!(b_commit.as_ref().unwrap().status, 200);
    let (reverse, no_write) = sync_test_peer(&f, &a, &vault, &key, &a_local, 33).await;
    assert_eq!(sum(&reverse), 17);
    assert!(no_write.is_none());
    assert_eq!(
        f.usage_put(&a, old.tag(), &a_pending).await.json,
        a_commit.json
    );
    assert_eq!(f.usage_meta(&b).await.json["revision"], "2");
    a_local.push(record(4));
    b_local.push(record(2));
    assert_eq!(
        sync_test_peer(&f, &a, &vault, &key, &a_local, 34)
            .await
            .1
            .unwrap()
            .status,
        200
    );
    let (merged, write) = sync_test_peer(&f, &b, &vault, &key, &b_local, 35).await;
    assert_eq!(sum(&merged), 23);
    assert_eq!(write.unwrap().status, 200);
    let (a_restored, no_write) = sync_test_peer(&f, &a, &vault, &key, &a_local, 36).await;
    assert_eq!(sum(&a_restored), 23);
    assert!(no_write.is_none());
    assert_eq!(f.usage_meta(&a).await.json["revision"], "4");

    let mut conflict = merged[0].clone();
    conflict["inputTokens"] = 0.into();
    assert!(merge_test_records(&merged, &[conflict]).is_err());
    let new_key = [55; 32];
    let new_vault = rekey(&vault, 37);
    let head = f.usage_meta(&a).await;
    let mut rotation = dual(&new_vault, head.tag(), 4, 38);
    rotation["usageSnapshot"] =
        encrypted_usage(rotation["usageSnapshot"].clone(), &new_key, &merged);
    let legacy_head = f.meta(&a).await;
    assert_eq!(f.rotate(&a, legacy_head.tag(), &rotation).await.status, 200);
    let f = f.reopen(UsageMode::Enabled);
    let head = f.usage_meta(&b).await;
    let downloaded = f.usage_download(&b, head.tag()).await;
    assert!(open_usage(downloaded.json.clone(), &key).is_err());
    assert_eq!(sum(&open_usage(downloaded.json, &new_key).unwrap()), 23);
}

fn encrypted_usage(mut value: Value, key: &[u8; 32], records: &[Value]) -> Value {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let snapshot: usage::UsageSnapshot = serde_json::from_value(value.clone()).unwrap();
    let json = serde_json::to_vec(&json!({"version":1,"records": records})).unwrap();
    let mut frame = (json.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&json);
    frame.resize(65_536, 0);
    getrandom::fill(&mut frame[json.len() + 4..]).unwrap();
    let nonce = URL_SAFE_NO_PAD.decode(&snapshot.nonce).unwrap();
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &frame,
                aad: &snapshot.aad(),
            },
        )
        .unwrap();
    value["ciphertextSha256"] = hash(&ciphertext).into();
    value["ciphertext"] = URL_SAFE_NO_PAD.encode(ciphertext).into();
    value
}

fn open_usage(value: Value, key: &[u8; 32]) -> Result<Vec<Value>, chacha20poly1305::Error> {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let snapshot: usage::UsageSnapshot = serde_json::from_value(value).unwrap();
    snapshot.validate("11").unwrap();
    let nonce = URL_SAFE_NO_PAD.decode(&snapshot.nonce).unwrap();
    let ciphertext = URL_SAFE_NO_PAD.decode(&snapshot.ciphertext).unwrap();
    let plaintext = XChaCha20Poly1305::new(key.into()).decrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: &ciphertext,
            aad: &snapshot.aad(),
        },
    )?;
    let len = u32::from_be_bytes(plaintext[..4].try_into().unwrap()) as usize;
    let payload: Value = serde_json::from_slice(&plaintext[4..4 + len]).unwrap();
    assert_eq!(payload["version"], 1);
    Ok(payload["records"].as_array().unwrap().clone())
}

async fn sync_test_peer(
    f: &Fixture,
    token: &str,
    vault: &Value,
    key: &[u8; 32],
    local: &[Value],
    nonce: u8,
) -> (Vec<Value>, Option<Reply>) {
    let head = f.usage_meta(token).await;
    let remote = open_usage(f.usage_download(token, head.tag()).await.json, key).unwrap();
    let merged = merge_test_records(&remote, local).unwrap();
    if merged == remote {
        return (merged, None);
    }
    let base = head.json["revision"].as_str().unwrap().parse().unwrap();
    let wire = encrypted_usage(usage_upload(vault, base, nonce), key, &merged);
    let result = f.usage_put(token, head.tag(), &wire).await;
    (merged, Some(result))
}

fn merge_test_records(remote: &[Value], local: &[Value]) -> Result<Vec<Value>, ()> {
    use std::collections::{BTreeMap, btree_map::Entry};
    let mut records = BTreeMap::new();
    for value in remote.iter().chain(local) {
        match records.entry(value["id"].as_str().unwrap()) {
            Entry::Vacant(slot) => {
                slot.insert(value.clone());
            }
            Entry::Occupied(slot) if slot.get() == value => {}
            Entry::Occupied(_) => return Err(()),
        }
    }
    Ok(records.into_values().collect())
}

fn sum(records: &[Value]) -> u64 {
    records
        .iter()
        .map(|item| item["inputTokens"].as_u64().unwrap())
        .sum()
}
