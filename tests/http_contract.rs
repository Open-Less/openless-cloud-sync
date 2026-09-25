mod common;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::*;
use serde_json::json;

#[tokio::test]
async fn authenticated_roundtrip_replay_rotation_delete_and_recreate() {
    let f = Fixture::new();
    let alice = f.login("github-alice").await;
    let bob = f.login("github-bob").await;
    let empty = f.meta(&alice).await;
    assert_eq!(empty.status, 200);
    assert_eq!(empty.json["state"], "empty");
    assert_eq!(empty.json["revision"], "0");
    let create = sample("11");
    let upload = f.put(&alice, empty.tag(), &create).await;
    assert_eq!(upload.status, 200);
    assert_eq!(upload.headers["idempotency-replayed"], "false");
    let active = f.meta(&alice).await;
    let download = f
        .request(
            "GET",
            "/v1/me/vault/snapshot",
            Some(&alice),
            &[("if-match", active.tag())],
            vec![],
        )
        .await;
    assert_eq!(download.status, 200);
    assert_eq!(download.json, create);
    let unchanged = f
        .request(
            "GET",
            "/v1/me/vault",
            Some(&alice),
            &[("if-none-match", active.tag())],
            vec![],
        )
        .await;
    assert_eq!(unchanged.status, 304);
    assert!(unchanged.body.is_empty());
    assert_eq!(f.meta(&bob).await.json["state"], "empty");
    let renamed = f.login("github-alice-renamed").await;
    assert_eq!(f.meta(&renamed).await.json, active.json);
    let operation_path = format!(
        "/v1/me/operations/{}",
        create["operationId"].as_str().unwrap()
    );
    assert_eq!(
        f.request("GET", &operation_path, Some(&bob), &[], vec![])
            .await
            .status,
        404
    );
    assert_eq!(
        f.request("GET", &operation_path, Some(&alice), &[], vec![])
            .await
            .json,
        upload.json
    );
    let mut change = next(&create, 3, "password_change");
    change["keyId"] = uuid::Uuid::new_v4().to_string().into();
    change["kdf"]["salt"] = URL_SAFE_NO_PAD.encode([5; 16]).into();
    assert_eq!(f.put(&alice, active.tag(), &change).await.status, 200);
    let replay = f.put(&renamed, empty.tag(), &create).await;
    assert_eq!(replay.status, 200);
    assert_eq!(replay.headers["idempotency-replayed"], "true");
    assert_eq!(replay.json, upload.json);
    let stale = next(&create, 4, "snapshot");
    assert_eq!(
        f.put(&alice, active.tag(), &stale).await.code(),
        "key_epoch_changed"
    );
    let current = f.meta(&alice).await;
    let delete = json!({"protocolVersion":1,"baseRevision":"2","operationId":uuid::Uuid::new_v4().to_string(),"expectedVaultId":create["vaultId"]});
    let headers = [
        ("if-match", current.tag()),
        ("idempotency-key", delete["operationId"].as_str().unwrap()),
        ("content-type", "application/json"),
    ];
    let deleted = f
        .request(
            "DELETE",
            "/v1/me/vault",
            Some(&alice),
            &headers,
            serde_json::to_vec(&delete).unwrap(),
        )
        .await;
    assert_eq!(deleted.status, 200);
    assert_eq!(deleted.json["committedRevision"], "3");
    assert!(deleted.json["ciphertextSha256"].is_null());
    let tombstone = f.meta(&alice).await;
    assert_eq!(tombstone.json["state"], "deleted");
    assert!(tombstone.json["keyId"].is_null());
    assert_eq!(
        f.request(
            "GET",
            "/v1/me/vault/snapshot",
            Some(&alice),
            &[("if-match", tombstone.tag())],
            vec![]
        )
        .await
        .code(),
        "vault_deleted"
    );
    let mut old_device = next(&change, 6, "snapshot");
    old_device["baseRevision"] = "3".into();
    old_device["revision"] = "4".into();
    assert_eq!(
        f.put(&alice, tombstone.tag(), &old_device).await.code(),
        "vault_deleted"
    );
    let replay_delete = f
        .request(
            "DELETE",
            "/v1/me/vault",
            Some(&alice),
            &headers,
            serde_json::to_vec(&delete).unwrap(),
        )
        .await;
    assert_eq!(replay_delete.json, deleted.json);
    let mut recreate = sample("11");
    recreate["baseRevision"] = "3".into();
    recreate["revision"] = "4".into();
    assert_eq!(f.put(&alice, tombstone.tag(), &recreate).await.status, 200);
    assert_eq!(f.meta(&alice).await.json["revision"], "4");
    let signed_out = f
        .request("DELETE", "/v1/auth/session", Some(&alice), &[], vec![])
        .await;
    assert_eq!(signed_out.status, 204);
    assert!(signed_out.body.is_empty());
    assert_eq!(f.meta(&alice).await.status, 401);
    assert_eq!(
        f.request("DELETE", "/v1/auth/session", Some(&alice), &[], vec![])
            .await
            .status,
        401
    );
}

#[tokio::test]
async fn invalid_input_never_changes_vault() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let empty = f.meta(&token).await;
    let sample = sample("11");
    for (field, value, code) in [
        ("ownerGithubId", json!("22"), "owner_mismatch"),
        ("protocolVersion", json!(2), "unsupported_protocol"),
        ("payloadSchemaVersion", json!(2), "unsupported_protocol"),
        ("nonce", json!("AAAA"), "invalid_crypto_header"),
        ("cryptoProfile", json!("weak"), "invalid_crypto_header"),
        (
            "ciphertextSha256",
            json!("0".repeat(64)),
            "invalid_crypto_header",
        ),
        ("revision", json!("01"), "invalid_request"),
        (
            "baseRevision",
            json!("18446744073709551616"),
            "invalid_request",
        ),
        ("revision", json!(2), "invalid_request"),
        (
            "vaultId",
            json!("A86D53AB-B1E1-4C22-A5D8-1A06AF6CD9FF"),
            "invalid_request",
        ),
        ("password", json!("must-not-be-accepted"), "invalid_request"),
    ] {
        let mut bad = sample.clone();
        bad[field] = value;
        let reply = f.put(&token, empty.tag(), &bad).await;
        assert_eq!(reply.code(), code, "field {field}");
        assert!(
            !String::from_utf8(reply.body)
                .unwrap()
                .contains("must-not-be-accepted")
        );
    }
    let mut bad = sample.clone();
    bad["kdf"]["parallelism"] = json!(1);
    assert_eq!(
        f.put(&token, empty.tag(), &bad).await.code(),
        "invalid_crypto_header"
    );
    let mut bad = sample.clone();
    bad["kdf"]["salt"] = json!("AB".repeat(11));
    assert_eq!(
        f.put(&token, empty.tag(), &bad).await.code(),
        "invalid_crypto_header"
    );
    let body = serde_json::to_string(&sample).unwrap();
    for duplicate in [
        body.replacen("{", "{\"protocolVersion\":1,", 1),
        body.replace("\"iterations\":3", "\"iterations\":3,\"iterations\":3"),
    ] {
        let reply = f
            .request(
                "PUT",
                "/v1/me/vault/snapshot",
                Some(&token),
                &[
                    ("if-match", empty.tag()),
                    ("idempotency-key", sample["operationId"].as_str().unwrap()),
                    ("content-type", "application/json"),
                ],
                duplicate.into_bytes(),
            )
            .await;
        assert_eq!(reply.code(), "invalid_request");
    }
    assert_eq!(f.meta(&token).await.json, empty.json);
}

#[tokio::test]
async fn preconditions_sizes_media_origins_and_https_are_enforced() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let sample = sample("11");
    let bytes = serde_json::to_vec(&sample).unwrap();
    let id = sample["operationId"].as_str().unwrap();
    assert_eq!(
        f.request("GET", "/v1/me/vault/snapshot", Some(&token), &[], vec![])
            .await
            .status,
        428
    );
    for tag in ["*", "W/\"weak\"", "\"a\",\"b\""] {
        assert_eq!(
            f.request(
                "GET",
                "/v1/me/vault/snapshot",
                Some(&token),
                &[("if-match", tag)],
                vec![]
            )
            .await
            .status,
            400
        );
    }
    assert_eq!(
        f.request(
            "PUT",
            "/v1/me/vault/snapshot",
            Some(&token),
            &[("idempotency-key", id)],
            bytes.clone()
        )
        .await
        .status,
        415
    );
    assert_eq!(
        f.request(
            "PUT",
            "/v1/me/vault/snapshot",
            Some(&token),
            &[
                ("idempotency-key", id),
                ("content-length", "25165825"),
                ("content-type", "application/json")
            ],
            vec![]
        )
        .await
        .status,
        413
    );
    assert_eq!(
        f.request(
            "DELETE",
            "/v1/me/vault",
            Some(&token),
            &[
                ("idempotency-key", id),
                ("content-type", "application/json")
            ],
            vec![32; 8193]
        )
        .await
        .status,
        413
    );
    assert_eq!(
        f.request(
            "GET",
            "/v1/me/vault",
            Some(&token),
            &[("origin", "https://evil.example")],
            vec![]
        )
        .await
        .status,
        400
    );
    assert_eq!(
        f.request(
            "GET",
            "/v1/me/vault?ownerGithubId=22",
            Some(&token),
            &[],
            vec![]
        )
        .await
        .status,
        400
    );
    assert_eq!(
        f.request(
            "GET",
            "/v1/me/vault",
            None,
            &[("x-dev-user", "11"), ("cookie", "session=anything")],
            vec![]
        )
        .await
        .status,
        401
    );
    let cors = f
        .request(
            "OPTIONS",
            "/v1/me/vault",
            None,
            &[
                ("origin", "https://allowed.example"),
                ("access-control-request-method", "PUT"),
                ("access-control-request-headers", "Authorization,If-Match"),
            ],
            vec![],
        )
        .await;
    assert_eq!(cors.status, 204);
    assert_eq!(
        cors.headers["access-control-allow-origin"],
        "https://allowed.example"
    );
    let f = Fixture::https(true);
    assert_eq!(
        f.request("GET", "/v1/capabilities", None, &[], vec![])
            .await
            .status,
        400
    );
    assert_eq!(
        f.request(
            "GET",
            "/v1/capabilities",
            None,
            &[("x-forwarded-proto", "https"), ("x-real-ip", "192.0.2.10")],
            vec![]
        )
        .await
        .status,
        200
    );
    assert_eq!(
        f.request(
            "POST",
            "/v1/auth/github",
            Some("github-alice"),
            &[
                ("x-forwarded-proto", "https,http"),
                ("x-real-ip", "192.0.2.10")
            ],
            vec![]
        )
        .await
        .status,
        400
    );
}

#[tokio::test]
async fn nonce_reuse_and_changed_requests_cannot_commit() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let empty = f.meta(&token).await;
    let create = sample("11");
    assert_eq!(f.put(&token, empty.tag(), &create).await.status, 200);
    let active = f.meta(&token).await;
    let repeat_nonce = next(&create, 2, "snapshot");
    assert_eq!(
        f.put(&token, active.tag(), &repeat_nonce).await.code(),
        "invalid_crypto_header"
    );
    let snapshot = next(&create, 3, "snapshot");
    assert_eq!(f.put(&token, active.tag(), &snapshot).await.status, 200);
    let reused = next(&snapshot, 2, "snapshot");
    let latest = f.meta(&token).await;
    assert_eq!(
        f.put(&token, latest.tag(), &reused).await.code(),
        "invalid_crypto_header"
    );
    let mut altered = create.clone();
    altered["nonce"] = URL_SAFE_NO_PAD.encode([8; 24]).into();
    assert_eq!(
        f.put(&token, empty.tag(), &altered).await.code(),
        "idempotency_key_reused"
    );
    assert_eq!(
        f.put(&token, latest.tag(), &create).await.code(),
        "idempotency_key_reused"
    );
    let mut rotate = next(&snapshot, 5, "password_change");
    assert_eq!(
        f.put(&token, latest.tag(), &rotate).await.code(),
        "invalid_crypto_header"
    );
    rotate["keyId"] = uuid::Uuid::new_v4().to_string().into();
    assert_eq!(
        f.put(&token, latest.tag(), &rotate).await.code(),
        "invalid_crypto_header"
    );
    assert_eq!(f.meta(&token).await.json["revision"], "2");
}

#[tokio::test]
async fn limits_expiry_and_auth_exchange_are_real() {
    let f = Fixture::new();
    assert_eq!(
        f.request("POST", "/v1/auth/github", Some("wrong-app"), &[], vec![])
            .await
            .code(),
        "wrong_oauth_app"
    );
    assert_eq!(
        f.request("POST", "/v1/auth/github", Some("invalid"), &[], vec![])
            .await
            .status,
        401
    );
    let token = f.login("github-alice").await;
    let db = rusqlite::Connection::open(f.dir.path().join("sync.db")).unwrap();
    db.execute(
        "UPDATE sessions SET expires_at=?1",
        [chrono::Utc::now().timestamp() - 1],
    )
    .unwrap();
    assert_eq!(f.meta(&token).await.code(), "session_expired");
    let token = f.login("github-alice").await;
    for _ in 0..120 {
        assert_eq!(f.meta(&token).await.status, 200);
    }
    let limited = f.meta(&token).await;
    assert_eq!(limited.status, 429);
    assert!(
        limited.headers["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    for _ in 0..16 {
        assert_eq!(
            f.request("POST", "/v1/auth/github", Some("invalid"), &[], vec![])
                .await
                .status,
            401
        );
    }
    assert_eq!(
        f.request("POST", "/v1/auth/github", Some("github-alice"), &[], vec![])
            .await
            .status,
        429
    );
}

#[tokio::test]
async fn maximum_padded_snapshot_is_accepted_without_truncation() {
    let f = Fixture::new();
    let token = f.login("github-alice").await;
    let empty = f.meta(&token).await;
    let mut create = sample("11");
    let bytes = vec![42; openless_cloud_sync::protocol::MAX_CIPHERTEXT];
    create["ciphertextSha256"] = openless_cloud_sync::protocol::hash(&bytes).into();
    create["ciphertext"] = URL_SAFE_NO_PAD.encode(&bytes).into();
    assert_eq!(f.put(&token, empty.tag(), &create).await.status, 200);
    let metadata = f.meta(&token).await;
    assert_eq!(metadata.json["ciphertextBytes"], bytes.len());
    let downloaded = f
        .request(
            "GET",
            "/v1/me/vault/snapshot",
            Some(&token),
            &[("if-match", metadata.tag())],
            vec![],
        )
        .await;
    assert_eq!(downloaded.json, create);
    let mut oversized = next(&create, 3, "snapshot");
    oversized["ciphertext"] = URL_SAFE_NO_PAD.encode(vec![42; bytes.len() + 1]).into();
    assert_eq!(
        f.put(&token, metadata.tag(), &oversized).await.code(),
        "payload_too_large"
    );
}
