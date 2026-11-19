mod common;
use common::*;
use serde_json::json;

#[tokio::test]
async fn export_contract_samples() {
    let f = Fixture::new();
    let mut samples = vec![];
    let mut record = |path: &str, method: &str, reply: &Reply| {
        let headers = reply
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), json!(v.to_str().unwrap())))
            .collect::<serde_json::Map<_, _>>();
        samples.push(json!({"path":path,"method":method,"status":reply.status.to_string(),"headers":headers,"body":reply.json}));
    };
    record(
        "/v1/capabilities",
        "get",
        &f.request("GET", "/v1/capabilities", None, &[], vec![])
            .await,
    );
    let auth = f
        .request("POST", "/v1/auth/github", Some("github-alice"), &[], vec![])
        .await;
    record("/v1/auth/github", "post", &auth);
    let token = auth.json["accessToken"].as_str().unwrap();
    let empty = f.meta(token).await;
    record("/v1/me/vault", "get", &empty);
    record(
        "/v1/me/vault/snapshot",
        "get",
        &f.request(
            "GET",
            "/v1/me/vault/snapshot",
            Some(token),
            &[("if-match", empty.tag())],
            vec![],
        )
        .await,
    );
    let create = sample("11");
    record(
        "/v1/me/vault/snapshot",
        "put",
        &f.put(token, empty.tag(), &create).await,
    );
    let meta = f.meta(token).await;
    record("/v1/me/vault", "get", &meta);
    record(
        "/v1/me/vault",
        "get",
        &f.request(
            "GET",
            "/v1/me/vault",
            Some(token),
            &[("if-none-match", meta.tag())],
            vec![],
        )
        .await,
    );
    record(
        "/v1/me/vault/snapshot",
        "get",
        &f.request(
            "GET",
            "/v1/me/vault/snapshot",
            Some(token),
            &[("if-match", meta.tag())],
            vec![],
        )
        .await,
    );
    record(
        "/v1/me/operations/{operationId}",
        "get",
        &f.request(
            "GET",
            &format!(
                "/v1/me/operations/{}",
                create["operationId"].as_str().unwrap()
            ),
            Some(token),
            &[],
            vec![],
        )
        .await,
    );
    record(
        FEATURE,
        "get",
        &f.request("GET", FEATURE, None, &[], vec![]).await,
    );
    let empty_usage = f.usage_meta(token).await;
    record(USAGE, "get", &empty_usage);
    record(
        USAGE_SNAPSHOT,
        "get",
        &f.usage_download(token, empty_usage.tag()).await,
    );
    let usage = usage_upload(&create, 0, 3);
    record(
        USAGE_SNAPSHOT,
        "put",
        &f.usage_put(token, empty_usage.tag(), &usage).await,
    );
    let current_usage = f.usage_meta(token).await;
    record(USAGE, "get", &current_usage);
    record(
        USAGE,
        "get",
        &f.request(
            "GET",
            USAGE,
            Some(token),
            &[("if-none-match", current_usage.tag())],
            vec![],
        )
        .await,
    );
    record(
        USAGE_SNAPSHOT,
        "get",
        &f.usage_download(token, current_usage.tag()).await,
    );
    record(
        "/v1/me/vault/usage/operations/{operationId}",
        "get",
        &f.operation(token, true, &usage["operationId"]).await,
    );
    let new = rekey(&create, 4);
    record(VAULT_SNAPSHOT, "put", &f.put(token, meta.tag(), &new).await);
    let rotate = dual(&new, current_usage.tag(), 1, 5);
    record(ROTATE, "put", &f.rotate(token, meta.tag(), &rotate).await);
    record(ROTATE, "put", &f.rotate(token, meta.tag(), &rotate).await);
    let meta = f.meta(token).await;
    let delete = json!({"protocolVersion":1,"baseRevision":"2","operationId":uuid::Uuid::new_v4().to_string(),"expectedVaultId":create["vaultId"]});
    record(
        "/v1/me/vault",
        "delete",
        &f.request(
            "DELETE",
            "/v1/me/vault",
            Some(token),
            &[
                ("if-match", meta.tag()),
                ("idempotency-key", delete["operationId"].as_str().unwrap()),
                ("content-type", "application/json"),
            ],
            serde_json::to_vec(&delete).unwrap(),
        )
        .await,
    );
    record("/v1/me/vault", "get", &f.meta(token).await);
    record(
        "/v1/auth/session",
        "delete",
        &f.request("DELETE", "/v1/auth/session", Some(token), &[], vec![])
            .await,
    );
    record("/v1/me/vault", "get", &f.meta(token).await);
    if let Ok(path) = std::env::var("SYNC_CONTRACT_SAMPLES") {
        std::fs::write(path, serde_json::to_vec(&samples).unwrap()).unwrap();
    }
    assert_eq!(samples.len(), 24);
}
