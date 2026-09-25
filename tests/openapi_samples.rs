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
    let delete = json!({"protocolVersion":1,"baseRevision":"1","operationId":uuid::Uuid::new_v4().to_string(),"expectedVaultId":create["vaultId"]});
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
    assert_eq!(samples.len(), 13);
}
