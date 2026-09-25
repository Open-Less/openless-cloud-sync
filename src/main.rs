use openless_cloud_sync::{
    auth::GithubVerifier,
    config::Config,
    server::{AppState, router},
    store::Store,
};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .init();
    if let Err(message) = run().await {
        tracing::error!(event = "startup_or_server_failure", reason = message);
        std::process::exit(1);
    }
}
async fn run() -> Result<(), &'static str> {
    let config = Config::from_env()?;
    if let Some(parent) = config.database.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "cannot create database directory")?;
    }
    let store = Store::open(&config.database).map_err(|_| "cannot open database")?;
    store
        .maintain()
        .await
        .map_err(|_| "database maintenance failed")?;
    let verifier = GithubVerifier::new(
        config.github_client_id.clone(),
        config.github_client_secret.clone(),
    )
    .map_err(|_| "cannot initialize GitHub verifier")?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|_| "cannot bind listener")?;
    let maintenance = store.clone();
    let worker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            if maintenance.maintain().await.is_err() {
                tracing::error!(event = "maintenance_failed");
            }
        }
    });
    let state = Arc::new(AppState::new(config, store, Arc::new(verifier)));
    tracing::info!(
        event = "service_started",
        version = env!("CARGO_PKG_VERSION")
    );
    let result = axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .map_err(|_| "HTTP server failed");
    worker.abort();
    result
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
