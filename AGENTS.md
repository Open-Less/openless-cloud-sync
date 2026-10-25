# OpenLess Cloud Sync

## Scope

This repository is an independent encrypted cloud-sync service. The requirements and public contract are the files linked from [docs/index.md](docs/index.md). The service uses Rust/Axum and SQLite; application integration belongs in `1-app/`. Passing local tests does not prove deployment, cross-platform acceptance, or an independent security review.

## Boundaries

- The cloud service receives encrypted configuration snapshots only. Plaintext encryption passwords, derived keys, configuration, and service API keys must never enter server interfaces, logs, or operations tools.
- GitHub is used only to establish account identity. Data isolation uses the numeric GitHub ID; never bind existing data by username.
- Use reviewed cryptographic primitives. Do not invent algorithms, downgrade to plaintext, or promise that a system is impossible to break.
- This service has a contract independent of the style-pack marketplace. Do not extend the legacy `/me/sync` endpoint into an API that sends plaintext API keys.
- Service code, protocols, and tests must remain open to source review. Deployment credentials, user data, and keys do not belong in source. Before a public release, document the license and third-party license boundaries.

## Documentation maintenance

Behavioral requirements are defined by `requirements.md`; fields and HTTP behavior by `http-api.md` and `openapi.yaml`; encrypted byte formats by `encryption-protocol.md`; application changes by `client-integration.md`. When changing a contract, also check error codes, examples, acceptance criteria, and relative links. Deployment information belongs in `docs/deployment.md`; verification evidence belongs in `docs/server-acceptance.md`.

## Development and verification

Run these checks from this directory:

```text
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo audit --deny warnings
```

Use `Cargo.lock`. The complete verification commands are in the README. Application logic is in `src/`, migrations are in `migrations/`, tests are in `tests/`, and operations templates are in `deploy/`.

Changes must not widen size, identity, or HTTPS boundaries. Do not add development identity configuration or a production authentication entry point that can switch to an arbitrary upstream. Database changes require an atomic migration, failure rollback, and compatibility verification. Production databases and environment files must not enter source, packaged artifacts, or logs.

## Contribution workflow

- Follow the required `beta -> task` flow: when a `beta` integration branch exists, start from its latest revision and create a dedicated `task/<name>` branch. Never push task commits directly to `beta` or `main`. This server repository currently has no `beta` branch, so tasks explicitly based on the server's latest `main` use a dedicated task branch from `main`.
- Submit changes through a pull request targeting `main`. Do not push directly to `main`, and do not treat a local commit as submission.
- Wait for and review every required CI check before reporting the pull request as complete or mergeable. A local pass does not replace the required CI review.
- Commit only source code, tests, build or deployment configuration, and unfinished planning documents. Remove completed reports, local build records, generated artifacts, and obsolete planning files.
- All source-code comments must be written in English.
