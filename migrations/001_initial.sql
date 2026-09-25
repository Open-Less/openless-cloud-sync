CREATE TABLE IF NOT EXISTS vaults (
    owner TEXT PRIMARY KEY,
    metadata TEXT NOT NULL,
    snapshot BLOB,
    CHECK (json_extract(metadata, '$.ownerGithubId') = owner)
) STRICT;
CREATE TABLE IF NOT EXISTS operations (
    owner TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    receipt TEXT NOT NULL,
    committed_at INTEGER NOT NULL,
    PRIMARY KEY (owner, operation_id)
) STRICT;
CREATE INDEX IF NOT EXISTS operations_expiry ON operations(committed_at);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS rate_events (
    bucket TEXT NOT NULL,
    identity TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS rate_lookup ON rate_events(bucket, identity, occurred_at);
CREATE INDEX IF NOT EXISTS rate_expiry ON rate_events(occurred_at);
-- Non-content commitments prevent reuse of vault IDs, key IDs, salts and nonces.
CREATE TABLE IF NOT EXISTS used_values (
    owner TEXT NOT NULL,
    scope TEXT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY(owner, scope, digest)
) STRICT;
PRAGMA user_version = 1;
