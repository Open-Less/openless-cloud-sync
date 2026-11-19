CREATE TABLE service_usage (
    owner TEXT PRIMARY KEY REFERENCES vaults(owner),
    metadata TEXT NOT NULL,
    snapshot BLOB NOT NULL,
    CHECK (json_extract(metadata, '$.ownerGithubId') = owner)
) STRICT;
CREATE TABLE service_usage_operations (
    owner TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    receipt TEXT NOT NULL,
    committed_at INTEGER NOT NULL,
    PRIMARY KEY (owner, operation_id)
) STRICT;
CREATE INDEX service_usage_operations_expiry ON service_usage_operations(committed_at);
PRAGMA user_version = 2;
