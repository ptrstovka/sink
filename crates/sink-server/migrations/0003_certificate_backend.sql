CREATE TABLE certificate_accounts (
    provider TEXT NOT NULL,
    account_scope TEXT NOT NULL,
    external_account_id TEXT NOT NULL,
    private_state BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (provider, account_scope),
    CHECK (provider = 'cloudflare'),
    CHECK (length(account_scope) BETWEEN 1 AND 2048),
    CHECK (length(external_account_id) BETWEEN 1 AND 2048),
    CHECK (length(private_state) > 0)
);

CREATE TABLE managed_certificates (
    target TEXT PRIMARY KEY COLLATE NOCASE,
    target_kind TEXT NOT NULL,
    provider TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    certificate_chain_pem BLOB,
    private_key_pem BLOB,
    not_before INTEGER,
    not_after INTEGER,
    retry_at INTEGER,
    cooldown_until INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL,
    CHECK (target_kind IN ('base', 'namespace')),
    CHECK (provider = 'cloudflare'),
    CHECK (lifecycle_state IN ('pending', 'ready', 'retry_scheduled', 'failed', 'retained')),
    CHECK (length(target) BETWEEN 1 AND 253),
    CHECK (target = lower(target)),
    CHECK (substr(target, 1, 1) <> '.' AND substr(target, -1, 1) <> '.'),
    CHECK (instr(target, '..') = 0),
    CHECK (updated_at >= 0),
    CHECK (
        (lifecycle_state IN ('ready', 'retained')
            AND certificate_chain_pem IS NOT NULL
            AND length(certificate_chain_pem) > 0
            AND private_key_pem IS NOT NULL
            AND length(private_key_pem) > 0
            AND not_before IS NOT NULL
            AND not_after IS NOT NULL
            AND not_before >= 0
            AND not_after > not_before
            AND retry_at IS NULL
            AND cooldown_until IS NULL)
        OR
        (lifecycle_state = 'retry_scheduled'
            AND certificate_chain_pem IS NULL
            AND private_key_pem IS NULL
            AND not_before IS NULL
            AND not_after IS NULL
            AND retry_at IS NOT NULL
            AND retry_at >= 0
            AND (cooldown_until IS NULL OR cooldown_until >= 0))
        OR
        (lifecycle_state IN ('pending', 'failed')
            AND certificate_chain_pem IS NULL
            AND private_key_pem IS NULL
            AND not_before IS NULL
            AND not_after IS NULL
            AND retry_at IS NULL
            AND cooldown_until IS NULL)
    )
);

CREATE INDEX managed_certificates_state_idx
    ON managed_certificates(lifecycle_state);
CREATE INDEX managed_certificates_expiry_idx
    ON managed_certificates(not_after)
    WHERE lifecycle_state IN ('ready', 'retained');

CREATE TABLE certificate_orders (
    target TEXT PRIMARY KEY COLLATE NOCASE
        REFERENCES managed_certificates(target) ON DELETE RESTRICT,
    target_kind TEXT NOT NULL,
    provider TEXT NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_id TEXT,
    reason TEXT NOT NULL,
    order_state TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    consecutive_failures INTEGER NOT NULL,
    retry_at INTEGER,
    cooldown_until INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL,
    CHECK (target_kind IN ('base', 'namespace')),
    CHECK (provider = 'cloudflare'),
    CHECK (owner_kind IN ('platform', 'user')),
    CHECK (reason IN ('base_provisioning', 'namespace_claim', 'renewal')),
    CHECK (order_state IN ('queued', 'in_progress', 'retry_scheduled', 'succeeded', 'failed')),
    CHECK (length(target) BETWEEN 1 AND 253),
    CHECK (target = lower(target)),
    CHECK (attempts >= 0 AND attempts <= 4294967295),
    CHECK (consecutive_failures >= 0 AND consecutive_failures <= 4294967295),
    CHECK (updated_at >= 0),
    CHECK (last_error IS NULL OR length(last_error) <= 1024),
    CHECK (
        (target_kind = 'base' AND owner_kind = 'platform' AND owner_id IS NULL
            AND reason IN ('base_provisioning', 'renewal'))
        OR
        (target_kind = 'namespace' AND owner_kind = 'user'
            AND owner_id IS NOT NULL AND length(owner_id) BETWEEN 1 AND 128
            AND reason IN ('namespace_claim', 'renewal'))
    ),
    CHECK (
        (order_state = 'retry_scheduled' AND retry_at IS NOT NULL AND retry_at >= 0)
        OR
        (order_state <> 'retry_scheduled' AND retry_at IS NULL)
    ),
    CHECK (cooldown_until IS NULL OR cooldown_until >= 0)
);

CREATE INDEX certificate_orders_state_idx ON certificate_orders(order_state);
CREATE INDEX certificate_orders_owner_pending_idx
    ON certificate_orders(owner_id, order_state)
    WHERE owner_kind = 'user'
      AND order_state IN ('queued', 'in_progress', 'retry_scheduled');

CREATE TRIGGER managed_certificates_identity_immutable
BEFORE UPDATE OF target, target_kind, provider ON managed_certificates
BEGIN
    SELECT RAISE(ABORT, 'certificate identity is immutable');
END;

CREATE TRIGGER certificate_orders_target_identity_immutable
BEFORE UPDATE OF target, target_kind, provider ON certificate_orders
BEGIN
    SELECT RAISE(ABORT, 'certificate order target identity is immutable');
END;

CREATE TRIGGER certificate_orders_active_cycle_identity_immutable
BEFORE UPDATE OF owner_kind, owner_id, reason ON certificate_orders
WHEN NOT (
        OLD.owner_kind IS NEW.owner_kind
        AND OLD.owner_id IS NEW.owner_id
        AND OLD.reason IS NEW.reason
    )
    AND NOT (
        OLD.order_state IN ('succeeded', 'failed')
        AND NEW.order_state IN ('queued', 'in_progress')
    )
BEGIN
    SELECT RAISE(ABORT, 'active certificate order cycle identity is immutable');
END;
