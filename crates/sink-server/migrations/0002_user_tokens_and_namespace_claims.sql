DROP INDEX users_enabled_idx;
ALTER TABLE users RENAME TO users_legacy;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    token_generation INTEGER NOT NULL DEFAULT 1 CHECK (token_generation > 0),
    auth_revision INTEGER NOT NULL DEFAULT 1 CHECK (auth_revision > 0),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO users (
    id,
    username,
    enabled,
    token_generation,
    auth_revision,
    created_at,
    updated_at
)
SELECT
    id,
    username,
    enabled,
    token_generation,
    auth_revision,
    created_at,
    updated_at
FROM users_legacy;

CREATE INDEX users_enabled_idx ON users(enabled);

CREATE TABLE user_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL COLLATE NOCASE,
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (user_id, name)
);

INSERT INTO user_tokens (
    user_id,
    name,
    token_digest,
    generation,
    created_at,
    updated_at
)
SELECT
    id,
    'default',
    token_digest,
    token_generation,
    created_at,
    updated_at
FROM users_legacy;

CREATE INDEX user_tokens_user_id_idx ON user_tokens(user_id);

DROP TABLE users_legacy;

CREATE TABLE namespace_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    fqdn TEXT NOT NULL COLLATE NOCASE UNIQUE,
    parent_id INTEGER REFERENCES namespace_claims(id) ON DELETE RESTRICT,
    depth INTEGER NOT NULL CHECK (depth > 0),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'failed', 'retrying', 'releasing')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (length(fqdn) BETWEEN 1 AND 253),
    CHECK (fqdn = lower(fqdn)),
    CHECK (substr(fqdn, 1, 1) <> '.' AND substr(fqdn, -1, 1) <> '.'),
    CHECK (instr(fqdn, '..') = 0),
    CHECK (
        (parent_id IS NULL AND depth = 1)
        OR (parent_id IS NOT NULL AND depth > 1)
    )
);

CREATE INDEX namespace_claims_user_id_idx ON namespace_claims(user_id);
CREATE INDEX namespace_claims_parent_id_idx ON namespace_claims(parent_id);
CREATE INDEX namespace_claims_state_idx ON namespace_claims(state);

CREATE TRIGGER namespace_claims_validate_parent_insert
BEFORE INSERT ON namespace_claims
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM namespace_claims AS parent
        WHERE parent.id = NEW.parent_id
          AND parent.user_id = NEW.user_id
          AND parent.depth + 1 = NEW.depth
          AND instr(NEW.fqdn, '.') > 1
          AND NEW.fqdn = substr(NEW.fqdn, 1, instr(NEW.fqdn, '.') - 1)
              || '.' || parent.fqdn
          AND parent.state <> 'releasing'
    ) THEN RAISE(ABORT, 'invalid namespace parent') END;
END;

CREATE TRIGGER namespace_claims_identity_immutable
BEFORE UPDATE OF user_id, fqdn, parent_id, depth ON namespace_claims
BEGIN
    SELECT RAISE(ABORT, 'namespace identity is immutable');
END;
