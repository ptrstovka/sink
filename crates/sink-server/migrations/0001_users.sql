CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    token_generation INTEGER NOT NULL DEFAULT 1 CHECK (token_generation > 0),
    auth_revision INTEGER NOT NULL DEFAULT 1 CHECK (auth_revision > 0),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX users_enabled_idx ON users(enabled);
