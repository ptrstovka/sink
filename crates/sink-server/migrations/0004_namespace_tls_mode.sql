ALTER TABLE namespace_claims
ADD COLUMN tls_mode TEXT NOT NULL DEFAULT 'managed'
    CHECK (tls_mode IN ('managed', 'passthrough'));

CREATE INDEX namespace_claims_tls_mode_state_idx
    ON namespace_claims(tls_mode, state);

CREATE TRIGGER namespace_claims_tls_mode_immutable
BEFORE UPDATE OF tls_mode ON namespace_claims
BEGIN
    SELECT RAISE(ABORT, 'namespace TLS mode is immutable');
END;

CREATE TRIGGER namespace_claims_passthrough_state_insert
BEFORE INSERT ON namespace_claims
WHEN NEW.tls_mode = 'passthrough'
  AND NEW.state NOT IN ('active', 'releasing')
BEGIN
    SELECT RAISE(ABORT, 'passthrough namespace must be active or releasing');
END;

CREATE TRIGGER namespace_claims_passthrough_state_update
BEFORE UPDATE OF state ON namespace_claims
WHEN NEW.tls_mode = 'passthrough'
  AND NEW.state NOT IN ('active', 'releasing')
BEGIN
    SELECT RAISE(ABORT, 'passthrough namespace must be active or releasing');
END;

CREATE TRIGGER namespace_claims_passthrough_overlap_insert
BEFORE INSERT ON namespace_claims
WHEN NEW.tls_mode = 'passthrough'
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM namespace_claims AS existing
        WHERE existing.tls_mode = 'passthrough'
          AND existing.state <> 'releasing'
          AND (
              existing.fqdn = NEW.fqdn
              OR existing.fqdn = substr(NEW.fqdn, instr(NEW.fqdn, '.') + 1)
              OR NEW.fqdn = substr(existing.fqdn, instr(existing.fqdn, '.') + 1)
          )
    ) THEN RAISE(ABORT, 'overlapping passthrough namespace') END;
END;
