-- glc_v1 audit log. Append-only; the application layer never issues
-- UPDATE or DELETE against this table.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT,
    curr_hash       TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- Append-only enforcement via triggers (Leak 2 fix)
CREATE TRIGGER IF NOT EXISTS audit_log_append_only_del 
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only (deletion forbidden)');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_append_only_upd 
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only (updates forbidden)');
END;

-- Schema version table: any change to the columns above requires a
-- documented version bump. Migrations are not automatic.
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));
