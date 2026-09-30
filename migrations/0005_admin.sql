ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

ALTER TABLE users ADD COLUMN last_seen INTEGER;

CREATE TABLE admin_audit (
                             id      INTEGER PRIMARY KEY AUTOINCREMENT,
                             at      INTEGER NOT NULL,
                             admin   TEXT    NOT NULL,
                             action  TEXT    NOT NULL,
                             target  TEXT,
                             detail  TEXT
);
CREATE INDEX idx_admin_audit_at ON admin_audit(at);
