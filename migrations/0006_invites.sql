CREATE TABLE invite_codes (
                              code       TEXT PRIMARY KEY,
                              created_at INTEGER NOT NULL,
                              expires_at INTEGER,
                              used_by    TEXT,
                              used_at    INTEGER
);
