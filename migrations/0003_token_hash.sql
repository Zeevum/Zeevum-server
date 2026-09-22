DROP TABLE sessions;

CREATE TABLE sessions (
                          token_hash TEXT PRIMARY KEY NOT NULL, -- sha256(token), lowercase hex
                          user_id    BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          expires_at INTEGER NOT NULL
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
