CREATE TABLE users (
                       id       BLOB PRIMARY KEY NOT NULL,
                       chat_id  INTEGER NOT NULL UNIQUE,
                       login    TEXT COLLATE NOCASE NOT NULL UNIQUE,
                       password TEXT NOT NULL,
                       created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
                          token      TEXT PRIMARY KEY NOT NULL,
                          user_id    BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          expires_at INTEGER NOT NULL
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE chats (
                       id   BLOB PRIMARY KEY NOT NULL,
                       type TEXT NOT NULL CHECK (type IN ('private', 'group')),
                       title TEXT,
                       created_at INTEGER NOT NULL
);

CREATE TABLE chat_members (
                              chat_id   BLOB NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                              user_id   BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                              joined_at INTEGER NOT NULL,
                              PRIMARY KEY (chat_id, user_id)
);
CREATE INDEX idx_chat_members_user ON chat_members(user_id);

CREATE TABLE messages (
                          id        BLOB PRIMARY KEY NOT NULL,
                          chat_id   BLOB NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                          sender_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          content   TEXT NOT NULL,
                          timestamp INTEGER NOT NULL,
                          is_read   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_messages_chat_ts ON messages(chat_id, timestamp);

CREATE TABLE friends (
                         user_id   BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                         friend_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                         status    TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
                         PRIMARY KEY (user_id, friend_id)
);
CREATE INDEX idx_friends_target ON friends(friend_id, status);