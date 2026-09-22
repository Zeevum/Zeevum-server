ALTER TABLE chats ADD COLUMN last_seq INTEGER NOT NULL DEFAULT 0;

CREATE TABLE messages_new (
                              id        BLOB PRIMARY KEY NOT NULL,
                              chat_id   BLOB NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                              sender_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                              content   TEXT NOT NULL,
                              timestamp INTEGER NOT NULL,
                              is_read   INTEGER NOT NULL DEFAULT 0,
                              seq       INTEGER NOT NULL
);

INSERT INTO messages_new (id, chat_id, sender_id, content, timestamp, is_read, seq)
SELECT id,
       chat_id,
       sender_id,
       content,
    timestamp,
    is_read,
    ROW_NUMBER() OVER (PARTITION BY chat_id ORDER BY timestamp, rowid)
FROM messages;

DROP TABLE messages;

ALTER TABLE messages_new RENAME TO messages;

UPDATE chats
SET last_seq = COALESCE((SELECT MAX(seq) FROM messages WHERE chat_id = chats.id), 0);

CREATE UNIQUE INDEX idx_messages_chat_seq ON messages(chat_id, seq);