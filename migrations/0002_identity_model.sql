ALTER TABLE users RENAME COLUMN chat_id TO user_id;

CREATE TABLE user_id_seq (last INTEGER NOT NULL);

INSERT INTO user_id_seq (last) SELECT COALESCE(MAX(user_id), 0) FROM users;

CREATE TABLE private_chats (
                               chat_id BLOB PRIMARY KEY NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                               user_a  BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                               user_b  BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                               UNIQUE (user_a, user_b),
                               CHECK (user_a < user_b)
);

INSERT OR IGNORE INTO private_chats (chat_id, user_a, user_b)
SELECT cm1.chat_id,
       MIN(cm1.user_id, cm2.user_id),
       MAX(cm1.user_id, cm2.user_id)
FROM chat_members cm1
         JOIN chat_members cm2 ON cm2.chat_id = cm1.chat_id AND cm2.user_id > cm1.user_id
         JOIN chats c ON c.id = cm1.chat_id AND c.type = 'private';
