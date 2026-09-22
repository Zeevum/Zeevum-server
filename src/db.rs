use anyhow::{Context, Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Local, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
    SqliteSynchronous,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
use zxcvbn::Score;

#[derive(Debug)]
pub struct User {
    pub id: Uuid,
    pub user_id: i64,
    pub login: String,
    pub password: String,
    #[allow(dead_code)]
    pub created_at: DateTime<Local>,
}

pub async fn init_database(db_path: &Path) -> Result<SqlitePool> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let opts = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    Ok(pool)
}

pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub fn get_db_path() -> Result<PathBuf> {
    let base_dir = if cfg!(target_os = "windows") {
        let appdata = std::env::var("APPDATA").context("APPDATA not set")?;
        PathBuf::from(appdata.replace("Roaming", "LocalLow"))
    } else {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg)
        } else {
            let home = std::env::var("HOME").context("HOME not set")?;
            PathBuf::from(home).join(".local/share")
        }
    };
    let db_dir = base_dir.join("Zeevum").join("Zeevum-server").join("db");
    Ok(db_dir.join("database.sqlite"))
}

/// Runs inside the caller's transaction. Reading a counter instead of probing
/// for a free value removes both the collision window and the unbounded retry
/// loop the old random ids needed.
async fn allocate_user_id(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<i64> {
    sqlx::query("UPDATE user_id_seq SET last = last + 1")
        .execute(&mut **tx)
        .await
        .context("advance user id counter")?;

    let (next,): (i64,) = sqlx::query_as("SELECT last FROM user_id_seq")
        .fetch_one(&mut **tx)
        .await
        .context("read user id counter")?;

    Ok(next)
}

pub async fn add_user(pool: &SqlitePool, login: &str, raw_password: &str) -> Result<User> {
    if !validate_login(login) {
        anyhow::bail!("invalid login: must be 3-32 letters, numbers or underscores");
    }

    let entropy = zxcvbn::zxcvbn(raw_password, &[]);
    if entropy.score() < Score::Two {
        anyhow::bail!("password is too weak");
    }

    let id = Uuid::new_v4();
    let hashed_password = hash_password(raw_password).context("hashing password")?;
    let now = Utc::now().timestamp();

    // One transaction for "take an id, insert the row", so two concurrent
    // registrations can no longer race for the same value.
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("begin registration transaction")?;

    let user_id = allocate_user_id(&mut tx).await?;

    sqlx::query(
        "INSERT INTO users (id, user_id, login, password, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(login)
    .bind(&hashed_password)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await.context("commit registration")?;

    Ok(User {
        id,
        user_id,
        login: login.to_string(),
        password: hashed_password,
        created_at: Local::now(),
    })
}

pub async fn get_user_by_login(pool: &SqlitePool, login: &str) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, user_id, login, password, created_at FROM users WHERE login = ?")
            .bind(login)
            .fetch_optional(pool)
            .await?;

    if let Some(user_row) = row {
        Ok(Some(
            map_row_to_user(&user_row).expect("Error mapping User data"),
        ))
    } else {
        Ok(None)
    }
}

/// The token itself is never stored, a database gets read as a whole, a backup,
/// a misplaced disk, a stray `SELECT *`. Constant-time comparison is absent on
/// purpose, lookups go by the hash, so nothing secret is being compared.
fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

pub async fn create_session(
    pool: &SqlitePool,
    user_id: Uuid,
    duration_hours: f64,
) -> Result<(String, i64)> {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let expires_at = now + (duration_hours * 3600.0) as i64;

    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;

    Ok((token, expires_at))
}

pub async fn validate_session(
    pool: &SqlitePool,
    token: &str,
    duration_hours: f64,
) -> Result<Option<(User, i64)>> {
    let now = Utc::now().timestamp();

    let hash = token_hash(token);
    let session_row =
        sqlx::query("SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?")
            .bind(&hash)
            .bind(now)
            .fetch_optional(pool)
            .await?;

    if let Some(session_row) = session_row {
        let user_id: Uuid = session_row.try_get("user_id")?;
        let new_expires_at = now + (duration_hours * 3600.0) as i64;

        sqlx::query("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
            .bind(new_expires_at)
            .bind(&hash)
            .execute(pool)
            .await?;

        let user_row =
            sqlx::query("SELECT id, user_id, login, password, created_at FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_one(pool)
                .await?;

        return Ok(Some((map_row_to_user(&user_row)?, new_expires_at)));
    }
    Ok(None)
}

/// Nothing ever removed expired sessions, so the table grew forever, one row
/// per client start and one per dropped connection.
/// Revoking here is what stops the token being used again, the caller only
/// closes the socket.
pub async fn revoke_session(pool: &SqlitePool, token: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(token_hash(token))
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Also what a password change will want, an attacker who already has a token
/// must not keep it just because the password is no longer the weak part.
pub async fn revoke_all_sessions(pool: &SqlitePool, user_id: Uuid) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delete_expired_sessions(pool: &SqlitePool) -> Result<u64> {
    let now = Utc::now().timestamp();
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn get_user_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, user_id, login, password, created_at FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;

    if let Some(user_row) = row {
        Ok(Some(
            map_row_to_user(&user_row).expect("Error mapping User data"),
        ))
    } else {
        Ok(None)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub async fn delete_user(pool: &SqlitePool, id: &Uuid) -> Result<bool> {
    let rows = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(rows.rows_affected() > 0)
}

pub fn validate_login(nick: &str) -> bool {
    let len = nick.len();
    if !(3..=32).contains(&len) {
        return false;
    }
    nick.chars()
        .all(|char| char.is_ascii_alphanumeric() || char == '_')
}

fn map_row_to_user(row: &SqliteRow) -> Result<User> {
    let id = row.try_get("id")?;
    let user_id: i64 = row.try_get("user_id")?;
    let login: String = row.try_get("login")?;
    let password: String = row.try_get("password")?;
    let timestamp: i64 = row.try_get("created_at")?;
    let dt_utc = match DateTime::from_timestamp_secs(timestamp) {
        Some(dt) => dt,
        None => return Err(anyhow!("invalid timestamp")),
    };
    let created_at = dt_utc.with_timezone(&Local);

    Ok(User {
        id,
        user_id,
        login,
        password,
        created_at,
    })
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(phc_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Sorts a pair of users into a canonical order, so that "Alice and Bob" and
/// "Bob and Alice" resolve to the same conversation.
fn ordered_pair(a: &Uuid, b: &Uuid) -> (Uuid, Uuid) {
    if a <= b { (*a, *b) } else { (*b, *a) }
}

/// Uniqueness comes from `private_chats`, not from the hope that two requests
/// will not arrive at the same moment.
pub async fn get_or_create_private_chat(
    pool: &SqlitePool,
    user1_id: &Uuid,
    user2_id: &Uuid,
) -> Result<Uuid> {
    if user1_id == user2_id {
        anyhow::bail!("a user cannot have a direct conversation with themselves");
    }

    let (user_a, user_b) = ordered_pair(user1_id, user2_id);

    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("failed to begin transaction")?;

    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT chat_id FROM private_chats WHERE user_a = ? AND user_b = ?")
            .bind(user_a)
            .bind(user_b)
            .fetch_optional(&mut *tx)
            .await?;

    if let Some((chat_id,)) = existing {
        return Ok(chat_id);
    }

    let chat_id = Uuid::new_v4();
    let now = Utc::now().timestamp();

    sqlx::query("INSERT INTO chats (id, type, created_at) VALUES (?, 'private', ?)")
        .bind(chat_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

    // Both memberships and the pair row go in together, a chat that exists but
    // is not listed in private_chats would be orphaned on the next lookup.
    sqlx::query("INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)")
        .bind(chat_id)
        .bind(user_a)
        .bind(now)
        .execute(&mut *tx)
        .await?;

    sqlx::query("INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)")
        .bind(chat_id)
        .bind(user_b)
        .bind(now)
        .execute(&mut *tx)
        .await?;

    sqlx::query("INSERT INTO private_chats (chat_id, user_a, user_b) VALUES (?, ?, ?)")
        .bind(chat_id)
        .bind(user_a)
        .bind(user_b)
        .execute(&mut *tx)
        .await?;

    tx.commit().await.context("failed to commit private chat")?;
    Ok(chat_id)
}

pub async fn save_chat_message(
    pool: &SqlitePool,
    message_id: &Uuid,
    chat_id: &Uuid,
    sender_id: &Uuid,
    content: &str,
) -> Result<()> {
    let now = Utc::now().timestamp();

    sqlx::query("INSERT INTO messages (id, chat_id, sender_id, content, timestamp, is_read) VALUES (?, ?, ?, ?, ?, 0)")
        .bind(message_id)
        .bind(chat_id)
        .bind(sender_id)
        .bind(content)
        .bind(now)
        .execute(pool)
        .await?;

    Ok(())
}

/// Newest first, the caller is expected to reverse this before showing it.
pub async fn get_chat_history(
    pool: &SqlitePool,
    chat_id: &Uuid,
    limit: i64,
) -> Result<Vec<(Uuid, i64, String, i64, bool)>> {
    let rows = sqlx::query_as(
        "SELECT m.id, u.user_id, m.content, m.timestamp, m.is_read FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.chat_id = ? ORDER BY m.timestamp DESC LIMIT ?",
    )
    .bind(chat_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Marks a message read, but only if the reader belongs to its conversation
/// and is not its author. Returns the public id of the sender when a
/// notification is due, on the first read only, otherwise `None`.
pub async fn mark_message_as_read_checked(
    pool: &SqlitePool,
    message_id: &Uuid,
    reader_id: &Uuid,
) -> Result<Option<(Uuid, i64)>> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("failed to begin transaction")?;

    // Membership is checked here, not by the caller, the reader must belong to
    // the conversation the message is in, and must not be its author.
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT m.chat_id, m.sender_id FROM messages m
         JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.user_id = ?
         WHERE m.id = ? AND m.sender_id != ?",
    )
    .bind(reader_id)
    .bind(message_id)
    .bind(reader_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((chat_id, sender_id)) = row else {
        return Ok(None);
    };

    let result = sqlx::query("UPDATE messages SET is_read = 1 WHERE id = ? AND is_read = 0")
        .bind(message_id)
        .execute(&mut *tx)
        .await?;

    if result.rows_affected() == 0 {
        return Ok(None);
    }

    // Protocol v2 addresses everything by conversation, so the sender is not
    // enough, the client needs to know which conversation to mark.
    let (sender_user_id,): (i64,) = sqlx::query_as("SELECT user_id FROM users WHERE id = ?")
        .bind(sender_id)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Some((chat_id, sender_user_id)))
}

pub async fn get_user_by_user_id(pool: &SqlitePool, user_id: i64) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, user_id, login, password, created_at FROM users WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;

    if let Some(user_row) = row {
        Ok(Some(map_row_to_user(&user_row)?))
    } else {
        Ok(None)
    }
}

/// Returns `false` when there was nothing to accept. The `UPDATE` silently
/// affected zero rows, and the insert that followed created an accepted
/// friendship out of nothing.
pub async fn accept_friend_request(
    pool: &SqlitePool,
    acceptor: &Uuid,
    requester: &Uuid,
) -> Result<bool> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("begin accept friend request")?;

    // Strictly the direction "they asked me". Accepting a request you sent
    // yourself must not work, and neither must accepting one that was never
    // sent at all.
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'pending')",
    )
        .bind(requester)
        .bind(acceptor)
        .fetch_one(&mut *tx)
        .await?;

    if !pending {
        return Ok(false);
    }

    sqlx::query("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ?")
        .bind(requester)
        .bind(acceptor)
        .execute(&mut *tx)
        .await?;

    // The acceptor may have sent a request of their own on the way here, it is
    // moot now. Left in place it would keep showing up as an incoming request
    // from somebody who is already in the friend list.
    sqlx::query("DELETE FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'pending'")
        .bind(acceptor)
        .bind(requester)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, 'accepted') \
         ON CONFLICT DO NOTHING",
    )
    .bind(acceptor)
    .bind(requester)
    .execute(&mut *tx)
    .await?;

    tx.commit()
        .await
        .context("commit accepted friend request")?;

    Ok(true)
}

pub async fn get_friends_list(pool: &SqlitePool, user_id: &Uuid) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query(
        "SELECT u.user_id, u.login FROM friends f
         JOIN users u ON f.friend_id = u.id
         WHERE f.user_id = ? AND f.status = 'accepted'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut friends = Vec::new();
    for row in rows {
        let user_id: i64 = row.try_get("user_id")?;
        let login: String = row.try_get("login")?;
        friends.push((user_id, login));
    }

    Ok(friends)
}

pub async fn get_pending_requests(pool: &SqlitePool, user_id: &Uuid) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query(
        "SELECT u.user_id, u.login FROM friends f
        JOIN users u ON f.user_id = u.id
        WHERE f.friend_id = ? AND f.status = 'pending'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut reqs = Vec::new();
    for row in rows {
        let user_id: i64 = row.try_get("user_id")?;
        let login: String = row.try_get("login")?;
        reqs.push((user_id, login));
    }

    Ok(reqs)
}

/// A pending request does not count, and neither direction is privileged.
/// A pending request does not count, and neither direction is privileged.
pub async fn are_friends(pool: &SqlitePool, a: &Uuid, b: &Uuid) -> Result<bool> {
    let accepted: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM friends WHERE status = 'accepted' AND user_id = ? AND friend_id = ?) \
         OR EXISTS(SELECT 1 FROM friends WHERE status = 'accepted' AND user_id = ? AND friend_id = ?)",
    )
        .bind(a)
        .bind(b)
        .bind(b)
        .bind(a)
        .fetch_one(pool)
        .await?;

    Ok(accepted)
}

/// What came of a friend request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendReqOutcome {
    /// A new pending request was stored.
    Sent,
    /// The same request was already waiting, so the other side was not told again.
    AlreadyPending,
    /// The two are already friends.
    AlreadyFriends,
}

/// Requests are directional, only the recipient can accept one. An existing
/// request is not announced a second time, otherwise the command is a
/// ready-made notification pump.
/// The authorization check for everything addressed by `conv_id`. The question
/// is asked of the conversation, not of the pair, which is what lets group
/// chats reuse it unchanged.
pub async fn is_member(pool: &SqlitePool, conv_id: &Uuid, user_id: &Uuid) -> Result<bool> {
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?)",
    )
    .bind(conv_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(member)
}

/// Used to deliver a message without assuming there are exactly two participants.
pub async fn member_user_ids(pool: &SqlitePool, conv_id: &Uuid) -> Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT u.user_id FROM chat_members cm
         JOIN users u ON u.id = cm.user_id
         WHERE cm.chat_id = ?",
    )
    .bind(conv_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn add_friend_request(
    pool: &SqlitePool,
    from: &Uuid,
    to: &Uuid,
) -> Result<FriendReqOutcome> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("begin friend request")?;

    let accepted: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM friends WHERE status = 'accepted' AND user_id = ? AND friend_id = ?) \
         OR EXISTS(SELECT 1 FROM friends WHERE status = 'accepted' AND user_id = ? AND friend_id = ?)",
    )
        .bind(from)
        .bind(to)
        .bind(to)
        .bind(from)
        .fetch_one(&mut *tx)
        .await?;

    if accepted {
        return Ok(FriendReqOutcome::AlreadyFriends);
    }

    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'pending')",
    )
        .bind(from)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;

    if pending {
        return Ok(FriendReqOutcome::AlreadyPending);
    }

    sqlx::query("INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, 'pending')")
        .bind(from)
        .bind(to)
        .execute(&mut *tx)
        .await?;

    tx.commit().await.context("commit friend request")?;

    Ok(FriendReqOutcome::Sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    async fn setup_pool() -> Result<SqlitePool> {
        let opts = SqliteConnectOptions::from_str("sqlite://:memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(pool)
    }

    #[tokio::test]
    async fn test_full_flow() -> Result<()> {
        let pool = setup_pool().await?;

        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        assert!(get_user_by_login(&pool, "alice").await?.is_some());

        let c1 = get_or_create_private_chat(&pool, &alice.id, &bob.id).await?;
        let c2 = get_or_create_private_chat(&pool, &bob.id, &alice.id).await?;
        assert_eq!(c1, c2);

        let msg_id = Uuid::new_v4();
        save_chat_message(&pool, &msg_id, &c1, &alice.id, "hello").await?;
        let history = get_chat_history(&pool, &c1, 50).await?;
        assert_eq!(history.len(), 1);

        let (token, _) = create_session(&pool, alice.id, 720.0).await?;
        assert!(validate_session(&pool, &token, 720.0).await?.is_some());

        add_friend_request(&pool, &bob.id, &alice.id).await?;
        accept_friend_request(&pool, &alice.id, &bob.id).await?;
        assert_eq!(get_friends_list(&pool, &alice.id).await?.len(), 1);
        assert_eq!(get_pending_requests(&pool, &alice.id).await?.len(), 0);

        assert!(delete_user(&pool, &alice.id).await?);
        assert!(validate_session(&pool, &token, 720.0).await?.is_none());
        assert!(get_friends_list(&pool, &bob.id).await?.is_empty());
        assert!(get_user_by_login(&pool, "Alice").await?.is_none());
        Ok(())
    }

    async fn session_count(pool: &SqlitePool) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM sessions")
            .fetch_one(pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Fails if we start writing the token itself again instead of its hash.
    #[tokio::test]
    async fn session_token_is_never_stored_in_plaintext() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;

        let (token, _) = create_session(&pool, alice.id, 720.0).await?;

        // The row must not be findable by the raw token.
        let by_token: Option<(String,)> =
            sqlx::query_as("SELECT token_hash FROM sessions WHERE token_hash = ?")
                .bind(&token)
                .fetch_optional(&pool)
                .await?;
        assert!(
            by_token.is_none(),
            "raw token is stored in the database: {token}"
        );

        // It must be findable by the hash, and validation must still work.
        let by_hash: Option<(String,)> =
            sqlx::query_as("SELECT token_hash FROM sessions WHERE token_hash = ?")
                .bind(token_hash(&token))
                .fetch_optional(&pool)
                .await?;
        assert!(by_hash.is_some(), "session is not findable by token hash");
        assert!(validate_session(&pool, &token, 720.0).await?.is_some());

        Ok(())
    }

    /// Arriving with a token must not add a row. `validate_session` renews
    /// the one already there, and every extra row used to be permanent.
    #[tokio::test]
    async fn token_login_does_not_create_another_session_row() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;

        let (token, _) = create_session(&pool, alice.id, 720.0).await?;
        let after_login = session_count(&pool).await?;

        for _ in 0..5 {
            assert!(validate_session(&pool, &token, 720.0).await?.is_some());
        }

        assert_eq!(
            session_count(&pool).await?,
            after_login,
            "token login added session rows"
        );
        Ok(())
    }

    #[tokio::test]
    async fn revoked_token_stops_working() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;

        let (token, _) = create_session(&pool, alice.id, 720.0).await?;
        assert!(validate_session(&pool, &token, 720.0).await?.is_some());

        assert_eq!(revoke_session(&pool, &token).await?, 1);
        assert!(validate_session(&pool, &token, 720.0).await?.is_none());
        Ok(())
    }

    /// "Log out everywhere" has to take the other device down with it, not
    /// only the one that asked.
    #[tokio::test]
    async fn revoking_all_sessions_kills_the_other_device() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;

        let (phone, _) = create_session(&pool, alice.id, 720.0).await?;
        let (laptop, _) = create_session(&pool, alice.id, 720.0).await?;

        assert_eq!(revoke_all_sessions(&pool, alice.id).await?, 2);
        assert!(validate_session(&pool, &phone, 720.0).await?.is_none());
        assert!(validate_session(&pool, &laptop, 720.0).await?.is_none());
        Ok(())
    }

    /// A session of another user is not ours to revoke.
    #[tokio::test]
    async fn revoking_all_sessions_leaves_other_users_alone() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "another_password_456_B!").await?;

        let (alice_token, _) = create_session(&pool, alice.id, 720.0).await?;
        let (bob_token, _) = create_session(&pool, bob.id, 720.0).await?;

        assert_eq!(revoke_all_sessions(&pool, alice.id).await?, 1);
        assert!(
            validate_session(&pool, &alice_token, 720.0)
                .await?
                .is_none()
        );
        assert!(validate_session(&pool, &bob_token, 720.0).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn expired_sessions_are_deleted_and_live_ones_are_kept() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;

        let (token, _) = create_session(&pool, alice.id, 720.0).await?;
        assert_eq!(
            delete_expired_sessions(&pool).await?,
            0,
            "a live session was deleted"
        );

        // Push the expiry into the past, the row must go. Note it is the
        // timestamp that has to move behind "now", not just below the old
        // expiry, that one is still a month away.
        sqlx::query("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
            .bind(Utc::now().timestamp() - 1)
            .bind(token_hash(&token))
            .execute(&pool)
            .await?;

        assert_eq!(delete_expired_sessions(&pool).await?, 1);
        assert!(validate_session(&pool, &token, 720.0).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_msg_read_authorization() -> Result<()> {
        let pool = setup_pool().await?;

        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;
        let carol = add_user(&pool, "Carol", "carol_password_789_C!").await?;
        let chat = get_or_create_private_chat(&pool, &alice.id, &bob.id).await?;

        let msg_id = Uuid::new_v4();
        save_chat_message(&pool, &msg_id, &chat, &alice.id, "hi bob").await?;

        assert!(
            mark_message_as_read_checked(&pool, &msg_id, &carol.id)
                .await?
                .is_none()
        );
        assert!(
            mark_message_as_read_checked(&pool, &msg_id, &alice.id)
                .await?
                .is_none()
        );

        let is_read: i64 = sqlx::query_scalar("SELECT is_read FROM messages WHERE id = ?")
            .bind(msg_id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(is_read, 0);

        // The reader is told both who to notify and which conversation the
        // message belongs to.
        assert_eq!(
            mark_message_as_read_checked(&pool, &msg_id, &bob.id).await?,
            Some((chat, alice.user_id))
        );
        assert!(
            mark_message_as_read_checked(&pool, &msg_id, &bob.id)
                .await?
                .is_none()
        );
        Ok(())
    }

    /// The upgrade path, a database built by 0001 that already holds accounts
    /// must keep every existing number once 0002 has run.
    #[tokio::test]
    async fn migration_0002_preserves_existing_ids_and_chats() -> Result<()> {
        let opts = SqliteConnectOptions::from_str("sqlite://:memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;

        sqlx::raw_sql(include_str!("../migrations/0001_initial_schema.sql"))
            .execute(&pool)
            .await?;

        let alice_id = Uuid::new_v4();
        let bob_id = Uuid::new_v4();

        for (id, login, number) in [
            (alice_id, "alice", 4_242_424_i64),
            (bob_id, "bob", 9_999_999_i64),
        ] {
            sqlx::query(
                "INSERT INTO users (id, chat_id, login, password, created_at) VALUES (?, ?, ?, ?, ?)",
            )
                .bind(id)
                .bind(number)
                .bind(login)
                .bind("hash")
                .bind(0_i64)
                .execute(&pool)
                .await?;
        }

        // A conversation built the 0001 way, a chat row plus two memberships,
        // and nothing anywhere that says "these two belong together".
        let old_chat = Uuid::new_v4();
        sqlx::query("INSERT INTO chats (id, type, created_at) VALUES (?, 'private', 0)")
            .bind(old_chat)
            .execute(&pool)
            .await?;
        for member in [alice_id, bob_id] {
            sqlx::query("INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, 0)")
                .bind(old_chat)
                .bind(member)
                .execute(&pool)
                .await?;
        }

        // sqlx runs every migration inside a transaction, so 0002 must work there too.
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(include_str!("../migrations/0002_identity_model.sql"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        // Renamed, not renumbered, these numbers are already stored in other
        // people's friend lists.
        let (alice_number,): (i64,) =
            sqlx::query_as("SELECT user_id FROM users WHERE login = 'alice'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(alice_number, 4_242_424);

        // The counter continues above the highest number already in use.
        let (seq,): (i64,) = sqlx::query_as("SELECT last FROM user_id_seq")
            .fetch_one(&pool)
            .await?;
        assert_eq!(seq, 9_999_999);

        let carol = add_user(&pool, "Carol", "carol_password_789_C!").await?;
        assert_eq!(carol.user_id, 10_000_000);

        // The existing conversation is adopted, in either order. Without the
        // backfill this would open a second, empty copy of the same dialogue.
        assert_eq!(
            get_or_create_private_chat(&pool, &alice_id, &bob_id).await?,
            old_chat
        );
        assert_eq!(
            get_or_create_private_chat(&pool, &bob_id, &alice_id).await?,
            old_chat
        );

        let (chats,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chats")
            .fetch_one(&pool)
            .await?;
        assert_eq!(chats, 1);

        Ok(())
    }

    /// A pending request is not a friendship, and acceptance works from either
    /// side of the pair.
    #[tokio::test]
    async fn friendship_is_only_accepted_and_is_symmetric() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        assert!(!are_friends(&pool, &alice.id, &bob.id).await?);

        // Alice asks, Bob has not answered yet.
        add_friend_request(&pool, &alice.id, &bob.id).await?;
        assert!(!are_friends(&pool, &alice.id, &bob.id).await?);
        assert!(!are_friends(&pool, &bob.id, &alice.id).await?);

        // Bob accepts. Alice is the requester, Bob the acceptor.
        assert!(accept_friend_request(&pool, &bob.id, &alice.id).await?);
        assert!(are_friends(&pool, &alice.id, &bob.id).await?);
        assert!(are_friends(&pool, &bob.id, &alice.id).await?);

        Ok(())
    }

    /// Nobody can accept a friendship that was never offered.
    ///
    /// The old code updated zero rows and then inserted an accepted friendship
    /// anyway, so this returned success and created a friendship from nothing.
    #[tokio::test]
    async fn accept_without_a_request_changes_nothing() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        assert!(!accept_friend_request(&pool, &bob.id, &alice.id).await?);
        assert!(!are_friends(&pool, &alice.id, &bob.id).await?);

        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM friends")
            .fetch_one(&pool)
            .await?;
        assert_eq!(rows, 0, "a friendship was created out of nothing");

        Ok(())
    }

    /// Accepting a request you sent yourself must not work, the other side has
    /// not agreed to anything.
    #[tokio::test]
    async fn accepting_your_own_request_does_not_work() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        // Bob asks Alice.
        assert_eq!(
            add_friend_request(&pool, &bob.id, &alice.id).await?,
            FriendReqOutcome::Sent
        );

        // Bob cannot accept his own request.
        assert!(!accept_friend_request(&pool, &bob.id, &alice.id).await?);
        assert!(!are_friends(&pool, &alice.id, &bob.id).await?);

        // Alice can, and then it sticks.
        assert!(accept_friend_request(&pool, &alice.id, &bob.id).await?);
        assert!(are_friends(&pool, &alice.id, &bob.id).await?);

        Ok(())
    }

    /// Accepting must not leave the acceptor's own request hanging, otherwise
    /// the same person shows up both as a friend and as an incoming request.
    #[tokio::test]
    async fn accepting_clears_the_acceptors_own_moot_request() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        // Both ask each other.
        assert_eq!(
            add_friend_request(&pool, &alice.id, &bob.id).await?,
            FriendReqOutcome::Sent
        );
        assert_eq!(
            add_friend_request(&pool, &bob.id, &alice.id).await?,
            FriendReqOutcome::Sent
        );

        // Bob accepts the request Alice sent.
        assert!(accept_friend_request(&pool, &bob.id, &alice.id).await?);
        assert!(are_friends(&pool, &alice.id, &bob.id).await?);

        // Alice must not see a pending request from someone already in her
        // friend list.
        let pending = get_pending_requests(&pool, &alice.id).await?;
        assert!(
            pending.is_empty(),
            "stale request from a friend: {pending:?}"
        );

        let friends = get_friends_list(&pool, &alice.id).await?;
        assert_eq!(friends.len(), 1);

        Ok(())
    }

    /// The three outcomes, so the handler can avoid re-announcing a request
    /// that is already sitting on the other side's screen.
    #[tokio::test]
    async fn friend_request_reports_its_outcome() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        assert_eq!(
            add_friend_request(&pool, &alice.id, &bob.id).await?,
            FriendReqOutcome::Sent
        );
        assert_eq!(
            add_friend_request(&pool, &alice.id, &bob.id).await?,
            FriendReqOutcome::AlreadyPending
        );

        // The reverse direction is a separate request, not a duplicate.
        assert_eq!(
            add_friend_request(&pool, &bob.id, &alice.id).await?,
            FriendReqOutcome::Sent
        );

        assert!(accept_friend_request(&pool, &bob.id, &alice.id).await?);

        assert_eq!(
            add_friend_request(&pool, &alice.id, &bob.id).await?,
            FriendReqOutcome::AlreadyFriends
        );

        Ok(())
    }

    /// The pair is stored in a canonical order, so asking for a conversation in
    /// either direction must not produce two of them.
    #[tokio::test]
    async fn private_chat_is_one_per_pair() -> Result<()> {
        let pool = setup_pool().await?;
        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        let forward = get_or_create_private_chat(&pool, &alice.id, &bob.id).await?;
        let backward = get_or_create_private_chat(&pool, &bob.id, &alice.id).await?;
        assert_eq!(forward, backward);

        let (chats,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chats")
            .fetch_one(&pool)
            .await?;
        assert_eq!(chats, 1);

        assert!(
            get_or_create_private_chat(&pool, &alice.id, &alice.id)
                .await
                .is_err()
        );

        Ok(())
    }

    /// A number must never come back, not even after the account that held the
    /// highest one is deleted.
    #[tokio::test]
    async fn deleted_user_id_is_never_reused() -> Result<()> {
        let pool = setup_pool().await?;

        let alice = add_user(&pool, "Alice", "best_password_123_A!").await?;
        let bob = add_user(&pool, "Bob", "other_password_456_B!").await?;

        let highest = bob.user_id;
        assert!(delete_user(&pool, &bob.id).await?);
        assert!(delete_user(&pool, &alice.id).await?);

        let carol = add_user(&pool, "Carol", "carol_password_789_C!").await?;
        assert_eq!(carol.user_id, highest + 1);

        // Looking up the dead number finds nobody, it does not resurrect Alice.
        assert!(get_user_by_user_id(&pool, alice.user_id).await?.is_none());

        Ok(())
    }
}
