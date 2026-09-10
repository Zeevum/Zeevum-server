use anyhow::{Context, Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Local, Utc};
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
    SqliteSynchronous,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zxcvbn::Score;

#[derive(Debug)]
#[allow(dead_code)]
pub struct User {
    pub id: Uuid,
    pub chat_id: i64,
    pub login: String,
    pub password: String,
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

async fn generate_unique_chat_id(pool: &SqlitePool) -> i64 {
    loop {
        let id = (rand::random::<u32>() % 9000000 + 1000000) as i64;

        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE chat_id = ?)")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap_or(true);

        if !exists {
            return id;
        }
    }
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
    let chat_id = generate_unique_chat_id(pool).await;
    let hashed_password = hash_password(raw_password).expect("Error while hashing password!");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before epoch")
        .as_secs() as i64;

    sqlx::query(
        "INSERT INTO users (id, chat_id, login, password, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(chat_id)
    .bind(login)
    .bind(&hashed_password)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(User {
        id,
        chat_id,
        login: login.to_string(),
        password: hashed_password,
        created_at: DateTime::from(SystemTime::now()),
    })
}

pub async fn get_user_by_login(pool: &SqlitePool, login: &str) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, chat_id, login, password, created_at FROM users WHERE login = ?")
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

pub async fn create_session(
    pool: &SqlitePool,
    user_id: Uuid,
    duration_hours: f64,
) -> Result<(String, i64)> {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let expires_at = now + (duration_hours * 3600.0) as i64;

    sqlx::query("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&token)
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
) -> Result<Option<User>> {
    let now = Utc::now().timestamp();

    let session_row =
        sqlx::query("SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?")
            .bind(token)
            .bind(now)
            .fetch_optional(pool)
            .await?;

    if let Some(session_row) = session_row {
        let user_id: Uuid = session_row.try_get("user_id")?;
        let new_expires_at = now + (duration_hours * 3600.0) as i64;

        sqlx::query("UPDATE sessions SET expires_at = ? WHERE token = ?")
            .bind(new_expires_at)
            .bind(token)
            .execute(pool)
            .await?;

        let user_row =
            sqlx::query("SELECT id, chat_id, login, password, created_at FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_one(pool)
                .await?;

        return Ok(Some(map_row_to_user(&user_row)?));
    }
    Ok(None)
}

pub async fn get_user_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, chat_id, login, password, created_at FROM users WHERE id = ?")
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
    let chat_id: i64 = row.try_get("chat_id")?;
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
        chat_id,
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

pub async fn get_or_create_private_chat(
    pool: &SqlitePool,
    user1_id: &Uuid,
    user2_id: &Uuid,
) -> Result<Uuid> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("failed to begin transaction")?;

    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT c.id FROM chats c
            JOIN chat_members cm1 ON c.id = cm1.chat_id AND cm1.user_id = ?
            JOIN chat_members cm2 ON c.id = cm2.chat_id AND cm2.user_id = ?
            WHERE c.type = 'private'",
    )
    .bind(user1_id)
    .bind(user2_id)
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

    sqlx::query("INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)")
        .bind(chat_id)
        .bind(user1_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

    sqlx::query("INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)")
        .bind(chat_id)
        .bind(user2_id)
        .bind(now)
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

pub async fn get_chat_history(
    pool: &SqlitePool,
    chat_id: &Uuid,
    limit: i64,
) -> Result<Vec<(Uuid, Uuid, String, i64, bool)>> {
    let rows = sqlx::query_as(
        "SELECT id, `sender_id`, content, timestamp, is_read FROM messages
            WHERE chat_id = ? ORDER BY timestamp DESC LIMIT ?",
    )
    .bind(chat_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Помечает сообщение прочитанным, только если reader — участник чата этого
/// сообщения и не его автор. Возвращает chat_id отправителя, если уведомить
/// нужно (только что прочитано впервые), иначе None.
pub async fn mark_message_as_read_checked(
    pool: &SqlitePool,
    message_id: &Uuid,
    reader_id: &Uuid,
) -> Result<Option<i64>> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .context("failed to begin transaction")?;

    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT m.sender_id FROM messages m
         JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.user_id = ?
         WHERE m.id = ? AND m.sender_id != ?",
    )
    .bind(reader_id)
    .bind(message_id)
    .bind(reader_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((sender_id,)) = row else {
        return Ok(None);
    };

    let result = sqlx::query("UPDATE messages SET is_read = 1 WHERE id = ? AND is_read = 0")
        .bind(message_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    if result.rows_affected() > 0 {
        let sender = get_user_by_id(pool, sender_id).await?;
        Ok(sender.map(|u| u.chat_id))
    } else {
        Ok(None)
    }
}

pub async fn get_user_by_chat_id(pool: &SqlitePool, chat_id: &i64) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, chat_id, login, password, created_at FROM users WHERE chat_id = ?")
            .bind(chat_id)
            .fetch_optional(pool)
            .await?;

    if let Some(user_row) = row {
        Ok(Some(map_row_to_user(&user_row)?))
    } else {
        Ok(None)
    }
}

pub async fn accept_friend_request(
    pool: &SqlitePool,
    user_id: &Uuid,
    friend_id: &Uuid,
) -> Result<()> {
    sqlx::query("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ?")
        .bind(friend_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'accepted')",
    )
    .bind(user_id)
    .bind(friend_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_friends_list(pool: &SqlitePool, user_id: &Uuid) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query(
        "SELECT u.chat_id, u.login FROM friends f
         JOIN users u ON f.friend_id = u.id
         WHERE f.user_id = ? AND f.status = 'accepted'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut friends = Vec::new();
    for row in rows {
        let chat_id: i64 = row.try_get("chat_id")?;
        let login: String = row.try_get("login")?;
        friends.push((chat_id, login));
    }

    Ok(friends)
}

pub async fn get_pending_requests(pool: &SqlitePool, user_id: &Uuid) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query(
        "SELECT u.chat_id, u.login FROM friends f
        JOIN users u ON f.user_id = u.id
        WHERE f.friend_id = ? AND f.status = 'pending'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut reqs = Vec::new();
    for row in rows {
        let chat_id: i64 = row.try_get("chat_id")?;
        let login: String = row.try_get("login")?;
        reqs.push((chat_id, login));
    }

    Ok(reqs)
}

pub async fn add_friend_request(pool: &SqlitePool, user_id: &Uuid, friend_id: &Uuid) -> Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'pending')",
    )
    .bind(user_id)
    .bind(friend_id)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    async fn setup_pool() -> Result<SqlitePool> {
        let opts =
            SqliteConnectOptions::from_str("sqlite://:memory:")?.foreign_keys(true);
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

        assert_eq!(
            mark_message_as_read_checked(&pool, &msg_id, &bob.id).await?,
            Some(alice.chat_id)
        );
        assert!(
            mark_message_as_read_checked(&pool, &msg_id, &bob.id)
                .await?
                .is_none()
        );
        Ok(())
    }
}
