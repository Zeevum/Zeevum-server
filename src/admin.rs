//! Admin commands, run from a shell on the host that runs the server.
//!
//! Nothing in here travels over the wire. The reasoning is in
//! `ADMIN-PROPOSAL.md`: admin frames would end up in every client that never
//! calls them, and a leaked ordinary session token would then open the admin
//! side as well. Access to the shell *is* the authorisation, so there is no
//! login here.
//!
//! The boundary is the whole point of the module: an admin manages users and
//! never sees a conversation. That is not a promise left in a comment, the
//! tests read every statement in [`ALL_QUERIES`] and check it.

use anyhow::{Context, Result, anyhow, bail};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chrono::{Local, TimeZone, Utc};
use sqlx::SqlitePool;

use crate::config::Config;
use crate::db;

// ---------------------------------------------------------------------------
// Every statement this side can issue, in one place so that the tests can
// read them and hold the module to the boundary it claims.
// ---------------------------------------------------------------------------

const COUNT_ADMINS: &str = "SELECT COUNT(*) FROM users WHERE is_admin = 1";
const COUNT_USERS: &str = "SELECT COUNT(*) FROM users";
const COUNT_CHATS: &str = "SELECT COUNT(*) FROM chats";
const COUNT_SESSIONS: &str = "SELECT COUNT(*) FROM sessions";
const COUNT_SESSIONS_OF: &str = "SELECT COUNT(*) FROM sessions WHERE user_id = ?";
const USER_BY_LOGIN: &str =
    "SELECT id, user_id, login, created_at, last_seen, is_admin FROM users WHERE login = ?";
const LIST_USERS: &str =
    "SELECT id, user_id, login, created_at, last_seen, is_admin FROM users ORDER BY user_id";
const PROMOTE: &str = "UPDATE users SET is_admin = 1 WHERE login = ?";
const DEMOTE: &str = "UPDATE users SET is_admin = 0 WHERE login = ?";
const SET_TEMPORARY_PASSWORD: &str =
    "UPDATE users SET password = ?, must_change_password = 1 WHERE login = ?";
const DROP_SESSIONS: &str = "DELETE FROM sessions WHERE user_id = ?";
const LIST_SESSIONS_OF: &str = "SELECT token_hash, expires_at FROM sessions WHERE user_id = ?";
const AUDIT: &str =
    "INSERT INTO admin_audit (at, admin, action, target, detail) VALUES (?, ?, ?, ?, ?)";
const READ_AUDIT: &str =
    "SELECT at, admin, action, target, detail FROM admin_audit ORDER BY id DESC LIMIT ?";

/// When, who, what, on whom, and why it failed.
type AuditRow = (i64, String, String, Option<String>, Option<String>);

/// What the tests hold this module to. Kept next to the statements it lists,
const INSERT_INVITE: &str =
    "INSERT INTO invite_codes (code, created_at, expires_at) VALUES (?, ?, ?)";
const LIST_INVITES: &str = "SELECT i.code, i.created_at, i.expires_at, i.used_at, u.login \
                            FROM invite_codes i LEFT JOIN users u ON u.id = i.used_by \
                            ORDER BY i.created_at DESC";
const REVOKE_INVITE: &str = "DELETE FROM invite_codes WHERE code = ? AND used_by IS NULL";

/// and the statements are only ever used through these constants, so the list
/// cannot fall behind the code.
pub const ALL_QUERIES: &[(&str, &str)] = &[
    ("count_admins", COUNT_ADMINS),
    ("count_users", COUNT_USERS),
    ("count_chats", COUNT_CHATS),
    ("count_sessions", COUNT_SESSIONS),
    ("count_sessions_of", COUNT_SESSIONS_OF),
    ("user_by_login", USER_BY_LOGIN),
    ("list_users", LIST_USERS),
    ("promote", PROMOTE),
    ("demote", DEMOTE),
    ("set_temporary_password", SET_TEMPORARY_PASSWORD),
    ("drop_sessions", DROP_SESSIONS),
    ("list_sessions_of", LIST_SESSIONS_OF),
    ("audit", AUDIT),
    ("read_audit", READ_AUDIT),
    ("insert_invite", INSERT_INVITE),
    ("list_invites", LIST_INVITES),
    ("revoke_invite", REVOKE_INVITE),
];

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// One row of `list-users` and the head of `show-user`.
struct UserRow {
    id: uuid::Uuid,
    user_id: i64,
    login: String,
    created_at: i64,
    last_seen: Option<i64>,
    is_admin: bool,
}

async fn user_by_login(pool: &SqlitePool, login: &str) -> Result<UserRow> {
    let row: (uuid::Uuid, i64, String, i64, Option<i64>, i32) = sqlx::query_as(USER_BY_LOGIN)
        .bind(login)
        .fetch_optional(pool)
        .await?
        .with_context(|| format!("no such user: {login}"))?;

    Ok(UserRow {
        id: row.0,
        user_id: row.1,
        login: row.2,
        created_at: row.3,
        last_seen: row.4,
        is_admin: row.5 != 0,
    })
}

async fn count(pool: &SqlitePool, sql: &'static str) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as(sql).fetch_one(pool).await?;
    Ok(n)
}

/// A stamp the reader can use, or a dash when nobody has been here yet.
fn stamp(seconds: Option<i64>) -> String {
    match seconds {
        Some(s) => Local
            .timestamp_opt(s, 0)
            .single()
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| s.to_string()),
        None => "-".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// The first admin. Refuses once there is one, because this is how the very
/// first account is raised and not a way to hand the role around afterwards.
pub async fn promote(pool: &SqlitePool, login: &str) -> Result<()> {
    if count(pool, COUNT_ADMINS).await? > 0 {
        bail!(
            "an admin already exists; promote is only for the first one, demote before naming another"
        );
    }

    let user = user_by_login(pool, login).await?;
    sqlx::query(PROMOTE).bind(login).execute(pool).await?;

    println!("{login} (id {}) is now the admin.", user.user_id);
    Ok(())
}

pub async fn demote(pool: &SqlitePool, login: &str) -> Result<()> {
    let user = user_by_login(pool, login).await?;
    if !user.is_admin {
        bail!("{login} is not an admin");
    }

    sqlx::query(DEMOTE).bind(login).execute(pool).await?;
    println!("{login} is no longer the admin.");
    Ok(())
}

pub async fn list_users(pool: &SqlitePool) -> Result<()> {
    let rows: Vec<(uuid::Uuid, i64, String, i64, Option<i64>, i32)> =
        sqlx::query_as(LIST_USERS).fetch_all(pool).await?;

    if rows.is_empty() {
        println!("No users.");
        return Ok(());
    }

    println!(
        "{:<6} {:<24} {:>20} {:>20}  admin",
        "id", "login", "registered", "last seen"
    );
    for (_, user_id, login, created_at, last_seen, is_admin) in rows {
        println!(
            "{:<6} {:<24} {:>20} {:>20}  {}",
            user_id,
            login,
            stamp(Some(created_at)),
            stamp(last_seen),
            if is_admin != 0 { "yes" } else { "" }
        );
    }
    Ok(())
}

pub async fn show_user(pool: &SqlitePool, login: &str) -> Result<()> {
    let user = user_by_login(pool, login).await?;
    let sessions: i64 = count_of(pool, &user.id).await?;

    println!("login:       {}", user.login);
    println!("user_id:     {}", user.user_id);
    println!("registered:  {}", stamp(Some(user.created_at)));
    println!("last seen:   {}", stamp(user.last_seen));
    println!("admin:       {}", if user.is_admin { "yes" } else { "no" });
    println!("sessions:    {sessions}");
    Ok(())
}

pub async fn list_sessions(pool: &SqlitePool, login: &str) -> Result<()> {
    let user = user_by_login(pool, login).await?;
    let rows: Vec<(String, i64)> = sqlx::query_as(LIST_SESSIONS_OF)
        .bind(user.id)
        .fetch_all(pool)
        .await?;

    if rows.is_empty() {
        println!("{login} has no active sessions.");
        return Ok(());
    }

    // A fingerprint, not the hash: the hash is the credential, and there is
    // no reason to put a usable one on a terminal.
    for (hash, expires_at) in rows {
        println!(
            "{}  expires {}",
            &hash[..hash.len().min(8)],
            stamp(Some(expires_at))
        );
    }
    Ok(())
}

/// Everything the user has, everywhere. This is the answer to a compromised
/// account that does not involve deleting it.
pub async fn revoke_sessions(pool: &SqlitePool, login: &str) -> Result<()> {
    let user = user_by_login(pool, login).await?;
    let removed = sqlx::query(DROP_SESSIONS)
        .bind(user.id)
        .execute(pool)
        .await?;

    println!("{} session(s) ended for {login}.", removed.rows_affected());
    Ok(())
}

/// A password cannot be read back, it is an argon2 hash, so helping someone
/// in can only mean setting a new one. Temporary is what makes that honest:
/// the admin knows the password until the user changes it, and the flag makes
/// sure the server does not quietly allow it to stay that way.
pub async fn reset_password(pool: &SqlitePool, login: &str) -> Result<()> {
    let _user = user_by_login(pool, login).await?;

    let temporary = random_code();
    let hash = db::hash_password(&temporary).context("hashing the temporary password")?;

    sqlx::query(SET_TEMPORARY_PASSWORD)
        .bind(&hash)
        .bind(login)
        .execute(pool)
        .await?;

    // The old tokens are still out there and still work.
    let removed = sqlx::query(DROP_SESSIONS)
        .bind(_user.id)
        .execute(pool)
        .await?;

    println!("Temporary password for {login}: {temporary}");
    println!("They must change it at the next login.");
    if removed.rows_affected() > 0 {
        println!("{} existing session(s) ended.", removed.rows_affected());
    }
    Ok(())
}

/// The log of what has been done, and of what was refused. Reading it is
/// itself a command, so it is recorded too: an audit nobody can read is half
/// an audit, and one that hides who read it is hiding the wrong thing.
pub async fn audit(pool: &SqlitePool, limit: i64) -> Result<()> {
    let rows: Vec<AuditRow> = sqlx::query_as(READ_AUDIT)
        .bind(limit)
        .fetch_all(pool)
        .await?;

    if rows.is_empty() {
        println!("Nothing has been done yet.");
        return Ok(());
    }

    for (at, admin, action, target, detail) in rows {
        let who = target.unwrap_or_else(|| "-".to_string());
        match detail {
            Some(d) => println!(
                "{}  {:<12} {:<16} {:<16} refused: {d}",
                stamp(Some(at)),
                admin,
                action,
                who
            ),
            None => println!("{}  {:<12} {:<16} {}", stamp(Some(at)), admin, action, who),
        }
    }
    Ok(())
}

/// Whole numbers about the server, never about a person. Message counts are
/// left out on purpose: they would be the one figure here that says something
/// about what people wrote to each other, and it buys nothing.
pub async fn stats(pool: &SqlitePool) -> Result<()> {
    println!("users:       {}", count(pool, COUNT_USERS).await?);
    println!("admins:      {}", count(pool, COUNT_ADMINS).await?);
    println!("chats:       {}", count(pool, COUNT_CHATS).await?);
    println!("sessions:    {}", count(pool, COUNT_SESSIONS).await?);
    Ok(())
}

async fn count_of(pool: &SqlitePool, id: &uuid::Uuid) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as(COUNT_SESSIONS_OF)
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Random, and uniform: bytes outside the alphabet are thrown away rather
/// than folded, which a modulo would not do.
fn random_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const LENGTH: usize = 16;

    let mut rng = OsRng;
    let mut out = String::with_capacity(LENGTH);

    while out.len() < LENGTH {
        for byte in rng.next_u32().to_le_bytes() {
            if (byte as usize) < ALPHABET.len() {
                out.push(ALPHABET[byte as usize] as char);
                if out.len() == LENGTH {
                    break;
                }
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Who ran the command. There is no login here, so this is the account on the
/// host, which is the closest thing to an identity that exists.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Written whether the command worked or not: a refused command is exactly
/// what an audit log is for, and one that only records successes is a log of
/// the wrong things.
async fn record_audit(
    pool: &SqlitePool,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    sqlx::query(AUDIT)
        .bind(Utc::now().timestamp())
        .bind(whoami())
        .bind(action)
        .bind(target)
        .bind(detail)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const USAGE: &str = "\
usage: Zeevum-server admin <command> [login]

  promote <login>          make the first admin, refuses once there is one
  demote <login>           take the role away
  list-users               id, login, when they joined, when last seen
  show-user <login>        the same, and how many sessions they have
  list-sessions <login>    active sessions and when they expire
  revoke-sessions <login>  end every session they have
  reset-password <login>   a temporary one, must be changed at next login
  audit [n]                the last n things done, refused ones included
  stats                    whole numbers about the server
  invite-new [days]        issue an invite code, optionally expiring in N days
  invite-list              every code: created, expiry, who spent it
  invite-revoke <code>     kill a code that has not been used";

pub async fn run(args: &[String]) -> Result<()> {
    let command = match args.first().map(|s| s.as_str()) {
        Some(c) => c,
        None => {
            println!("{USAGE}");
            bail!("no admin subcommand given");
        }
    };
    let target = args.get(1).map(|s| s.as_str());

    // The same database the server would open, which is not necessarily the
    // one under AppData: DB_PATH in the environment wins, and a development
    // server usually points it somewhere else entirely.
    let db_path = Config::db_path_from_env();

    // Printed because the whole point of this step is not to be run against
    // the wrong file, and as an absolute path because a relative one means
    // two different files depending on where the command was started from.
    println!("database: {}", Config::absolute(&db_path).display());

    let pool = db::init_database(&db_path).await?;
    db::migrate(&pool).await?;

    dispatch_audited(&pool, command, target).await
}

/// The audit is not a separate step the caller has to remember: a command
/// that could run without leaving a trace would be the one that mattered.
async fn dispatch_audited(pool: &SqlitePool, command: &str, target: Option<&str>) -> Result<()> {
    let outcome = dispatch(pool, command, target).await;

    // Written either way, including the command that does not exist and the
    // login that is not there.
    let detail = outcome.as_ref().err().map(|e| e.to_string());
    record_audit(pool, command, target, detail.as_deref()).await?;

    outcome
}

async fn dispatch(pool: &SqlitePool, command: &str, target: Option<&str>) -> Result<()> {
    let needs_login = !matches!(
        command,
        "list-users" | "stats" | "audit" | "invite-new" | "invite-list" | "invite-revoke"
    );

    let login = match target {
        Some(l) => l,
        None if needs_login => return Err(anyhow!("{command} needs a login")),
        None => "",
    };

    match command {
        "promote" => promote(pool, login).await,
        "demote" => demote(pool, login).await,
        "list-users" => list_users(pool).await,
        "show-user" => show_user(pool, login).await,
        "list-sessions" => list_sessions(pool, login).await,
        "revoke-sessions" => revoke_sessions(pool, login).await,
        "reset-password" => reset_password(pool, login).await,
        "audit" => {
            let limit = match target {
                Some(n) => n
                    .parse::<i64>()
                    .context("the count must be a whole number")?,
                None => 20,
            };
            audit(pool, limit).await
        }
        "stats" => stats(pool).await,
        "invite-new" => invite_new(pool, target).await,
        "invite-list" => invite_list(pool).await,
        "invite-revoke" => match target {
            Some(code) => invite_revoke(pool, code).await,
            None => Err(anyhow!("invite-revoke needs a code")),
        },
        other => {
            println!("{USAGE}");
            Err(anyhow!("unknown admin subcommand '{other}'"))
        }
    }
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

/// One row of `invite-list`.
type InviteRow = (String, i64, Option<i64>, Option<i64>, Option<String>);

async fn invite_new(pool: &SqlitePool, days: Option<&str>) -> Result<()> {
    let expires_at = match days {
        Some(d) => {
            let days: i64 = d
                .parse()
                .context("the number of days must be a whole number")?;
            Some(Utc::now().timestamp() + days * 86_400)
        }
        None => None,
    };

    let code = random_code();
    sqlx::query(INSERT_INVITE)
        .bind(&code)
        .bind(Utc::now().timestamp())
        .bind(expires_at)
        .execute(pool)
        .await?;

    match expires_at {
        Some(at) => println!("invite: {code} (expires {})", stamp(Some(at))),
        None => println!("invite: {code} (no expiry)"),
    }
    Ok(())
}

async fn invite_list(pool: &SqlitePool) -> Result<()> {
    let rows: Vec<InviteRow> = sqlx::query_as(LIST_INVITES).fetch_all(pool).await?;

    for (code, created, expires, used_at, used_by) in rows {
        let spent = match (used_by, used_at) {
            (Some(login), Some(at)) => format!("{login} at {}", stamp(Some(at))),
            _ => "unused".to_string(),
        };
        println!(
            "{code}  created {}  expires {}  {spent}",
            stamp(Some(created)),
            stamp(expires)
        );
    }
    Ok(())
}

async fn invite_revoke(pool: &SqlitePool, code: &str) -> Result<()> {
    let result = sqlx::query(REVOKE_INVITE).bind(code).execute(pool).await?;
    if result.rows_affected() == 1 {
        println!("invite {code} revoked");
        Ok(())
    } else {
        Err(anyhow!("no unused invite {code}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    use zxcvbn::Score;

    async fn setup_pool() -> Result<SqlitePool> {
        let opts = SqliteConnectOptions::from_str("sqlite://:memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(pool)
    }

    async fn add(pool: &SqlitePool, login: &str) -> Result<()> {
        db::add_user(pool, login, "correct horse battery staple 7!").await?;
        Ok(())
    }

    async fn audit_rows(pool: &SqlitePool) -> Result<i64> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_audit")
            .fetch_one(pool)
            .await?;
        Ok(n)
    }

    async fn is_admin(pool: &SqlitePool, login: &str) -> Result<bool> {
        let (flag,): (i32,) = sqlx::query_as("SELECT is_admin FROM users WHERE login = ?")
            .bind(login)
            .fetch_one(pool)
            .await?;
        Ok(flag != 0)
    }

    async fn must_change(pool: &SqlitePool, login: &str) -> Result<bool> {
        let (flag,): (i32,) =
            sqlx::query_as("SELECT must_change_password FROM users WHERE login = ?")
                .bind(login)
                .fetch_one(pool)
                .await?;
        Ok(flag != 0)
    }

    /// The boundary, checked rather than promised. An admin may see who a
    /// user is, never what they wrote, and never anything that lets them in.
    #[test]
    fn no_admin_query_reads_the_password() {
        for (name, sql) in ALL_QUERIES {
            let lower = sql.to_lowercase();
            if lower.contains("select") {
                assert!(
                    !lower.contains("password"),
                    "{name} selects a password column: {sql}"
                );
            }
        }
    }

    /// Not "does not return messages", simply never mentioned. A count of
    /// messages is about what two people said to each other, and no whole
    /// number about the server needs it.
    #[test]
    fn no_admin_query_mentions_messages() {
        for (name, sql) in ALL_QUERIES {
            assert!(
                !sql.to_lowercase().contains("messages"),
                "{name} touches the messages table: {sql}"
            );
        }
    }

    /// Refusals included: a log of successes only is a log of the wrong
    /// things.
    #[tokio::test]
    async fn issuing_an_invite_leaves_a_row_and_an_audit_row() -> Result<()> {
        let pool = setup_pool().await?;
        dispatch_audited(&pool, "invite-new", None).await?;

        let (codes,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_codes")
            .fetch_one(&pool)
            .await?;
        assert_eq!(codes, 1);
        assert_eq!(audit_rows(&pool).await?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn invite_new_with_a_number_of_days_sets_the_expiry() -> Result<()> {
        let pool = setup_pool().await?;
        dispatch_audited(&pool, "invite-new", Some("7")).await?;

        let (with_expiry,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM invite_codes WHERE expires_at IS NOT NULL")
                .fetch_one(&pool)
                .await?;
        assert_eq!(with_expiry, 1);
        Ok(())
    }

    #[tokio::test]
    async fn revoking_removes_an_unused_code_and_refuses_a_spent_one() -> Result<()> {
        let pool = setup_pool().await?;
        let now = Utc::now().timestamp();

        sqlx::query("INSERT INTO invite_codes (code, created_at) VALUES ('SPENTONE', ?)")
            .bind(now)
            .execute(&pool)
            .await?;
        db::add_user_with(
            &pool,
            "Bob",
            "correct horse battery staple 7!",
            Some("SPENTONE"),
        )
        .await?;
        assert!(
            dispatch_audited(&pool, "invite-revoke", Some("SPENTONE"))
                .await
                .is_err()
        );

        sqlx::query("INSERT INTO invite_codes (code, created_at) VALUES ('FRESHONE', ?)")
            .bind(now)
            .execute(&pool)
            .await?;
        dispatch_audited(&pool, "invite-revoke", Some("FRESHONE")).await?;

        let (left,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_codes")
            .fetch_one(&pool)
            .await?;
        assert_eq!(left, 1, "only the spent code may remain");
        Ok(())
    }

    #[tokio::test]
    async fn every_command_leaves_exactly_one_audit_row() -> Result<()> {
        for command in [
            "promote",
            "demote",
            "list-users",
            "show-user",
            "list-sessions",
            "revoke-sessions",
            "reset-password",
            "stats",
            "audit",
            "does-not-exist",
        ] {
            let pool = setup_pool().await?;
            add(&pool, "alice").await?;

            let args: Vec<String> = match command {
                "list-users" | "stats" | "audit" => vec![command.to_string()],
                _ => vec![command.to_string(), "alice".to_string()],
            };
            let _ = dispatch_audited(&pool, command, args.get(1).map(|s| s.as_str())).await;
            assert_eq!(
                audit_rows(&pool).await?,
                1,
                "{command} did not leave exactly one audit row"
            );
        }
        Ok(())
    }

    /// The bootstrap: exactly one admin, named once. Take the check away and
    /// anyone at the shell can hand themselves the role at any time.
    #[tokio::test]
    async fn promote_refuses_once_there_is_an_admin() -> Result<()> {
        let pool = setup_pool().await?;
        add(&pool, "alice").await?;
        add(&pool, "bob").await?;

        promote(&pool, "alice").await?;
        assert!(is_admin(&pool, "alice").await?);

        let refused = promote(&pool, "bob").await;
        assert!(refused.is_err(), "a second promote was allowed");
        assert!(!is_admin(&pool, "bob").await?);
        Ok(())
    }

    #[tokio::test]
    async fn demote_refuses_when_they_are_not_an_admin() -> Result<()> {
        let pool = setup_pool().await?;
        add(&pool, "alice").await?;
        assert!(demote(&pool, "alice").await.is_err());
        Ok(())
    }

    /// Without this the reset is a quiet way in that never expires: the admin
    /// knows the password, and nothing forces the user to replace it.
    #[tokio::test]
    async fn reset_password_sets_the_flag_and_ends_the_sessions() -> Result<()> {
        let pool = setup_pool().await?;
        add(&pool, "alice").await?;
        db::create_session(
            &pool,
            {
                let (id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM users WHERE login = ?")
                    .bind("alice")
                    .fetch_one(&pool)
                    .await?;
                id
            },
            24.0,
        )
        .await?;

        assert!(!must_change(&pool, "alice").await?);
        reset_password(&pool, "alice").await?;
        assert!(
            must_change(&pool, "alice").await?,
            "the password was reset without being marked temporary"
        );

        let (sessions,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await?;
        assert_eq!(sessions, 0, "the old tokens are still valid");
        Ok(())
    }

    /// It has to be one the server would have accepted at registration,
    /// otherwise the user is locked out of changing it.
    #[test]
    fn the_temporary_password_would_pass_registration() {
        for _ in 0..64 {
            let password = random_code();
            let score = zxcvbn::zxcvbn(&password, &[]).score();
            assert!(
                score >= Score::Three,
                "generated a weak temporary password: {password} ({score:?})"
            );
        }
    }

    #[tokio::test]
    async fn a_login_is_remembered_as_last_seen() -> Result<()> {
        let pool = setup_pool().await?;
        add(&pool, "alice").await?;

        let (id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM users WHERE login = ?")
            .bind("alice")
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            sqlx::query_as::<_, (Option<i64>,)>("SELECT last_seen FROM users WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await?
                .0,
            None
        );

        db::create_session(&pool, id, 24.0).await?;
        assert!(
            sqlx::query_as::<_, (Option<i64>,)>("SELECT last_seen FROM users WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await?
                .0
                .is_some(),
            "a login did not record last_seen"
        );
        Ok(())
    }

    /// A log that cannot be read back is half a log. This is the manual check
    /// from the proposal, written down as a test.
    #[tokio::test]
    async fn what_was_done_comes_back_out_of_the_audit() -> Result<()> {
        let pool = setup_pool().await?;
        add(&pool, "alice").await?;

        dispatch_audited(&pool, "promote", Some("alice")).await?;
        let _ = dispatch_audited(&pool, "promote", Some("bob")).await;

        let rows: Vec<AuditRow> = sqlx::query_as(READ_AUDIT).bind(10).fetch_all(&pool).await?;
        assert_eq!(rows.len(), 2, "both the done and the refused one are there");

        assert_eq!(rows[1].2, "promote");
        assert_eq!(rows[1].3.as_deref(), Some("alice"));
        assert!(rows[0].4.is_some(), "the refusal carries its reason");

        audit(&pool, 10).await?;
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_user_is_refused_everywhere() -> Result<()> {
        let pool = setup_pool().await?;
        for command in [
            "show-user",
            "list-sessions",
            "revoke-sessions",
            "reset-password",
        ] {
            assert!(
                dispatch_audited(&pool, command, Some("nobody"))
                    .await
                    .is_err(),
                "{command} accepted a login that does not exist"
            );
        }
        Ok(())
    }
}
