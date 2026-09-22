use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use zeevum_protocol::{AuthMethod, ClientMsg, ErrorCode, PROTOCOL_VERSION, ServerMsg, decode, pow};

use crate::db;
use crate::frames::{frame, read_frame};
use crate::server::AppContext;

/// A machine-readable code for the client and a detail string for the logs.
#[derive(Debug)]
pub enum HandshakeError {
    Auth(ErrorCode, String),
    Protocol(ErrorCode, String),
}

impl HandshakeError {
    pub fn code(&self) -> ErrorCode {
        match self {
            HandshakeError::Auth(code, _) | HandshakeError::Protocol(code, _) => code.clone(),
        }
    }

    /// Human-readable context. Logged by the server, never relied upon by the client.
    pub fn detail(&self) -> &str {
        match self {
            HandshakeError::Auth(_, detail) | HandshakeError::Protocol(_, detail) => detail,
        }
    }
}

/// The distinction is about the `sessions` table, a client that arrived with a
/// token already has a row and validating it renewed the expiry.
pub enum AuthOutcome {
    /// Password or registration, this is where a token is born.
    NewSession(db::User),
    /// Token, the row it belongs to, and the expiry it was just renewed to.
    ReusedSession(db::User, String, i64),
}

pub async fn handshake(
    stream: &mut TlsStream<TcpStream>,
    peer: SocketAddr,
    ctx: &AppContext,
) -> Result<AuthOutcome, HandshakeError> {
    use HandshakeError::{Auth, Protocol};

    let line = tokio::time::timeout(ctx.config.handshake_timeout, read_frame(stream))
        .await
        .map_err(|_| Protocol(ErrorCode::MalformedFrame, "handshake timed out".into()))?
        .map_err(|e| Protocol(ErrorCode::MalformedFrame, format!("read error: {e}")))?;

    let msg: ClientMsg = decode(line.trim())
        .map_err(|_| Protocol(ErrorCode::MalformedFrame, "unparseable Auth frame".into()))?;

    let ClientMsg::Auth {
        protocol_version,
        method,
    } = msg
    else {
        return Err(Protocol(
            ErrorCode::MalformedFrame,
            "first frame was not Auth".into(),
        ));
    };

    debug!("Auth request from {peer} (proto v{protocol_version})");

    if protocol_version != PROTOCOL_VERSION {
        return Err(Protocol(
            ErrorCode::UnsupportedProtocolVersion {
                server_version: PROTOCOL_VERSION,
            },
            format!("client speaks v{protocol_version}, server speaks v{PROTOCOL_VERSION}"),
        ));
    }

    let method = match method {
        AuthMethod::Register { login, password } => {
            let challenge = pow::generate_challenge();
            let bits = ctx.config.pow_difficulty.bits();

            let challenge_frame = frame(&ServerMsg::PowChallenge {
                challenge: challenge.clone(),
                difficulty_bits: bits,
            });
            stream
                .write_all(challenge_frame.as_bytes())
                .await
                .map_err(|e| Protocol(ErrorCode::Internal, format!("write error: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| Protocol(ErrorCode::Internal, format!("write error: {e}")))?;

            let solve_line = tokio::time::timeout(ctx.config.handshake_timeout, read_frame(stream))
                .await
                .map_err(|_| Protocol(ErrorCode::MalformedFrame, "proof of work timed out".into()))?
                .map_err(|e| Protocol(ErrorCode::MalformedFrame, format!("read error: {e}")))?;
            let solved: ClientMsg = decode(solve_line.trim()).map_err(|_| {
                Protocol(
                    ErrorCode::MalformedFrame,
                    "unparseable PowSolution frame".into(),
                )
            })?;
            let ClientMsg::PowSolution { nonce } = solved else {
                return Err(Protocol(
                    ErrorCode::MalformedFrame,
                    "expected PowSolution".into(),
                ));
            };
            if !pow::verify(&challenge, nonce, bits) {
                return Err(Protocol(
                    ErrorCode::RegistrationFailed,
                    "proof of work did not verify".into(),
                ));
            }
            AuthMethod::Register { login, password }
        }
        m => m,
    };

    let outcome = match method {
        AuthMethod::Token { token } => {
            validate_session(&ctx.pool, &token, ctx.config.session_duration_hours)
                .await
                .map(|(user, expires_at)| AuthOutcome::ReusedSession(user, token, expires_at))
        }
        AuthMethod::Login { login, password } => {
            login_user(&ctx.pool, &login, &password, &ctx.fake_hash)
                .await
                .map(AuthOutcome::NewSession)
        }
        AuthMethod::Register { login, password } => register_user(&ctx.pool, &login, &password)
            .await
            .map(AuthOutcome::NewSession),
    };

    outcome.map_err(|(code, detail)| Auth(code, detail))
}

async fn validate_session(
    pool: &sqlx::SqlitePool,
    token: &str,
    duration: f64,
) -> Result<(db::User, i64), (ErrorCode, String)> {
    db::validate_session(pool, token, duration)
        .await
        .map_err(|e| (ErrorCode::Internal, format!("session lookup failed: {e}")))?
        .ok_or_else(|| {
            (
                ErrorCode::InvalidCredentials,
                "invalid or expired token".into(),
            )
        })
}

async fn register_user(
    pool: &sqlx::SqlitePool,
    login: &str,
    password: &str,
) -> Result<db::User, (ErrorCode, String)> {
    match db::add_user(pool, login, password).await {
        Ok(user) => Ok(user),
        Err(e) => {
            warning!("Registration failed for '{login}': {e}");
            Err((
                ErrorCode::RegistrationFailed,
                "login taken, malformed, or password too weak".into(),
            ))
        }
    }
}

async fn login_user(
    pool: &sqlx::SqlitePool,
    login: &str,
    password: &str,
    fake_hash: &str,
) -> Result<db::User, (ErrorCode, String)> {
    if let Some(existing) = db::get_user_by_login(pool, login)
        .await
        .map_err(|e| (ErrorCode::Internal, format!("login lookup failed: {e}")))?
    {
        if db::verify_password(password, &existing.password) {
            return Ok(existing);
        }
    } else {
        // Burn the same amount of time as a real verification, so that the
        // response time does not reveal whether the login exists.
        let _ = db::verify_password(password, fake_hash);
    }
    Err((
        ErrorCode::InvalidCredentials,
        "wrong login or password".into(),
    ))
}
