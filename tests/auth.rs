mod common;

use std::time::Duration;

use common::{TestClient, TestServer, authenticate, login, register};
use sqlx::Row;
use zeevum_protocol::{AuthMethod, ClientMsg, ErrorCode, PROTOCOL_VERSION, ServerMsg};

/// Long enough to clear the server-side zxcvbn check, score 2 or more.
const PASSWORD: &str = "something_really_strong_123_A!";

#[tokio::test]
async fn registration_then_login_succeed() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    let session = register(&mut alice, "alice", PASSWORD).await;
    assert!(session.user_id > 0, "server must assign a public user id");
    assert!(!session.token.is_empty(), "server must issue a token");

    let mut returning = TestClient::connect(&server).await;
    let again = login(&mut returning, "alice", PASSWORD)
        .await
        .expect("login with the right password");
    assert_eq!(again.user_id, session.user_id, "same user, same public id");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    register(&mut alice, "alice", PASSWORD).await;

    let mut attacker = TestClient::connect(&server).await;
    let result = login(&mut attacker, "alice", "definitely not the password").await;
    assert!(result.is_err(), "wrong password must be rejected");
}

#[tokio::test]
async fn login_for_unknown_user_is_rejected() {
    let server = TestServer::start().await;

    let mut client = TestClient::connect(&server).await;
    let result = login(&mut client, "ghost", PASSWORD).await;
    assert!(result.is_err(), "unknown login must be rejected");
}

/// Break `connection.rs` and it fails, even though every unit test still passes.
#[tokio::test]
async fn reconnecting_by_token_does_not_grow_the_sessions_table() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    let first = register(&mut alice, "alice", PASSWORD).await;
    drop(alice);

    let rows_after_registration = session_rows(&server.pool).await;

    for _ in 0..3 {
        let mut client = TestClient::connect(&server).await;
        let session = authenticate(
            &mut client,
            AuthMethod::Token {
                token: first.token.clone(),
            },
        )
        .await
        .expect("token authentication");
        assert_eq!(session.user_id, first.user_id);
        drop(client);
    }

    assert_eq!(
        session_rows(&server.pool).await,
        rows_after_registration,
        "token login created new session rows"
    );
}

async fn session_rows(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query("SELECT COUNT(*) AS n FROM sessions")
        .fetch_one(pool)
        .await
        .expect("count sessions")
        .get("n")
}

/// Logging out must kill the token, not just close the socket, an open
/// connection is not the same thing as a live session.
#[tokio::test]
async fn logout_makes_the_token_useless() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    let session = register(&mut alice, "alice", PASSWORD).await;
    assert_eq!(session_rows(&server.pool).await, 1);

    alice
        .send(&ClientMsg::Logout {
            all_sessions: false,
        })
        .await;

    // Drain what is queued, FriendList and PendingReqs arrive right after login,
    // then the socket has to go quiet. Bounded, so a server that never hangs up
    // fails the test instead of stalling it.
    let hung_up = tokio::time::timeout(Duration::from_secs(5), async {
        while alice.recv().await.is_some() {}
    })
    .await;
    assert!(hung_up.is_ok(), "server should hang up");
    drop(alice);

    assert_eq!(session_rows(&server.pool).await, 0);

    let mut again = TestClient::connect(&server).await;
    let result = authenticate(
        &mut again,
        AuthMethod::Token {
            token: session.token,
        },
    )
    .await;
    assert!(result.is_err(), "a revoked token must not authenticate");
}

/// "Log out everywhere" has to take the other device down with it, which is
/// the whole point of the flag.
#[tokio::test]
async fn logout_everywhere_kills_the_other_device() {
    let server = TestServer::start().await;

    let mut phone = TestClient::connect(&server).await;
    let phone_session = register(&mut phone, "alice", PASSWORD).await;
    drop(phone);

    // A second device logs in with the password and mints its own session.
    let mut laptop = TestClient::connect(&server).await;
    let laptop_session = login(&mut laptop, "alice", PASSWORD).await.expect("login");
    assert_eq!(session_rows(&server.pool).await, 2);

    laptop.send(&ClientMsg::Logout { all_sessions: true }).await;

    let hung_up = tokio::time::timeout(Duration::from_secs(5), async {
        while laptop.recv().await.is_some() {}
    })
    .await;
    assert!(hung_up.is_ok(), "server should hang up");
    drop(laptop);

    assert_eq!(session_rows(&server.pool).await, 0);

    for token in [laptop_session.token, phone_session.token] {
        let mut client = TestClient::connect(&server).await;
        let result = authenticate(&mut client, AuthMethod::Token { token }).await;
        assert!(result.is_err(), "every session should be revoked");
    }
}

#[tokio::test]
async fn token_opens_a_new_session_without_a_password() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    let first = register(&mut alice, "alice", PASSWORD).await;
    drop(alice);

    let mut again = TestClient::connect(&server).await;
    let second = authenticate(
        &mut again,
        AuthMethod::Token {
            token: first.token.clone(),
        },
    )
    .await
    .expect("token authentication");
    assert_eq!(second.user_id, first.user_id);
}

#[tokio::test]
async fn unsupported_protocol_version_is_rejected() {
    let server = TestServer::start().await;

    let mut client = TestClient::connect(&server).await;
    client
        .send(&ClientMsg::Auth {
            protocol_version: PROTOCOL_VERSION + 1,
            method: AuthMethod::Login {
                login: "alice".to_string(),
                password: PASSWORD.to_string(),
            },
        })
        .await;

    match client.recv().await {
        Some(ServerMsg::Error {
            code: ErrorCode::UnsupportedProtocolVersion { server_version },
            ..
        }) => {
            assert_eq!(
                server_version, PROTOCOL_VERSION,
                "the refusal must name the version the server speaks"
            );
        }
        other => panic!("expected UnsupportedProtocolVersion, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_frame_closes_the_connection() {
    let server = TestServer::start().await;

    let mut client = TestClient::connect(&server).await;
    let payload = "x".repeat(70 * 1024);
    client.send_raw(format!("{payload}\n").as_bytes()).await;

    // The server reports the failure first, then hangs up, so the
    // assertion is about reaching EOF at all, not about the very next frame.
    let mut closed = false;
    for _ in 0..8 {
        if client.recv().await.is_none() {
            closed = true;
            break;
        }
    }
    assert!(
        closed,
        "server must drop a connection that exceeds MAX_LINE_BYTES"
    );
}

/// Break `kick_all` and it fails, even though every test that only counts rows
/// still passes.
#[tokio::test]
async fn logout_everywhere_closes_the_other_device() {
    let server = TestServer::start().await;

    let mut phone = TestClient::connect(&server).await;
    register(&mut phone, "alice", PASSWORD).await;

    let mut laptop = TestClient::connect(&server).await;
    login(&mut laptop, "alice", PASSWORD).await.expect("login");

    laptop.send(&ClientMsg::Logout { all_sessions: true }).await;

    let hung_up = tokio::time::timeout(Duration::from_secs(5), async {
        while laptop.recv().await.is_some() {}
    })
    .await;
    assert!(hung_up.is_ok(), "server should hang up");
    drop(laptop);

    // The phone did nothing of its own and must be closed anyway.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while phone.recv().await.is_some() {}
    })
    .await;
    assert!(closed.is_ok(), "the other device should have been kicked");
}
