mod common;

use common::{TestClient, TestServer, authenticate, login, register};
use zeevum_protocol::{AuthMethod, ClientMsg, ErrorCode, PROTOCOL_VERSION, ServerMsg};

/// Long enough to clear the server-side zxcvbn check
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
