//! Registration behind invitations, end to end.

mod common;

use common::TestClient;
use zeevum_protocol::AuthMethod;
use zeevum_server::config::RegistrationMode;

const PASSWORD: &str = "correct horse battery staple 7!";

async fn issue_code(server: &common::TestServer, code: &str) {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("INSERT INTO invite_codes (code, created_at) VALUES (?, ?)")
        .bind(code)
        .bind(now)
        .execute(&server.pool)
        .await
        .expect("issue code");
}

#[tokio::test]
async fn without_a_code_registration_is_refused() {
    let server = common::TestServer::start_with(|c| {
        c.registration = RegistrationMode::Invite;
    })
    .await;

    let mut client = TestClient::connect(&server).await;
    let refused = common::authenticate(
        &mut client,
        AuthMethod::Register {
            login: "alice".to_string(),
            password: PASSWORD.to_string(),
            invite_code: None,
        },
    )
    .await
    .expect_err("registration without a code must be refused");

    assert!(refused.contains("Registration failed"), "{refused}");
}

#[tokio::test]
async fn a_code_registers_exactly_one_account() {
    let server = common::TestServer::start_with(|c| {
        c.registration = RegistrationMode::Invite;
    })
    .await;
    issue_code(&server, "TESTCODE0000001").await;

    let mut client = TestClient::connect(&server).await;
    common::authenticate(
        &mut client,
        AuthMethod::Register {
            login: "alice".to_string(),
            password: PASSWORD.to_string(),
            invite_code: Some("TESTCODE0000001".to_string()),
        },
    )
    .await
    .expect("a valid code must register");

    let mut second = TestClient::connect(&server).await;
    let refused = common::authenticate(
        &mut second,
        AuthMethod::Register {
            login: "bob".to_string(),
            password: PASSWORD.to_string(),
            invite_code: Some("TESTCODE0000001".to_string()),
        },
    )
    .await
    .expect_err("a spent code must not register a second account");

    assert!(refused.contains("Registration failed"), "{refused}");
}

/// A server that has not chosen invitations keeps working exactly as it
/// did, including for a client that sends a code nobody asked for.
#[tokio::test]
async fn open_mode_ignores_the_code() {
    let server = common::TestServer::start_with(|c| {
        c.registration = RegistrationMode::Open;
    })
    .await;

    let mut client = TestClient::connect(&server).await;
    common::authenticate(
        &mut client,
        AuthMethod::Register {
            login: "alice".to_string(),
            password: PASSWORD.to_string(),
            invite_code: Some("IGNORED000000001".to_string()),
        },
    )
    .await
    .expect("open mode must register without looking at the code");

    let (registered,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&server.pool)
        .await
        .expect("count users");
    assert_eq!(registered, 1);
}

#[tokio::test]
async fn closed_mode_refuses_everybody() {
    let server = common::TestServer::start_with(|c| {
        c.registration = RegistrationMode::Closed;
    })
    .await;

    let mut client = TestClient::connect(&server).await;
    let refused = common::authenticate(
        &mut client,
        AuthMethod::Register {
            login: "alice".to_string(),
            password: PASSWORD.to_string(),
            invite_code: None,
        },
    )
    .await
    .expect_err("closed mode must refuse registration");

    assert!(refused.contains("Registration failed"), "{refused}");
}
