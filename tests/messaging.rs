mod common;

use uuid::Uuid;
use zeevum_protocol::{ClientMsg, ErrorCode, ServerMsg};

use common::{TestClient, TestServer, befriend, new_message_id, register, resolve_dm};

const PASSWORD: &str = "something_really_strong_123_A!";

/// Two connected users who are friends, plus the conversation between them
struct Pair {
    alice: TestClient,
    john: TestClient,
    alice_id: i64,
    john_id: i64,
    conv: Uuid,
}

/// Registers two users, befriends them and resolves their conversation
async fn two_friends(server: &TestServer) -> Pair {
    let mut alice = TestClient::connect(server).await;
    let alice_id = register(&mut alice, "alice", PASSWORD).await.user_id;

    let mut john = TestClient::connect(server).await;
    let john_id = register(&mut john, "john", PASSWORD).await.user_id;

    befriend(&mut alice, &mut john, alice_id, john_id).await;

    let conv = resolve_dm(&mut alice, john_id)
        .await
        .expect("friends can resolve their conversation");

    Pair {
        alice,
        john,
        alice_id,
        john_id,
        conv,
    }
}

#[tokio::test]
async fn search_finds_a_registered_user() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    register(&mut alice, "alice", PASSWORD).await;
    let john = {
        let mut john = TestClient::connect(&server).await;
        register(&mut john, "john", PASSWORD).await
    };

    alice
        .send(&ClientMsg::SearchUser {
            login: "john".to_string(),
        })
        .await;

    match alice
        .recv_until(|m| matches!(m, ServerMsg::UserFound { .. } | ServerMsg::UserNotFound))
        .await
    {
        ServerMsg::UserFound { user } => assert_eq!(user.user_id, john.user_id),
        other => panic!("expected UserFound, got {other:?}"),
    }
}

#[tokio::test]
async fn search_for_unknown_user_reports_not_found() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    register(&mut alice, "alice", PASSWORD).await;

    alice
        .send(&ClientMsg::SearchUser {
            login: "ghost".to_string(),
        })
        .await;

    let reply = alice
        .recv_until(|m| matches!(m, ServerMsg::UserFound { .. } | ServerMsg::UserNotFound))
        .await;
    assert!(matches!(reply, ServerMsg::UserNotFound), "got {reply:?}");
}

/// The conversation is resolved once and then addressed by id
#[tokio::test]
async fn resolving_a_conversation_twice_returns_the_same_id() {
    let server = TestServer::start().await;
    let mut pair = two_friends(&server).await;

    let again = resolve_dm(&mut pair.alice, pair.john_id)
        .await
        .expect("resolving again");
    assert_eq!(again, pair.conv);

    let from_john = resolve_dm(&mut pair.john, pair.alice_id)
        .await
        .expect("resolving from the other side");
    assert_eq!(from_john, pair.conv);
}

#[tokio::test]
async fn message_is_delivered_and_acknowledged() {
    let server = TestServer::start().await;
    let mut pair = two_friends(&server).await;

    let message_id = new_message_id();
    pair.alice
        .send(&ClientMsg::SendMsg {
            message_id,
            conv_id: pair.conv,
            content: "hello john".to_string(),
        })
        .await;

    match pair
        .alice
        .recv_until(|m| matches!(m, ServerMsg::MsgAck { .. }))
        .await
    {
        ServerMsg::MsgAck {
            message_id: id,
            conv_id,
        } => {
            assert_eq!(id, message_id);
            assert_eq!(conv_id, pair.conv);
        }
        other => panic!("expected MsgAck, got {other:?}"),
    }

    match pair
        .john
        .recv_until(|m| matches!(m, ServerMsg::RecvMsg { .. }))
        .await
    {
        ServerMsg::RecvMsg {
            content,
            sender_user_id,
            conv_id,
            ..
        } => {
            assert_eq!(content, "hello john");
            assert_eq!(sender_user_id, pair.alice_id);
            assert_eq!(conv_id, pair.conv);
        }
        other => panic!("expected RecvMsg, got {other:?}"),
    }
}

#[tokio::test]
async fn history_is_returned_for_a_conversation() {
    let server = TestServer::start().await;
    let mut pair = two_friends(&server).await;

    for content in ["first", "second"] {
        pair.alice
            .send(&ClientMsg::SendMsg {
                message_id: new_message_id(),
                conv_id: pair.conv,
                content: content.to_string(),
            })
            .await;
        pair.alice
            .recv_until(|m| matches!(m, ServerMsg::MsgAck { .. }))
            .await;
    }

    let mut alice_again = TestClient::connect(&server).await;
    common::authenticate(
        &mut alice_again,
        zeevum_protocol::AuthMethod::Login {
            login: "alice".to_string(),
            password: PASSWORD.to_string(),
        },
    )
    .await
    .expect("re-login");

    alice_again
        .send(&ClientMsg::HistoryReq { conv_id: pair.conv })
        .await;

    let mut messages = Vec::new();
    loop {
        match alice_again.recv().await {
            Some(ServerMsg::HistoryMsg { content, .. }) => messages.push(content),
            Some(ServerMsg::HistoryEnd { .. }) => break,
            Some(_) => continue,
            None => panic!("connection closed while streaming history"),
        }
    }

    messages.sort();
    assert_eq!(messages, vec!["first".to_string(), "second".to_string()]);
}

/// The whole point of `conv_id`, a stranger who somehow learns the id of a
/// conversation must still not be able to use it
#[tokio::test]
async fn stranger_cannot_read_someone_elses_conversation() {
    let server = TestServer::start().await;
    let mut pair = two_friends(&server).await;

    pair.alice
        .send(&ClientMsg::SendMsg {
            message_id: new_message_id(),
            conv_id: pair.conv,
            content: "not for carol".to_string(),
        })
        .await;
    pair.alice
        .recv_until(|m| matches!(m, ServerMsg::MsgAck { .. }))
        .await;

    let mut carol = TestClient::connect(&server).await;
    register(&mut carol, "carol", PASSWORD).await;

    carol
        .send(&ClientMsg::HistoryReq { conv_id: pair.conv })
        .await;

    let reply = carol
        .recv_until(|m| {
            matches!(
                m,
                ServerMsg::HistoryMsg { .. }
                    | ServerMsg::HistoryEnd { .. }
                    | ServerMsg::Error { .. }
            )
        })
        .await;

    match reply {
        ServerMsg::Error {
            code: ErrorCode::NotAMember,
            ..
        } => {}
        other => panic!("expected NotAMember, got {other:?}"),
    }
}

#[tokio::test]
async fn stranger_cannot_write_into_someone_elses_conversation() {
    let server = TestServer::start().await;
    let mut pair = two_friends(&server).await;

    let mut carol = TestClient::connect(&server).await;
    register(&mut carol, "carol", PASSWORD).await;

    carol
        .send(&ClientMsg::SendMsg {
            message_id: new_message_id(),
            conv_id: pair.conv,
            content: "let me in".to_string(),
        })
        .await;

    let reply = carol
        .recv_until(|m| matches!(m, ServerMsg::MsgAck { .. } | ServerMsg::Error { .. }))
        .await;

    assert!(
        !matches!(reply, ServerMsg::MsgAck { .. }),
        "a message from a non-member was stored: {reply:?}"
    );

    pair.john
        .send(&ClientMsg::HistoryReq { conv_id: pair.conv })
        .await;
    let history_end = pair
        .john
        .recv_until(|m| matches!(m, ServerMsg::HistoryEnd { .. }))
        .await;
    assert!(matches!(history_end, ServerMsg::HistoryEnd { .. }));
}

/// Not being friends is enough to keep a conversation from existing at all
#[tokio::test]
async fn stranger_cannot_open_a_conversation() {
    let server = TestServer::start().await;

    let mut john = TestClient::connect(&server).await;
    let john_id = register(&mut john, "john", PASSWORD).await.user_id;

    let mut carol = TestClient::connect(&server).await;
    register(&mut carol, "carol", PASSWORD).await;

    match resolve_dm(&mut carol, john_id).await {
        Err(ErrorCode::NotFriends) => {}
        other => panic!("expected NotFriends, got {other:?}"),
    }
}

#[tokio::test]
async fn resolving_a_conversation_with_yourself_is_refused() {
    let server = TestServer::start().await;

    let mut alice = TestClient::connect(&server).await;
    let alice_id = register(&mut alice, "alice", PASSWORD).await.user_id;

    match resolve_dm(&mut alice, alice_id).await {
        Err(ErrorCode::CannotTargetYourself) => {}
        other => panic!("expected CannotTargetYourself, got {other:?}"),
    }
}
