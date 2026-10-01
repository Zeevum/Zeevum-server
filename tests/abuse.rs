//! Abuse, end to end: the limiter as the client meets it.

mod common;

use std::time::Duration;

use common::{TestClient, TestServer};
use zeevum_protocol::{AuthMethod, ClientMsg, ServerMsg};

/// L2: an address gets a handful of accounts, not an unlimited supply. The
/// refusal happens before the proof of work, so the refusal is also cheap
/// for the server.
#[tokio::test]
async fn the_fourth_registration_from_one_address_is_refused() {
    let server = TestServer::start_with(|c| {
        c.reg_per_ip_per_hour = 3;
    })
    .await;

    for i in 0..3 {
        let mut client = TestClient::connect(&server).await;
        let login = format!("user{i}");
        common::register(&mut client, &login, "correct horse battery staple 7!").await;
    }

    let mut client = TestClient::connect(&server).await;
    let refused = common::authenticate(
        &mut client,
        AuthMethod::Register {
            login: "user3".to_string(),
            password: "correct horse battery staple 7!".to_string(),
            invite_code: None,
        },
    )
    .await
    .expect_err("the fourth registration from one address must be refused");

    assert!(refused.contains("Registration failed"), "{refused}");
}

/// L4: a burst of connections is cut before TLS. The TCP connection is
/// accepted, then closed without a single byte of handshake, which is the
/// entire point of checking before the cryptography.
#[tokio::test]
async fn a_connection_burst_is_cut_before_tls() {
    let server = TestServer::start_with(|c| {
        c.conn_per_ip_per_10s = 3;
    })
    .await;

    // Three connections are allowed, and they fail their handshakes
    // honestly rather than being cut.
    for _ in 0..3 {
        let mut client = TestClient::connect(&server).await;
        let refused = common::authenticate(
            &mut client,
            AuthMethod::Token {
                token: "not a token".to_string(),
            },
        )
        .await
        .expect_err("within the limit the handshake must run, not be cut");
        assert!(refused.contains("Wrong login or password"), "{refused}");
    }

    // The fourth and fifth from the same address are closed on arrival.
    for _ in 0..2 {
        let mut raw = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("tcp connect");
        let mut buf = [0u8; 1];
        use tokio::io::AsyncReadExt;
        match raw.read(&mut buf).await {
            // EOF: closed cleanly without an answer.
            Ok(0) => {}
            // A reset means closed too, the difference does not matter here.
            Err(_) => {}
            Ok(_) => panic!("the server answered a connection it should have cut"),
        }
    }
}

/// L3: a flood is paced and then cut. The burst itself is served, the
/// frames past it are delayed until the client has starved the bucket for
/// twice the burst, and then the connection goes away.
#[tokio::test]
async fn a_frame_flood_is_served_its_burst_then_cut() {
    let server = TestServer::start_with(|c| {
        c.msg_burst = 5;
        c.msg_per_sec = 1;
    })
    .await;

    let mut client = TestClient::connect(&server).await;
    common::register(&mut client, "flooder", "correct horse battery staple 7!").await;

    // 30 frames into a bucket of 5 refilling at one per second.
    for i in 0..30 {
        client
            .send(&ClientMsg::SendMsg {
                message_id: uuid::Uuid::new_v4(),
                conv_id: uuid::Uuid::new_v4(),
                content: format!("flood {i}"),
            })
            .await;
    }

    // Whatever made it through is answered with NotAMember (the
    // conversation does not exist), then the connection is cut. The
    // post-handshake burst arrives first and is not part of the flood.
    let mut answered = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(30), client.recv()).await {
            Err(_) => panic!("the server neither answered the flood nor cut it"),
            Ok(Some(msg)) => match msg {
                ServerMsg::FriendList { .. }
                | ServerMsg::PendingReqs { .. }
                | ServerMsg::UnreadSummary { .. } => continue,
                ServerMsg::Error { .. } => answered += 1,
                other => panic!("unexpected frame: {other:?}"),
            },
            Ok(None) => break,
        }
    }

    assert!(
        answered >= 5,
        "even the burst was not served: {answered} frames"
    );
    assert!(
        answered < 30,
        "the whole flood was served, the cut never happened"
    );
}
