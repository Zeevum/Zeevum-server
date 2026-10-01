use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::{AsyncWriteExt, BufReader as AsyncBufReader, split};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use zeevum_protocol::{ClientMsg, ErrorCode, ServerMsg, UnreadEntry, UserBrief, decode};

use crate::db;
use crate::frames::{frame, read_frame};
use crate::handlers::{self, Flow};
use crate::handshake::{self, HandshakeError};
use crate::ratelimit::{TokenBucket, Verdict};
use crate::server::AppContext;

pub async fn handle_client(
    stream: TcpStream,
    peer_address: SocketAddr,
    ctx: AppContext,
    tls_acceptor: TlsAcceptor,
) {
    let peer_ip = peer_address.ip();

    {
        // L4 first: it counts connections and refuses the excess before
        // TLS, so a flooding address never costs a handshake. L1 next: an
        // address that has failed too many handshakes is not served
        // either. One lock for both, the critical section is a handful of
        // instructions.
        let mut limiter = ctx.rate_limiter.lock().unwrap();
        let now = Instant::now();
        if !limiter.connection_allowed(peer_ip, now) {
            warning!("Connection from {peer_address} cut: too many connections from this address");
            return;
        }
        if limiter.handshake_blocked(peer_ip, now) {
            warning!("Connection from {peer_address} blocked due to rate limit");
            return;
        }
    }

    trace!("Handling connection from: {peer_address}");

    stream.set_nodelay(true).ok();

    let mut tls_stream = match tls_acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warning!("TLS handshake failed for {peer_address}: {e}");
            return;
        }
    };

    let outcome = match handshake::handshake(&mut tls_stream, peer_address, &ctx).await {
        Ok(o) => {
            ctx.rate_limiter
                .lock()
                .unwrap()
                .clear_handshake_failures(peer_ip, Instant::now());
            o
        }
        Err(e) => {
            warning!(
                "Handshake failed for {peer_address}: [{}] {}",
                e.code(),
                e.detail()
            );

            // Only bad credentials count against the IP, a client that simply
            // speaks the wrong protocol version is not attacking anything.
            if matches!(e, HandshakeError::Auth(..)) {
                ctx.rate_limiter
                    .lock()
                    .unwrap()
                    .record_handshake_failure(peer_ip, Instant::now());
            }

            // The detail stays on the server, it can mention internals. The
            // client gets the code and decides what to show.
            send(
                &mut tls_stream,
                &frame(&ServerMsg::Error {
                    code: e.code(),
                    detail: None,
                }),
            )
            .await;
            return;
        }
    };

    let (mut user, token, expires_at) = match outcome {
        // Password and registration are where a token is born.
        handshake::AuthOutcome::NewSession(user) => {
            match db::create_session(&ctx.pool, user.id, ctx.config.session_duration_hours).await {
                Ok((token, expires_at)) => (user, token, expires_at),
                Err(e) => {
                    error!("Failed to create session: {e}");
                    send(
                        &mut tls_stream,
                        &frame(&ServerMsg::Error {
                            code: ErrorCode::Internal,
                            detail: None,
                        }),
                    )
                    .await;
                    return;
                }
            }
        }
        // The client arrived with a token, that row exists and validating it
        // has just renewed the expiry, creating another one adds a row per reconnect.
        handshake::AuthOutcome::ReusedSession(user, token, expires_at) => (user, token, expires_at),
    };

    // Ties this connection to its row in `sessions`, Logout needs it to revoke the right one.
    let session_token = token.clone();

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let tx_cleanup = tx.clone();
    // Lets the hub close this connection, which "log out everywhere" needs, without
    // a signal the read loop would sit in read_frame until the client spoke.
    let (kick_tx, mut kick_rx) = tokio::sync::watch::channel(false);
    ctx.hub.register(user.user_id, tx, kick_tx);

    let (reader, mut writer) = split(tls_stream);
    let mut reader = AsyncBufReader::new(reader);

    info!("User {} ({}) entered main loop", user.login, peer_address);

    let write_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if writer.write_all(message.as_bytes()).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    let user_login = user.login.clone();

    let _ = ctx.hub.send_to(
        user.user_id,
        &frame(&ServerMsg::AuthOk {
            user_id: user.user_id,
            token,
            expires_at,
            must_change_password: user.must_change_password,
        }),
    );

    match db::get_friends_list(&ctx.pool, &user.id).await {
        Ok(friends) => {
            let entries = friends
                .into_iter()
                .map(|(user_id, login)| UserBrief { user_id, login })
                .collect();
            let _ = ctx
                .hub
                .send_to(user.user_id, &frame(&ServerMsg::FriendList { entries }));
        }
        Err(e) => error!("Failed to load friend list for {user_login}: {e}"),
    }

    match db::get_pending_requests(&ctx.pool, &user.id).await {
        Ok(reqs) => {
            let entries = reqs
                .into_iter()
                .map(|(user_id, login)| UserBrief { user_id, login })
                .collect();
            let _ = ctx
                .hub
                .send_to(user.user_id, &frame(&ServerMsg::PendingReqs { entries }));
        }
        Err(e) => error!("Failed to load pending requests for {user_login}: {e}"),
    }

    // After the friend list, never before it. The client empties its counts
    // when the list arrives, so a summary sent first would be wiped.
    match db::unread_summary(&ctx.pool, &user.id).await {
        Ok(rows) => {
            let entries = rows
                .into_iter()
                .map(|row| UnreadEntry {
                    conv_id: row.conv_id,
                    peer: UserBrief {
                        user_id: row.peer_user_id,
                        login: row.peer_login,
                    },
                    count: row.count as u32,
                })
                .collect();
            let _ = ctx
                .hub
                .send_to(user.user_id, &frame(&ServerMsg::UnreadSummary { entries }));
        }
        Err(e) => error!("Failed to load unread counts for {user_login}: {e}"),
    }

    // L3: frames per connection. It lives here, in the connection, because
    // two connections of one user are two buckets, and none of this needs
    // a lock.
    let mut bucket = TokenBucket::new(ctx.config.msg_burst, ctx.config.msg_per_sec);

    loop {
        let frame_res = tokio::select! {
            res = tokio::time::timeout(ctx.config.read_timeout, read_frame(&mut reader)) => res,
            // Revoked from the outside, the read future is dropped mid-flight.
            _ = kick_rx.changed() => {
                info!("Session revoked, closing {peer_address} ({user_login})");
                break;
            }
        };

        match frame_res {
            Err(_) => {
                warning!("Read timeout for {peer_address} ({user_login})");
                break;
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    trace!(
                        "Client {peer_address} ({user_login}) dropped connection without TLS close_notify"
                    );
                } else {
                    warning!("Error reading from {peer_address} ({user_login}): {e}");
                }
                break;
            }
            Ok(Ok(line)) => {
                if !line.ends_with('\n') {
                    trace!("Connection {peer_address} ({user_login}) closed mid-frame");
                    break;
                }

                let payload = line.trim();
                if payload.is_empty() {
                    continue;
                }
                trace!("Frame from {user_login}: {} bytes", payload.len());

                let cmd: ClientMsg = match decode(payload) {
                    Ok(c) => c,
                    Err(_) => {
                        warning!("Malformed frame from {user_login}, dropping connection");
                        break;
                    }
                };

                // The frame pays its token before it is allowed to cost a
                // database write. A locked account pays too: ChangePassword
                // spam is still spam.
                match bucket.verdict(Instant::now()) {
                    Verdict::Now => {}
                    Verdict::Wait(how_long) => tokio::time::sleep(how_long).await,
                    Verdict::Cut => {
                        warning!("Cutting {peer_address} ({user_login}): frame flood");
                        break;
                    }
                }

                // A password that has to be replaced locks the account until
                // it is. Checked here, in front of the dispatch and not
                // inside it, so that there is no way past: not by sending
                // some other frame first, and not through a handler that
                // forgets to guard itself.
                if user.must_change_password && !is_change_password(&cmd) {
                    let _ = ctx.hub.send_to(
                        user.user_id,
                        &frame(&ServerMsg::Error {
                            code: ErrorCode::MustChangePassword,
                            detail: None,
                        }),
                    );
                    continue;
                }

                let changed = is_change_password(&cmd);

                match handlers::dispatch(cmd, &user, &ctx, &session_token).await {
                    Flow::Continue => {
                        if changed {
                            // Read back rather than assumed: the database is
                            // the only thing that knows whether the lock is
                            // gone, and failing closed keeps it.
                            user.must_change_password =
                                db::must_change_password(&ctx.pool, user.id)
                                    .await
                                    .unwrap_or(true);
                        }
                    }
                    Flow::Disconnect => break,
                }
            }
        }
    }

    ctx.hub.unregister_if(user.user_id, &tx_cleanup);
    write_task.abort();
    trace!("Connection finished for: {peer_address} ({user_login})");
}

/// The one frame a locked account is allowed to send.
fn is_change_password(cmd: &ClientMsg) -> bool {
    matches!(cmd, ClientMsg::ChangePassword { .. })
}

/// Ignores transport errors, the caller drops the connection anyway.
async fn send(stream: &mut TlsStream<TcpStream>, data: &str) {
    let _ = stream.write_all(data.as_bytes()).await;
    let _ = stream.flush().await;
}
