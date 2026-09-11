//! Dispatch of authenticated client commands (protocol v2)
//!
//! Everything is addressed by conversation, never by peer - that is what keeps
//! group chats additive later

use uuid::Uuid;
use zeevum_protocol::{ClientMsg, ErrorCode, MAX_MESSAGE_LEN, ServerMsg, UserBrief};

use crate::db;
use crate::db::FriendReqOutcome;
use crate::frames::frame;
use crate::server::AppContext;

/// What the connection loop should do once a command has been handled
pub enum Flow {
    /// Keep reading frames
    Continue,
    /// Drop the connection
    Disconnect,
}

/// Sends a refusal the client can branch on
///
/// The detail stays on the server, it can mention internals, and the client is
/// expected to render its own text for a code
fn refuse(ctx: &AppContext, to_user_id: i64, code: ErrorCode) {
    let _ = ctx
        .hub
        .send_to(to_user_id, &frame(&ServerMsg::Error { code, detail: None }));
}

/// Reports a failure that the client cannot act on
fn fail(ctx: &AppContext, to_user_id: i64, what: &str, e: &anyhow::Error) {
    error!("{what}: {e}");
    refuse(ctx, to_user_id, ErrorCode::Internal);
}

fn brief(user: &db::User) -> UserBrief {
    UserBrief {
        user_id: user.user_id,
        login: user.login.clone(),
    }
}

/// Opens the direct conversation with a user, creating it on first use
async fn on_resolve_dm(
    ctx: &AppContext,
    user: &db::User,
    peer_user_id: i64,
) -> anyhow::Result<Flow> {
    if peer_user_id == user.user_id {
        refuse(ctx, user.user_id, ErrorCode::CannotTargetYourself);
        return Ok(Flow::Continue);
    }

    let Some(peer) = db::get_user_by_user_id(&ctx.pool, peer_user_id).await? else {
        refuse(ctx, user.user_id, ErrorCode::UserNotFound);
        return Ok(Flow::Continue);
    };

    if !db::are_friends(&ctx.pool, &user.id, &peer.id).await? {
        refuse(ctx, user.user_id, ErrorCode::NotFriends);
        return Ok(Flow::Continue);
    }

    let conv_id = db::get_or_create_private_chat(&ctx.pool, &user.id, &peer.id).await?;

    let _ = ctx.hub.send_to(
        user.user_id,
        &frame(&ServerMsg::DmResolved {
            conv_id,
            peer: brief(&peer),
        }),
    );

    Ok(Flow::Continue)
}

/// Streams the history of a conversation the caller belongs to
async fn on_history_req(ctx: &AppContext, user: &db::User, conv_id: Uuid) -> anyhow::Result<Flow> {
    if !db::is_member(&ctx.pool, &conv_id, &user.id).await? {
        refuse(ctx, user.user_id, ErrorCode::NotAMember);
        return Ok(Flow::Continue);
    }

    let mut history = db::get_chat_history(&ctx.pool, &conv_id, zeevum_protocol::HISTORY_LIMIT)
        .await?
        .into_iter()
        .map(
            |(message_id, sender, content, timestamp, is_read)| ServerMsg::HistoryMsg {
                message_id,
                conv_id,
                sender_user_id: sender,
                timestamp,
                content,
                is_read,
            },
        )
        .collect::<Vec<_>>();

    history.reverse();

    for message in history {
        let _ = ctx.hub.send_to(user.user_id, &frame(&message));
    }

    let _ = ctx
        .hub
        .send_to(user.user_id, &frame(&ServerMsg::HistoryEnd { conv_id }));

    Ok(Flow::Continue)
}

/// Stores a message and pushes it to the other participants
async fn on_send_msg(
    ctx: &AppContext,
    user: &db::User,
    message_id: Uuid,
    conv_id: Uuid,
    content: String,
) -> anyhow::Result<Flow> {
    if content.len() > MAX_MESSAGE_LEN {
        refuse(ctx, user.user_id, ErrorCode::MessageTooLong);
        return Ok(Flow::Continue);
    }

    if !db::is_member(&ctx.pool, &conv_id, &user.id).await? {
        refuse(ctx, user.user_id, ErrorCode::NotAMember);
        return Ok(Flow::Continue);
    }

    db::save_chat_message(&ctx.pool, &message_id, &conv_id, &user.id, &content).await?;

    let _ = ctx.hub.send_to(
        user.user_id,
        &frame(&ServerMsg::MsgAck {
            message_id,
            conv_id,
        }),
    );

    let timestamp = chrono::Utc::now().timestamp();
    let recipients = db::member_user_ids(&ctx.pool, &conv_id).await?;

    for recipient in recipients {
        if recipient == user.user_id {
            continue;
        }
        let _ = ctx.hub.send_to(
            recipient,
            &frame(&ServerMsg::RecvMsg {
                message_id,
                conv_id,
                sender_user_id: user.user_id,
                timestamp,
                content: content.clone(),
            }),
        );
    }

    Ok(Flow::Continue)
}

/// Handles one command from an authenticated user
///
/// Every reply is pushed into the users outgoing queue in [`crate::hub::Hub`]
/// a user that is not connected simply does not receive it
pub async fn dispatch(cmd: ClientMsg, user: &db::User, ctx: &AppContext) -> Flow {
    let user_id = user.id;
    let my_user_id = user.user_id;

    match cmd {
        ClientMsg::Auth { .. } => {
            warning!("Unexpected Auth frame from {}", user.login);
            Flow::Disconnect
        }

        ClientMsg::PowSolution { .. } => {
            warning!("Unexpected PowSolution frame from {}", user.login);
            Flow::Disconnect
        }

        ClientMsg::SearchUser { login } => {
            match db::get_user_by_login(&ctx.pool, &login).await {
                Ok(Some(found)) => {
                    let _ = ctx.hub.send_to(
                        my_user_id,
                        &frame(&ServerMsg::UserFound {
                            user: brief(&found),
                        }),
                    );
                }
                Ok(None) => {
                    let _ = ctx
                        .hub
                        .send_to(my_user_id, &frame(&ServerMsg::UserNotFound));
                }
                Err(e) => fail(
                    ctx,
                    my_user_id,
                    &format!("SearchUser failed for {login}"),
                    &e,
                ),
            }
            Flow::Continue
        }

        ClientMsg::FriendReq { target_user_id } => {
            match db::get_user_by_user_id(&ctx.pool, target_user_id).await {
                Ok(Some(target)) => {
                    match db::add_friend_request(&ctx.pool, &user_id, &target.id).await {
                        Ok(FriendReqOutcome::Sent) => {
                            let _ = ctx.hub.send_to(
                                target_user_id,
                                &frame(&ServerMsg::IncomingReq { from: brief(user) }),
                            );
                            let _ = ctx.hub.send_to(
                                my_user_id,
                                &frame(&ServerMsg::FriendReqSent {
                                    user: brief(&target),
                                }),
                            );
                        }
                        Ok(FriendReqOutcome::AlreadyPending) => {
                            let _ = ctx.hub.send_to(
                                my_user_id,
                                &frame(&ServerMsg::FriendReqSent {
                                    user: brief(&target),
                                }),
                            );
                        }
                        Ok(FriendReqOutcome::AlreadyFriends) => {
                            refuse(ctx, my_user_id, ErrorCode::AlreadyFriends)
                        }
                        Err(e) => fail(
                            ctx,
                            my_user_id,
                            &format!("FriendReq from {}", user.login),
                            &e,
                        ),
                    }
                }
                Ok(None) => refuse(ctx, my_user_id, ErrorCode::UserNotFound),
                Err(e) => fail(
                    ctx,
                    my_user_id,
                    &format!("FriendReq lookup for {}", user.login),
                    &e,
                ),
            }
            Flow::Continue
        }

        ClientMsg::AcceptFriend { target_user_id } => {
            match db::get_user_by_user_id(&ctx.pool, target_user_id).await {
                Ok(Some(target)) => {
                    match db::accept_friend_request(&ctx.pool, &user_id, &target.id).await {
                        Ok(true) => {
                            let _ = ctx.hub.send_to(
                                target_user_id,
                                &frame(&ServerMsg::FriendAdded { user: brief(user) }),
                            );
                            let _ = ctx.hub.send_to(
                                my_user_id,
                                &frame(&ServerMsg::FriendAdded {
                                    user: brief(&target),
                                }),
                            );
                        }
                        Ok(false) => refuse(ctx, my_user_id, ErrorCode::NoPendingRequest),
                        Err(e) => fail(
                            ctx,
                            my_user_id,
                            &format!("AcceptFriend from {}", user.login),
                            &e,
                        ),
                    }
                }
                Ok(None) => refuse(ctx, my_user_id, ErrorCode::UserNotFound),
                Err(e) => fail(
                    ctx,
                    my_user_id,
                    &format!("AcceptFriend lookup for {}", user.login),
                    &e,
                ),
            }
            Flow::Continue
        }

        ClientMsg::ResolveDm { peer_user_id } => {
            match on_resolve_dm(ctx, user, peer_user_id).await {
                Ok(flow) => flow,
                Err(e) => {
                    fail(
                        ctx,
                        user.user_id,
                        &format!("ResolveDm for {}", user.login),
                        &e,
                    );
                    Flow::Continue
                }
            }
        }

        ClientMsg::HistoryReq { conv_id } => match on_history_req(ctx, user, conv_id).await {
            Ok(flow) => flow,
            Err(e) => {
                fail(
                    ctx,
                    user.user_id,
                    &format!("HistoryReq for {}", user.login),
                    &e,
                );
                Flow::Continue
            }
        },

        ClientMsg::SendMsg {
            message_id,
            conv_id,
            content,
        } => match on_send_msg(ctx, user, message_id, conv_id, content).await {
            Ok(flow) => flow,
            Err(e) => {
                fail(
                    ctx,
                    user.user_id,
                    &format!("SendMsg from {}", user.login),
                    &e,
                );
                Flow::Continue
            }
        },

        ClientMsg::MarkRead { message_id } => {
            match db::mark_message_as_read_checked(&ctx.pool, &message_id, &user_id).await {
                Ok(Some((conv_id, sender_user_id))) => {
                    let _ = ctx.hub.send_to(
                        sender_user_id,
                        &frame(&ServerMsg::MsgRead {
                            message_id,
                            conv_id,
                        }),
                    );
                }
                Ok(None) => {}
                Err(e) => fail(
                    ctx,
                    user.user_id,
                    &format!("MarkRead from {}", user.login),
                    &e,
                ),
            }
            Flow::Continue
        }
    }
}
