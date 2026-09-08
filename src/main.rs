mod config;
mod db;
mod logger;
mod hub;

use dotenvy::dotenv;

use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio::sync::mpsc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader, split};

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use Zeevum_protocol::{
    ClientMsg, PROTOCOL_VERSION, MAX_MESSAGE_LEN, ServerMsg, UserBrief, AuthMethod, decode, encode,
    pow,
};

use crate::config::Config;
use crate::hub::Hub;

static CONFIG: LazyLock<Config> = LazyLock::new(|| Config::from_env());

struct RateLimiter {
    attempts: HashMap<IpAddr, Vec<Instant>>,
    window: Duration,
    max_attempts: usize,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            window: Duration::from_secs(300),
            max_attempts: 5,
        }
    }
    fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(times) = self.attempts.get(ip) {
            let now = Instant::now();
            let recent: Vec<_> = times.iter().filter(|&&t| now.duration_since(t) < self.window).collect();
            return recent.len() >= self.max_attempts;
        }
        false
    }
    fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let times = self.attempts.entry(ip).or_insert_with(Vec::new);
        times.push(now);
        times.retain(|&t| now.duration_since(t) < self.window);
    }
    fn clear_attempts(&mut self, ip: &IpAddr) {
        self.attempts.remove(ip);
    }
}

enum HandshakeError {
    Auth(String),
    Protocol(String),
}

fn load_tls_config() -> Arc<ServerConfig> {
    let cert_file = &mut BufReader::new(File::open(&CONFIG.tls_cert_path).expect("Failed to open cert file"));
    let key_file = &mut BufReader::new(File::open(&CONFIG.tls_key_path).expect("Failed to open key file"));

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<Result<_, _>>()
        .expect("Failed to parse certs");

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(key_file).expect("Failed to parse key");

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build TLS config");

    Arc::new(config)
}

fn frame(msg: &ServerMsg) -> String {
    encode(msg).expect("ServerMsg serialization cannot fail")
}

async fn read_frame<S>(reader: &mut S) -> std::io::Result<String>
where
    S: AsyncBufReadExt + Unpin,
{
    use Zeevum_protocol::MAX_LINE_BYTES;

    let mut out: Vec<u8> = Vec::with_capacity(512);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            out.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            if out.len() > MAX_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "frame exceeds MAX_LINE_BYTES",
                ));
            }
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        out.extend_from_slice(available);
        let used = available.len();
        reader.consume(used);
        if out.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame exceeds MAX_LINE_BYTES",
            ));
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
    logger::init("Zeevum-server", CONFIG.log_level);
    info!("Zeevum-server v{} starting (protocol v{PROTOCOL_VERSION})", env!("CARGO_PKG_VERSION"));

    let _ = ctrlc::set_handler(move || {
        info!("Program exit with CTRL+C");
        std::thread::sleep(Duration::from_millis(50));
        std::process::exit(0);
    });

    let listener = TcpListener::bind(&CONFIG.server_address).await.expect("Failed to bind listener");
    info!("Server listening on {}", &CONFIG.server_address);

    let pool = db::init_database(&CONFIG.db_path).await.expect("Failed to open database");
    db::migrate(&pool).await.expect("Migration failed");

    let tls_acceptor = TlsAcceptor::from(load_tls_config());
    let fake_hash = db::hash_password("fake_password_for_timing_attack").expect("Failed to generate fake hash");
    let fake_hash_arc = Arc::new(fake_hash);

    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let hub: Hub = Hub::new();

    loop {
        match listener.accept().await {
            Ok((stream, peer_address)) => {
                let pool_clone = pool.clone();
                let tls_acceptor_clone = tls_acceptor.clone();
                let fake_hash_clone = fake_hash_arc.clone();
                let rate_limiter_clone = rate_limiter.clone();
                let hub_clone = hub.clone();

                tokio::spawn(async move {
                    handle_client(stream, peer_address, pool_clone, tls_acceptor_clone, fake_hash_clone, rate_limiter_clone, hub_clone).await;
                });
            }
            Err(e) => error!("Failed to accept connection: {e}"),
        }
    }
}

async fn handle_client(
    stream: TcpStream,
    peer_address: SocketAddr,
    pool: sqlx::SqlitePool,
    tls_acceptor: TlsAcceptor,
    fake_hash: Arc<String>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    hub: Hub,
) {
    let peer_ip = peer_address.ip();

    {
        let limiter = rate_limiter.lock().unwrap();
        if limiter.is_blocked(&peer_ip) {
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

    let user = match handshake(&mut tls_stream, peer_address, &pool, &fake_hash).await {
        Ok(u) => {
            rate_limiter.lock().unwrap().clear_attempts(&peer_ip);
            u
        }
        Err(HandshakeError::Auth(reason)) => {
            warning!("Authentication failed for {peer_address}: {reason}");
            rate_limiter.lock().unwrap().record_failure(peer_ip);
            let _ = tls_stream.write_all(frame(&ServerMsg::AuthFailed { reason }).as_bytes()).await;
            let _ = tls_stream.flush().await;
            return;
        }
        Err(HandshakeError::Protocol(reason)) => {
            warning!("Auth handshake failed for {peer_address}: {reason}");
            let _ = tls_stream.write_all(frame(&ServerMsg::AuthFailed { reason }).as_bytes()).await;
            let _ = tls_stream.flush().await;
            return;
        }
    };

    let (token, expires_at) = match db::create_session(&pool, user.id, CONFIG.session_duration_hours).await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create session: {e}");
            let _ = tls_stream.write_all(frame(&ServerMsg::AuthFailed { reason: "Internal server error".into() }).as_bytes()).await;
            return;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let tx_cleanup = tx.clone();
    hub.register(user.chat_id, tx);

    let (reader, mut writer) = split(tls_stream);
    let mut reader = AsyncBufReader::new(reader);

    info!("User {} ({}) entered main loop", user.login, peer_address);

    let write_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if writer.write_all(message.as_bytes()).await.is_err() { break; }
            if writer.flush().await.is_err() { break; }
        }
    });

    let user_chat_id = user.chat_id;
    let user_login = user.login.clone();
    let user_id = user.id;

    let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::AuthOk {
        chat_id: user_chat_id,
        token,
        expires_at,
    }));

    if let Ok(friends) = db::get_friends_list(&pool, &user_id).await {
        let entries = friends.into_iter().map(|(chat_id, login)| UserBrief { chat_id, login }).collect();
        let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::FriendList { entries }));
    }
    if let Ok(reqs) = db::get_pending_requests(&pool, &user_id).await {
        let entries = reqs.into_iter().map(|(chat_id, login)| UserBrief { chat_id, login }).collect();
        let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::PendingReqs { entries }));
    }

    loop {
        let frame_res = tokio::time::timeout(CONFIG.read_timeout, read_frame(&mut reader)).await;
        match frame_res {
            Err(_) => {
                warning!("Read timeout for {peer_address} ({user_login})");
                break;
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    trace!("Client {peer_address} ({user_login}) dropped connection without TLS close_notify");
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
                if payload.is_empty() { continue; }
                trace!("Frame from {user_login}: {} bytes", payload.len());

                let cmd: ClientMsg = match decode(payload) {
                    Ok(c) => c,
                    Err(_) => {
                        warning!("Malformed frame from {user_login}, dropping connection");
                        break;
                    }
                };

                match cmd {
                    ClientMsg::Auth { .. } => {
                        warning!("Unexpected Auth frame from {user_login}");
                        break;
                    }
                    ClientMsg::SearchUser { login } => {
                        match db::get_user_by_login(&pool, &login).await {
                            Ok(Some(found)) => {
                                let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::UserFound {
                                    user: UserBrief { chat_id: found.chat_id, login: found.login },
                                }));
                            }
                            _ => {
                                let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::UserNotFound));
                            }
                        }
                    }
                    ClientMsg::FriendReq { target_chat_id } => {
                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &target_chat_id).await {
                            let _ = db::add_friend_request(&pool, &user_id, &target.id).await;
                            let _ = hub.send_to(target_chat_id, &frame(&ServerMsg::IncomingReq {
                                from: UserBrief { chat_id: user_chat_id, login: user_login.clone() },
                            }));
                            let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::Info { text: "Request sent".into() }));
                        }
                    }
                    ClientMsg::AcceptFriend { target_chat_id } => {
                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &target_chat_id).await {
                            let _ = db::accept_friend_request(&pool, &user_id, &target.id).await;
                            let _ = hub.send_to(target_chat_id, &frame(&ServerMsg::FriendAdded {
                                user: UserBrief { chat_id: user_chat_id, login: user_login.clone() },
                            }));
                            let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::FriendAdded {
                                user: UserBrief { chat_id: target.chat_id, login: target.login },
                            }));
                        }
                    }
                    ClientMsg::HistoryReq { peer_chat_id } => {
                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &peer_chat_id).await {
                            if let Ok(chat_id) = db::get_or_create_private_chat(&pool, &user_id, &target.id).await {
                                if let Ok(history) = db::get_chat_history(&pool, &chat_id, Zeevum_protocol::HISTORY_LIMIT).await {
                                    for (msg_id, sender_id, content, ts, is_read) in history {
                                        let sender_chat_id = if sender_id == user_id { user_chat_id } else { target.chat_id };
                                        let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::HistoryMsg {
                                            message_id: msg_id,
                                            sender_chat_id,
                                            timestamp: ts,
                                            content,
                                            is_read,
                                        }));
                                    }
                                    let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::HistoryEnd));
                                }
                            }
                        }
                    }
                    ClientMsg::SendMsg { message_id, peer_chat_id, content } => {
                        if content.len() > MAX_MESSAGE_LEN {
                            let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::Info { text: "Message too long".into() }));
                            continue;
                        }
                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &peer_chat_id).await {
                            if let Ok(chat_id) = db::get_or_create_private_chat(&pool, &user_id, &target.id).await {
                                let _ = db::save_chat_message(&pool, &message_id, &chat_id, &user_id, &content).await;
                                let _ = hub.send_to(user_chat_id, &frame(&ServerMsg::MsgAck { message_id }));

                                let ts = chrono::Utc::now().timestamp();
                                let _ = hub.send_to(target.chat_id, &frame(&ServerMsg::RecvMsg {
                                    message_id,
                                    chat_id,
                                    sender_chat_id: user_chat_id,
                                    timestamp: ts,
                                    content,
                                }));
                            }
                        }
                    }
                    ClientMsg::MarkRead { message_id } => {
                        if let Ok(Some(sender_chat_id)) =
                            db::mark_message_as_read_checked(&pool, &message_id, &user_id).await
                        {
                            let _ = hub.send_to(sender_chat_id, &frame(&ServerMsg::MsgRead { message_id }));
                        }
                    }
                    ClientMsg::PowSolution { .. } => {
                        warning!("Unexpected PowSolution frame from {user_login}");
                        break;
                    }
                }
            }
        }
    }

    hub.unregister_if(user_chat_id, &tx_cleanup);
    write_task.abort();
    trace!("Connection finished for: {peer_address} ({user_login})");
}

async fn handshake(
    stream: &mut TlsStream<TcpStream>,
    peer: SocketAddr,
    pool: &sqlx::SqlitePool,
    fake_hash: &str,
) -> Result<db::User, HandshakeError> {
    use HandshakeError::{Auth, Protocol};

    let line = tokio::time::timeout(CONFIG.handshake_timeout, read_frame(stream))
        .await
        .map_err(|_| Protocol("Handshake timeout".into()))?
        .map_err(|e| Protocol(format!("Read error: {e}")))?;

    let msg: ClientMsg = decode(line.trim()).map_err(|_| Protocol("Malformed frame".into()))?;

    let ClientMsg::Auth { protocol_version, method } = msg else {
        return Err(Protocol("Expected Auth frame".into()));
    };

    debug!("Auth request from {peer} (proto v{protocol_version})");

    if protocol_version != PROTOCOL_VERSION {
        return Err(Protocol(format!(
            "Protocol version {protocol_version} is not supported. Server speaks v{PROTOCOL_VERSION}. Update your client."
        )));
    }

    let method = match method {
        AuthMethod::Register { login, password } => {
            let challenge = pow::generate_challenge();
            let bits = CONFIG.pow_difficulty.bits();

            let challenge_frame = frame(&ServerMsg::PowChallenge { challenge: challenge.clone(), difficulty_bits: bits });
            stream.write_all(challenge_frame.as_bytes()).await.map_err(|e| Protocol(format!("Write error: {e}")))?;
            stream.flush().await.map_err(|e| Protocol(format!("Write error: {e}")))?;

            let solve_line = tokio::time::timeout(CONFIG.handshake_timeout, read_frame(stream))
                .await
                .map_err(|_| Protocol("PoW timeout".into()))?
                .map_err(|e| Protocol(format!("Read error: {e}")))?;
            let solved: ClientMsg = decode(solve_line.trim()).map_err(|_| Protocol("Malformed PoW frame".into()))?;
            let ClientMsg::PowSolution { nonce } = solved else {
                return Err(Protocol("Expected PowSolution frame".into()));
            };
            if !pow::verify(&challenge, nonce, bits) {
                return Err(Protocol("Invalid PoW solution".into()));
            }
            AuthMethod::Register { login, password }
        }
        m => m,
    };

    let user_result = match method {
        AuthMethod::Token { token } => validate_session(pool, &token, CONFIG.session_duration_hours).await,
        AuthMethod::Login { login, password } => login_user(pool, &login, &password, fake_hash).await,
        AuthMethod::Register { login, password } => register_user(pool, &login, &password).await,
    };

    user_result.map_err(Auth)
}

async fn validate_session(pool: &sqlx::SqlitePool, token: &str, duration: f64) -> Result<db::User, String> {
    db::validate_session(pool, token, duration).await
        .map_err(|e| format!("Session error: {e}"))?
        .ok_or_else(|| "Invalid or expired token".to_string())
}

async fn register_user(pool: &sqlx::SqlitePool, login: &str, password: &str) -> Result<db::User, String> {
    match db::add_user(pool, login, password).await {
        Ok(user) => Ok(user),
        Err(e) => {
            warning!("Registration failed for '{login}': {e}");
            Err("Registration failed. Check login format and password strength.".to_string())
        }
    }
}

async fn login_user(pool: &sqlx::SqlitePool, login: &str, password: &str, fake_hash: &str) -> Result<db::User, String> {
    if let Some(existing) = db::get_user_by_login(pool, login).await.map_err(|e| e.to_string())? {
        if db::verify_password(password, &existing.password) {
            return Ok(existing);
        }
    } else {
        let _ = db::verify_password(password, fake_hash);
    }
    Err("Wrong login or password!".to_string())
}