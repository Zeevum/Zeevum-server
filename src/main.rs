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
use tokio_rustls::TlsAcceptor;
use tokio::sync::mpsc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use rand::RngExt;
use uuid::Uuid;

use crate::config::Config;
use crate::hub::Hub;

static CONFIG: LazyLock<Config> = LazyLock::new(|| Config::from_env());

#[derive(Debug, PartialEq)]
enum AuthType { Token, Register, Login }

#[derive(Debug)]
struct HandshakeData {
    auth_type: AuthType,
    login: String,
    password: String,
}

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

#[tokio::main]
async fn main() {
    dotenv().ok();
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
    logger::init("Zeevum-server", CONFIG.log_level);
    info!("Zeevum-server v{} starting", env!("CARGO_PKG_VERSION"));

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

    let user_handshake_data = match get_user_handshake_data_async(&mut tls_stream, peer_address).await {
        Ok(data) => data,
        Err(e) => {
            warning!("Auth handshake failed for {peer_address}: {e}");
            let _ = tls_stream.write_all(e.to_string().as_bytes()).await;
            let _ = tls_stream.flush().await;
            return;
        }
    };

    let user_result = match user_handshake_data.auth_type {
        AuthType::Token => validate_session(&pool, &user_handshake_data.login, CONFIG.session_duration_hours).await,
        AuthType::Login => login_user(&pool, &user_handshake_data.login, &user_handshake_data.password, &fake_hash).await,
        AuthType::Register => register_user(&pool, &user_handshake_data.login, &user_handshake_data.password).await,
    };

    let user = match user_result {
        Ok(u) => {
            rate_limiter.lock().unwrap().clear_attempts(&peer_ip);
            u
        },
        Err(error_message) => {
            warning!("Authentication failed for {peer_address}: {error_message}");
            rate_limiter.lock().unwrap().record_failure(peer_ip);
            let _ = tls_stream.write_all(format!("AUTH_FAILED {}\n", error_message).as_bytes()).await;
            let _ = tls_stream.flush().await;
            return;
        }
    };

    let (token, expires_at) = match db::create_session(&pool, user.id, CONFIG.session_duration_hours).await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create session: {e}");
            let _ = tls_stream.write_all(b"AUTH_FAILED Internal server error\n").await;
            return;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let tx_cleanup = tx.clone();
    hub.register(user.chat_id, tx);

    let (reader, mut writer) = tokio::io::split(tls_stream);
    let mut reader = AsyncBufReader::new(reader);

    info!("User {} ({}) entered main loop", user.login, peer_address);

    let write_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if writer.write_all(message.as_bytes()).await.is_err() { break; }
            if writer.flush().await.is_err() { break; }
        }
    });

    let mut buf = String::new();
    let user_chat_id = user.chat_id;
    let user_login = user.login.clone();
    let user_id = user.id;

    let _ = hub.send_to(user_chat_id, &format!("AUTH_OK {} {} {}\n", user_chat_id, token, expires_at));

    if let Ok(friends) = db::get_friends_list(&pool, &user_id).await {
        let list: Vec<String> = friends.iter().map(|(id, login)| format!("{}:{}", id, login)).collect();
        let _ = hub.send_to(user_chat_id, &format!("FRIEND_LIST {}\n", list.join(",")));
    }
    if let Ok(reqs) = db::get_pending_requests(&pool, &user_id).await {
        let list: Vec<String> = reqs.iter().map(|(id, login)| format!("{}:{}", id, login)).collect();
        let _ = hub.send_to(user_chat_id, &format!("PENDING_REQS {}\n", list.join(",")));
    }

    loop {
        buf.clear();
        match tokio::time::timeout(CONFIG.read_timeout, reader.read_line(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                let message = buf.trim().to_string();
                if message.is_empty() { continue; }
                trace!("Message from {user_login}: {} bytes", message.len());

                if let Some(rest) = message.strip_prefix("SEARCH ") {
                    if let Ok(Some(found)) = db::get_user_by_login(&pool, rest).await {
                        let _ = hub.send_to(user_chat_id, &format!("USER_FOUND {} {}\n", found.chat_id, found.login));
                    } else {
                        let _ = hub.send_to(user_chat_id, "USER_NOT_FOUND\n");
                    }
                }
                else if let Some(rest) = message.strip_prefix("FRIEND_REQ ") {
                    if let Ok(target_chat_id) = rest.parse::<i64>() {
                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &target_chat_id).await {
                            let _ = db::add_friend_request(&pool, &user_id, &target.id).await;
                            let _ = hub.send_to(target_chat_id, &format!("INCOMING_REQ {} {}\n", user_chat_id, user_login));
                            let _ = hub.send_to(user_chat_id, "INFO Request sent\n");
                        }
                    }
                }
                else if let Some(rest) = message.strip_prefix("ACCEPT_FRIEND ") {
                    if let Ok(target_chat_id) = rest.parse::<i64>() {
                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &target_chat_id).await {
                            let _ = db::accept_friend_request(&pool, &user_id, &target.id).await;
                            let _ = hub.send_to(target_chat_id, &format!("FRIEND_ADDED {} {}\n", user_chat_id, user_login));
                            let _ = hub.send_to(user_chat_id, &format!("FRIEND_ADDED {} {}\n", target_chat_id, target.login));
                        }
                    }
                }
                else if let Some(rest) = message.strip_prefix("GET_HISTORY ") {
                    if let Some(parts) = rest.split_whitespace().next() {
                        if let Ok(target_chat_id) = parts.parse::<i64>() {
                            if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &target_chat_id).await {
                                if let Ok(chat_id) = db::get_or_create_private_chat(&pool, &user_id, &target.id).await {
                                    if let Ok(history) = db::get_chat_history(&pool, &chat_id, 50).await {
                                        for (msg_id, sender_id, content, ts) in history {
                                            let sender_chat = if sender_id == user_id { user_chat_id } else { target_chat_id };
                                            let _ = hub.send_to(user_chat_id, &format!("HISTORY_MSG {} {} {} {}\n", msg_id, sender_chat, ts, content));
                                        }
                                        let _ = hub.send_to(user_chat_id, "HISTORY_END\n");
                                    }
                                }
                            }
                        }
                    }
                }
                else if let Some(rest) = message.strip_prefix("SEND_MSG ") {
                    let parts: Vec<&str> = rest.splitn(3, ' ').collect();
                    if parts.len() == 3 {
                        let msg_uuid = match Uuid::parse_str(parts[0]) { Ok(u) => u, Err(_) => continue };
                        let target_chat_id = match parts[1].parse::<i64>() { Ok(u) => u, Err(_) => continue };
                        let content = parts[2];

                        if let Ok(Some(target)) = db::get_user_by_chat_id(&pool, &target_chat_id).await {
                            if let Ok(chat_id) = db::get_or_create_private_chat(&pool, &user_id, &target.id).await {
                                let _ = db::save_chat_message(&pool, &msg_uuid, &chat_id, &user_id, content).await;
                                let _ = hub.send_to(user_chat_id, &format!("MSG_ACK {}\n", msg_uuid));

                                let ts = chrono::Utc::now().timestamp();
                                let _ = hub.send_to(target_chat_id, &format!("RECV_MSG {} {} {} {} {}\n", msg_uuid, chat_id, user_chat_id, ts, content));
                            }
                        }
                    }
                }
                else if let Some(rest) = message.strip_prefix("MSG_READ ") {
                    if let Ok(msg_uuid) = Uuid::parse_str(rest.trim()) {
                        if let Ok(Some(sender_chat_id)) =
                            db::mark_message_as_read_checked(&pool, &msg_uuid, &user_id).await
                        {
                            let _ = hub.send_to(sender_chat_id, &format!("MSG_READ {}\n", msg_uuid));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    trace!("Client {peer_address} ({user_login}) dropped connection without TLS close_notify");
                } else {
                    warning!("Error reading from {peer_address} ({user_login}): {e}");
                }
                break;
            }
            Err(_) => {
                warning!("Read timeout for {peer_address} ({user_login})");
                break;
            }
        }
    }

    hub.unregister_if(user_chat_id, &tx_cleanup);
    write_task.abort();
    trace!("Connection finished for: {peer_address} ({user_login})");
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

async fn get_user_handshake_data_async<S: AsyncBufReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    address: SocketAddr,
) -> Result<HandshakeData, String> {
    let mut line = String::new();

    match tokio::time::timeout(CONFIG.handshake_timeout, stream.read_line(&mut line)).await {
        Ok(Ok(0)) => return Err("Client disconnected before sending handshake\n".to_string()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(format!("Failed to read handshake: {e}\n")),
        Err(_) => return Err("Handshake timeout\n".to_string()),
    }

    let line = line.trim();
    let mut parts = line.splitn(3, ' ');
    let command = parts.next().ok_or("Missing command\n".to_string())?;
    let login = parts.next().unwrap_or("");
    let password = parts.next().unwrap_or("");

    let auth_type = match command.to_uppercase().as_str() {
        "AUTH_TOKEN" => AuthType::Token,
        "LOGIN" => AuthType::Login,
        "REGISTER" => AuthType::Register,
        _ => return Err("Invalid command\n".to_string()),
    };

    if auth_type != AuthType::Token && (login.is_empty() || password.is_empty()) {
        return Err("Missing login or password\n".to_string());
    }

    if auth_type == AuthType::Register {
        let challenge: String = (0..16)
            .map(|_| format!("{:x}", rand::rng().random_range(0..16)))
            .collect();
        let difficulty = CONFIG.pow_difficulty;

        stream.write_all(format!("SOLVE {} {}\n", challenge, difficulty).as_bytes()).await.map_err(|e| format!("Write error: {e}\n"))?;
        stream.flush().await.map_err(|e| format!("Flush error: {e}\n"))?;

        let mut solve_line = String::new();
        match tokio::time::timeout(CONFIG.handshake_timeout, stream.read_line(&mut solve_line)).await {
            Ok(Ok(0)) => return Err("Client disconnected before sending PoW\n".to_string()),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("Failed to read PoW: {e}\n")),
            Err(_) => return Err("PoW timeout\n".to_string()),
        }

        let solve_line = solve_line.trim();
        if let Some(nonce_str) = solve_line.strip_prefix("SOLVED ") {
            if let Ok(nonce) = nonce_str.parse::<u64>() {
                if !verify_pow(&challenge, nonce, difficulty) {
                    return Err("Invalid PoW solution\n".to_string());
                }
            } else {
                return Err("Invalid PoW format\n".to_string());
            }
        } else {
            return Err("Did not receive PoW solution\n".to_string());
        }
    }

    Ok(HandshakeData {
        auth_type,
        login: login.to_string(),
        password: password.to_string(),
    })
}

fn verify_pow(challenge: &str, nonce: u64, difficulty: usize) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(nonce.to_string().as_bytes());
    let result = hasher.finalize();

    match difficulty {
        4 => result[30] == 0 && result[31] == 0,
        5 => result[30] == 0 && result[31] == 0 && result[29] < 0x10,
        6 => result[29] == 0 && result[30] == 0 && result[31] == 0,
        _ => false,
    }
}