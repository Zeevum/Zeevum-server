#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};
use uuid::Uuid;

use zeevum_protocol::pow::Difficulty;
use zeevum_protocol::{
    AuthMethod, ClientMsg, ErrorCode, PROTOCOL_VERSION, ServerMsg, decode, encode, pow,
};

use zeevum_server::logger::LogLevel;
use zeevum_server::{AppContext, Config, serve};

const TIMEOUT: Duration = Duration::from_secs(10);

static INIT: Once = Once::new();

pub struct TestServer {
    pub addr: SocketAddr,
    /// Tests that count rows need it, a behaviour can be wrong in the database
    /// and still look right on the wire.
    pub pool: sqlx::SqlitePool,
    roots: RootCertStore,
    /// Kept alive so the temporary directory outlives the test.
    _dir: TempDir,
}

impl TestServer {
    pub async fn start() -> Self {
        INIT.call_once(|| {
            // The binary does this in `main`, a test binary has to do it itself.
            let _ = rustls::crypto::ring::default_provider().install_default();
            // Without init the logger falls back to stderr at every level.
            zeevum_server::logger::init("Zeevum-server-test", LogLevel::Error);
        });

        let dir = TempDir::new().expect("failed to create temp dir");

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("failed to generate certificate");

        let cert_path = dir.path().join("localhost.crt");
        let key_path = dir.path().join("localhost.key");
        let cert_pem = cert.pem();
        std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert");
        std::fs::write(&key_path, signing_key.serialize_pem()).expect("write key");

        let mut roots = RootCertStore::empty();
        let der: CertificateDer<'static> =
            CertificateDer::from_pem_slice(cert_pem.as_bytes()).expect("parse cert der");
        roots.add(der).expect("add root");

        let config = Config {
            server_address: "127.0.0.1:0".to_string(),
            db_path: dir.path().join("test.sqlite"),
            read_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            tls_cert_path: cert_path,
            tls_key_path: key_path,
            // Weak keeps PoW solving negligible inside tests.
            pow_difficulty: Difficulty::Weak,
            session_duration_hours: 24.0,
            log_level: LogLevel::Error,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let ctx = AppContext::new(config).await.expect("build context");
        let pool = ctx.pool.clone();

        tokio::spawn(async move {
            if let Err(e) = serve(ctx, listener).await {
                eprintln!("test server stopped: {e}");
            }
        });

        Self {
            addr,
            roots,
            pool,
            _dir: dir,
        }
    }
}

pub struct TestClient {
    rx: BufReader<tokio::io::ReadHalf<TlsStream<TcpStream>>>,
    tx: tokio::io::WriteHalf<TlsStream<TcpStream>>,
}

impl TestClient {
    pub async fn connect(server: &TestServer) -> Self {
        let config = ClientConfig::builder()
            .with_root_certificates(server.roots.clone())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = TcpStream::connect(server.addr).await.expect("tcp connect");
        let name = ServerName::try_from("localhost").expect("server name");
        let stream = connector.connect(name, tcp).await.expect("tls connect");

        let (rx, tx) = tokio::io::split(stream);
        Self {
            rx: BufReader::new(rx),
            tx,
        }
    }

    pub async fn send(&mut self, msg: &ClientMsg) {
        let line = encode(msg).expect("encode");
        self.tx
            .write_all(line.as_bytes())
            .await
            .expect("write frame");
        self.tx.flush().await.expect("flush");
    }

    /// `None` means the server closed the connection.
    pub async fn recv(&mut self) -> Option<ServerMsg> {
        let mut line = String::new();
        match timeout(TIMEOUT, self.rx.read_line(&mut line)).await {
            Ok(Ok(0)) => None,
            Ok(Ok(_)) => Some(decode(line.trim()).expect("decode frame")),
            // The server currently drops the TLS stream without sending
            // close_notify, so rustls reports that as an error rather than EOF.
            // Either way the connection is gone, see step 5.5.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => None,
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => panic!("timed out waiting for a frame"),
        }
    }

    pub async fn recv_until<F>(&mut self, f: F) -> ServerMsg
    where
        F: Fn(&ServerMsg) -> bool,
    {
        loop {
            match self.recv().await {
                Some(msg) if f(&msg) => return msg,
                Some(_) => continue,
                None => panic!("connection closed while waiting for a frame"),
            }
        }
    }

    /// Writes raw bytes, bypassing encoding. Used to test the framing layer.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.tx.write_all(bytes).await.expect("write raw");
        self.tx.flush().await.expect("flush raw");
    }
}

#[derive(Debug)]
pub struct Session {
    pub user_id: i64,
    pub token: String,
}

pub async fn authenticate(client: &mut TestClient, method: AuthMethod) -> Result<Session, String> {
    client
        .send(&ClientMsg::Auth {
            protocol_version: PROTOCOL_VERSION,
            method,
        })
        .await;

    loop {
        match client.recv().await {
            Some(ServerMsg::PowChallenge {
                challenge,
                difficulty_bits,
            }) => {
                let nonce = pow::solve(&challenge, difficulty_bits);
                client.send(&ClientMsg::PowSolution { nonce }).await;
            }
            Some(ServerMsg::AuthOk { user_id, token, .. }) => {
                return Ok(Session { user_id, token });
            }
            Some(ServerMsg::Error { code, .. }) => return Err(format!("{code}")),
            Some(other) => panic!("unexpected frame during handshake: {other:?}"),
            None => panic!("connection closed during handshake"),
        }
    }
}

pub async fn register(client: &mut TestClient, login: &str, password: &str) -> Session {
    authenticate(
        client,
        AuthMethod::Register {
            login: login.to_string(),
            password: password.to_string(),
        },
    )
    .await
    .expect("registration failed")
}

pub async fn login(
    client: &mut TestClient,
    login: &str,
    password: &str,
) -> Result<Session, String> {
    authenticate(
        client,
        AuthMethod::Login {
            login: login.to_string(),
            password: password.to_string(),
        },
    )
    .await
}

/// The acknowledgement frames are consumed, so a caller that starts reading
/// right afterwards is not surprised by them.
pub async fn befriend(from: &mut TestClient, to: &mut TestClient, from_id: i64, to_id: i64) {
    from.send(&ClientMsg::FriendReq {
        target_user_id: to_id,
    })
    .await;

    // The other side hears about the request...
    match to
        .recv_until(|m| matches!(m, ServerMsg::IncomingReq { .. }))
        .await
    {
        ServerMsg::IncomingReq { from: who } => assert_eq!(who.user_id, from_id),
        other => panic!("expected IncomingReq, got {other:?}"),
    }

    // ...and names the requester when accepting.
    to.send(&ClientMsg::AcceptFriend {
        target_user_id: from_id,
    })
    .await;

    to.recv_until(|m| matches!(m, ServerMsg::FriendAdded { .. }))
        .await;
    from.recv_until(|m| matches!(m, ServerMsg::FriendAdded { .. }))
        .await;
}

pub async fn resolve_dm(client: &mut TestClient, peer_user_id: i64) -> Result<Uuid, ErrorCode> {
    client.send(&ClientMsg::ResolveDm { peer_user_id }).await;

    loop {
        match client.recv().await {
            Some(ServerMsg::DmResolved { conv_id, .. }) => return Ok(conv_id),
            Some(ServerMsg::Error { code, .. }) => return Err(code),
            Some(_) => continue,
            None => panic!("connection closed while resolving a conversation"),
        }
    }
}

pub fn new_message_id() -> Uuid {
    Uuid::new_v4()
}
